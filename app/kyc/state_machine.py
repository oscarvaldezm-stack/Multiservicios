"""
Máquina de estados del KYC: ÚNICA vía para cambiar kyc_profiles.status.

- ALLOWED_TRANSITIONS define qué pares existen y quién puede ejecutarlos.
- transition() bloquea la fila (SELECT ... FOR UPDATE), valida versión, actor,
  asignación y motivo, aplica efectos (fechas, ciclo, revisor asignado) y escribe
  historial + auditoría + evento de notificación en la MISMA transacción.
- Un trigger de PostgreSQL (migración 0002) repite la validación de pares, para que
  ni un script ni un UPDATE manual puedan saltarse la tabla.

Las precondiciones de negocio (documentos completos, domicilio confirmado, etc.)
las aporta la capa de servicio mediante el parámetro `precondition`.
"""
from __future__ import annotations

import enum
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.models.enums import ActorType, AdminRole, KycStatus
from app.models.kyc import KycProfile, KycStatusHistory, OutboxEvent

S = KycStatus


class Who(str, enum.Enum):
    """Quién puede ejecutar una transición."""

    TECHNICIAN = "TECHNICIAN"          # el dueño del expediente
    REVIEWER = "REVIEWER"              # KYC_REVIEWER; si el caso está en revisión, debe estar asignado a él
    SUPERVISOR = "SUPERVISOR"          # KYC_SUPERVISOR
    SYSTEM = "SYSTEM"                  # jobs automáticos


@dataclass(frozen=True)
class Rule:
    who: frozenset[Who]
    reason_required: bool = False
    notify: str | None = None          # tipo de evento para el outbox


def _r(*who: Who, reason: bool = False, notify: str | None = None) -> Rule:
    return Rule(frozenset(who), reason, notify)


ALLOWED_TRANSITIONS: dict[tuple[KycStatus, KycStatus], Rule] = {
    (S.NOT_STARTED, S.PENDING_DOCUMENTS): _r(Who.TECHNICIAN, Who.SYSTEM),
    (S.PENDING_DOCUMENTS, S.SUBMITTED): _r(Who.TECHNICIAN, notify="kyc.submitted"),
    (S.SUBMITTED, S.UNDER_REVIEW): _r(Who.REVIEWER, Who.SUPERVISOR, notify="kyc.under_review"),
    (S.UNDER_REVIEW, S.SUBMITTED): _r(Who.REVIEWER, Who.SUPERVISOR, Who.SYSTEM),  # liberar caso
    (S.UNDER_REVIEW, S.APPROVED): _r(Who.REVIEWER, Who.SUPERVISOR, notify="kyc.approved"),
    (S.UNDER_REVIEW, S.CORRECTION_REQUIRED): _r(Who.REVIEWER, Who.SUPERVISOR, reason=True,
                                                notify="kyc.correction_required"),
    (S.UNDER_REVIEW, S.REJECTED): _r(Who.SUPERVISOR, reason=True, notify="kyc.rejected"),
    (S.CORRECTION_REQUIRED, S.SUBMITTED): _r(Who.TECHNICIAN, notify="kyc.submitted"),
    (S.APPROVED, S.SUSPENDED): _r(Who.SUPERVISOR, reason=True, notify="kyc.suspended"),
    (S.APPROVED, S.EXPIRED): _r(Who.SYSTEM, reason=True, notify="kyc.expired"),
    (S.EXPIRED, S.SUBMITTED): _r(Who.TECHNICIAN, notify="kyc.submitted"),
    (S.SUSPENDED, S.UNDER_REVIEW): _r(Who.SUPERVISOR, reason=True, notify="kyc.under_review"),
}

# Estados desde los que el técnico envía un NUEVO ciclo de revisión.
_NEW_CYCLE_FROM = {S.PENDING_DOCUMENTS, S.CORRECTION_REQUIRED, S.EXPIRED}


# ---------------------------------------------------------------------------
# Errores (la API los traduce a códigos HTTP)
# ---------------------------------------------------------------------------
class KycTransitionError(Exception):
    http_status = 409
    code = "KYC_TRANSITION_ERROR"


class InvalidTransition(KycTransitionError):
    code = "KYC_INVALID_TRANSITION"


class StaleVersion(KycTransitionError):
    code = "KYC_STALE_VERSION"


class ActorNotAllowed(KycTransitionError):
    http_status = 403
    code = "KYC_ACTOR_NOT_ALLOWED"


class NotAssignedReviewer(KycTransitionError):
    http_status = 403
    code = "KYC_NOT_ASSIGNED"


class ReasonRequired(KycTransitionError):
    http_status = 422
    code = "KYC_REASON_REQUIRED"


class ProfileNotFound(KycTransitionError):
    http_status = 404
    code = "KYC_NOT_FOUND"


# ---------------------------------------------------------------------------
def _actor_capacities(actor: Actor, profile: KycProfile) -> set[Who]:
    caps: set[Who] = set()
    if actor.actor_type == ActorType.SYSTEM:
        caps.add(Who.SYSTEM)
    elif actor.actor_type == ActorType.TECHNICIAN:
        if actor.user_id == profile.technician_id:
            caps.add(Who.TECHNICIAN)
    elif actor.actor_type == ActorType.ADMIN:
        if actor.has_role(AdminRole.KYC_SUPERVISOR):
            caps.add(Who.SUPERVISOR)
        if actor.has_role(AdminRole.KYC_REVIEWER):
            caps.add(Who.REVIEWER)
    return caps


def can_transition(from_status: KycStatus, to_status: KycStatus) -> bool:
    return (from_status, to_status) in ALLOWED_TRANSITIONS


def transition(
    db: Session,
    profile_id: uuid.UUID,
    to_status: KycStatus,
    actor: Actor,
    *,
    reason_code: str | None = None,
    note: str | None = None,
    expected_version: int | None = None,
    precondition: Callable[[KycProfile], None] | None = None,
    ctx: RequestContext | None = None,
) -> KycProfile:
    """Aplica una transición. No hace commit: el llamador controla la transacción."""
    profile = db.execute(
        select(KycProfile).where(KycProfile.id == profile_id).with_for_update()
    ).scalar_one_or_none()
    if profile is None:
        raise ProfileNotFound("Expediente no encontrado")

    from_status = profile.status
    rule = ALLOWED_TRANSITIONS.get((from_status, to_status))
    if rule is None:
        raise InvalidTransition(f"Transición no permitida: {from_status.value} → {to_status.value}")

    if expected_version is not None and expected_version != profile.version:
        raise StaleVersion("El expediente cambió mientras lo revisabas; recarga e intenta de nuevo")

    caps = _actor_capacities(actor, profile) & rule.who
    if not caps:
        raise ActorNotAllowed("No tienes permiso para esta acción sobre el expediente")

    # Un revisor (sin rol de supervisor) solo decide sobre el caso que tiene asignado.
    if from_status == S.UNDER_REVIEW and caps == {Who.REVIEWER} and profile.assigned_reviewer_id != actor.user_id:
        raise NotAssignedReviewer("Este caso no está asignado a ti")

    if rule.reason_required and not reason_code:
        raise ReasonRequired("Esta acción requiere un motivo")

    if precondition is not None:
        precondition(profile)

    now = datetime.now(timezone.utc)
    profile.status = to_status
    _apply_effects(profile, from_status, to_status, actor, now)

    db.add(KycStatusHistory(
        kyc_profile_id=profile.id,
        from_status=from_status,
        to_status=to_status,
        actor_id=actor.user_id,
        actor_type=actor.actor_type,
        reason_code=reason_code,
        note=note,
        request_id=ctx.request_id if ctx else None,
    ))
    write_audit(
        db,
        action=f"kyc.status.{to_status.value.lower()}",
        actor=actor,
        technician_id=profile.technician_id,
        kyc_profile_id=profile.id,
        target_type="kyc_profile",
        target_id=str(profile.id),
        reason_code=reason_code,
        reason_note=note,
        changes={"status": {"from": from_status.value, "to": to_status.value}, "version": profile.version},
        ctx=ctx,
    )
    if rule.notify:
        db.add(OutboxEvent(
            event_type=rule.notify,
            aggregate_type="kyc_profile",
            aggregate_id=profile.id,
            recipient_user_id=profile.technician_id,
            payload={"status": to_status.value, "reason_code": reason_code},
        ))
    db.flush()
    return profile


def _apply_effects(profile: KycProfile, from_status: KycStatus, to_status: KycStatus,
                   actor: Actor, now: datetime) -> None:
    if to_status == S.SUBMITTED and from_status in _NEW_CYCLE_FROM:
        profile.cycle += 1
        profile.submitted_at = now
    elif to_status == S.UNDER_REVIEW and from_status == S.SUSPENDED:
        profile.cycle += 1                 # la reactivación es una revisión nueva, con su propio registro

    if to_status == S.UNDER_REVIEW:
        profile.assigned_reviewer_id = actor.user_id
        profile.assigned_at = now
    elif from_status == S.UNDER_REVIEW:
        profile.assigned_reviewer_id = None
        profile.assigned_at = None

    if to_status == S.APPROVED:
        profile.approved_at = now
        profile.approved_by_id = actor.user_id
        profile.suspended_at = None
    elif to_status == S.REJECTED:
        profile.rejected_at = now
    elif to_status == S.SUSPENDED:
        profile.suspended_at = now

    profile.version += 1
