"""
Decisiones sobre expedientes KYC (Fase 4): tomar / liberar caso, decidir cada documento,
aprobar, pedir corrección, rechazar, suspender y reactivar.

Controles:
- Permiso del rol (Permission.*) + acceso al objeto (asignado a él o supervisor, en su región).
- Concurrencia: FOR UPDATE sobre el expediente + `expected_version` (dos revisores no pisan
  la decisión del otro).
- Aprobar exige que TODOS los documentos enviados estén decididos y que cada categoría
  obligatoria tenga uno aprobado y vigente. Si hay señales de riesgo (mismo número de
  documento o el mismo archivo en otro expediente), solo un SUPERVISOR puede aprobar.
- Motivos siempre del catálogo y del alcance correcto; nota obligatoria cuando el motivo la pide.
- Suspender o vencer a un técnico le quita de inmediato las órdenes que aún no inicia.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.audit.writer import write_audit, write_audit_detached
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.kyc.access import can_read_case, region_scope
from app.kyc.permissions import Permission, permissions_for
from app.kyc.requirements import REQUIRED_CATEGORIES
from app.kyc.state_machine import KycTransitionError, transition
from app.models import (
    AuditResult,
    DocumentCategory,
    DocumentDecision,
    KycAddress,
    KycDocument,
    KycDocumentReview,
    KycDocumentStatus,
    KycProfile,
    KycReview,
    KycStatus,
    ReasonScope,
    RejectionReason,
    ReviewDecision,
    ScanStatus,
)

S = KycStatus
D = KycDocumentStatus

# Estados de documento "vivos" dentro del expediente (lo demás es historia).
_DECIDABLE = {D.PENDING_REVIEW, D.APPROVED, D.REJECTED}
_NOT_FOUND = DomainError("Expediente no encontrado", code="KYC_CASE_NOT_FOUND", http_status=404)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _need(actor: Actor, perm: Permission, ctx: RequestContext | None = None) -> None:
    if perm not in permissions_for(actor.admin_roles):
        write_audit_detached(action="admin.permission.denied", actor=actor, result=AuditResult.DENIED,
                             target_type="permission", target_id=perm.value, ctx=ctx)
        raise DomainError("No tienes permiso para esta acción", code="PERMISSION_DENIED", http_status=403)


def _lock_profile(db: Session, case_id: uuid.UUID) -> KycProfile:
    profile = db.execute(select(KycProfile).where(KycProfile.id == case_id).with_for_update()).scalar_one_or_none()
    if profile is None:
        raise _NOT_FOUND
    return profile


def _reason(db: Session, code: str | None, scope: ReasonScope, note: str | None) -> RejectionReason:
    reason = db.scalar(select(RejectionReason).where(RejectionReason.code == (code or ""),
                                                     RejectionReason.scope == scope,
                                                     RejectionReason.is_active.is_(True)))
    if reason is None:
        raise DomainError("Motivo inválido para esta acción", code="KYC_REASON_INVALID", http_status=422,
                          extra={"scope": scope.value})
    if reason.requires_note and not (note and note.strip()):
        raise DomainError("Este motivo requiere una nota explicativa", code="KYC_NOTE_REQUIRED", http_status=422)
    return reason


def _current_review(db: Session, profile: KycProfile) -> KycReview:
    review = db.scalar(select(KycReview).where(KycReview.kyc_profile_id == profile.id,
                                               KycReview.cycle == profile.cycle))
    if review is None:
        review = KycReview(kyc_profile_id=profile.id, cycle=profile.cycle)
        db.add(review)
        db.flush()
    return review


def _live_documents(db: Session, profile: KycProfile) -> list[KycDocument]:
    return db.scalars(
        select(KycDocument)
        .where(KycDocument.kyc_profile_id == profile.id, KycDocument.deleted_at.is_(None),
               KycDocument.status.in_(_DECIDABLE))
        .options(selectinload(KycDocument.files), selectinload(KycDocument.document_type))
    ).all()


def _deny(actor: Actor, case_id: uuid.UUID, ctx: RequestContext | None, technician_id=None) -> DomainError:
    """El intento queda auditado en su propia transacción (el error hace rollback de la principal)."""
    write_audit_detached(action="kyc.case.access_denied", actor=actor, result=AuditResult.DENIED,
                         technician_id=technician_id, target_type="kyc_profile", target_id=str(case_id), ctx=ctx)
    return _NOT_FOUND


def _require_case_access(db: Session, actor: Actor, profile: KycProfile, ctx: RequestContext | None = None) -> None:
    if not can_read_case(db, actor, profile):
        raise _deny(actor, profile.id, ctx, profile.technician_id)   # mismo 404 que un caso inexistente


# =============================================================================
# Tomar y liberar
# =============================================================================
def claim(db: Session, actor: Actor, case_id: uuid.UUID, ctx: RequestContext | None = None) -> KycProfile:
    _need(actor, Permission.KYC_CASE_CLAIM, ctx)
    profile = _lock_profile(db, case_id)
    regions = region_scope(db, actor)
    if regions and Permission.KYC_CASE_READ_ANY not in permissions_for(actor.admin_roles):
        addr = db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None
        if addr is None or addr.state_id not in regions:
            raise _deny(actor, case_id, ctx, profile.technician_id)
    if profile.status != S.SUBMITTED:
        raise DomainError("Este caso ya no está disponible para tomarse", code="KYC_CASE_NOT_CLAIMABLE",
                          http_status=409, extra={"status": profile.status.value})
    active = db.scalar(select(func.count()).select_from(KycProfile).where(
        KycProfile.assigned_reviewer_id == actor.user_id, KycProfile.status == S.UNDER_REVIEW))
    if active >= get_settings().KYC_MAX_ACTIVE_CLAIMS:
        raise DomainError("Tienes demasiados casos tomados; termina o libera alguno", code="KYC_TOO_MANY_CLAIMS",
                          http_status=409)
    transition(db, profile.id, S.UNDER_REVIEW, actor, ctx=ctx)
    review = _current_review(db, profile)
    review.reviewer_id, review.claimed_at = actor.user_id, _now()
    db.flush()
    return profile


def release(db: Session, actor: Actor, case_id: uuid.UUID, expected_version: int | None,
            ctx: RequestContext | None = None) -> KycProfile:
    _need(actor, Permission.KYC_CASE_CLAIM, ctx)
    profile = _lock_profile(db, case_id)
    _require_case_access(db, actor, profile, ctx)
    transition(db, profile.id, S.SUBMITTED, actor, expected_version=expected_version, ctx=ctx)
    return profile


# =============================================================================
# Documentos
# =============================================================================
def decide_document(db: Session, actor: Actor, case_id: uuid.UUID, document_id: uuid.UUID,
                    decision: DocumentDecision, reason_code: str | None, note: str | None,
                    ctx: RequestContext | None = None) -> KycDocument:
    _need(actor, Permission.KYC_DOCUMENT_DECIDE, ctx)
    profile = _lock_profile(db, case_id)
    _require_case_access(db, actor, profile, ctx)
    if profile.status != S.UNDER_REVIEW:
        raise DomainError("Solo se deciden documentos de un caso en revisión", code="KYC_NOT_UNDER_REVIEW",
                          http_status=409)
    if Permission.KYC_CASE_READ_ANY not in permissions_for(actor.admin_roles) \
            and profile.assigned_reviewer_id != actor.user_id:
        raise _deny(actor, case_id, ctx, profile.technician_id)
    doc = db.scalar(select(KycDocument).where(KycDocument.id == document_id, KycDocument.kyc_profile_id == profile.id,
                                              KycDocument.deleted_at.is_(None))
                    .options(selectinload(KycDocument.files)).with_for_update())
    if doc is None:
        raise DomainError("Documento no encontrado", code="KYC_DOCUMENT_NOT_FOUND", http_status=404)
    # Se puede cambiar de opinión dentro del mismo ciclo, no reescribir decisiones de ciclos anteriores.
    if doc.status not in _DECIDABLE or (doc.status != D.PENDING_REVIEW and doc.review_cycle != profile.cycle):
        raise DomainError("Este documento no está pendiente de revisión en este ciclo",
                          code="KYC_DOCUMENT_NOT_DECIDABLE", http_status=409, extra={"status": doc.status.value})

    reason = None
    if decision == DocumentDecision.REJECTED:
        reason = _reason(db, reason_code, ReasonScope.DOCUMENT, note)
    else:
        live = [f for f in doc.files if f.purged_at is None]
        if not live or any(f.scan_status != ScanStatus.CLEAN for f in live):
            raise DomainError("No se puede aprobar un documento con archivos sin escaneo limpio",
                              code="KYC_DOCUMENT_NOT_CLEAN", http_status=409)

    review = _current_review(db, profile)
    row = db.scalar(select(KycDocumentReview).where(KycDocumentReview.review_id == review.id,
                                                    KycDocumentReview.document_id == doc.id))
    if row is None:
        row = KycDocumentReview(review_id=review.id, document_id=doc.id, reviewer_id=actor.user_id,
                                decision=decision)
        db.add(row)
    row.decision, row.reason_id, row.note, row.reviewer_id = decision, reason.id if reason else None, note, actor.user_id

    before = doc.status
    doc.status = D.APPROVED if decision == DocumentDecision.APPROVED else D.REJECTED
    doc.review_cycle, doc.reviewed_at, doc.reviewed_by_id = profile.cycle, _now(), actor.user_id
    doc.rejection_reason_id = reason.id if reason else None
    doc.rejection_note = note if reason else None
    write_audit(db, action=f"kyc.document.{doc.status.value.lower()}", actor=actor,
                technician_id=profile.technician_id, kyc_profile_id=profile.id, document_id=doc.id,
                target_type="kyc_document", target_id=str(doc.id), reason_code=reason.code if reason else None,
                reason_note=note, changes={"status": {"from": before.value, "to": doc.status.value}}, ctx=ctx)
    db.flush()
    return doc


# =============================================================================
# Decisión del caso
# =============================================================================
def _approval_blockers(db: Session, profile: KycProfile, docs: list[KycDocument]) -> list[str]:
    """Qué impide aprobar. Vacío = se puede."""
    s = get_settings()
    blockers: list[str] = []
    today = date.today()
    reference = (profile.submitted_at or _now()).date()        # antigüedad del comprobante al enviarse
    approved = {c: [d for d in docs if d.status == D.APPROVED and d.document_type.category == c]
                for c in REQUIRED_CATEGORIES}
    if not approved[DocumentCategory.IDENTITY]:
        blockers.append("DOC_IDENTITY")
    elif not any(d.expires_at is None or d.expires_at > today for d in approved[DocumentCategory.IDENTITY]):
        blockers.append("DOC_IDENTITY_EXPIRED")
    proofs = [d for d in approved[DocumentCategory.ADDRESS] if d.address_id == profile.current_address_id]
    if not proofs:
        blockers.append("DOC_ADDRESS_PROOF")
    elif not any(d.issued_at and d.issued_at >= reference - timedelta(
            days=d.document_type.max_age_days or s.KYC_ADDRESS_PROOF_MAX_AGE_DAYS) for d in proofs):
        blockers.append("DOC_ADDRESS_PROOF_TOO_OLD")
    if not approved[DocumentCategory.SELFIE]:
        blockers.append("DOC_SELFIE")
    if not (profile.curp_hash and profile.rfc_hash and profile.current_address_id):
        blockers.append("PERSONAL_DATA")
    return blockers


def decide(db: Session, actor: Actor, case_id: uuid.UUID, decision: ReviewDecision, *,
           reason_code: str | None, note: str | None, expected_version: int | None,
           ctx: RequestContext | None = None) -> KycProfile:
    perm = {ReviewDecision.APPROVED: Permission.KYC_APPROVE,
            ReviewDecision.CORRECTION_REQUIRED: Permission.KYC_REQUEST_CORRECTION,
            ReviewDecision.REJECTED: Permission.KYC_REJECT_FINAL}[decision]
    _need(actor, perm, ctx)
    profile = _lock_profile(db, case_id)
    _require_case_access(db, actor, profile, ctx)
    if profile.status != S.UNDER_REVIEW:
        raise DomainError("El caso no está en revisión", code="KYC_NOT_UNDER_REVIEW", http_status=409)
    if expected_version is not None and expected_version != profile.version:
        raise DomainError("El expediente cambió mientras lo revisabas; recarga e intenta de nuevo",
                          code="KYC_STALE_VERSION", http_status=409)

    docs = _live_documents(db, profile)
    undecided = [str(d.id) for d in docs if d.status == D.PENDING_REVIEW]
    reason = None
    to_status: KycStatus
    if decision == ReviewDecision.APPROVED:
        if undecided:
            raise DomainError("Decide todos los documentos antes de aprobar", code="KYC_DOCUMENTS_UNDECIDED",
                              http_status=409, extra={"documents": undecided})
        blockers = _approval_blockers(db, profile, docs)
        if blockers:
            raise DomainError("El expediente no cumple los requisitos para aprobarse",
                              code="KYC_APPROVAL_BLOCKED", http_status=409, extra={"missing": blockers})
        risky = sorted({flag for d in docs for flag in (d.risk_flags or [])})
        if risky and Permission.KYC_CASE_READ_ANY not in permissions_for(actor.admin_roles):
            # Cuatro ojos: señales de posible fraude las libera solo un supervisor.
            raise DomainError("Este expediente tiene señales de riesgo; debe aprobarlo un supervisor",
                              code="KYC_SUPERVISOR_REQUIRED", http_status=403, extra={"risk_flags": risky})
        to_status = S.APPROVED
    elif decision == ReviewDecision.CORRECTION_REQUIRED:
        reason = _reason(db, reason_code, ReasonScope.CORRECTION, note)
        if reason.code == "CORRECCION_DOCUMENTOS" and not any(d.status == D.REJECTED for d in docs):
            raise DomainError("Marca como rechazado al menos un documento para pedir su corrección",
                              code="KYC_NOTHING_TO_CORRECT", http_status=409)
        to_status = S.CORRECTION_REQUIRED
    else:
        reason = _reason(db, reason_code, ReasonScope.REJECTION, note)
        to_status = S.REJECTED

    transition(db, profile.id, to_status, actor, reason_code=reason.code if reason else None, note=note, ctx=ctx)

    now = _now()
    review = _current_review(db, profile)
    review.decision, review.decided_at, review.notes = decision, now, note
    review.reason_id = reason.id if reason else None
    review.reviewer_id = review.reviewer_id or actor.user_id
    if to_status == S.APPROVED:
        s = get_settings()
        ids = [d for d in docs if d.status == D.APPROVED and d.document_type.category == DocumentCategory.IDENTITY]
        expiries = [d.expires_at for d in ids if d.expires_at]
        profile.expires_at = (datetime.combine(min(expiries), datetime.min.time(), tzinfo=timezone.utc)
                              if expiries else None)
        profile.revalidation_due_at = now + timedelta(days=30 * s.KYC_REVALIDATION_MONTHS)
        profile.has_background_check_badge = any(
            d.status == D.APPROVED and d.document_type.category == DocumentCategory.BACKGROUND_CHECK for d in docs)
        # Reaprobado tras una suspensión o un vencimiento: su cuenta de pagos vuelve a poder cobrar.
        from app.payments.accounts import unblock_for_kyc
        unblock_for_kyc(db, profile.technician_id)
    db.flush()
    return profile


# =============================================================================
# Suspensión y reactivación
# =============================================================================
def suspend(db: Session, actor: Actor, case_id: uuid.UUID, reason_code: str, note: str | None,
            ctx: RequestContext | None = None) -> KycProfile:
    from app.orders.service import release_technician_orders
    from app.payments.accounts import block_for_kyc

    _need(actor, Permission.KYC_SUSPEND, ctx)
    profile = _lock_profile(db, case_id)
    _require_case_access(db, actor, profile, ctx)
    reason = _reason(db, reason_code, ReasonScope.SUSPENSION, note)
    transition(db, profile.id, S.SUSPENDED, actor, reason_code=reason.code, note=note, ctx=ctx)
    release_technician_orders(db, profile.technician_id, "TECHNICIAN_SUSPENDED")
    block_for_kyc(db, profile.technician_id, "KYC_SUSPENDED")
    return profile


def reinstate(db: Session, actor: Actor, case_id: uuid.UUID, note: str,
              ctx: RequestContext | None = None) -> KycProfile:
    """SUSPENDED → UNDER_REVIEW (nuevo ciclo, asignado a quien reactiva). Luego se aprueba normalmente."""
    _need(actor, Permission.KYC_REINSTATE, ctx)
    profile = _lock_profile(db, case_id)
    _require_case_access(db, actor, profile, ctx)
    reason = _reason(db, "REACTIVACION", ReasonScope.SUSPENSION, note)
    transition(db, profile.id, S.UNDER_REVIEW, actor, reason_code=reason.code, note=note, ctx=ctx)
    review = _current_review(db, profile)
    review.reviewer_id, review.claimed_at = actor.user_id, _now()
    db.flush()
    return profile


# =============================================================================
# Trabajos automáticos (worker)
# =============================================================================
def release_stale_claims(db: Session, now: datetime | None = None) -> int:
    """Casos tomados y abandonados más de KYC_REVIEW_CLAIM_TIMEOUT_HOURS vuelven a la cola."""
    now = now or _now()
    limit = now - timedelta(hours=get_settings().KYC_REVIEW_CLAIM_TIMEOUT_HOURS)
    ids = db.scalars(select(KycProfile.id).where(KycProfile.status == S.UNDER_REVIEW,
                                                 KycProfile.assigned_at < limit)).all()
    done = 0
    for pid in ids:
        try:
            with db.begin_nested():          # si un revisor decidió justo ahora, solo se salta ese caso
                transition(db, pid, S.SUBMITTED, Actor.system(), note="Liberado por tiempo sin decisión")
            done += 1
        except KycTransitionError:
            continue
    db.flush()
    return done


def expire_approvals(db: Session, now: datetime | None = None) -> int:
    """APPROVED con identificación vencida o revalidación cumplida → EXPIRED (deja de recibir órdenes)."""
    from app.orders.service import release_technician_orders
    from app.payments.accounts import block_for_kyc

    now = now or _now()
    rows = db.scalars(select(KycProfile).where(
        KycProfile.status == S.APPROVED,
        ((KycProfile.expires_at.isnot(None)) & (KycProfile.expires_at <= now))
        | ((KycProfile.revalidation_due_at.isnot(None)) & (KycProfile.revalidation_due_at <= now)),
    )).all()
    done = 0
    for p in rows:
        try:
            with db.begin_nested():          # un caso que cambió de estado a la vez no aborta el lote
                transition(db, p.id, S.EXPIRED, Actor.system(), reason_code="DOCUMENTO_OBLIGATORIO_VENCIDO")
                release_technician_orders(db, p.technician_id, "TECHNICIAN_KYC_EXPIRED")
                block_for_kyc(db, p.technician_id, "KYC_EXPIRED")
            done += 1
        except KycTransitionError:
            continue
    db.flush()
    return done
