"""
Cuenta de pagos del técnico (sección 4 del doc de pagos).

- Solo se crea con el KYC en APPROVED. La CLABE y los datos bancarios los captura y guarda
  el proveedor en su propio formulario; aquí solo el id de la cuenta y su estado.
- Se precargan nombre legal, fecha de nacimiento, domicilio, correo y teléfono del expediente
  KYC (nunca CURP ni RFC: los pide el proveedor si los necesita). Esa transferencia de datos
  debe declararse en el aviso de privacidad.
- El estado refleja al proveedor y solo cambia al consultarlo (webhook account.updated en la
  Fase 4, o la consulta explícita del técnico): nunca por lo que diga la app.
- Aparte está el BLOQUEO de la plataforma (`blocked_reason`): KYC suspendido o vencido, o un
  nombre en el proveedor distinto al del KYC (evita cobrar a la cuenta de otra persona). Una
  cuenta bloqueada no recibe pagos nuevos; nunca se borra.
"""
from __future__ import annotations

import unicodedata
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.errors import DomainError
from app.models import (
    KycAddress,
    KycProfile,
    KycStatus,
    MxState,
    OutboxEvent,
    PaymentAccountStatus,
    TechnicianPaymentAccount,
    User,
)
from app.payments.providers.base import AccountPrefill, AccountStatusInfo, OnboardingLink, PaymentProvider

S = PaymentAccountStatus

# Deben coincidir EXACTAMENTE con el trigger de la migración 0007 (lo verifica una prueba).
ALLOWED_ACCOUNT_TRANSITIONS: frozenset[tuple[PaymentAccountStatus, PaymentAccountStatus]] = frozenset({
    (S.NOT_CREATED, S.ONBOARDING),
    (S.ONBOARDING, S.PENDING_VERIFICATION), (S.ONBOARDING, S.ENABLED), (S.ONBOARDING, S.DISABLED),
    (S.PENDING_VERIFICATION, S.ENABLED), (S.PENDING_VERIFICATION, S.ONBOARDING),
    (S.PENDING_VERIFICATION, S.DISABLED),
    (S.ENABLED, S.RESTRICTED), (S.ENABLED, S.DISABLED),
    (S.RESTRICTED, S.ENABLED), (S.RESTRICTED, S.DISABLED),
})

KYC_BLOCKS = frozenset({"KYC_SUSPENDED", "KYC_EXPIRED"})
NAME_MISMATCH = "NAME_MISMATCH"
PROVIDER_DEAUTHORIZED = "PROVIDER_DEAUTHORIZED"     # el técnico desconectó la plataforma de su cuenta
SYNC_MIN_INTERVAL = timedelta(seconds=15)       # la consulta del técnico no martillea al proveedor


class PaymentAccountError(DomainError):
    http_status = 409
    code = "PAYMENT_ACCOUNT_ERROR"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# Lectura
# =============================================================================
def get_account(db: Session, technician_id: uuid.UUID, provider_name: str, *,
                lock: bool = False) -> TechnicianPaymentAccount | None:
    stmt = select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == technician_id,
                                                  TechnicianPaymentAccount.provider == provider_name)
    if lock:
        # populate_existing: lo bloqueado se relee aunque la sesión ya tuviera la fila cargada.
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    return db.scalar(stmt)


def can_receive_payments(db: Session, technician_id: uuid.UUID, provider_name: str) -> bool:
    """Regla crítica ampliada (la usará la Fase 3 al autorizar): cuenta ENABLED y sin bloqueo."""
    account = get_account(db, technician_id, provider_name)
    return account is not None and account.can_receive_payments


def _approved_profile(db: Session, technician_id: uuid.UUID) -> KycProfile:
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == technician_id)
                        .with_for_update(read=True))
    if profile is None or profile.status != KycStatus.APPROVED:
        raise PaymentAccountError("Tu verificación de identidad aún no está aprobada", code="KYC_NOT_APPROVED",
                                  http_status=403)
    return profile


# =============================================================================
# Alta y formulario del proveedor
# =============================================================================
def _prefill(db: Session, technician: User, profile: KycProfile) -> AccountPrefill:
    last = " ".join(p for p in (profile.paternal_surname, profile.maternal_surname) if p)
    addr = db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None
    state = db.get(MxState, addr.state_id) if addr else None
    line1 = f"{addr.street} {addr.exterior_number}".strip() if addr else None
    line2 = None
    if addr:
        line2 = ", ".join(p for p in (f"Int. {addr.interior_number}" if addr.interior_number else None,
                                      addr.settlement) if p)
    return AccountPrefill(technician_id=technician.id, email=technician.email,
                          first_names=profile.first_names or technician.full_name, last_names=last,
                          birth_date=profile.birth_date, phone=technician.phone, address_line1=line1,
                          address_line2=line2 or None, city=addr.city if addr else None,
                          state=state.name if state else None, postal_code=addr.postal_code if addr else None)


def create_account(db: Session, technician: User, provider: PaymentProvider,
                   ctx: RequestContext | None = None) -> TechnicianPaymentAccount:
    profile = _approved_profile(db, technician.id)
    # Fila primero (ON CONFLICT) y bloqueo: dos peticiones simultáneas no crean dos cuentas.
    db.execute(insert(TechnicianPaymentAccount).values(id=uuid.uuid4(), technician_id=technician.id,
                                                       provider=provider.name)
               .on_conflict_do_nothing(constraint="uq_technician_payment_accounts_technician_provider"))
    account = get_account(db, technician.id, provider.name, lock=True)
    if account.provider_account_id is not None:
        raise PaymentAccountError("Ya tienes una cuenta de pagos", code="PAYMENT_ACCOUNT_EXISTS")
    account.provider_account_id = provider.create_connected_account(_prefill(db, technician, profile))
    _move(account, S.ONBOARDING)
    db.flush()
    write_audit(db, action="payment_account.created", actor=Actor.of(technician), technician_id=technician.id,
                target_type="technician_payment_account", target_id=str(account.id),
                changes={"provider": provider.name}, ctx=ctx)
    return account


def onboarding_link(db: Session, technician: User, provider: PaymentProvider) -> OnboardingLink:
    _approved_profile(db, technician.id)
    account = get_account(db, technician.id, provider.name)
    if account is None or account.provider_account_id is None:
        raise PaymentAccountError("Primero crea tu cuenta de pagos", code="PAYMENT_ACCOUNT_NOT_FOUND",
                                  http_status=404)
    if account.status == S.DISABLED:
        raise PaymentAccountError("Tu cuenta de pagos está deshabilitada; contacta a soporte",
                                  code="PAYMENT_ACCOUNT_DISABLED")
    return provider.create_onboarding_link(account.provider_account_id)


# =============================================================================
# Sincronización con el proveedor
# =============================================================================
def _move(account: TechnicianPaymentAccount, to: PaymentAccountStatus) -> bool:
    if account.status == to:
        return False
    if (account.status, to) not in ALLOWED_ACCOUNT_TRANSITIONS:
        raise PaymentAccountError(f"Cuenta de pagos: {account.status.value} → {to.value} no permitido",
                                  code="PAYMENT_ACCOUNT_INVALID_TRANSITION")
    account.status = to
    account.version += 1
    if to == S.ENABLED and account.enabled_at is None:
        account.enabled_at = _now()
    return True


def derive_status(current: PaymentAccountStatus, info: AccountStatusInfo) -> PaymentAccountStatus:
    """Estado propio a partir de lo que reporta el proveedor."""
    if info.disabled_reason and info.disabled_reason.startswith("rejected"):
        return S.DISABLED
    if info.transfers_active and info.payouts_enabled and not info.requirements_due:
        return S.ENABLED
    if current in (S.ENABLED, S.RESTRICTED):
        return S.RESTRICTED
    return S.PENDING_VERIFICATION if info.details_submitted else S.ONBOARDING


def _norm(text_: str | None) -> str:
    if not text_:
        return ""
    t = unicodedata.normalize("NFKD", text_)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return " ".join(t.upper().replace("-", " ").split())


def name_matches(profile: KycProfile, info: AccountStatusInfo) -> bool | None:
    """None si el proveedor no expone el nombre. Acepta apellido paterno solo o ambos apellidos."""
    if not info.legal_first_name and not info.legal_last_name:
        return None
    first_ok = _norm(info.legal_first_name) == _norm(profile.first_names)
    paternal, maternal = _norm(profile.paternal_surname), _norm(profile.maternal_surname)
    last_ok = _norm(info.legal_last_name) in {paternal, f"{paternal} {maternal}".strip()}
    return first_ok and last_ok


def sync_account(db: Session, account: TechnicianPaymentAccount, provider: PaymentProvider, *,
                 force: bool = False, ctx: RequestContext | None = None) -> TechnicianPaymentAccount:
    """Consulta al proveedor y aplica el estado. La llamará el worker de webhooks (account.updated)."""
    if account.provider_account_id is None:
        return account
    if not force and account.last_synced_at and _now() - account.last_synced_at < SYNC_MIN_INTERVAL:
        return account
    info = provider.get_account_status(account.provider_account_id)
    before = account.status
    was_eligible = account.can_receive_payments
    target = derive_status(before, info)
    if (before, target) in ALLOWED_ACCOUNT_TRANSITIONS or before == target:
        _move(account, target)
    # Si no es una transición válida (p. ej. el proveedor reactiva una cuenta DISABLED) se conserva el
    # estado y queda en la auditoría para que finanzas lo revise.
    account.transfers_active = info.transfers_active
    account.payouts_enabled = info.payouts_enabled
    account.details_submitted = info.details_submitted
    account.requirements_due = list(info.requirements_due) or None
    account.provider_disabled_reason = info.disabled_reason[:80] if info.disabled_reason else None
    account.last_synced_at = _now()

    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == account.technician_id))
    match = name_matches(profile, info) if profile else None
    newly_mismatched = match is False and account.name_matches_kyc is not False
    account.name_matches_kyc = match
    if newly_mismatched and account.blocked_reason is None:
        account.blocked_reason = NAME_MISMATCH
    db.flush()

    if newly_mismatched:
        # Alerta a supervisión: no se revela nada al técnico más allá de "en revisión".
        db.add(OutboxEvent(event_type="payment_account.name_mismatch", aggregate_type="technician_payment_account",
                           aggregate_id=account.id, payload={"technician_id": str(account.technician_id)}))
    if account.status != before or newly_mismatched or target != account.status:
        write_audit(db, action="payment_account.synced", actor=Actor.system(), technician_id=account.technician_id,
                    target_type="technician_payment_account", target_id=str(account.id),
                    changes={"from": before.value, "to": account.status.value, "provider_status": target.value,
                             "name_matches_kyc": match, "blocked_reason": account.blocked_reason}, ctx=ctx)
    if account.status != before:
        db.add(OutboxEvent(event_type=f"payment_account.{account.status.value.lower()}",
                           aggregate_type="technician_payment_account", aggregate_id=account.id,
                           recipient_user_id=account.technician_id, payload={"status": account.status.value}))
    if was_eligible and not account.can_receive_payments:
        _release_orders(db, account.technician_id)
    db.flush()
    return account


def _release_orders(db: Session, technician_id: uuid.UUID) -> None:
    """Sin cuenta para cobrar, sus órdenes no iniciadas vuelven a la bolsa (y se anulan sus reservas)."""
    from app.orders.service import release_technician_orders

    release_technician_orders(db, technician_id, "PAYMENT_ACCOUNT_NOT_ENABLED")


# =============================================================================
# Bloqueos de la plataforma
# =============================================================================
def block_for_kyc(db: Session, technician_id: uuid.UUID, reason: str) -> None:
    """KYC suspendido o vencido: la cuenta no se borra; se bloquea (no recibe pagos nuevos)."""
    assert reason in KYC_BLOCKS  # noqa: S101
    for account in db.scalars(select(TechnicianPaymentAccount).where(
            TechnicianPaymentAccount.technician_id == technician_id).with_for_update().execution_options(populate_existing=True)).all():
        if account.blocked_reason in (None, *KYC_BLOCKS):      # un NAME_MISMATCH pendiente no se pisa
            account.blocked_reason = reason
            account.version += 1
    db.flush()


def block(db: Session, account: TechnicianPaymentAccount, reason: str) -> None:
    """Bloqueo de la plataforma sobre una cuenta YA bloqueada en la sesión; suelta sus órdenes si podía cobrar."""
    was_eligible = account.can_receive_payments
    if account.blocked_reason in (None, *KYC_BLOCKS, NAME_MISMATCH):
        account.blocked_reason = reason
        account.version += 1
    db.flush()
    if was_eligible:
        _release_orders(db, account.technician_id)


def unblock_for_kyc(db: Session, technician_id: uuid.UUID) -> None:
    """KYC aprobado de nuevo: se quita solo el bloqueo que puso el KYC."""
    for account in db.scalars(select(TechnicianPaymentAccount).where(
            TechnicianPaymentAccount.technician_id == technician_id).with_for_update().execution_options(populate_existing=True)).all():
        if account.blocked_reason in KYC_BLOCKS:
            account.blocked_reason = None
            account.version += 1
    db.flush()


def resolve_name_review(db: Session, actor: Actor, account_id: uuid.UUID, *, approve: bool, note: str,
                        ctx: RequestContext | None = None) -> TechnicianPaymentAccount:
    """Un supervisor revisa la diferencia de nombre: la libera (mismo titular) o deshabilita la cuenta."""
    account = db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.id == account_id)
                        .with_for_update().execution_options(populate_existing=True))
    if account is None:
        raise PaymentAccountError("Cuenta no encontrada", code="PAYMENT_ACCOUNT_NOT_FOUND", http_status=404)
    if account.blocked_reason != NAME_MISMATCH:
        raise PaymentAccountError("La cuenta no está en revisión de nombre", code="PAYMENT_ACCOUNT_NOT_IN_REVIEW")
    if approve:
        # block_for_kyc no pisa un NAME_MISMATCH: si el KYC se suspendió o venció mientras tanto,
        # ese bloqueo estaba "escondido" detrás y ahora es el que queda (no se libera la cuenta).
        profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == account.technician_id))
        kyc_block = {KycStatus.SUSPENDED: "KYC_SUSPENDED", KycStatus.EXPIRED: "KYC_EXPIRED"}.get(
            profile.status if profile is not None else None)
        account.blocked_reason = kyc_block
        account.name_matches_kyc = True
    else:
        account.blocked_reason = "NAME_REJECTED"
    account.version += 1
    db.flush()
    if not approve:
        _release_orders(db, account.technician_id)
    write_audit(db, action="payment_account.name_review", actor=actor, technician_id=account.technician_id,
                target_type="technician_payment_account", target_id=str(account.id),
                reason_code="APPROVED" if approve else "REJECTED", reason_note=note, ctx=ctx)
    return account
