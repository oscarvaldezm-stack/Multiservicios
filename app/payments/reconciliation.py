"""
Conciliación con el proveedor (sección 8 del doc de pagos): la red de seguridad por si un
webhook nunca llega.

Una vez al día (RECONCILIATION_INTERVAL_HOURS) compara los cobros de la ventana
(RECONCILIATION_WINDOW_HOURS), más todos los que siguen abiertos, contra el proveedor:
- Estado atrasado en nuestra base (p. ej. autorizado aquí, cobrado allá): se corrige por la
  misma vía que un webhook (apply_provider_state), que solo avanza por transiciones válidas.
- Lo que NO es seguro corregir solo se alerta a finanzas (`payment.reconciliation_mismatch`):
  montos distintos, un estado que la máquina no admite (cobrado aquí, anulado allá) o cobros
  que existen solo en el proveedor.
- Cuentas de técnicos sin sincronizar en 24 h se vuelven a consultar.
Cada corrida queda en la auditoría con sus conteos.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor
from app.core.config import get_settings
from app.models import AuditLog, OutboxEvent, Payment, PaymentStatus, TechnicianPaymentAccount
from app.payments import accounts
from app.payments import service as payments
from app.payments.providers.base import PaymentProvider, ProviderError

log = logging.getLogger("payments")
P = PaymentStatus
OPEN = (P.PENDING, P.REQUIRES_ACTION, P.PROCESSING, P.AUTHORIZED)
# Para el proveedor el cobro sigue "succeeded" aunque aquí esté reembolsado o en disputa: eso es consistente.
AFTER_CAPTURE = frozenset({P.PAID, P.PARTIALLY_REFUNDED, P.REFUNDED, P.DISPUTED, P.CHARGED_BACK})


def consistent(ours: PaymentStatus, provider: PaymentStatus) -> bool:
    return ours == provider or (provider == P.PAID and ours in AFTER_CAPTURE)
RUN_ACTION = "payment.reconciliation.run"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _alert(db: Session, kind: str, key: str, now: datetime, **payload) -> bool:
    """Una alerta por (tipo, objeto) cada 24 h: no se inunda a finanzas con lo mismo."""
    aggregate = uuid.uuid5(uuid.NAMESPACE_URL, f"reconciliation:{kind}:{key}")
    recent = db.scalar(select(OutboxEvent.id).where(
        OutboxEvent.aggregate_id == aggregate, OutboxEvent.event_type == "payment.reconciliation_mismatch",
        OutboxEvent.created_at >= now - timedelta(hours=24)))
    if recent is not None:
        return False
    db.add(OutboxEvent(event_type="payment.reconciliation_mismatch", aggregate_type="payment",
                       aggregate_id=aggregate, payload={"kind": kind, **payload}))
    return True


def due(db: Session, now: datetime) -> bool:
    interval = timedelta(hours=get_settings().RECONCILIATION_INTERVAL_HOURS)
    last = db.scalar(select(AuditLog.occurred_at).where(AuditLog.action == RUN_ACTION)
                     .order_by(AuditLog.id.desc()).limit(1))
    return last is None or now - last >= interval - timedelta(minutes=5)


def reconcile(db: Session, provider: PaymentProvider | None = None, *, now: datetime | None = None,
              force: bool = False) -> int:
    """Trabajo del worker. Devuelve correcciones + alertas nuevas (0 si no tocaba correr)."""
    from app.payments.providers import get_provider

    provider = provider or get_provider()
    now = now or _now()
    if not force and not due(db, now):
        return 0
    s = get_settings()
    since = now - timedelta(hours=s.RECONCILIATION_WINDOW_HOURS)
    counts = {"checked": 0, "fixed": 0, "alerts": 0, "provider_only": 0, "accounts_synced": 0, "errors": 0}

    # 1. Nuestros cobros: los recientes y todos los que siguen abiertos.
    ids = db.scalars(select(Payment.id).where(
        Payment.provider_payment_id.is_not(None),
        or_(Payment.created_at >= since, Payment.updated_at >= since, Payment.status.in_(OPEN)))).all()
    for pid in ids:
        try:
            with db.begin_nested():
                payment = db.scalar(select(Payment).where(Payment.id == pid).with_for_update(skip_locked=True)
                                    .execution_options(populate_existing=True))
                if payment is None:
                    continue
                counts["checked"] += 1
                pp = provider.get_payment(payment.provider_payment_id)
                if pp.amount_cents != payment.amount_cents:
                    counts["alerts"] += _alert(db, "AMOUNT_MISMATCH", str(payment.id), now,
                                               payment_id=str(payment.id), ours=payment.amount_cents,
                                               provider=pp.amount_cents)
                    continue
                if payment.captured_cents and pp.amount_received_cents \
                        and pp.amount_received_cents != payment.captured_cents:
                    # Lo asentado no es lo que de verdad se cobró (captura parcial perdida, captura manual).
                    counts["alerts"] += _alert(db, "CAPTURE_MISMATCH", str(payment.id), now,
                                               payment_id=str(payment.id), ours=payment.captured_cents,
                                               provider=pp.amount_received_cents)
                if not consistent(payment.status, pp.status):
                    counts["fixed"] += payments.apply_provider_state(db, payment, pp)
                    if not consistent(payment.status, pp.status):
                        counts["alerts"] += _alert(db, "STATUS_MISMATCH", str(payment.id), now,
                                                   payment_id=str(payment.id), ours=payment.status.value,
                                                   provider=pp.status.value)
        except ProviderError:
            counts["errors"] += 1
            log.warning("Conciliación: no se pudo consultar el pago %s", pid)

    # 2. Cobros que existen solo en el proveedor.
    try:
        remote = provider.list_payments(since, now)
    except ProviderError:
        remote = []
        counts["errors"] += 1
    known = set(db.scalars(select(Payment.provider_payment_id).where(
        Payment.provider_payment_id.in_([r.provider_payment_id for r in remote if r.provider_payment_id]))).all())
    for r in remote:
        if r.provider_payment_id in known:
            continue
        orphan = None
        if r.metadata_payment_id:                       # autorizado en el proveedor, pero no quedó el id aquí
            try:
                orphan = db.get(Payment, uuid.UUID(r.metadata_payment_id), with_for_update=True)
            except ValueError:
                orphan = None
        if orphan is not None and orphan.provider_payment_id is None:
            counts["fixed"] += payments.apply_provider_state(db, orphan, r)
            continue
        counts["provider_only"] += 1
        counts["alerts"] += _alert(db, "PROVIDER_ONLY", r.provider_payment_id or "?", now,
                                   provider_payment_id=r.provider_payment_id, amount=r.amount_cents,
                                   provider_status=r.status.value)

    # 3. Cuentas de técnicos sin sincronizar en 24 h.
    stale = db.scalars(select(TechnicianPaymentAccount.id).where(
        TechnicianPaymentAccount.provider_account_id.is_not(None),
        or_(TechnicianPaymentAccount.last_synced_at.is_(None),
            TechnicianPaymentAccount.last_synced_at < now - timedelta(hours=24)))).all()
    for aid in stale:
        try:
            with db.begin_nested():
                account = db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.id == aid)
                                    .with_for_update(skip_locked=True).execution_options(populate_existing=True))
                if account is not None:
                    accounts.sync_account(db, account, provider, force=True)
                    counts["accounts_synced"] += 1
        except ProviderError:
            counts["errors"] += 1

    write_audit(db, action=RUN_ACTION, actor=Actor.system(), target_type="payments", changes=counts)
    db.flush()
    return counts["fixed"] + counts["alerts"]
