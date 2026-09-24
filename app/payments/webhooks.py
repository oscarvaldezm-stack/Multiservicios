"""
Webhooks del proveedor (sección 8 del doc de pagos).

Recepción (app/api/routes/webhooks.py): la firma se verifica sobre el cuerpo crudo, el evento
se guarda con INSERT ... ON CONFLICT (provider, provider_event_id) DO NOTHING y se responde 200
de inmediato. Nada se procesa en la petición: si tardara, el proveedor reintentaría y habría
más duplicados.

Procesamiento (este módulo, desde el worker):
- Toma eventos pendientes con SELECT ... FOR UPDATE SKIP LOCKED (varias réplicas no chocan).
- NO confía en el contenido del evento: vuelve a consultar el objeto al proveedor y aplica ese
  estado. Un evento falsificado que pasara la firma, o uno viejo que llegara tarde, no puede
  dejar un estado incorrecto.
- Cada evento corre en su propio savepoint: si falla, suma un intento y se reintenta con espera
  creciente; al llegar a WEBHOOK_MAX_ATTEMPTS pasa a DEAD y se alerta a finanzas.
- Reembolsos (refund.*) y contracargos (charge.dispute.*) se aplican con sus módulos (Fase 5).
- Del evento solo se guarda lo mínimo (id, tipo, objeto, cuenta, modo): nada de correos,
  nombres ni datos de facturación.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor
from app.core.config import get_settings
from app.models import (
    OutboxEvent,
    Payment,
    PaymentWebhookEvent,
    Payout,
    PayoutStatus,
    TechnicianPaymentAccount,
    WebhookEventStatus,
)
from app.payments import accounts
from app.payments import service as payments
from app.payments.providers.base import PaymentProvider, ProviderError, WebhookEvent

log = logging.getLogger("payments")
W = WebhookEventStatus

# Eventos que no hace falta procesar: los cubren refund.* o no cambian nada nuestro.
NOT_NEEDED = ("charge.refunded", "charge.updated", "transfer.reversed", "charge.dispute.funds_withdrawn",
              "charge.dispute.funds_reinstated")
_PAYOUT_STATUS = {"pending": PayoutStatus.PENDING, "in_transit": PayoutStatus.IN_TRANSIT, "paid": PayoutStatus.PAID,
                  "failed": PayoutStatus.FAILED, "canceled": PayoutStatus.CANCELED}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _provider(provider: PaymentProvider | None) -> PaymentProvider:
    if provider is not None:
        return provider
    from app.payments.providers import get_provider

    return get_provider()


def expected_livemode() -> bool:
    s = get_settings()
    key = s.STRIPE_SECRET_KEY.get_secret_value() if s.STRIPE_SECRET_KEY else ""
    return "_live_" in key


# =============================================================================
# Recepción
# =============================================================================
def store(db: Session, provider_name: str, event: WebhookEvent, endpoint: str) -> bool:
    """Guarda el evento verificado. Devuelve False si ya existía (duplicado neutralizado)."""
    inserted = db.execute(
        insert(PaymentWebhookEvent).values(
            provider=provider_name, provider_event_id=event.provider_event_id, type=event.type[:80],
            account_id=event.account_id, signature_valid=True,
            payload={"endpoint": endpoint, "object_id": event.object_id, "object_type": event.object_type,
                     "livemode": event.livemode, "created": event.created})
        .on_conflict_do_nothing(constraint="uq_payment_webhook_events_provider_event")
        .returning(PaymentWebhookEvent.id)
    ).scalar_one_or_none()
    return inserted is not None


# =============================================================================
# Procesamiento
# =============================================================================
def backoff(attempts: int) -> timedelta:
    """1, 2, 4, 8... minutos, con tope de 6 horas."""
    return min(timedelta(minutes=2 ** max(attempts - 1, 0)), timedelta(hours=6))


def process_pending(db: Session, provider: PaymentProvider | None = None, *, now: datetime | None = None,
                    limit: int = 100) -> int:
    """Trabajo del worker. Devuelve cuántos eventos quedaron resueltos (procesados o ignorados)."""
    provider = _provider(provider)
    now = now or _now()
    max_attempts = get_settings().WEBHOOK_MAX_ATTEMPTS
    events = db.scalars(
        select(PaymentWebhookEvent)
        .where(PaymentWebhookEvent.status.in_((W.PENDING, W.FAILED)), PaymentWebhookEvent.next_attempt_at <= now)
        .order_by(PaymentWebhookEvent.received_at).limit(limit)
        .with_for_update(skip_locked=True).execution_options(populate_existing=True)
    ).all()
    done = 0
    for ev in events:
        try:
            with db.begin_nested():
                status, note = _handle(db, ev, provider)
        except Exception as exc:  # noqa: BLE001  (un evento roto no detiene a los demás)
            ev.attempts += 1
            ev.last_error = (getattr(exc, "code", None) or type(exc).__name__)[:500]   # sin mensajes con datos
            if ev.attempts >= max_attempts:
                ev.status = W.DEAD
                db.add(OutboxEvent(event_type="payment.webhook_dead", aggregate_type="payment_webhook_event",
                                   aggregate_id=uuid.uuid5(uuid.NAMESPACE_URL, f"webhook:{ev.id}"),
                                   payload={"event_id": ev.provider_event_id, "type": ev.type,
                                            "last_error": ev.last_error}))
                log.error("Webhook %s agotó sus intentos (%s)", ev.provider_event_id, ev.last_error)
            else:
                ev.status = W.FAILED
                ev.next_attempt_at = now + backoff(ev.attempts)
            continue
        ev.status, ev.last_error, ev.processed_at = status, note, now
        done += 1
    db.flush()
    return done


def _handle(db: Session, ev: PaymentWebhookEvent, provider: PaymentProvider) -> tuple[WebhookEventStatus, str | None]:
    data = ev.payload or {}
    if bool(data.get("livemode")) != expected_livemode():
        logging.getLogger("security").warning("Webhook %s con modo distinto al de las claves", ev.provider_event_id)
        return W.IGNORED, "LIVEMODE_MISMATCH"
    t, object_id = ev.type, data.get("object_id")
    if t.startswith("payment_intent."):
        return _on_payment_intent(db, object_id, provider)
    if t == "account.updated":
        return _on_account_updated(db, ev.account_id or object_id, provider)
    if t == "account.application.deauthorized":
        return _on_deauthorized(db, ev.account_id)
    if t.startswith("payout."):
        return _on_payout(db, ev.account_id, object_id, provider)
    if t in NOT_NEEDED:
        return W.IGNORED, "NOT_NEEDED"
    if t.startswith("refund.") or t == "charge.refund.updated":
        return _on_refund(db, object_id, provider)
    if t.startswith("charge.dispute."):
        return _on_dispute(db, object_id, provider)
    return W.IGNORED, "UNHANDLED_EVENT_TYPE"


def _on_refund(db: Session, object_id: str | None, provider: PaymentProvider):
    from app.payments import refunds

    if not object_id:
        return W.IGNORED, "MISSING_OBJECT"
    row = refunds.apply_provider_refund(db, provider.get_refund(object_id))
    return (W.PROCESSED, None) if row is not None else (W.IGNORED, "UNKNOWN_PAYMENT")


def _on_dispute(db: Session, object_id: str | None, provider: PaymentProvider):
    from app.payments import disputes

    if not object_id:
        return W.IGNORED, "MISSING_OBJECT"
    row = disputes.sync_from_provider(db, provider.get_dispute(object_id), provider)
    return (W.PROCESSED, None) if row is not None else (W.IGNORED, "UNKNOWN_PAYMENT")


def _find_payment(db: Session, provider_payment_id: str | None, metadata_payment_id: str | None) -> Payment | None:
    conds = []
    if provider_payment_id:
        conds.append(Payment.provider_payment_id == provider_payment_id)
    if metadata_payment_id:
        try:
            conds.append(Payment.id == uuid.UUID(metadata_payment_id))
        except ValueError:
            pass
    if not conds:
        return None
    return db.scalar(select(Payment).where(or_(*conds)).with_for_update()
                     .execution_options(populate_existing=True))


def _on_payment_intent(db: Session, object_id: str | None, provider: PaymentProvider):
    if not object_id:
        return W.IGNORED, "MISSING_OBJECT"
    pp = provider.get_payment(object_id)                  # el estado real, no el del evento
    payment = _find_payment(db, object_id, pp.metadata_payment_id)
    if payment is None:
        return W.IGNORED, "UNKNOWN_PAYMENT"               # la conciliación lo reporta
    if payment.provider_payment_id not in (None, object_id):
        return W.IGNORED, "PAYMENT_ID_MISMATCH"
    payments.apply_provider_state(db, payment, pp)
    return W.PROCESSED, None


def _account(db: Session, provider_account_id: str | None) -> TechnicianPaymentAccount | None:
    if not provider_account_id:
        return None
    return db.scalar(select(TechnicianPaymentAccount)
                     .where(TechnicianPaymentAccount.provider_account_id == provider_account_id)
                     .with_for_update().execution_options(populate_existing=True))


def _on_account_updated(db: Session, provider_account_id: str | None, provider: PaymentProvider):
    account = _account(db, provider_account_id)
    if account is None:
        return W.IGNORED, "UNKNOWN_ACCOUNT"
    accounts.sync_account(db, account, provider, force=True)
    return W.PROCESSED, None


def _on_deauthorized(db: Session, provider_account_id: str | None):
    """El técnico desconectó la plataforma de su cuenta: ya no se le puede transferir."""
    account = _account(db, provider_account_id)
    if account is None:
        return W.IGNORED, "UNKNOWN_ACCOUNT"
    accounts.block(db, account, accounts.PROVIDER_DEAUTHORIZED)
    write_audit(db, action="payment_account.deauthorized", actor=Actor.system(), technician_id=account.technician_id,
                target_type="technician_payment_account", target_id=str(account.id))
    return W.PROCESSED, None


def _on_payout(db: Session, provider_account_id: str | None, payout_id: str | None, provider: PaymentProvider):
    account = _account(db, provider_account_id)
    if account is None or not payout_id:
        return W.IGNORED, "UNKNOWN_ACCOUNT"
    info = provider.get_payout(account.provider_account_id, payout_id)
    status = _PAYOUT_STATUS.get(info.status, PayoutStatus.PENDING)
    if info.amount_cents <= 0:
        return W.IGNORED, "EMPTY_PAYOUT"
    previous = db.scalar(select(Payout.status).where(Payout.provider_payout_id == info.provider_payout_id))
    stmt = insert(Payout).values(id=uuid.uuid4(), technician_account_id=account.id,
                                 provider_payout_id=info.provider_payout_id, amount_cents=info.amount_cents,
                                 currency=info.currency, status=status, arrival_date=info.arrival_date,
                                 failure_code=info.failure_code)
    db.execute(stmt.on_conflict_do_update(
        index_elements=["provider_payout_id"],
        set_={"status": status, "arrival_date": info.arrival_date, "failure_code": info.failure_code,
              "updated_at": _now()}))
    if status == PayoutStatus.FAILED and previous != PayoutStatus.FAILED:
        # Casi siempre una CLABE inválida: el técnico debe corregirla en el formulario del proveedor.
        db.add(OutboxEvent(event_type="payout.failed", aggregate_type="technician_payment_account",
                           aggregate_id=account.id, recipient_user_id=account.technician_id,
                           payload={"failure_code": info.failure_code}))
    return W.PROCESSED, None


# =============================================================================
# Reintento de anulaciones que el proveedor no aceptó en su momento
# =============================================================================
def retry_voids(db: Session, provider: PaymentProvider | None = None, *, limit: int = 50) -> int:
    provider = _provider(provider)
    max_attempts = get_settings().WEBHOOK_MAX_ATTEMPTS
    rows = db.scalars(select(OutboxEvent).where(
        OutboxEvent.event_type == "payment.void_requested", OutboxEvent.processed_at.is_(None),
        OutboxEvent.attempts < max_attempts).limit(limit).with_for_update(skip_locked=True)).all()
    done = 0
    for row in rows:
        try:
            provider.cancel_authorization(row.payload["provider_payment_id"], row.aggregate_id)
        except ProviderError as exc:
            row.attempts += 1
            row.last_error = exc.code
            continue
        row.processed_at = _now()
        done += 1
    db.flush()
    return done
