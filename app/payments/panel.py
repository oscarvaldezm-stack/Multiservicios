"""
Panel de finanzas (Fase 6): alertas, bandeja de webhooks y límites por usuario.

- Alertas: los eventos que el módulo de pagos deja para finanzas (conciliación, webhooks DEAD,
  reembolsos fallidos o pendientes de segunda firma, contracargos, cargos no cobrados, cuentas
  con nombre distinto...). Se listan y se marcan como atendidas (auditado).
- Webhooks: consulta de la bandeja y reencolado de un evento DEAD o ignorado (tras corregir la causa).
- Límites por usuario en los POST de dinero (el límite por IP lo pone Nginx).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.models import IdempotencyKey, OutboxEvent, PaymentRefund, PaymentWebhookEvent, WebhookEventStatus

W = WebhookEventStatus

# Eventos internos (sin destinatario) que atiende finanzas.
ALERT_TYPES = (
    "payment.reconciliation_mismatch", "payment.webhook_dead", "payment.authorization_expiring",
    "payment.authorization_expired", "payment.captured_under_dispute", "payment.dispute_opened",
    "payment.refunded_outside_app", "refund.failed", "refund.failed_after_success",
    "refund.second_approval_required", "refund.requested", "dispute.reversal_failed",
    "cancellation_fee.not_collected", "payment_account.name_mismatch", "risk.chargeback_lost",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# Alertas
# =============================================================================
def list_alerts(db: Session, *, include_acknowledged: bool = False, event_type: str | None = None,
                limit: int = 100) -> list[OutboxEvent]:
    stmt = select(OutboxEvent).where(OutboxEvent.event_type.in_(ALERT_TYPES), OutboxEvent.recipient_user_id.is_(None))
    if not include_acknowledged:
        stmt = stmt.where(OutboxEvent.processed_at.is_(None))
    if event_type:
        stmt = stmt.where(OutboxEvent.event_type == event_type)
    return db.scalars(stmt.order_by(OutboxEvent.created_at.desc()).limit(limit)).all()


def acknowledge(db: Session, actor: Actor, alert_id: uuid.UUID, note: str,
                ctx: RequestContext | None = None) -> OutboxEvent:
    alert = db.scalar(select(OutboxEvent).where(OutboxEvent.id == alert_id, OutboxEvent.event_type.in_(ALERT_TYPES),
                                                OutboxEvent.recipient_user_id.is_(None)).with_for_update())
    if alert is None:
        raise DomainError("Alerta no encontrada", code="ALERT_NOT_FOUND", http_status=404)
    if alert.processed_at is not None:
        raise DomainError("La alerta ya se atendió", code="ALERT_ALREADY_ACKNOWLEDGED", http_status=409)
    alert.processed_at = _now()
    db.flush()
    write_audit(db, action="finance.alert.acknowledged", actor=actor, target_type="outbox_event",
                target_id=str(alert.id), reason_code=alert.event_type[:40], reason_note=note, ctx=ctx)
    return alert


# =============================================================================
# Webhooks
# =============================================================================
def list_webhooks(db: Session, *, status: WebhookEventStatus | None = None, limit: int = 100) -> list[PaymentWebhookEvent]:
    stmt = select(PaymentWebhookEvent)
    if status is not None:
        stmt = stmt.where(PaymentWebhookEvent.status == status)
    return db.scalars(stmt.order_by(PaymentWebhookEvent.received_at.desc()).limit(limit)).all()


def requeue_webhook(db: Session, actor: Actor, event_id: int, note: str,
                    ctx: RequestContext | None = None) -> PaymentWebhookEvent:
    """Un evento DEAD o ignorado vuelve a la bandeja (el worker lo re-consulta al proveedor como siempre)."""
    ev = db.scalar(select(PaymentWebhookEvent).where(PaymentWebhookEvent.id == event_id).with_for_update())
    if ev is None:
        raise DomainError("Evento no encontrado", code="WEBHOOK_NOT_FOUND", http_status=404)
    if ev.status not in (W.DEAD, W.IGNORED):
        raise DomainError("Solo se reencola un evento DEAD o ignorado", code="WEBHOOK_NOT_REQUEUEABLE",
                          http_status=409)
    before = ev.status
    ev.status, ev.attempts, ev.next_attempt_at, ev.processed_at = W.PENDING, 0, _now(), None
    db.flush()
    write_audit(db, action="finance.webhook.requeued", actor=actor, target_type="payment_webhook_event",
                target_id=str(ev.id), reason_note=note, changes={"from": before.value, "type": ev.type}, ctx=ctx)
    return ev


# =============================================================================
# Límites por usuario
# =============================================================================
def _limited(message: str) -> DomainError:
    return DomainError(message, code="RATE_LIMITED", http_status=429)


def check_payment_method_rate(db: Session, user_id: uuid.UUID) -> None:
    since = _now() - timedelta(minutes=1)
    n = db.scalar(select(func.count()).select_from(IdempotencyKey).where(
        IdempotencyKey.user_id == user_id, IdempotencyKey.endpoint.like("orders/%/payment-method"),
        IdempotencyKey.created_at >= since))
    if n >= get_settings().RATE_PAYMENT_METHOD_PER_MINUTE:
        raise _limited("Demasiados intentos; espera un minuto")


def check_refund_request_rate(db: Session, user_id: uuid.UUID) -> None:
    since = _now() - timedelta(hours=1)
    n = db.scalar(select(func.count()).select_from(PaymentRefund).where(
        PaymentRefund.requested_by == user_id, PaymentRefund.created_at >= since))
    if n >= get_settings().RATE_REFUND_REQUESTS_PER_HOUR:
        raise _limited("Demasiadas solicitudes de reembolso; intenta más tarde")
