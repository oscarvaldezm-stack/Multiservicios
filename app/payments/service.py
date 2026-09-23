"""
Estado de los pagos visto desde la plataforma.

Aquí NO se habla con Stripe: estas funciones son las que invocará el manejador de
webhooks del proveedor (fase de pagos) una vez verificada la firma del evento. Nunca
hay un endpoint público que marque un pago como pagado: "pago confirmado" solo puede
venir del proveedor. Los cambios de estado son idempotentes (repetir el evento no cambia
nada); los reembolsos parciales se deduplicarán por id de evento del proveedor (fase de pagos).

Efectos sobre la orden:
  AUTHORIZED            → permite al técnico iniciar el trabajo
  CAPTURED              → orden COMPLETED pasa a PAID y enseguida a READY_FOR_REVIEW
  FAILED                → orden SCHEDULED/COMPLETED pasa a FAILED
  REFUNDED (total)      → orden pasa a REFUNDED y su reseña (si existe) se oculta
  PARTIALLY_REFUNDED    → la orden sigue calificable (el servicio sí ocurrió)
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.actor import Actor
from app.core.errors import DomainError
from app.models import OrderStatus, OutboxEvent, Payment, PaymentStatus, ServiceOrder

P = PaymentStatus
O = OrderStatus

ALLOWED_PAYMENT_TRANSITIONS: frozenset[tuple[PaymentStatus, PaymentStatus]] = frozenset({
    (P.PENDING, P.AUTHORIZED), (P.PENDING, P.FAILED), (P.PENDING, P.CANCELED),
    (P.AUTHORIZED, P.CAPTURED), (P.AUTHORIZED, P.CANCELED), (P.AUTHORIZED, P.FAILED),
    (P.CAPTURED, P.RELEASED), (P.CAPTURED, P.PARTIALLY_REFUNDED), (P.CAPTURED, P.REFUNDED),
    (P.RELEASED, P.PARTIALLY_REFUNDED), (P.RELEASED, P.REFUNDED), (P.PARTIALLY_REFUNDED, P.REFUNDED),
    (P.PARTIALLY_REFUNDED, P.RELEASED),
})
_LIVE = (P.PENDING, P.AUTHORIZED, P.CAPTURED, P.RELEASED, P.PARTIALLY_REFUNDED, P.REFUNDED)
_CENT = Decimal("0.01")


class PaymentError(DomainError):
    http_status = 409
    code = "PAYMENT_ERROR"


def active_payment(db: Session, order_id, *, lock: bool = False) -> Payment | None:
    stmt = select(Payment).where(Payment.service_order_id == order_id, Payment.status.in_(_LIVE))
    if lock:
        stmt = stmt.with_for_update()
    return db.scalar(stmt)


def create_for_order(db: Session, order: ServiceOrder, provider: str = "stripe") -> Payment:
    """Intención de pago al fijarse precio y fecha (orden SCHEDULED)."""
    existing = active_payment(db, order.id)
    if existing is not None:
        return existing
    amount = Decimal(order.agreed_price).quantize(_CENT)
    # Comisión de la categoría (catálogo). IVA y retenciones: fase de pagos (decisión D6).
    fee = (amount * Decimal(order.category.commission_rate)).quantize(_CENT, rounding=ROUND_HALF_UP)
    payment = Payment(service_order_id=order.id, amount=amount, platform_fee=fee, technician_payout=amount - fee,
                      provider=provider)
    db.add(payment)
    db.flush()
    return payment


def _move(payment: Payment, to: PaymentStatus) -> bool:
    if payment.status == to:
        return False                                   # evento repetido: idempotente
    if (payment.status, to) not in ALLOWED_PAYMENT_TRANSITIONS:
        raise PaymentError(f"Pago: {payment.status.value} → {to.value} no permitido", code="PAYMENT_INVALID_TRANSITION")
    payment.status = to
    return True


def cancel_for_order(db: Session, order: ServiceOrder) -> None:
    """Orden cancelada o técnico retirado: se anula la intención / autorización."""
    payment = active_payment(db, order.id, lock=True)
    if payment is None or payment.status not in (P.PENDING, P.AUTHORIZED):
        return
    was_authorized = payment.status == P.AUTHORIZED
    _move(payment, P.CANCELED)
    if was_authorized:
        db.add(OutboxEvent(event_type="payment.void_requested", aggregate_type="payment", aggregate_id=payment.id,
                           payload={"provider_payment_id": payment.provider_payment_id}))


def request_capture(db: Session, order: ServiceOrder) -> None:
    payment = active_payment(db, order.id)
    if payment is not None and payment.status == P.AUTHORIZED:
        db.add(OutboxEvent(event_type="payment.capture_requested", aggregate_type="payment",
                           aggregate_id=payment.id, payload={"provider_payment_id": payment.provider_payment_id}))


# =============================================================================
# Manejadores de eventos del proveedor (webhook ya verificado)
# =============================================================================
def mark_authorized(db: Session, payment: Payment, *, provider_payment_id: str,
                    payment_method_fingerprint: str | None = None) -> None:
    if _move(payment, P.AUTHORIZED):
        payment.authorized_at = datetime.now(timezone.utc)
        payment.provider_payment_id = provider_payment_id
        payment.payment_method_fingerprint = payment_method_fingerprint
        db.flush()


def mark_captured(db: Session, payment: Payment) -> None:
    from app.orders import service as orders

    if not _move(payment, P.CAPTURED):
        return
    payment.captured_at = datetime.now(timezone.utc)
    db.flush()
    orders.on_payment_captured(db, payment.service_order_id)


def mark_released(db: Session, payment: Payment) -> None:
    if _move(payment, P.RELEASED):
        payment.released_at = datetime.now(timezone.utc)
        db.flush()


def mark_failed(db: Session, payment: Payment, failure_code: str) -> None:
    from app.orders import service as orders

    if not _move(payment, P.FAILED):
        return
    payment.failure_code = failure_code[:60]
    db.flush()
    orders.on_payment_failed(db, payment.service_order_id, failure_code)


def mark_refunded(db: Session, payment: Payment, amount: Decimal) -> None:
    """Reembolso confirmado por el proveedor. Total si alcanza el monto cobrado."""
    from app.orders import service as orders

    amount = Decimal(amount).quantize(_CENT)
    if amount <= 0:
        raise PaymentError("Monto de reembolso inválido", code="PAYMENT_INVALID_REFUND")
    total = min(payment.amount, payment.amount_refunded + amount)
    full = total >= payment.amount
    moved = _move(payment, P.REFUNDED if full else P.PARTIALLY_REFUNDED) or payment.status == P.PARTIALLY_REFUNDED
    if not moved:
        return
    payment.amount_refunded = total
    payment.refunded_at = datetime.now(timezone.utc)
    db.flush()
    if full:
        orders.on_full_refund(db, payment.service_order_id, Actor.system())
