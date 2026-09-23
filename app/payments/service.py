"""
Estado de los pagos visto desde la plataforma.

Aquí NO se habla con Stripe: estas funciones son las que invocará el worker de webhooks
(Fase 4) una vez verificada la firma y re-consultado el objeto en el proveedor. Nunca hay
un endpoint público que marque un pago como pagado: "pago confirmado" solo puede venir del
proveedor. Los cambios de estado son idempotentes (repetir el evento no cambia nada).

Importes: todo en centavos. El monto y el reparto los calcula el CommissionEngine a partir
del precio acordado de la orden; el desglose se congela en commission_transactions y cada
cobro, reembolso o contracargo se asienta en el libro contable.

Efectos sobre la orden:
  AUTHORIZED            → permite al técnico iniciar el trabajo
  PAID                  → orden COMPLETED pasa a PAID y enseguida a READY_FOR_REVIEW
  FAILED                → orden SCHEDULED/COMPLETED pasa a FAILED
  REFUNDED (total)      → orden pasa a REFUNDED y su reseña (si existe) se oculta
  PARTIALLY_REFUNDED    → la orden sigue calificable (el servicio sí ocurrió)
  DISPUTED / CHARGED_BACK → sin efecto sobre la orden en Fase 1 (Fase 5: disputas)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.actor import Actor
from app.core.config import get_settings
from app.models import (
    PAYMENT_CONFIRMED,
    CommissionTransaction,
    KycProfile,
    OutboxEvent,
    Payment,
    PaymentKind,
    PaymentStatus,
    ServiceOrder,
)
from app.payments import ledger
from app.payments.commission import RuleTerms, TaxRates, compute, resolve_rule, to_cents
from app.payments.state_machine import (  # noqa: F401  (reexportados para el resto de la app)
    ALLOWED_PAYMENT_TRANSITIONS,
    CANCELLABLE,
    LIVE,
    PaymentError,
    move,
)

P = PaymentStatus


def _now() -> datetime:
    return datetime.now(timezone.utc)


def active_payment(db: Session, order_id: uuid.UUID, *, lock: bool = False) -> Payment | None:
    """El pago SERVICE vivo de la orden (a lo más uno, por el índice único parcial)."""
    stmt = select(Payment).where(Payment.service_order_id == order_id, Payment.kind == PaymentKind.SERVICE,
                                 Payment.status.in_(LIVE))
    if lock:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    return db.scalar(stmt)


@dataclass(frozen=True)
class OrderPaymentSummary:
    confirmed: bool                  # hay un pago SERVICE en PAID o PARTIALLY_REFUNDED
    status: PaymentStatus | None
    amount_cents: int
    refunded_cents: int


def get_order_payment_summary(db: Session, order_id: uuid.UUID) -> OrderPaymentSummary:
    """Única lectura que usan otros módulos (reseñas) para saber si una orden está pagada."""
    p = active_payment(db, order_id)
    if p is None:
        return OrderPaymentSummary(confirmed=False, status=None, amount_cents=0, refunded_cents=0)
    return OrderPaymentSummary(confirmed=p.status in PAYMENT_CONFIRMED, status=p.status,
                               amount_cents=p.amount_cents, refunded_cents=p.refunded_cents)


def _technician_has_rfc(db: Session, technician_id: uuid.UUID | None) -> bool:
    if technician_id is None:
        return False
    return db.scalar(select(KycProfile.rfc_hash).where(KycProfile.technician_id == technician_id)) is not None


def create_for_order(db: Session, order: ServiceOrder, *, provider: str | None = None) -> Payment:
    """Intención de pago al fijarse precio y fecha (orden SCHEDULED). El monto sale del motor, nunca del cliente."""
    existing = active_payment(db, order.id)
    if existing is not None:
        return existing
    s = get_settings()
    rule = resolve_rule(db, category_id=order.category_id, technician_id=order.technician_id)
    breakdown = compute(to_cents(order.agreed_price), RuleTerms.of(rule),
                        TaxRates.current(_technician_has_rfc(db, order.technician_id)))
    payment = Payment(service_order_id=order.id, payer_id=order.client_id, kind=PaymentKind.SERVICE,
                      provider=provider or s.PAYMENT_PROVIDER, currency=s.PAYMENT_CURRENCY,
                      amount_cents=breakdown.charge_cents)
    db.add(payment)
    db.flush()
    t, x = breakdown.terms, breakdown.taxes
    db.add(CommissionTransaction(
        payment_id=payment.id, rule_id=t.rule_id, rule_scope=t.scope.value, rule_type=t.type.value,
        rate_bp=t.rate_bp, fixed_cents=t.fixed_cents, min_cents=t.min_cents, max_cents=t.max_cents,
        service_tax_bp=x.service_tax_bp, commission_tax_bp=x.commission_tax_bp,
        isr_withholding_bp=x.isr_withholding_bp, iva_withholding_bp=x.iva_withholding_bp,
        technician_has_rfc=x.technician_has_rfc, price_cents=breakdown.price_cents,
        service_tax_cents=breakdown.service_tax_cents, gross_cents=breakdown.gross_cents,
        discount_cents=breakdown.discount_cents, commission_cents=breakdown.commission_cents,
        commission_tax_cents=breakdown.commission_tax_cents, withholding_isr_cents=breakdown.withholding_isr_cents,
        withholding_iva_cents=breakdown.withholding_iva_cents, technician_cents=breakdown.technician_cents,
    ))
    db.flush()
    return payment


def cancel_for_order(db: Session, order: ServiceOrder) -> None:
    """Orden cancelada o técnico retirado: se anula la intención / autorización."""
    payment = active_payment(db, order.id, lock=True)
    if payment is None or payment.status not in CANCELLABLE:
        return
    was_authorized = payment.status == P.AUTHORIZED
    move(payment, P.CANCELLED)
    payment.cancelled_at = _now()
    if was_authorized:
        db.add(OutboxEvent(event_type="payment.void_requested", aggregate_type="payment", aggregate_id=payment.id,
                           payload={"provider_payment_id": payment.provider_payment_id}))
    db.flush()


def request_capture(db: Session, order: ServiceOrder) -> None:
    payment = active_payment(db, order.id)
    if payment is not None and payment.status == P.AUTHORIZED:
        db.add(OutboxEvent(event_type="payment.capture_requested", aggregate_type="payment",
                           aggregate_id=payment.id, payload={"provider_payment_id": payment.provider_payment_id,
                                                             "amount_cents": payment.amount_cents}))


# =============================================================================
# Manejadores de eventos del proveedor (webhook ya verificado)
# =============================================================================
def mark_requires_action(db: Session, payment: Payment) -> None:
    if move(payment, P.REQUIRES_ACTION):
        db.flush()


def mark_processing(db: Session, payment: Payment) -> None:
    if move(payment, P.PROCESSING):
        db.flush()


def mark_authorized(db: Session, payment: Payment, *, provider_payment_id: str,
                    payment_method_fingerprint: str | None = None) -> None:
    if move(payment, P.AUTHORIZED):
        now = _now()
        payment.authorized_at = now
        payment.capture_deadline = now + timedelta(hours=get_settings().PAYMENT_AUTHORIZATION_VALID_HOURS)
        payment.provider_payment_id = provider_payment_id
        payment.payment_method_fingerprint = payment_method_fingerprint
        db.flush()


def mark_captured(db: Session, payment: Payment) -> None:
    """payment_intent.succeeded: cobro completo; se asienta el reparto congelado."""
    from app.orders import service as orders

    if not move(payment, P.PAID):
        return
    payment.captured_cents = payment.amount_cents
    payment.captured_at = _now()
    db.flush()
    ledger.post_capture(db, payment, _breakdown(db, payment))
    orders.on_payment_captured(db, payment.service_order_id)


def mark_failed(db: Session, payment: Payment, failure_code: str) -> None:
    from app.orders import service as orders

    if not move(payment, P.FAILED):
        return
    payment.failure_code = failure_code[:60]
    db.flush()
    orders.on_payment_failed(db, payment.service_order_id, failure_code)


def mark_refunded(db: Session, payment: Payment, amount_cents: int) -> None:
    """Reembolso confirmado por el proveedor (monto de ESTE reembolso). Total si alcanza lo cobrado."""
    from app.orders import service as orders

    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents <= 0:
        raise PaymentError("Monto de reembolso inválido", code="PAYMENT_INVALID_REFUND")
    if payment.status not in (P.PAID, P.PARTIALLY_REFUNDED, P.REFUNDED):
        raise PaymentError("Solo se reembolsa un pago cobrado", code="PAYMENT_INVALID_REFUND")
    total = min(payment.captured_cents, payment.refunded_cents + amount_cents)
    delta = total - payment.refunded_cents
    if delta <= 0:
        return                                          # ya estaba reembolsado por completo
    full = total >= payment.captured_cents
    move(payment, P.REFUNDED if full else P.PARTIALLY_REFUNDED)
    payment.refunded_cents = total
    payment.refunded_at = _now()
    db.flush()
    ledger.post_refund(db, payment, delta)
    if full:
        orders.on_full_refund(db, payment.service_order_id, Actor.system())


def mark_disputed(db: Session, payment: Payment) -> None:
    """charge.dispute.created: el banco del cliente abrió un contracargo."""
    if move(payment, P.DISPUTED):
        db.flush()


def mark_dispute_closed(db: Session, payment: Payment, *, won: bool) -> None:
    """charge.dispute.closed: ganada vuelve a su estado cobrado; perdida es CHARGED_BACK y se asienta."""
    if payment.status != P.DISPUTED:
        return
    if won:
        move(payment, P.PARTIALLY_REFUNDED if payment.refunded_cents else P.PAID)
        db.flush()
        return
    lost = payment.captured_cents - payment.refunded_cents
    move(payment, P.CHARGED_BACK)
    db.flush()
    if lost > 0:
        ledger.post_refund(db, payment, lost, entry_type="CHARGEBACK")


def _breakdown(db: Session, payment: Payment) -> CommissionTransaction:
    b = db.scalar(select(CommissionTransaction).where(CommissionTransaction.payment_id == payment.id))
    if b is None:
        raise PaymentError("El pago no tiene desglose de comisión", code="PAYMENT_BREAKDOWN_MISSING",
                           http_status=500)
    return b
