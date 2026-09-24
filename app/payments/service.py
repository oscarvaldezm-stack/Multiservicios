"""
Estado de los pagos visto desde la plataforma.

"Pago confirmado" solo puede venir del proveedor: ningún endpoint recibe un estado. El
estado cambia (a) justo después de una llamada al proveedor que lo confirma (autorizar,
capturar, anular, consultar) o (b) cuando el worker de webhooks (Fase 4) procese un evento
verificado; ambos caminos pasan por `apply_provider_state`. Repetir un evento no hace nada.

Importes: todo en centavos. El monto y el reparto los calcula el CommissionEngine a partir
del precio acordado de la orden; el desglose se congela en commission_transactions y cada
cobro, reembolso o contracargo se asienta en el libro contable.

Flujo del dinero (Fase 3, decisiones D5 y D7):
  SCHEDULED   el cliente elige una tarjeta guardada para la orden (Idempotency-Key)
  "en camino" el técnico sale → se AUTORIZA el cobro (captura manual, cargo de destino)
  AUTHORIZED  el técnico puede iniciar
  COMPLETED   el cliente aprueba (o pasan 72 h) → el worker CAPTURA → PAID
  24 h antes de vencer la autorización, si el cliente no ha respondido, se aprueba y captura.

Efectos sobre la orden:
  AUTHORIZED            → permite al técnico iniciar el trabajo
  FAILED al autorizar   → la orden sigue SCHEDULED; se avisa al cliente y hay un pago nuevo
                          para que elija otra tarjeta (el técnico no sale)
  FAILED al capturar    → orden COMPLETED pasa a FAILED
  PAID                  → orden COMPLETED pasa a PAID y enseguida a READY_FOR_REVIEW
  REFUNDED (total)      → orden pasa a REFUNDED y su reseña (si existe) se oculta
  PARTIALLY_REFUNDED    → la orden sigue calificable (el servicio sí ocurrió)
  DISPUTED / CHARGED_BACK → sin efecto sobre la orden todavía (Fase 5: disputas)
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.actor import Actor
from app.core.config import get_settings
from app.core.errors import DomainError
from app.models import (
    PAYMENT_CONFIRMED,
    CommissionTransaction,
    KycProfile,
    OrderStatus,
    OutboxEvent,
    Payment,
    PaymentCustomer,
    PaymentKind,
    PaymentStatus,
    PaymentTransaction,
    PaymentTransactionType,
    ServiceOrder,
    User,
)
from app.payments import ledger
from app.payments.commission import RuleTerms, TaxRates, compute, resolve_rule, to_cents
from app.payments.providers.base import AuthorizationRequest, PaymentProvider, ProviderError, ProviderPayment
from app.payments.state_machine import (  # noqa: F401  (reexportados para el resto de la app)
    ALLOWED_PAYMENT_TRANSITIONS,
    CANCELLABLE,
    LIVE,
    PaymentError,
    move,
)

P = PaymentStatus
O = OrderStatus
log = logging.getLogger("payments")
CAPTURE_SAFETY_MARGIN = timedelta(hours=24)       # se captura a más tardar 24 h antes de que venza la autorización


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _provider(provider: PaymentProvider | None) -> PaymentProvider:
    if provider is not None:
        return provider
    from app.payments.providers import get_provider

    return get_provider()


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


def _record(db: Session, payment: Payment, type_: PaymentTransactionType, status: str, *,
            amount_cents: int | None = None, failure_code: str | None = None) -> None:
    """Historial de lo que pasó en el proveedor (solo inserción; un registro por tipo y objeto)."""
    if not payment.provider_payment_id:
        return
    db.execute(insert(PaymentTransaction).values(
        payment_id=payment.id, type=type_, provider_object_id=payment.provider_payment_id,
        amount_cents=payment.amount_cents if amount_cents is None else amount_cents, status=status,
        failure_code=failure_code, raw_status=payment.status.value)
        .on_conflict_do_nothing(constraint="uq_payment_transactions_type_object"))


def _breakdown(db: Session, payment: Payment) -> CommissionTransaction:
    b = db.scalar(select(CommissionTransaction).where(CommissionTransaction.payment_id == payment.id))
    if b is None:
        raise PaymentError("El pago no tiene desglose de comisión", code="PAYMENT_BREAKDOWN_MISSING",
                           http_status=500)
    return b


def _snapshot(payment_id: uuid.UUID, src: CommissionTransaction) -> CommissionTransaction:
    """Copia del desglose de otro pago de la misma orden: regla, tasas e importes congelados."""
    return CommissionTransaction(
        payment_id=payment_id, rule_id=src.rule_id, rule_scope=src.rule_scope, rule_type=src.rule_type,
        rate_bp=src.rate_bp, fixed_cents=src.fixed_cents, min_cents=src.min_cents, max_cents=src.max_cents,
        service_tax_bp=src.service_tax_bp, commission_tax_bp=src.commission_tax_bp,
        isr_withholding_bp=src.isr_withholding_bp, iva_withholding_bp=src.iva_withholding_bp,
        technician_has_rfc=src.technician_has_rfc, price_cents=src.price_cents,
        service_tax_cents=src.service_tax_cents, gross_cents=src.gross_cents, discount_cents=src.discount_cents,
        commission_cents=src.commission_cents, commission_tax_cents=src.commission_tax_cents,
        withholding_isr_cents=src.withholding_isr_cents, withholding_iva_cents=src.withholding_iva_cents,
        technician_cents=src.technician_cents)


def create_for_order(db: Session, order: ServiceOrder, *, provider: str | None = None) -> Payment:
    """Intención de pago al fijarse precio y fecha (orden SCHEDULED). El monto sale del motor, nunca del cliente."""
    existing = active_payment(db, order.id)
    if existing is not None:
        return existing
    s = get_settings()
    rule = resolve_rule(db, category_id=order.category_id, technician_id=order.technician_id)
    b = compute(to_cents(order.agreed_price), RuleTerms.of(rule),
                TaxRates.current(_technician_has_rfc(db, order.technician_id)))
    payment = Payment(service_order_id=order.id, payer_id=order.client_id, kind=PaymentKind.SERVICE,
                      provider=provider or s.PAYMENT_PROVIDER, currency=s.PAYMENT_CURRENCY,
                      amount_cents=b.charge_cents)
    db.add(payment)
    db.flush()
    t, x = b.terms, b.taxes
    db.add(CommissionTransaction(
        payment_id=payment.id, rule_id=t.rule_id, rule_scope=t.scope.value, rule_type=t.type.value,
        rate_bp=t.rate_bp, fixed_cents=t.fixed_cents, min_cents=t.min_cents, max_cents=t.max_cents,
        service_tax_bp=x.service_tax_bp, commission_tax_bp=x.commission_tax_bp,
        isr_withholding_bp=x.isr_withholding_bp, iva_withholding_bp=x.iva_withholding_bp,
        technician_has_rfc=x.technician_has_rfc, price_cents=b.price_cents, service_tax_cents=b.service_tax_cents,
        gross_cents=b.gross_cents, discount_cents=b.discount_cents, commission_cents=b.commission_cents,
        commission_tax_cents=b.commission_tax_cents, withholding_isr_cents=b.withholding_isr_cents,
        withholding_iva_cents=b.withholding_iva_cents, technician_cents=b.technician_cents))
    db.flush()
    return payment


def _replacement(db: Session, failed: Payment) -> Payment:
    """Pago nuevo para la misma orden tras un rechazo: mismo monto y mismo desglose congelado."""
    new = Payment(service_order_id=failed.service_order_id, payer_id=failed.payer_id, kind=failed.kind,
                  provider=failed.provider, currency=failed.currency, amount_cents=failed.amount_cents)
    db.add(new)
    db.flush()
    db.add(_snapshot(new.id, _breakdown(db, failed)))
    db.flush()
    return new


# =============================================================================
# Cliente: tarjeta para la orden
# =============================================================================
def set_payment_method(db: Session, client: User, order: ServiceOrder, payment_method_id: str,
                       provider: PaymentProvider | None = None) -> Payment:
    """El cliente elige cuál de SUS tarjetas guardadas paga esta orden (orden ya bloqueada)."""
    provider = _provider(provider)
    if order.status != O.SCHEDULED:
        raise PaymentError("La tarjeta se elige cuando la orden está agendada", code="ORDER_NOT_SCHEDULED")
    payment = active_payment(db, order.id, lock=True)
    if payment is None:
        raise PaymentError("La orden no tiene un pago pendiente", code="ORDER_NO_PAYMENT")
    if payment.status != P.PENDING:
        raise PaymentError("El cobro ya se procesó; ya no se puede cambiar la tarjeta",
                           code="PAYMENT_METHOD_LOCKED", extra={"status": payment.status.value})
    customer = db.get(PaymentCustomer, (client.id, provider.name))
    owned = {c.provider_id for c in provider.list_saved_cards(customer.provider_customer_id)} if customer else set()
    if payment_method_id not in owned:                   # solo tarjetas del propio cliente
        raise DomainError("Tarjeta no encontrada", code="PAYMENT_METHOD_NOT_FOUND", http_status=422)
    payment.provider_payment_method_id = payment_method_id
    payment.version += 1
    db.flush()
    return payment


# =============================================================================
# Técnico "en camino": autorización (D7)
# =============================================================================
def authorize_for_departure(db: Session, order: ServiceOrder, provider: PaymentProvider | None = None) -> Payment:
    """
    Reserva el monto en la tarjeta del cliente con la división hacia la cuenta del técnico.
    La orden debe venir bloqueada. Un rechazo no es excepción: devuelve el pago FAILED (y ya
    existe uno nuevo PENDING para que el cliente elija otra tarjeta).
    """
    from app.payments import accounts

    provider = _provider(provider)
    payment = active_payment(db, order.id, lock=True)
    if payment is None:
        raise PaymentError("La orden no tiene un pago", code="ORDER_NO_PAYMENT")
    if payment.status in (P.AUTHORIZED, P.PROCESSING):
        return payment                                           # ya autorizado: repetir no cobra dos veces
    if payment.status == P.REQUIRES_ACTION:
        raise PaymentError("El cliente debe confirmar el cobro con su banco", code="PAYMENT_REQUIRES_ACTION")
    if payment.status != P.PENDING:
        raise PaymentError("El pago no se puede autorizar", code="PAYMENT_INVALID_TRANSITION")
    if not payment.provider_payment_method_id:
        db.add(OutboxEvent(event_type="payment.method_required", aggregate_type="service_order",
                           aggregate_id=order.id, recipient_user_id=order.client_id, payload={}))
        db.flush()
        raise PaymentError("El cliente aún no elige con qué tarjeta pagar", code="ORDER_PAYMENT_METHOD_MISSING")
    account = accounts.get_account(db, order.technician_id, provider.name, lock=True)
    if account is None or not account.can_receive_payments:
        raise PaymentError("Tu cuenta de pagos no está habilitada", code="PAYMENT_ACCOUNT_NOT_ENABLED",
                           http_status=403)
    customer = db.get(PaymentCustomer, (order.client_id, provider.name))
    if customer is None:
        raise PaymentError("El cliente no tiene tarjetas guardadas", code="ORDER_PAYMENT_METHOD_MISSING")
    b = _breakdown(db, payment)
    payment.technician_account_id = account.id
    result = provider.authorize(AuthorizationRequest(
        payment_id=payment.id, order_id=order.id, amount_cents=payment.amount_cents, currency=payment.currency,
        customer_id=customer.provider_customer_id, payment_method_id=payment.provider_payment_method_id,
        destination_account_id=account.provider_account_id, application_fee_cents=b.application_fee_cents))
    apply_provider_state(db, payment, result)
    return payment


# =============================================================================
# Reconciliación: el estado del proveedor manda
# =============================================================================
def apply_provider_state(db: Session, payment: Payment, pp: ProviderPayment) -> bool:
    """
    Aplica lo que reporta el proveedor. Si el evento llega "adelantado" (p. ej. PAID sin haber visto
    AUTHORIZED) se recorren las transiciones intermedias válidas; uno viejo que retrocedería se ignora.
    Devuelve True si hubo cambio.
    """
    if pp.provider_payment_id and payment.provider_payment_id is None:
        payment.provider_payment_id = pp.provider_payment_id
    before = payment.status
    target = pp.status
    if target == before:
        db.flush()
        return False
    if target == P.AUTHORIZED and before in (P.PENDING, P.REQUIRES_ACTION, P.PROCESSING):
        mark_authorized(db, payment, provider_payment_id=payment.provider_payment_id,
                        payment_method_fingerprint=pp.payment_method_fingerprint)
    elif target == P.PAID and before in (P.PENDING, P.REQUIRES_ACTION, P.PROCESSING, P.AUTHORIZED):
        if before != P.AUTHORIZED:
            mark_authorized(db, payment, provider_payment_id=payment.provider_payment_id,
                            payment_method_fingerprint=pp.payment_method_fingerprint)
        mark_captured(db, payment)
    elif target == P.REQUIRES_ACTION and before == P.PENDING:
        move(payment, P.REQUIRES_ACTION)
        db.add(OutboxEvent(event_type="payment.action_required", aggregate_type="payment", aggregate_id=payment.id,
                           recipient_user_id=payment.payer_id, payload={"order_id": str(payment.service_order_id)}))
    elif target == P.PROCESSING and before in (P.PENDING, P.REQUIRES_ACTION):
        move(payment, P.PROCESSING)
    elif target == P.FAILED and before in (P.PENDING, P.REQUIRES_ACTION, P.PROCESSING, P.AUTHORIZED):
        mark_failed(db, payment, pp.failure_code or "provider_failed")
    elif target == P.CANCELLED and before in CANCELLABLE:
        _cancelled_by_provider(db, payment, before)
    else:
        log.info("Evento de pago ignorado: %s → %s (pago %s)", before.value, target.value, payment.id)
        return False
    db.flush()
    return True


def _cancelled_by_provider(db: Session, payment: Payment, before: PaymentStatus) -> None:
    """La reserva se anuló fuera de nuestra app (p. ej. venció la autorización)."""
    move(payment, P.CANCELLED)
    payment.cancelled_at = _now()
    _record(db, payment, PaymentTransactionType.CANCEL, "provider_canceled")
    order = db.get(ServiceOrder, payment.service_order_id)
    if order is not None and order.status == O.SCHEDULED:
        _replacement(db, payment)                   # el técnico volverá a autorizar al salir
        order.departed_at = None
    elif before == P.AUTHORIZED:
        # Trabajo iniciado o terminado sin cobro posible: finanzas decide (D4, Fase 5).
        db.add(OutboxEvent(event_type="payment.authorization_expired", aggregate_type="payment",
                           aggregate_id=payment.id, payload={"order_id": str(payment.service_order_id),
                                                             "order_status": order.status.value if order else None}))


def refresh_from_provider(db: Session, payment: Payment, provider: PaymentProvider | None = None) -> Payment:
    """Consulta el cobro en el proveedor y aplica su estado (nunca recibe un estado de la app)."""
    if payment.provider_payment_id:
        apply_provider_state(db, payment, _provider(provider).get_payment(payment.provider_payment_id))
    return payment


def client_secret_for_action(payment: Payment, provider: PaymentProvider | None = None) -> str | None:
    """Solo en REQUIRES_ACTION y solo para el dueño (lo valida la ruta): completar 3D Secure en la app."""
    if payment.status != P.REQUIRES_ACTION or not payment.provider_payment_id:
        return None
    return _provider(provider).get_payment(payment.provider_payment_id).client_secret


# =============================================================================
# Anulación y captura
# =============================================================================
def cancel_for_order(db: Session, order: ServiceOrder, provider: PaymentProvider | None = None) -> None:
    """Orden cancelada o técnico retirado: se anula la intención / reserva."""
    payment = active_payment(db, order.id, lock=True)
    if payment is None or payment.status not in CANCELLABLE:
        return
    pid = payment.provider_payment_id
    move(payment, P.CANCELLED)
    payment.cancelled_at = _now()
    order.departed_at = None
    if pid:
        _record(db, payment, PaymentTransactionType.CANCEL, "requested")
        try:
            _provider(provider).cancel_authorization(pid, payment.id)
        except ProviderError:
            # Localmente ya no se capturará nunca; la reserva se libera sola al vencer. Se deja para reintento.
            log.warning("No se pudo anular la reserva %s; queda para reintento", payment.id)
            db.add(OutboxEvent(event_type="payment.void_requested", aggregate_type="payment",
                               aggregate_id=payment.id, payload={"provider_payment_id": pid}))
    db.flush()


def request_capture(db: Session, order: ServiceOrder) -> None:
    """Orden COMPLETED: la captura la hace el worker (capture_due). Aquí no se llama al proveedor."""


def capture(db: Session, payment: Payment, provider: PaymentProvider | None = None) -> Payment:
    """Cobra lo autorizado (pago YA bloqueado). Idempotente en el proveedor: capture:{pago}."""
    if payment.status != P.AUTHORIZED or not payment.provider_payment_id:
        return payment
    provider = _provider(provider)
    try:
        result = provider.capture(payment.provider_payment_id, payment.id, payment.amount_cents)
    except ProviderError as exc:
        if exc.retryable:
            raise
        # Rechazo del proveedor (p. ej. la autorización ya venció): se consulta el estado real.
        result = provider.get_payment(payment.provider_payment_id)
    apply_provider_state(db, payment, result)
    return payment


def capture_due(db: Session, provider: PaymentProvider | None = None, *, limit: int = 50) -> int:
    """Trabajo: captura los pagos AUTORIZADOS de órdenes que el cliente ya aprobó (o se aprobaron solas)."""
    ids = db.scalars(select(Payment.id).join(ServiceOrder, ServiceOrder.id == Payment.service_order_id).where(
        Payment.kind == PaymentKind.SERVICE, Payment.status == P.AUTHORIZED,
        ServiceOrder.status == O.COMPLETED).limit(limit)).all()
    done = 0
    for pid in ids:
        try:
            with db.begin_nested():
                payment = db.scalar(select(Payment).where(Payment.id == pid, Payment.status == P.AUTHORIZED)
                                    .with_for_update(skip_locked=True)
                                    .execution_options(populate_existing=True))
                if payment is None:
                    continue
                capture(db, payment, provider)
                done += payment.status == P.PAID
        except ProviderError:
            log.warning("Captura pendiente de reintento para el pago %s", pid)
    return done


def enforce_capture_deadline(db: Session, provider: PaymentProvider | None = None, now: datetime | None = None) -> int:
    """
    Salvaguarda de D5 + vencimiento: 24 h antes de que venza la autorización, si el cliente no ha
    respondido, la orden se aprueba sola y se captura. Si el trabajo sigue en curso o hay una
    disputa, se alerta a finanzas (decisión D4 pendiente) en lugar de cobrar.
    """
    from app.orders import service as orders

    now = now or _now()
    rows = db.execute(select(Payment.id, ServiceOrder.id, ServiceOrder.status)
                      .join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
                      .where(Payment.kind == PaymentKind.SERVICE, Payment.status == P.AUTHORIZED,
                             Payment.capture_deadline <= now + CAPTURE_SAFETY_MARGIN)).all()
    done = 0
    for payment_id, order_id, order_status in rows:
        if order_status == O.AWAITING_APPROVAL:
            with db.begin_nested():
                if orders.approve_before_authorization_expires(db, order_id):
                    done += 1
        elif order_status != O.COMPLETED:
            already = db.scalar(select(OutboxEvent.id).where(OutboxEvent.aggregate_id == payment_id,
                                                             OutboxEvent.event_type == "payment.authorization_expiring"))
            if already is None:
                db.add(OutboxEvent(event_type="payment.authorization_expiring", aggregate_type="payment",
                                   aggregate_id=payment_id,
                                   payload={"order_id": str(order_id), "order_status": order_status.value}))
    db.flush()
    return done


# =============================================================================
# Eventos del proveedor (llamados por apply_provider_state o por el worker de webhooks)
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
        _record(db, payment, PaymentTransactionType.AUTHORIZATION, "succeeded")


def mark_captured(db: Session, payment: Payment) -> None:
    """payment_intent.succeeded: cobro completo; se asienta el reparto congelado."""
    from app.orders import service as orders

    if not move(payment, P.PAID):
        return
    payment.captured_cents = payment.amount_cents
    payment.captured_at = _now()
    db.flush()
    _record(db, payment, PaymentTransactionType.CAPTURE, "succeeded", amount_cents=payment.captured_cents)
    ledger.post_capture(db, payment, _breakdown(db, payment))
    orders.on_payment_captured(db, payment.service_order_id)


def mark_failed(db: Session, payment: Payment, failure_code: str) -> None:
    """
    Orden todavía agendada (el técnico no ha iniciado) → sigue en pie: pago nuevo para que el
    cliente elija otra tarjeta y el técnico no sale. Falla al capturar → la orden COMPLETED pasa a FAILED.
    """
    from app.orders import service as orders

    before = payment.status
    if not move(payment, P.FAILED):
        return
    payment.failure_code = failure_code[:60]
    db.flush()
    _record(db, payment, PaymentTransactionType.CAPTURE if before == P.AUTHORIZED
            else PaymentTransactionType.AUTHORIZATION, "failed", failure_code=failure_code[:60])
    order = db.get(ServiceOrder, payment.service_order_id)
    if order is None or order.status != O.SCHEDULED:
        orders.on_payment_failed(db, payment.service_order_id, failure_code)
        return
    _replacement(db, payment)
    order.departed_at = None
    for recipient, event in ((order.client_id, "payment.authorization_failed"),
                             (order.technician_id, "order.payment_not_authorized")):
        db.add(OutboxEvent(event_type=event, aggregate_type="service_order", aggregate_id=order.id,
                           recipient_user_id=recipient, payload={"failure_code": failure_code[:60]}))
    db.flush()


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
