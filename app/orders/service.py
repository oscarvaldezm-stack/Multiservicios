"""
Casos de uso de las órdenes de servicio.

Reglas de seguridad:
- Todo acceso a una orden pasa por `get_for_user`: el cliente dueño o el técnico asignado;
  cualquier otro recibe 404 (no se confirma que exista). Sin IDOR/BOLA.
- Un técnico solo acepta si su KYC está APROBADO (dependencia VerifiedTechnician + FOR SHARE,
  y un trigger en la base lo repite), si está disponible y si ofrece esa categoría.
- Aceptar usa FOR UPDATE sobre la orden: dos técnicos no pueden ganar la misma orden.
- Regla crítica ampliada: aceptar, agendar o recibir una reserva directa exige KYC APROBADO
  y cuenta de pagos habilitada (también lo repite un trigger).
- El pago lo confirma solo el proveedor (app/payments/service.py). El cobro se autoriza cuando
  el técnico marca "en camino" (D7) e iniciar el trabajo exige el pago autorizado.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.orders.state_machine import PRE_START, OrderError, lock_order, transition
from app.payments import service as payments
from app.payments.commission import from_cents, to_cents
from app.models import (
    PAYMENT_CONFIRMED,
    OrderStatus,
    OutboxEvent,
    PaymentStatus,
    Review,
    ServiceCategory,
    PaymentAccountStatus,
    ServiceOrder,
    TechnicianPaymentAccount,
    TechnicianProfile,
    TechnicianService,
    User,
    UserRole,
)
from app.reviews import signals

O = OrderStatus
_NOT_FOUND = DomainError("Orden no encontrada", code="ORDER_NOT_FOUND", http_status=404)
# Estados en los que una disputa del cliente todavía se admite tras el pago.
_POST_PAYMENT = {O.PAID, O.READY_FOR_REVIEW, O.REVIEWED}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _actor(user: User) -> Actor:
    return Actor.of(user)


def _require_payment_account(db: Session, technician_id: uuid.UUID) -> None:
    from app.payments.accounts import can_receive_payments

    if not can_receive_payments(db, technician_id, get_settings().PAYMENT_PROVIDER):
        raise DomainError("Tu cuenta de pagos no está habilitada; complétala para recibir servicios",
                          code="PAYMENT_ACCOUNT_NOT_ENABLED", http_status=403)


def get_for_user(db: Session, user: User, order_id: uuid.UUID, *, lock: bool = False) -> ServiceOrder:
    order = lock_order(db, order_id) if lock else db.get(ServiceOrder, order_id)
    if order is None:
        raise _NOT_FOUND
    if user.role == UserRole.CLIENT and order.client_id == user.id:
        return order
    if user.role == UserRole.TECHNICIAN and order.technician_id == user.id:
        return order
    raise _NOT_FOUND


# =============================================================================
# Cliente
# =============================================================================
def create(db: Session, client: User, *, category_id: int, title: str, description: str, address_line: str,
           city: str, latitude: Decimal | None, longitude: Decimal | None,
           requested_technician_id: uuid.UUID | None, ctx: RequestContext | None) -> ServiceOrder:
    s = get_settings()
    category = db.get(ServiceCategory, category_id)
    if category is None or not category.is_active:
        raise DomainError("Categoría inválida", code="ORDER_CATEGORY_INVALID", http_status=422)
    open_count = db.scalar(select(func.count()).select_from(ServiceOrder).where(
        ServiceOrder.client_id == client.id, ServiceOrder.status == O.REQUESTED))
    if open_count >= s.ORDER_MAX_OPEN_PER_CLIENT:
        raise DomainError("Tienes demasiadas solicitudes abiertas", code="ORDER_TOO_MANY_OPEN", http_status=429)
    if requested_technician_id is not None:
        # Reserva directa: el técnico debe existir, estar aprobado, disponible y ofrecer la categoría.
        # Respuesta genérica para no revelar el estado KYC de un tercero.
        offers = db.scalar(select(func.count()).select_from(TechnicianService).join(
            TechnicianProfile, TechnicianProfile.user_id == TechnicianService.technician_id).join(
            TechnicianPaymentAccount, TechnicianPaymentAccount.technician_id == TechnicianService.technician_id).where(
            TechnicianService.technician_id == requested_technician_id, TechnicianService.category_id == category_id,
            TechnicianProfile.is_available.is_(True), TechnicianPaymentAccount.status == PaymentAccountStatus.ENABLED,
            TechnicianPaymentAccount.blocked_reason.is_(None)))
        if not offers:
            raise DomainError("Ese técnico no está disponible para esta categoría",
                              code="ORDER_TECHNICIAN_UNAVAILABLE", http_status=409)
    order = ServiceOrder(client_id=client.id, category_id=category_id, title=title, description=description,
                         address_line=address_line, city=city, latitude=latitude, longitude=longitude,
                         requested_technician_id=requested_technician_id)
    db.add(order)
    db.flush()           # el trigger revalida el KYC del técnico reservado
    signals.record(db, client.id, ctx)
    return order


def _after_completed(db: Session, order: ServiceOrder) -> None:
    """
    Orden recién COMPLETED: pide la captura del pago. Si el proveedor ya lo había capturado
    (captura automática o desde su panel), la orden avanza en ese momento a PAID → calificable;
    si no, avanzará cuando llegue el webhook de captura.
    """
    payment = payments.active_payment(db, order.id)
    if payment is not None and payment.status in PAYMENT_CONFIRMED:
        on_payment_captured(db, order.id)
    else:
        payments.request_capture(db, order)


def approve(db: Session, client: User, order_id: uuid.UUID, expected_version: int | None,
            ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, client, order_id, lock=True)
    transition(db, order, O.COMPLETED, _actor(client), expected_version=expected_version, ctx=ctx)
    _after_completed(db, order)
    _refresh_reputation(db, order.technician_id)
    return order


def cancel(db: Session, user: User, order_id: uuid.UUID, reason: str | None,
           ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, user, order_id, lock=True)
    if user.role == UserRole.TECHNICIAN:
        raise OrderError("El técnico no cancela: se retira de la orden", code="ORDER_USE_WITHDRAW")
    transition(db, order, O.CANCELLED, _actor(user), reason_code="CLIENT_CANCELLED", note=reason, ctx=ctx)
    payments.cancel_for_order(db, order)
    return order


def dispute(db: Session, client: User, order_id: uuid.UUID, reason: str, ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, client, order_id, lock=True)
    if order.status in _POST_PAYMENT:
        window = timedelta(days=get_settings().ORDER_DISPUTE_WINDOW_DAYS)
        if order.paid_at is None or _now() > order.paid_at + window:
            raise OrderError("El plazo para abrir una disputa ya venció", code="ORDER_DISPUTE_WINDOW_CLOSED")
    transition(db, order, O.DISPUTED, _actor(client), reason_code="CLIENT_DISPUTE", note=reason, ctx=ctx)
    return order


# =============================================================================
# Técnico
# =============================================================================
def feed(db: Session, technician: User, limit: int = 50) -> list[ServiceOrder]:
    cats = select(TechnicianService.category_id).where(TechnicianService.technician_id == technician.id)
    return db.scalars(
        select(ServiceOrder).where(
            ServiceOrder.status == O.REQUESTED, ServiceOrder.category_id.in_(cats),
            or_(ServiceOrder.requested_technician_id.is_(None), ServiceOrder.requested_technician_id == technician.id),
            ServiceOrder.client_id != technician.id,
        ).order_by(ServiceOrder.created_at).limit(limit)
    ).all()


def accept(db: Session, technician: User, order_id: uuid.UUID, agreed_price: Decimal,
           ctx: RequestContext | None) -> ServiceOrder:
    profile = db.get(TechnicianProfile, technician.id)
    if profile is None or not profile.is_available:
        raise OrderError("Márcate disponible para aceptar servicios", code="TECHNICIAN_NOT_AVAILABLE")
    _require_payment_account(db, technician.id)
    s = get_settings()
    price_cents = to_cents(agreed_price)
    if not s.PAYMENT_MIN_SERVICE_CENTS <= price_cents <= s.PAYMENT_MAX_SERVICE_CENTS:
        raise DomainError("El precio está fuera del rango admitido", code="ORDER_PRICE_OUT_OF_RANGE", http_status=422,
                          extra={"min": str(from_cents(s.PAYMENT_MIN_SERVICE_CENTS)),
                                 "max": str(from_cents(s.PAYMENT_MAX_SERVICE_CENTS))})
    order = lock_order(db, order_id)
    # Un técnico solo "ve" solicitudes abiertas de sus categorías (o reservadas a él).
    offers = db.get(TechnicianService, (technician.id, order.category_id)) if order else None
    if order is None or offers is None or order.status != O.REQUESTED \
            or order.requested_technician_id not in (None, technician.id):
        raise _NOT_FOUND
    order.agreed_price = agreed_price
    transition(db, order, O.ACCEPTED, _actor(technician), ctx=ctx)
    db.flush()           # trigger: KYC APROBADO y usuario activo, en esta misma transacción
    signals.record(db, technician.id, ctx)
    return order


def schedule(db: Session, technician: User, order_id: uuid.UUID, scheduled_at: datetime,
             ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, technician, order_id, lock=True)
    _require_payment_account(db, technician.id)
    if scheduled_at <= _now():
        raise DomainError("La fecha debe ser futura", code="ORDER_SCHEDULE_IN_PAST", http_status=422)
    order.scheduled_at = scheduled_at
    transition(db, order, O.SCHEDULED, _actor(technician), ctx=ctx)
    payments.create_for_order(db, order)
    return order


def withdraw(db: Session, technician: User, order_id: uuid.UUID, reason: str | None,
             ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, technician, order_id, lock=True)
    payments.cancel_for_order(db, order)
    transition(db, order, O.REQUESTED, _actor(technician), reason_code="TECHNICIAN_WITHDREW", note=reason, ctx=ctx)
    _refresh_reputation(db, technician.id)
    return order


def depart(db: Session, technician: User, order_id: uuid.UUID, ctx: RequestContext | None):
    """
    "En camino" (D7): se autoriza el cobro en la tarjeta que eligió el cliente. Si el banco lo
    rechaza, el técnico NO debe salir: la orden sigue agendada y el cliente elige otra tarjeta.
    Repetirlo con el pago ya autorizado no vuelve a cobrar.
    """
    order = get_for_user(db, technician, order_id, lock=True)
    if order.status != O.SCHEDULED:
        raise OrderError("Solo se sale a un servicio agendado", code="ORDER_NOT_SCHEDULED",
                         extra={"status": order.status.value})
    payment = payments.authorize_for_departure(db, order)
    if payment.status == PaymentStatus.AUTHORIZED and order.departed_at is None:
        order.departed_at = _now()
        order.version += 1
        db.add(OutboxEvent(event_type="order.technician_on_the_way", aggregate_type="service_order",
                           aggregate_id=order.id, recipient_user_id=order.client_id, payload={}))
    db.flush()
    return order, payment


def start(db: Session, technician: User, order_id: uuid.UUID, ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, technician, order_id, lock=True)
    payment = payments.active_payment(db, order.id)
    if payment is None or payment.status != PaymentStatus.AUTHORIZED:
        raise OrderError("El pago del cliente aún no está autorizado", code="ORDER_PAYMENT_NOT_AUTHORIZED")
    transition(db, order, O.IN_PROGRESS, _actor(technician), ctx=ctx)
    return order


def finish(db: Session, technician: User, order_id: uuid.UUID, ctx: RequestContext | None) -> ServiceOrder:
    order = get_for_user(db, technician, order_id, lock=True)
    transition(db, order, O.AWAITING_APPROVAL, _actor(technician), ctx=ctx)
    return order


# =============================================================================
# Efectos de pagos (llamados desde app/payments/service.py) y del KYC
# =============================================================================
def on_payment_captured(db: Session, order_id: uuid.UUID) -> None:
    order = lock_order(db, order_id)
    if order is None or order.status != O.COMPLETED:
        return
    system = Actor.system()
    transition(db, order, O.PAID, system)
    transition(db, order, O.READY_FOR_REVIEW, system)


def on_payment_failed(db: Session, order_id: uuid.UUID, failure_code: str) -> None:
    order = lock_order(db, order_id)
    if order is not None and order.status in (O.SCHEDULED, O.COMPLETED):
        transition(db, order, O.FAILED, Actor.system(), reason_code="PAYMENT_FAILED", note=failure_code[:500])


def on_full_refund(db: Session, order_id: uuid.UUID, actor: Actor) -> None:
    from app.reviews.service import hide_for_refund

    order = lock_order(db, order_id)
    if order is None or order.status not in (O.DISPUTED, O.READY_FOR_REVIEW, O.REVIEWED):
        return
    transition(db, order, O.REFUNDED, actor, reason_code="FULL_REFUND")
    review = db.scalar(select(Review).where(Review.service_order_id == order.id))
    if review is not None:
        hide_for_refund(db, review)
    _refresh_reputation(db, order.technician_id)


def release_technician_orders(db: Session, technician_id: uuid.UUID, reason_code: str) -> int:
    """El técnico dejó de estar aprobado: sus órdenes no iniciadas vuelven a la bolsa."""
    ids = db.scalars(select(ServiceOrder.id).where(ServiceOrder.technician_id == technician_id,
                                                   ServiceOrder.status.in_(PRE_START))).all()
    for oid in ids:
        order = lock_order(db, oid)
        if order is None or order.status not in PRE_START:
            continue
        payments.cancel_for_order(db, order)
        transition(db, order, O.REQUESTED, Actor.system(), reason_code=reason_code)
    # Reservas directas a ese técnico (incluidas las que acaban de volver a la bolsa): se abren a
    # cualquier técnico de la categoría y se avisa al cliente, para que no queden atoradas.
    direct = db.scalars(select(ServiceOrder).where(ServiceOrder.requested_technician_id == technician_id,
                                                   ServiceOrder.status == O.REQUESTED).with_for_update()).all()
    for order in direct:
        order.requested_technician_id = None
        order.version += 1
        db.add(OutboxEvent(event_type="order.direct_request_released", aggregate_type="service_order",
                           aggregate_id=order.id, recipient_user_id=order.client_id,
                           payload={"reason_code": reason_code}))
    db.flush()
    return len(ids)


# =============================================================================
# Administración: resolución de disputas
# =============================================================================
def resolve_dispute(db: Session, admin: Actor, order_id: uuid.UUID, outcome: str, refund_amount: Decimal | None,
                    note: str, ctx: RequestContext | None) -> ServiceOrder:
    """
    RELEASE        → el técnico cumplió: se captura/libera el pago; la orden queda calificable.
    PARTIAL_REFUND → el servicio ocurrió con fallas: reembolso parcial; sigue calificable.
    FULL_REFUND    → el servicio no se prestó: sin cobro (se anula) o reembolso total; no calificable.
    PARTIAL y FULL cuentan como disputa perdida para la reputación del técnico.
    """
    order = lock_order(db, order_id)
    if order is None:
        raise _NOT_FOUND
    if order.status != O.DISPUTED:
        raise OrderError("La orden no está en disputa", code="ORDER_NOT_DISPUTED")
    payment = payments.active_payment(db, order.id, lock=True)
    captured = payment is not None and payment.status in PAYMENT_CONFIRMED
    refundable_cents = payment.captured_cents - payment.refunded_cents if captured else 0
    refund_cents = to_cents(refund_amount) if refund_amount is not None else None
    has_review = db.scalar(select(func.count()).select_from(Review).where(Review.service_order_id == order.id)) > 0
    after_payment = O.REVIEWED if has_review else O.READY_FOR_REVIEW

    if outcome == "RELEASE":
        if captured:
            transition(db, order, after_payment, admin, reason_code="DISPUTE_RELEASED", note=note, ctx=ctx)
        elif payment is not None and payment.status == PaymentStatus.AUTHORIZED:
            transition(db, order, O.COMPLETED, admin, reason_code="DISPUTE_RELEASED", note=note, ctx=ctx)
            _after_completed(db, order)
        else:
            raise OrderError("No hay un pago que liberar", code="ORDER_NO_PAYMENT")
    elif outcome == "PARTIAL_REFUND":
        if not captured or refund_cents is None or not (0 < refund_cents < refundable_cents):
            raise DomainError("El reembolso parcial requiere un pago cobrado y un monto menor a lo que queda por reembolsar",
                              code="ORDER_INVALID_REFUND", http_status=422)
        db.add(_refund_request(payment.id, refund_cents))
        transition(db, order, after_payment, admin, reason_code="DISPUTE_PARTIAL_REFUND", note=note, ctx=ctx)
    elif outcome == "FULL_REFUND":
        if captured:
            # El reembolso lo confirma el proveedor (webhook) → la orden pasa a REFUNDED en ese momento.
            db.add(_refund_request(payment.id, refundable_cents))
        else:
            payments.cancel_for_order(db, order)
            transition(db, order, O.CANCELLED, admin, reason_code="DISPUTE_FULL_REFUND", note=note, ctx=ctx)
    else:
        raise DomainError("Resultado inválido", code="ORDER_INVALID_OUTCOME", http_status=422)

    write_audit(db, action="order.dispute.resolved", actor=admin, technician_id=order.technician_id,
                target_type="service_order", target_id=str(order.id), reason_code=outcome, reason_note=note,
                changes={"refund_amount": str(refund_amount) if refund_amount else None}, ctx=ctx)
    _refresh_reputation(db, order.technician_id)
    db.flush()
    return order


def _refund_request(payment_id: uuid.UUID, amount_cents: int) -> OutboxEvent:
    return OutboxEvent(event_type="payment.refund_requested", aggregate_type="payment", aggregate_id=payment_id,
                       payload={"amount_cents": amount_cents})


# =============================================================================
# Trabajos automáticos
# =============================================================================
def auto_approve(db: Session, now: datetime | None = None) -> int:
    """Decisión D5: si el cliente no responde en ORDER_AUTO_APPROVE_HOURS, el trabajo se da por aceptado."""
    now = now or _now()
    limit = now - timedelta(hours=get_settings().ORDER_AUTO_APPROVE_HOURS)
    ids = db.scalars(select(ServiceOrder.id).where(ServiceOrder.status == O.AWAITING_APPROVAL,
                                                   ServiceOrder.work_finished_at < limit)).all()
    for oid in ids:
        order = lock_order(db, oid)
        if order is not None and order.status == O.AWAITING_APPROVAL:
            transition(db, order, O.COMPLETED, Actor.system(), reason_code="AUTO_APPROVED")
            _after_completed(db, order)
            _refresh_reputation(db, order.technician_id)
    return len(ids)


def approve_before_authorization_expires(db: Session, order_id: uuid.UUID) -> bool:
    """La autorización vence en menos de 24 h y el cliente no respondió: se aprueba sola para poder cobrar."""
    order = lock_order(db, order_id)
    if order is None or order.status != O.AWAITING_APPROVAL:
        return False
    transition(db, order, O.COMPLETED, Actor.system(), reason_code="AUTO_APPROVED_AUTH_EXPIRING")
    _after_completed(db, order)
    _refresh_reputation(db, order.technician_id)
    return True


def expire_requests(db: Session, now: datetime | None = None) -> int:
    now = now or _now()
    limit = now - timedelta(hours=get_settings().ORDER_REQUEST_EXPIRY_HOURS)
    ids = db.scalars(select(ServiceOrder.id).where(ServiceOrder.status == O.REQUESTED,
                                                   ServiceOrder.created_at < limit)).all()
    for oid in ids:
        order = lock_order(db, oid)
        if order is not None and order.status == O.REQUESTED:
            transition(db, order, O.CANCELLED, Actor.system(), reason_code="REQUEST_EXPIRED")
    return len(ids)


def _refresh_reputation(db: Session, technician_id: uuid.UUID | None) -> None:
    if technician_id is not None:
        from app.reviews.reputation import recompute
        recompute(db, technician_id)
