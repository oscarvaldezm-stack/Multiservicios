"""
Reembolsos (sección 9 del doc de pagos).

Quién absorbe un reembolso lo decide el MOTIVO, con dos parámetros de Stripe:
- reverse_transfer: se recupera del técnico la parte proporcional de lo que se le transfirió.
- refund_application_fee: la plataforma devuelve la parte proporcional de su comisión (con su IVA
  y retenciones). Stripe solo lo permite si también se revierte la transferencia.
La plataforma absorbe el resto. Ejemplo (cobro $1,000, comisión $150, técnico $850, reembolso $300):
  falla del técnico (ambos)  → técnico devuelve $255, plataforma $45
  falla de la plataforma     → técnico $0, plataforma $300

Flujo: el cliente solicita (o finanzas crea, o sale de una disputa) → finanzas aprueba → se
ejecuta en el proveedor con Idempotency-Key refund:{id} → el estado final lo confirma el proveedor
(respuesta o webhook refund.*). Arriba de REFUND_DOUBLE_APPROVAL_CENTS (D8) hace falta una
segunda firma de FINANCE_ADMIN distinta a quien lo pidió (la base lo repite: four_eyes).
Una sola solicitud abierta por pago (índice único parcial) y el total nunca excede lo cobrado.

Si el técnico ya retiró su saldo, Stripe rechaza la reversión: el reembolso queda FAILED y se
alerta a finanzas, que decide si la plataforma lo cubre (otro reembolso con motivo de plataforma).
Las retenciones de ISR/IVA de un pago reembolsado requieren ajuste fiscal: lo define el contador.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.models import (
    ActorType,
    OrderStatus,
    OutboxEvent,
    Payment,
    PaymentRefund,
    PaymentStatus,
    RefundStatus,
    ServiceOrder,
    User,
)
from app.payments import ledger
from app.payments import service as payments
from app.payments.providers.base import PaymentProvider, ProviderError, RefundInfo, RefundRequest
from app.payments.state_machine import move

log = logging.getLogger("payments")
R, P = RefundStatus, PaymentStatus

# Deben coincidir EXACTAMENTE con el trigger de la migración 0009 (lo verifica una prueba).
ALLOWED_REFUND_TRANSITIONS: frozenset[tuple[RefundStatus, RefundStatus]] = frozenset({
    (R.REQUESTED, R.APPROVED), (R.REQUESTED, R.REJECTED),
    (R.APPROVED, R.PENDING), (R.APPROVED, R.SUCCEEDED), (R.APPROVED, R.FAILED),
    (R.PENDING, R.SUCCEEDED), (R.PENDING, R.FAILED),
})
OPEN = (R.REQUESTED, R.APPROVED, R.PENDING)
REFUNDABLE = (P.PAID, P.PARTIALLY_REFUNDED)


@dataclass(frozen=True)
class Policy:
    reverse_transfer: bool
    refund_application_fee: bool
    client_may_request: bool = False
    duplicate: bool = False
    label: str = ""


# Catálogo de motivos → política. Cambiar quién absorbe un motivo es un cambio revisado de código.
REASONS: dict[str, Policy] = {
    "SERVICE_NOT_PROVIDED": Policy(True, True, True, label="El técnico no prestó el servicio"),
    "SERVICE_DEFICIENT": Policy(True, True, True, label="El servicio quedó mal o incompleto"),
    "PRICE_ADJUSTMENT": Policy(True, True, label="Ajuste de precio acordado con el técnico"),
    "DUPLICATE_CHARGE": Policy(False, False, True, duplicate=True, label="Cobro duplicado"),
    "PLATFORM_ERROR": Policy(False, False, label="Error de la plataforma"),
    "COURTESY": Policy(False, False, label="Cortesía de la plataforma"),
    "OUTSIDE_APP": Policy(False, False, label="Reembolso hecho fuera de la app"),
}


class RefundError(DomainError):
    http_status = 409
    code = "REFUND_ERROR"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _move(refund: PaymentRefund, to: RefundStatus) -> None:
    """Cada cambio se escribe en seguida: así el trigger valida cada paso (no solo el estado final)."""
    if refund.status == to:
        return
    if (refund.status, to) not in ALLOWED_REFUND_TRANSITIONS:
        raise RefundError(f"Reembolso: {refund.status.value} → {to.value} no permitido",
                          code="REFUND_INVALID_TRANSITION")
    refund.status = to
    from sqlalchemy.orm import object_session

    session = object_session(refund)
    if session is not None:
        session.flush()


def _permissions(actor: Actor):
    from app.kyc.permissions import permissions_for

    return permissions_for(actor.admin_roles) if actor.actor_type == ActorType.ADMIN else frozenset()


def _require(actor: Actor, perm) -> None:
    if perm not in _permissions(actor):
        raise RefundError("No tienes permiso para esta acción", code="FORBIDDEN", http_status=403)


def _lock_payment(db: Session, payment_id: uuid.UUID) -> Payment:
    payment = db.scalar(select(Payment).where(Payment.id == payment_id).with_for_update()
                        .execution_options(populate_existing=True))
    if payment is None:
        raise RefundError("Pago no encontrado", code="PAYMENT_NOT_FOUND", http_status=404)
    return payment


def refundable_cents(db: Session, payment: Payment) -> int:
    """Lo que aún se puede devolver: cobrado − reembolsado − lo que ya está en curso."""
    in_flight = db.scalar(select(func.coalesce(func.sum(PaymentRefund.amount_cents), 0)).where(
        PaymentRefund.payment_id == payment.id, PaymentRefund.status.in_(OPEN))) or 0
    return payment.captured_cents - payment.refunded_cents - int(in_flight)


# =============================================================================
# Reparto: quién absorbe
# =============================================================================
@dataclass(frozen=True)
class Allocation:
    technician: int
    commission: int
    vat: int
    withholding: int
    platform: int


def allocate(db: Session, payment: Payment, amount_cents: int, policy: Policy) -> Allocation:
    """Proporcional a lo cobrado (redondeo hacia abajo en cada parte; la plataforma absorbe el remanente)."""
    b = payments.effective_breakdown(db, payment)
    charged = b.gross_cents - b.discount_cents

    def share(part: int) -> int:
        return part * amount_cents // charged

    technician = share(b.technician_cents) if policy.reverse_transfer else 0
    commission = vat = withholding = 0
    if policy.refund_application_fee:
        commission = share(b.commission_cents)
        vat = share(b.commission_tax_cents)
        withholding = share(b.withholding_isr_cents + b.withholding_iva_cents)
    platform = amount_cents - technician - commission - vat - withholding
    return Allocation(technician, commission, vat, withholding, platform)


# =============================================================================
# Alta: cliente, finanzas o disputa
# =============================================================================
def _create(db: Session, payment: Payment, *, amount_cents: int | None, reason_code: str, source: str,
            requested_by: uuid.UUID | None, note: str | None) -> PaymentRefund:
    policy = REASONS.get(reason_code)
    if policy is None:
        raise DomainError("Motivo de reembolso inválido", code="REFUND_INVALID_REASON", http_status=422)
    if payment.status not in REFUNDABLE:
        raise RefundError("Solo se reembolsa un pago cobrado", code="REFUND_PAYMENT_NOT_REFUNDABLE",
                          extra={"status": payment.status.value})
    if db.scalar(select(PaymentRefund.id).where(PaymentRefund.payment_id == payment.id,
                                                PaymentRefund.status.in_(OPEN))):
        raise RefundError("Ya hay un reembolso en curso para este pago", code="REFUND_ALREADY_OPEN")
    available = refundable_cents(db, payment)
    amount = available if amount_cents is None else amount_cents
    if not 0 < amount <= available:
        raise DomainError("El monto excede lo que queda por reembolsar", code="REFUND_EXCEEDS_CAPTURED",
                          http_status=422, extra={"available_cents": available})
    refund = PaymentRefund(payment_id=payment.id, amount_cents=amount, reason_code=reason_code,
                           reverse_transfer=policy.reverse_transfer,
                           refund_application_fee=policy.refund_application_fee,
                           request_source=source, requested_by=requested_by, note=(note or None) and note[:500])
    db.add(refund)
    db.flush()
    return refund


def request_by_client(db: Session, client: User, order_id: uuid.UUID, *, reason_code: str,
                      amount_cents: int | None, note: str | None) -> PaymentRefund:
    """El cliente pide un reembolso de su orden pagada, dentro del plazo de disputa."""
    from app.orders.service import get_for_user

    order = get_for_user(db, client, order_id, lock=True)
    if order.status not in (OrderStatus.PAID, OrderStatus.READY_FOR_REVIEW, OrderStatus.REVIEWED):
        raise RefundError("Esta orden no admite reembolso", code="REFUND_ORDER_NOT_ELIGIBLE")
    window = timedelta(days=get_settings().ORDER_DISPUTE_WINDOW_DAYS)
    if order.paid_at is None or _now() > order.paid_at + window:
        raise RefundError("El plazo para pedir un reembolso ya venció", code="REFUND_WINDOW_CLOSED")
    policy = REASONS.get(reason_code)
    if policy is None or not policy.client_may_request:
        raise DomainError("Motivo de reembolso inválido", code="REFUND_INVALID_REASON", http_status=422)
    payment = payments.active_payment(db, order.id, lock=True)
    if payment is None:
        raise RefundError("La orden no tiene un pago cobrado", code="REFUND_PAYMENT_NOT_REFUNDABLE")
    refund = _create(db, payment, amount_cents=amount_cents, reason_code=reason_code, source="CLIENT",
                     requested_by=client.id, note=note)
    db.add(OutboxEvent(event_type="refund.requested", aggregate_type="payment_refund", aggregate_id=refund.id,
                       payload={"order_id": str(order.id), "amount_cents": refund.amount_cents}))
    db.flush()
    return refund


def create_by_finance(db: Session, actor: Actor, payment_id: uuid.UUID, *, amount_cents: int | None,
                      reason_code: str, note: str, source: str = "FINANCE",
                      provider: PaymentProvider | None = None, ctx: RequestContext | None = None) -> PaymentRefund:
    """Finanzas crea un reembolso. Hasta el umbral se ejecuta con una sola firma; arriba espera la segunda."""
    from app.kyc.permissions import Permission

    _require(actor, Permission.REFUNDS_EXECUTE)
    payment = _lock_payment(db, payment_id)
    refund = _create(db, payment, amount_cents=amount_cents, reason_code=reason_code, source=source,
                     requested_by=actor.user_id, note=note)
    write_audit(db, action="refund.created", actor=actor, target_type="payment_refund", target_id=str(refund.id),
                reason_code=reason_code, reason_note=note,
                changes={"payment_id": str(payment.id), "amount_cents": refund.amount_cents, "source": source},
                ctx=ctx)
    if refund.amount_cents <= get_settings().REFUND_DOUBLE_APPROVAL_CENTS:
        _move(refund, R.APPROVED)
        execute(db, refund, provider)
    else:
        db.add(OutboxEvent(event_type="refund.second_approval_required", aggregate_type="payment_refund",
                           aggregate_id=refund.id, payload={"amount_cents": refund.amount_cents}))
    db.flush()
    return refund


def approve(db: Session, actor: Actor, refund_id: uuid.UUID, *, provider: PaymentProvider | None = None,
            ctx: RequestContext | None = None) -> PaymentRefund:
    from app.kyc.permissions import Permission

    _require(actor, Permission.REFUNDS_EXECUTE)
    refund = _lock_refund(db, refund_id)
    if refund.status != R.REQUESTED:
        raise RefundError("El reembolso no está pendiente de aprobación", code="REFUND_NOT_PENDING")
    if refund.requested_by == actor.user_id:
        raise RefundError("Quien pide un reembolso no puede aprobarlo", code="REFUND_FOUR_EYES", http_status=403)
    if refund.amount_cents > get_settings().REFUND_DOUBLE_APPROVAL_CENTS:
        _require(actor, Permission.REFUNDS_APPROVE_HIGH)
    _lock_payment(db, refund.payment_id)
    refund.approved_by = actor.user_id
    _move(refund, R.APPROVED)
    write_audit(db, action="refund.approved", actor=actor, target_type="payment_refund", target_id=str(refund.id),
                changes={"amount_cents": refund.amount_cents}, ctx=ctx)
    execute(db, refund, provider)
    return refund


def reject(db: Session, actor: Actor, refund_id: uuid.UUID, note: str, ctx: RequestContext | None = None) -> PaymentRefund:
    from app.kyc.permissions import Permission

    _require(actor, Permission.REFUNDS_EXECUTE)
    refund = _lock_refund(db, refund_id)
    if refund.status != R.REQUESTED:
        raise RefundError("El reembolso no está pendiente de aprobación", code="REFUND_NOT_PENDING")
    _move(refund, R.REJECTED)
    refund.failure_code = "REJECTED_BY_FINANCE"
    write_audit(db, action="refund.rejected", actor=actor, target_type="payment_refund", target_id=str(refund.id),
                reason_note=note, ctx=ctx)
    if refund.request_source == "CLIENT":
        db.add(OutboxEvent(event_type="refund.rejected", aggregate_type="payment_refund", aggregate_id=refund.id,
                           recipient_user_id=refund.requested_by, payload={}))
    db.flush()
    return refund


def _lock_refund(db: Session, refund_id: uuid.UUID) -> PaymentRefund:
    refund = db.scalar(select(PaymentRefund).where(PaymentRefund.id == refund_id).with_for_update()
                       .execution_options(populate_existing=True))
    if refund is None:
        raise RefundError("Reembolso no encontrado", code="REFUND_NOT_FOUND", http_status=404)
    return refund


# =============================================================================
# Ejecución y confirmación
# =============================================================================
def execute(db: Session, refund: PaymentRefund, provider: PaymentProvider | None = None) -> PaymentRefund:
    """Envía un reembolso APROBADO al proveedor. Un error de red lo deja APROBADO para reintento."""
    if refund.status != R.APPROVED:
        return refund
    payment = _lock_payment(db, refund.payment_id)
    provider = provider or payments._provider(None)
    refund.executed_at = _now()
    try:
        info = provider.refund(RefundRequest(
            refund_id=refund.id, provider_payment_id=payment.provider_payment_id, amount_cents=refund.amount_cents,
            reverse_transfer=refund.reverse_transfer, refund_application_fee=refund.refund_application_fee,
            duplicate=REASONS[refund.reason_code].duplicate))
    except ProviderError as exc:
        if exc.retryable:
            log.warning("Reembolso %s pendiente de reintento", refund.id)
            db.flush()
            return refund
        _fail(db, refund, exc.provider_code or exc.code)
        return refund
    apply_provider_refund(db, info, refund=refund)
    return refund


def _fail(db: Session, refund: PaymentRefund, code: str) -> None:
    _move(refund, R.FAILED)
    refund.failure_code = (code or "failed")[:60]
    # p. ej. balance_insufficient: el técnico ya retiró; finanzas decide si la plataforma lo cubre.
    db.add(OutboxEvent(event_type="refund.failed", aggregate_type="payment_refund", aggregate_id=refund.id,
                       payload={"failure_code": refund.failure_code, "amount_cents": refund.amount_cents}))
    db.flush()


def apply_provider_refund(db: Session, info: RefundInfo, *, refund: PaymentRefund | None = None) -> PaymentRefund | None:
    """Aplica el estado de un reembolso según el proveedor (respuesta o webhook refund.*)."""
    if refund is None:
        refund = _find(db, info)
    if refund is None:
        return _record_outside_app(db, info)
    if refund.provider_refund_id is None:
        refund.provider_refund_id = info.provider_refund_id
    if info.status == "succeeded" and refund.status in (R.APPROVED, R.PENDING):
        _succeed(db, refund)
    elif info.status in ("failed", "canceled") and refund.status in (R.APPROVED, R.PENDING):
        _fail(db, refund, info.failure_reason or info.status)
    elif info.status in ("pending", "requires_action") and refund.status == R.APPROVED:
        _move(refund, R.PENDING)
    elif info.status == "failed" and refund.status == R.SUCCEEDED:
        # Stripe puede fallar un reembolso ya exitoso (el banco lo rechaza): no se revierte solo.
        db.add(OutboxEvent(event_type="refund.failed_after_success", aggregate_type="payment_refund",
                           aggregate_id=refund.id, payload={"provider_refund_id": info.provider_refund_id}))
    db.flush()
    return refund


def _find(db: Session, info: RefundInfo) -> PaymentRefund | None:
    stmt = select(PaymentRefund).where(PaymentRefund.provider_refund_id == info.provider_refund_id)
    refund = db.scalar(stmt.with_for_update().execution_options(populate_existing=True))
    if refund is None and info.metadata_refund_id:
        try:
            refund = _lock_refund(db, uuid.UUID(info.metadata_refund_id))
        except (ValueError, RefundError):
            refund = None
    return refund


def _succeed(db: Session, refund: PaymentRefund) -> None:
    from app.orders import service as orders

    payment = _lock_payment(db, refund.payment_id)
    alloc = allocate(db, payment, refund.amount_cents, REASONS[refund.reason_code])
    refund.technician_recovered_cents = alloc.technician
    refund.commission_returned_cents = alloc.commission
    refund.vat_returned_cents = alloc.vat
    refund.withholding_returned_cents = alloc.withholding
    refund.platform_absorbed_cents = alloc.platform
    refund.succeeded_at = _now()
    _move(refund, R.SUCCEEDED)
    total = payment.refunded_cents + refund.amount_cents
    full = total >= payment.captured_cents
    move(payment, P.REFUNDED if full else P.PARTIALLY_REFUNDED)
    payment.refunded_cents = min(total, payment.captured_cents)
    payment.refunded_at = _now()
    db.flush()
    ledger.post_refund_allocation(db, payment, refund)
    order = db.get(ServiceOrder, payment.service_order_id)
    if order is not None:
        db.add(OutboxEvent(event_type="refund.succeeded", aggregate_type="payment_refund", aggregate_id=refund.id,
                           recipient_user_id=order.client_id, payload={"amount_cents": refund.amount_cents}))
    if full:
        orders.on_full_refund(db, payment.service_order_id, Actor.system())
    db.flush()


def _record_outside_app(db: Session, info: RefundInfo) -> PaymentRefund | None:
    """Reembolso hecho desde el panel del proveedor: se registra (la plataforma lo absorbe) y se alerta."""
    payment = db.scalar(select(Payment).where(Payment.provider_payment_id == info.provider_payment_id)
                        .with_for_update().execution_options(populate_existing=True)) \
        if info.provider_payment_id else None
    if payment is None or payment.status not in REFUNDABLE or info.status not in ("succeeded", "pending"):
        return None
    amount = min(info.amount_cents, payment.captured_cents - payment.refunded_cents)
    if amount <= 0:
        return None
    refund = PaymentRefund(payment_id=payment.id, amount_cents=amount, reason_code="OUTSIDE_APP",
                           reverse_transfer=False, refund_application_fee=False, request_source="OUTSIDE_APP",
                           provider_refund_id=info.provider_refund_id)
    db.add(refund)
    db.flush()
    _move(refund, R.APPROVED)
    db.add(OutboxEvent(event_type="payment.refunded_outside_app", aggregate_type="payment_refund",
                       aggregate_id=refund.id, payload={"provider_refund_id": info.provider_refund_id}))
    if info.status == "succeeded":
        _succeed(db, refund)
    else:
        _move(refund, R.PENDING)
    db.flush()
    return refund


def retry_approved(db: Session, provider: PaymentProvider | None = None, *, limit: int = 50) -> int:
    """Trabajo: reenvía los reembolsos aprobados que el proveedor no recibió (error de red)."""
    ids = db.scalars(select(PaymentRefund.id).where(PaymentRefund.status == R.APPROVED).limit(limit)).all()
    done = 0
    for rid in ids:
        with db.begin_nested():
            refund = db.scalar(select(PaymentRefund).where(PaymentRefund.id == rid, PaymentRefund.status == R.APPROVED)
                               .with_for_update(skip_locked=True).execution_options(populate_existing=True))
            if refund is not None:
                execute(db, refund, provider)
                done += refund.status != R.APPROVED
    return done
