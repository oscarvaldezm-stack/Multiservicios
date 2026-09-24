"""
Órdenes de servicio.

- Cliente: crear, ver las suyas, cancelar, aceptar el trabajo, abrir disputa.
- Técnico APROBADO: ver solicitudes de sus categorías, aceptar, agendar, retirarse,
  iniciar (con pago autorizado) y terminar.
- Cualquier orden ajena responde 404 (sin confirmar que existe).
El estado de pago NO se puede cambiar desde aquí: solo lo cambia el proveedor (su respuesta a
una llamada del backend o su webhook). El cliente solo elige CON QUÉ TARJETA paga (Idempotency-Key)
y el técnico marca "en camino", que autoriza el cobro.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, Path, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select

from app.api.deps import CurrentClient, CurrentTechnician, CurrentUser, DbSession, ReqCtx, VerifiedTechnician, \
    require_permission, require_roles
from app.core.actor import Actor
from app.core.errors import DomainError
from app.kyc.permissions import Permission
from app.models import OrderStatus, Payment, ServiceOrder, User, UserRole
from app.orders import service
from app.payments import idempotency, panel
from app.payments import service as payments
from app.payments.commission import from_cents
from app.schemas.payments import (
    DepartOut,
    OrderPaymentClientOut,
    OrderPaymentLineOut,
    OrderPaymentTechnicianOut,
    PaymentMethodIn,
)
from app.schemas.marketplace import (
    AcceptIn,
    DisputeIn,
    DisputeResolutionIn,
    FeedItemOut,
    OrderCreateIn,
    OrderOut,
    ReasonIn,
    ScheduleIn,
    VersionIn,
)

router = APIRouter(prefix="/orders", tags=["órdenes"])
client_router = APIRouter(prefix="/clients/me", tags=["órdenes"], dependencies=[Depends(require_roles(UserRole.CLIENT))])
tech_router = APIRouter(prefix="/technicians/me", tags=["órdenes"],
                        dependencies=[Depends(require_roles(UserRole.TECHNICIAN))])
admin_router = APIRouter(prefix="/admin/orders", tags=["órdenes (administración)"],
                         dependencies=[Depends(require_roles(UserRole.ADMIN))])

OrderId = Path(description="ID de la orden")


# ------------------------------------------------------------------ cliente
@router.post("", response_model=OrderOut, status_code=status.HTTP_201_CREATED, summary="Crear solicitud (cliente)")
def create_order(data: OrderCreateIn, client: CurrentClient, db: DbSession, ctx: ReqCtx):
    order = service.create(db, client, **data.model_dump(), ctx=ctx)
    db.commit()
    return order


@router.get("/{order_id}", response_model=OrderOut, summary="Ver una orden (cliente dueño o técnico asignado)")
def get_order(user: CurrentUser, db: DbSession, order_id: uuid.UUID = OrderId):
    return service.get_for_user(db, user, order_id)


@router.post("/{order_id}/cancel", response_model=OrderOut, summary="Cancelar (cliente, antes de iniciar)")
def cancel_order(data: ReasonIn, client: CurrentClient, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.cancel(db, client, order_id, data.reason, ctx)
    db.commit()
    return order


@router.post("/{order_id}/approve", response_model=OrderOut, summary="Aceptar el trabajo terminado (cliente)")
def approve_order(data: VersionIn, client: CurrentClient, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.approve(db, client, order_id, data.expected_version, ctx)
    db.commit()
    return order


@router.post("/{order_id}/dispute", response_model=OrderOut, summary="Abrir disputa (cliente)")
def dispute_order(data: DisputeIn, client: CurrentClient, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.dispute(db, client, order_id, data.reason, ctx)
    db.commit()
    return order


@client_router.get("/orders", response_model=list[OrderOut], summary="Mis órdenes (cliente)")
def my_client_orders(client: CurrentClient, db: DbSession, status_: OrderStatus | None = Query(None, alias="status"),
                     limit: int = Query(50, ge=1, le=100)):
    stmt = select(ServiceOrder).where(ServiceOrder.client_id == client.id)
    if status_:
        stmt = stmt.where(ServiceOrder.status == status_)
    return db.scalars(stmt.order_by(ServiceOrder.created_at.desc()).limit(limit)).all()


# ------------------------------------------------------------------ técnico
@tech_router.get("/jobs-feed", response_model=list[FeedItemOut],
                 summary="Solicitudes abiertas de mis categorías (solo técnicos APROBADOS)")
def jobs_feed(tech: VerifiedTechnician, db: DbSession):
    return [FeedItemOut(id=o.id, category_id=o.category_id, title=o.title, description=o.description, city=o.city,
                        created_at=o.created_at, direct_request=o.requested_technician_id == tech.id)
            for o in service.feed(db, tech)]


@tech_router.get("/orders", response_model=list[OrderOut], summary="Mis órdenes asignadas (técnico)")
def my_technician_orders(tech: CurrentTechnician, db: DbSession,
                         status_: OrderStatus | None = Query(None, alias="status"),
                         limit: int = Query(50, ge=1, le=100)):
    stmt = select(ServiceOrder).where(ServiceOrder.technician_id == tech.id)
    if status_:
        stmt = stmt.where(ServiceOrder.status == status_)
    return db.scalars(stmt.order_by(ServiceOrder.created_at.desc()).limit(limit)).all()


@router.post("/{order_id}/accept", response_model=OrderOut, summary="Aceptar una solicitud (técnico APROBADO)")
def accept_order(data: AcceptIn, tech: VerifiedTechnician, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.accept(db, tech, order_id, data.agreed_price, ctx)
    db.commit()
    return order


@router.post("/{order_id}/schedule", response_model=OrderOut, summary="Agendar (técnico asignado)")
def schedule_order(data: ScheduleIn, tech: VerifiedTechnician, db: DbSession, ctx: ReqCtx,
                   order_id: uuid.UUID = OrderId):
    order = service.schedule(db, tech, order_id, data.scheduled_at, ctx)
    db.commit()
    return order


@router.post("/{order_id}/withdraw", response_model=OrderOut, summary="Retirarse de la orden (técnico, antes de iniciar)")
def withdraw_order(data: ReasonIn, tech: CurrentTechnician, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.withdraw(db, tech, order_id, data.reason, ctx)
    db.commit()
    return order


@router.post("/{order_id}/depart", response_model=DepartOut,
             summary="En camino (técnico): autoriza el cobro en la tarjeta del cliente; si falla, no salgas")
def depart(tech: VerifiedTechnician, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    panel.check_provider_rate(db, tech.id)
    try:
        order, payment = service.depart(db, tech, order_id, ctx)
    except DomainError as exc:
        if exc.code == "ORDER_PAYMENT_METHOD_MISSING":
            db.commit()                      # conserva el aviso al cliente para que elija tarjeta
        raise
    db.commit()
    return DepartOut(order_id=str(order.id), payment_status=payment.status,
                     can_start=payment.status.value == "AUTHORIZED", failure_code=payment.failure_code)


@router.post("/{order_id}/start", response_model=OrderOut, summary="Iniciar trabajo (técnico APROBADO, pago autorizado)")
def start_order(tech: VerifiedTechnician, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.start(db, tech, order_id, ctx)
    db.commit()
    return order


@router.post("/{order_id}/finish", response_model=OrderOut, summary="Marcar trabajo terminado (técnico)")
def finish_order(tech: CurrentTechnician, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId):
    order = service.finish(db, tech, order_id, ctx)
    db.commit()
    return order


# ------------------------------------------------------------------ administración
@admin_router.get("/{order_id}", response_model=OrderOut, summary="Ver cualquier orden (soporte / finanzas)")
def admin_get_order(db: DbSession, order_id: uuid.UUID = OrderId,
                    _: Actor = Depends(require_permission(Permission.ORDERS_READ))):
    order = db.get(ServiceOrder, order_id)
    if order is None:
        from app.core.errors import DomainError
        raise DomainError("Orden no encontrada", code="ORDER_NOT_FOUND", http_status=404)
    return order


@admin_router.get("", response_model=list[OrderOut], summary="Buscar órdenes (soporte / finanzas)")
def admin_list_orders(db: DbSession, status_: OrderStatus | None = Query(None, alias="status"),
                      user_id: uuid.UUID | None = None, limit: int = Query(50, ge=1, le=200),
                      _: Actor = Depends(require_permission(Permission.ORDERS_READ))):
    stmt = select(ServiceOrder)
    if status_:
        stmt = stmt.where(ServiceOrder.status == status_)
    if user_id:
        stmt = stmt.where(or_(ServiceOrder.client_id == user_id, ServiceOrder.technician_id == user_id))
    return db.scalars(stmt.order_by(ServiceOrder.created_at.desc()).limit(limit)).all()


@admin_router.post("/{order_id}/dispute-resolution", response_model=OrderOut, summary="Resolver una disputa (finanzas)")
def resolve_dispute(data: DisputeResolutionIn, db: DbSession, ctx: ReqCtx, order_id: uuid.UUID = OrderId,
                    admin: Actor = Depends(require_permission(Permission.ORDERS_DISPUTE_RESOLVE))):
    order = service.resolve_dispute(db, admin, order_id, data.outcome, data.refund_amount, data.note, ctx)
    db.commit()
    return order


# ------------------------------------------------------------------ pago de la orden (Fase 3)
def _client_view(payment: Payment, client_secret: str | None = None) -> OrderPaymentClientOut:
    b = payment.breakdown
    return OrderPaymentClientOut(
        status=payment.status, currency=payment.currency, total=from_cents(payment.amount_cents),
        service_price=from_cents(b.price_cents), service_tax=from_cents(b.service_tax_cents),
        discount=from_cents(b.discount_cents), payment_method_selected=payment.provider_payment_method_id is not None,
        authorized_at=payment.authorized_at, captured_at=payment.captured_at,
        refunded=from_cents(payment.refunded_cents), client_secret=client_secret)


def _technician_view(payment: Payment) -> OrderPaymentTechnicianOut:
    b = payment.breakdown
    return OrderPaymentTechnicianOut(
        status=payment.status, currency=payment.currency, service_price=from_cents(b.price_cents),
        commission=from_cents(b.commission_cents), commission_tax=from_cents(b.commission_tax_cents),
        withholding_isr=from_cents(b.withholding_isr_cents), withholding_iva=from_cents(b.withholding_iva_cents),
        net=from_cents(b.technician_cents), authorized_at=payment.authorized_at, captured_at=payment.captured_at,
        capture_deadline=payment.capture_deadline)


def _payment_or_404(db, user: User, order_id: uuid.UUID, *, lock: bool = False) -> Payment:
    order = service.get_for_user(db, user, order_id, lock=lock)         # dueño o técnico asignado; si no, 404
    payment = payments.active_payment(db, order.id, lock=lock)
    if payment is None:
        raise DomainError("La orden todavía no tiene un pago", code="ORDER_NO_PAYMENT", http_status=404)
    return payment


@router.get("/{order_id}/payment", response_model=OrderPaymentClientOut | OrderPaymentTechnicianOut,
            summary="Pago de la orden (el cliente ve su total; el técnico, lo que recibe)")
def get_order_payment(user: CurrentUser, db: DbSession, order_id: uuid.UUID = OrderId):
    payment = _payment_or_404(db, user, order_id)
    if user.role == UserRole.TECHNICIAN:
        return _technician_view(payment)
    return _client_view(payment, payments.client_secret_for_action(payment))


@router.get("/{order_id}/payments", response_model=list[OrderPaymentLineOut],
            summary="Todos los cobros de la orden (servicio, ajustes, cargos por cancelación)")
def list_order_payments(user: CurrentUser, db: DbSession, order_id: uuid.UUID = OrderId):
    order = service.get_for_user(db, user, order_id)                      # dueño o técnico asignado; si no, 404
    rows = db.scalars(select(Payment).where(Payment.service_order_id == order.id).order_by(Payment.created_at))
    return [OrderPaymentLineOut(kind=p.kind.value, status=p.status.value, total=from_cents(p.amount_cents),
                                captured=from_cents(p.captured_cents), refunded=from_cents(p.refunded_cents),
                                created_at=p.created_at) for p in rows]


@router.post("/{order_id}/payment-method", response_model=OrderPaymentClientOut,
             summary="Elegir con qué tarjeta guardada se paga (cliente; requiere Idempotency-Key)")
def choose_payment_method(data: PaymentMethodIn, client: CurrentClient, db: DbSession,
                          idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
                          order_id: uuid.UUID = OrderId):
    panel.check_payment_method_rate(db, client.id)

    def operation() -> dict:
        order = service.get_for_user(db, client, order_id, lock=True)
        payment = payments.set_payment_method(db, client, order, data.payment_method_id)
        return _client_view(payment).model_dump(mode="json")

    code, body, replayed = idempotency.run(db, user_id=client.id, endpoint=f"orders/{order_id}/payment-method",
                                           key=idempotency_key, body=data.model_dump(), operation=operation)
    db.commit()
    return JSONResponse(body, status_code=code, headers={"Idempotent-Replayed": "true"} if replayed else None)


@router.post("/{order_id}/payment/refresh", response_model=OrderPaymentClientOut,
             summary="Volver a consultar el cobro en el proveedor (cliente; nunca recibe un estado)")
def refresh_order_payment(client: CurrentClient, db: DbSession, order_id: uuid.UUID = OrderId):
    panel.check_provider_rate(db, client.id)
    payment = _payment_or_404(db, client, order_id, lock=True)
    payments.refresh_from_provider(db, payment)
    db.commit()
    return _client_view(payment, payments.client_secret_for_action(payment))
