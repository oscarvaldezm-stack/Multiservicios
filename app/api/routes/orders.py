"""
Órdenes de servicio.

- Cliente: crear, ver las suyas, cancelar, aceptar el trabajo, abrir disputa.
- Técnico APROBADO: ver solicitudes de sus categorías, aceptar, agendar, retirarse,
  iniciar (con pago autorizado) y terminar.
- Cualquier orden ajena responde 404 (sin confirmar que existe).
El estado de pago NO se puede cambiar desde aquí: solo lo cambia el proveedor (webhook).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Path, Query, status
from sqlalchemy import or_, select

from app.api.deps import CurrentClient, CurrentTechnician, CurrentUser, DbSession, ReqCtx, VerifiedTechnician, \
    require_permission, require_roles
from app.core.actor import Actor
from app.kyc.permissions import Permission
from app.models import OrderStatus, ServiceOrder, UserRole
from app.orders import service
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
