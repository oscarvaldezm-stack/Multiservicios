"""
Máquina de estados de la orden de servicio: ÚNICA vía para cambiar service_orders.status.

Igual que en el KYC: la tabla ALLOWED_TRANSITIONS dice qué pares existen y quién los
ejecuta; transition() bloquea la fila, valida versión y actor, aplica fechas, escribe
historial + evento en la misma transacción. Un trigger (migración 0005) repite la tabla
en la base y otro impide que un técnico sin KYC APROBADO acepte, agende o inicie.

¿Qué estados permiten calificar?  Solo READY_FOR_REVIEW (y con el pago confirmado).
  - REQUESTED … COMPLETED, PAID   → todavía no (el servicio o el cobro no terminan)
  - READY_FOR_REVIEW              → sí, dentro de REVIEW_WINDOW_DAYS
  - REVIEWED                      → ya se calificó (una sola vez por orden)
  - DISPUTED                      → congelado hasta que se resuelva la disputa
  - CANCELLED, FAILED, REFUNDED   → nunca
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.actor import Actor, RequestContext
from app.core.errors import DomainError
from app.models import ActorType, OrderStatus, OrderStatusHistory, OutboxEvent, ServiceOrder

O = OrderStatus


class Who(str, enum.Enum):
    CLIENT = "CLIENT"            # dueño de la orden
    TECHNICIAN = "TECHNICIAN"    # técnico asignado (o, para aceptar, un técnico elegible)
    ADMIN = "ADMIN"              # con el permiso correspondiente (lo valida la ruta)
    SYSTEM = "SYSTEM"            # jobs y webhooks del proveedor de pagos


@dataclass(frozen=True)
class Rule:
    who: frozenset[Who]
    notify: str | None = None


def _r(*who: Who, notify: str | None = None) -> Rule:
    return Rule(frozenset(who), notify)


C, T, A, S = Who.CLIENT, Who.TECHNICIAN, Who.ADMIN, Who.SYSTEM

ALLOWED_TRANSITIONS: dict[tuple[OrderStatus, OrderStatus], Rule] = {
    (O.REQUESTED, O.ACCEPTED): _r(T, notify="order.accepted"),
    (O.REQUESTED, O.CANCELLED): _r(C, S, A, notify="order.cancelled"),
    (O.ACCEPTED, O.SCHEDULED): _r(T, notify="order.scheduled"),
    (O.ACCEPTED, O.REQUESTED): _r(T, S, notify="order.technician_withdrew"),
    (O.SCHEDULED, O.REQUESTED): _r(T, S, notify="order.technician_withdrew"),
    (O.ACCEPTED, O.CANCELLED): _r(C, A, notify="order.cancelled"),
    (O.SCHEDULED, O.CANCELLED): _r(C, A, notify="order.cancelled"),
    (O.SCHEDULED, O.IN_PROGRESS): _r(T, notify="order.started"),
    (O.SCHEDULED, O.FAILED): _r(S, notify="order.failed"),
    (O.IN_PROGRESS, O.AWAITING_APPROVAL): _r(T, notify="order.awaiting_approval"),
    (O.IN_PROGRESS, O.DISPUTED): _r(C, A, notify="order.disputed"),
    (O.AWAITING_APPROVAL, O.COMPLETED): _r(C, S, notify="order.completed"),
    (O.AWAITING_APPROVAL, O.DISPUTED): _r(C, notify="order.disputed"),
    (O.COMPLETED, O.PAID): _r(S),
    (O.COMPLETED, O.FAILED): _r(S, notify="order.failed"),
    (O.COMPLETED, O.DISPUTED): _r(S, notify="order.disputed"),                 # contracargo
    (O.PAID, O.READY_FOR_REVIEW): _r(S, notify="order.ready_for_review"),
    (O.PAID, O.DISPUTED): _r(C, S, notify="order.disputed"),
    (O.READY_FOR_REVIEW, O.DISPUTED): _r(C, S, notify="order.disputed"),
    (O.REVIEWED, O.DISPUTED): _r(C, S, notify="order.disputed"),
    (O.READY_FOR_REVIEW, O.REVIEWED): _r(C, S),
    (O.READY_FOR_REVIEW, O.REFUNDED): _r(A, S, notify="order.refunded"),
    (O.REVIEWED, O.REFUNDED): _r(A, S, notify="order.refunded"),
    (O.DISPUTED, O.COMPLETED): _r(A, notify="order.dispute_resolved"),
    (O.DISPUTED, O.READY_FOR_REVIEW): _r(A, S, notify="order.dispute_resolved"),
    (O.DISPUTED, O.REVIEWED): _r(A, S, notify="order.dispute_resolved"),
    (O.DISPUTED, O.REFUNDED): _r(A, S, notify="order.refunded"),
    (O.DISPUTED, O.CANCELLED): _r(A, notify="order.dispute_resolved"),
}

# Estados en los que el técnico debe tener KYC APROBADO para llegar a ellos (también en el trigger).
REQUIRES_APPROVED_TECHNICIAN = frozenset({O.ACCEPTED, O.SCHEDULED, O.IN_PROGRESS})
# Estados "abiertos" que un técnico suspendido debe soltar (vuelven a REQUESTED).
PRE_START = frozenset({O.ACCEPTED, O.SCHEDULED})
REVIEWABLE = O.READY_FOR_REVIEW


class OrderError(DomainError):
    http_status = 409
    code = "ORDER_ERROR"


def _caps(actor: Actor, order: ServiceOrder, to_status: OrderStatus) -> set[Who]:
    caps: set[Who] = set()
    if actor.actor_type == ActorType.SYSTEM:
        caps.add(Who.SYSTEM)
    elif actor.actor_type == ActorType.CLIENT and actor.user_id == order.client_id:
        caps.add(Who.CLIENT)
    elif actor.actor_type == ActorType.TECHNICIAN:
        if order.technician_id == actor.user_id:
            caps.add(Who.TECHNICIAN)
        elif order.status == O.REQUESTED and to_status == O.ACCEPTED and order.technician_id is None \
                and order.requested_technician_id in (None, actor.user_id):
            caps.add(Who.TECHNICIAN)
    elif actor.actor_type == ActorType.ADMIN:
        caps.add(Who.ADMIN)
    return caps


def lock_order(db: Session, order_id: uuid.UUID) -> ServiceOrder | None:
    return db.execute(select(ServiceOrder).where(ServiceOrder.id == order_id).with_for_update()).scalar_one_or_none()


def transition(db: Session, order: ServiceOrder, to_status: OrderStatus, actor: Actor, *,
               reason_code: str | None = None, note: str | None = None, expected_version: int | None = None,
               ctx: RequestContext | None = None) -> ServiceOrder:  # noqa: ARG001
    """Aplica una transición sobre una orden YA BLOQUEADA (lock_order). No hace commit."""
    from_status = order.status
    rule = ALLOWED_TRANSITIONS.get((from_status, to_status))
    if rule is None:
        raise OrderError(f"No se puede pasar de {from_status.value} a {to_status.value}",
                         code="ORDER_INVALID_TRANSITION", extra={"status": from_status.value})
    if expected_version is not None and expected_version != order.version:
        raise OrderError("La orden cambió; recarga e intenta de nuevo", code="ORDER_STALE_VERSION")
    if not (_caps(actor, order, to_status) & rule.who):
        raise OrderError("No puedes realizar esta acción sobre la orden", code="ORDER_ACTOR_NOT_ALLOWED",
                         http_status=403)

    now = datetime.now(timezone.utc)
    affected_technician = order.technician_id
    if to_status == O.ACCEPTED:
        order.technician_id = actor.user_id
        order.accepted_at = now
        affected_technician = actor.user_id
    elif to_status == O.REQUESTED:            # el técnico se retira (o pierde el KYC): la orden vuelve a la bolsa
        order.technician_id = None
        order.agreed_price = None
        order.scheduled_at = None
        order.accepted_at = None
    elif to_status == O.IN_PROGRESS:
        order.started_at = now
    elif to_status == O.AWAITING_APPROVAL:
        order.work_finished_at = now
    elif to_status == O.COMPLETED and order.completed_at is None:
        order.completed_at = now
    elif to_status == O.PAID:
        order.paid_at = now
    if to_status in (O.READY_FOR_REVIEW, O.REVIEWED) and order.paid_at is None:
        order.paid_at = now          # p. ej. disputa resuelta a favor del técnico: el plazo para calificar corre
    elif to_status == O.CANCELLED:
        order.cancelled_at = now
    elif to_status == O.DISPUTED:
        order.disputed_at = now
        order.status_before_dispute = from_status
    order.status = to_status
    order.version += 1

    db.add(OrderStatusHistory(order_id=order.id, from_status=from_status, to_status=to_status,
                              actor_id=actor.user_id, actor_type=actor.actor_type,
                              technician_id=affected_technician, reason_code=reason_code, note=note))
    # order_status_history ya es la traza (solo inserción). audit_logs se reserva para acciones de
    # administradores sobre órdenes (disputas), que escribe la capa de servicio: así las transiciones
    # normales no compiten por el candado de la cadena de auditoría.
    if rule.notify:
        for recipient in {order.client_id, affected_technician} - {None, actor.user_id}:
            db.add(OutboxEvent(event_type=rule.notify, aggregate_type="service_order", aggregate_id=order.id,
                               recipient_user_id=recipient, payload={"status": to_status.value,
                                                                     "reason_code": reason_code}))
    db.flush()
    return order
