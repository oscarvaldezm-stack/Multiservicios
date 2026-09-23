"""
Señales antifraude al crear o editar una reseña.

Nivel ALTO (la reseña se RETIENE: no es pública ni cuenta hasta que un moderador decida):
  SHARED_DEVICE_WITH_TECHNICIAN   el cliente y el técnico usaron el mismo dispositivo
  SAME_PAYMENT_METHOD_OTHER_CLIENT la misma tarjeta pagó órdenes de OTRA cuenta cliente que
                                   también calificó a este técnico (una persona, varias cuentas)
  OFFENSIVE_LANGUAGE              lenguaje ofensivo en el comentario
Nivel MEDIO (se publica con peso 0.5 en la reputación; dos o más: 0.25):
  SHARED_NETWORK_WITH_TECHNICIAN  misma red (IP) en los últimos 30 días
  NEW_CLIENT_ACCOUNT              cuenta con menos de 7 días
  LOW_VALUE_ORDER                 orden por debajo de REVIEW_MIN_ORDER_AMOUNT
  REVIEW_BURST                    el técnico recibió 5+ reseñas en 24 h
Informativa (no cambia el peso; el tope por cliente ya lo neutraliza):
  REPEAT_CLIENT                   el cliente ya calificó a este técnico en los últimos 90 días

Las señales NUNCA se muestran al cliente ni al técnico (enseñarían a evadirlas).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Payment, Review, ReviewStatus, ServiceOrder, SignalKind, User
from app.reviews.signals import shared_signals

HIGH = frozenset({"SHARED_DEVICE_WITH_TECHNICIAN", "SAME_PAYMENT_METHOD_OTHER_CLIENT", "OFFENSIVE_LANGUAGE"})
MEDIUM = frozenset({"SHARED_NETWORK_WITH_TECHNICIAN", "NEW_CLIENT_ACCOUNT", "LOW_VALUE_ORDER", "REVIEW_BURST"})


@dataclass(frozen=True)
class Assessment:
    flags: list[str]
    status: ReviewStatus
    weight: Decimal


def decide(flags: set[str]) -> Assessment:
    ordered = sorted(flags)
    if flags & HIGH:
        return Assessment(ordered, ReviewStatus.PENDING_MODERATION, Decimal("0"))
    medium = len(flags & MEDIUM)
    weight = Decimal("1") if medium == 0 else Decimal("0.5") if medium == 1 else Decimal("0.25")
    return Assessment(ordered, ReviewStatus.PUBLISHED, weight)


def assess(db: Session, client: User, order: ServiceOrder, payment: Payment, *, offensive: bool,
           now: datetime | None = None) -> Assessment:
    s = get_settings()
    now = now or datetime.now(timezone.utc)
    flags: set[str] = set()
    tech_id = order.technician_id

    shared = shared_signals(db, client.id, tech_id)
    if SignalKind.DEVICE in shared:
        flags.add("SHARED_DEVICE_WITH_TECHNICIAN")
    if SignalKind.IP in shared:
        flags.add("SHARED_NETWORK_WITH_TECHNICIAN")

    if payment.payment_method_fingerprint:
        other_clients = db.scalar(
            select(func.count(func.distinct(ServiceOrder.client_id)))
            .select_from(Payment).join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
            .join(Review, Review.service_order_id == ServiceOrder.id)
            .where(Payment.payment_method_fingerprint == payment.payment_method_fingerprint,
                   ServiceOrder.client_id != client.id, Review.technician_id == tech_id))
        if other_clients:
            flags.add("SAME_PAYMENT_METHOD_OTHER_CLIENT")

    if client.created_at and now - client.created_at < timedelta(days=7):
        flags.add("NEW_CLIENT_ACCOUNT")
    # Precio del servicio sin IVA (el que acordaron), no el cobro con impuestos.
    if order.agreed_price is None or order.agreed_price < Decimal(str(s.REVIEW_MIN_ORDER_AMOUNT)):
        flags.add("LOW_VALUE_ORDER")
    burst = db.scalar(select(func.count()).select_from(Review).where(
        Review.technician_id == tech_id, Review.created_at >= now - timedelta(hours=24)))
    if burst >= 5:
        flags.add("REVIEW_BURST")
    repeat = db.scalar(select(func.count()).select_from(Review).where(
        Review.technician_id == tech_id, Review.client_id == client.id,
        Review.created_at >= now - timedelta(days=90), Review.status != ReviewStatus.REMOVED))
    if repeat:
        flags.add("REPEAT_CLIENT")
    if offensive:
        flags.add("OFFENSIVE_LANGUAGE")
    return decide(flags)
