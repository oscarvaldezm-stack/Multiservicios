"""
Reputación del técnico (no es un promedio simple).

1. Calificación bayesiana ponderada (R, de 1 a 5)
       R = (C·m + Σ W_c · r̄_c) / (C + Σ W_c)
   - m = REPUTATION_PRIOR_MEAN (4.0) y C = REPUTATION_PRIOR_WEIGHT (5): con pocas reseñas
     el resultado se queda cerca de m; un técnico nuevo no llega a 5.0 con una sola reseña
     comprada, y uno bueno no se hunde por una sola mala.
   - Por reseña: w = peso antifraude (1, 0.5 o 0) × decaimiento temporal 0.5^(edad/365 días).
   - Por CLIENTE: sus reseñas a un mismo técnico se promedian (r̄_c) y su peso total se topa
     en W_c ≤ 1. Muchas órdenes pequeñas del mismo cliente no inflan la reputación.
   - Solo cuentan reseñas PUBLISHED (retenidas, ocultas o eliminadas: peso 0).

2. Confiabilidad operativa (0 a 1)
       completados / (completados + retiros del técnico + disputas perdidas)

3. Puntaje final (0 a 100), usado para ordenar resultados de búsqueda:
       100 × [0.60·(R−1)/4 + 0.20·confiabilidad + 0.12·experiencia + 0.08·antigüedad]
       − 10 por cada reseña positiva eliminada por fraude en 180 días (máx. 30)
   experiencia = min(1, log(1+servicios)/log(101))  ·  antigüedad = min(1, meses aprobado / 24)

Lo que ve el cliente: promedio simple de reseñas verificadas publicadas, número de
opiniones verificadas y servicios completados ("4.8 ★ · 115 opiniones verificadas · 120 servicios").
"""
from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import (
    ActorType,
    KycProfile,
    OrderStatus,
    OrderStatusHistory,
    Review,
    ReviewCategory,
    ReviewRating,
    ReviewStatus,
    ServiceOrder,
    TechnicianProfile,
    TechnicianReputation,
)

O = OrderStatus
COMPLETED_STATES = (O.COMPLETED, O.PAID, O.READY_FOR_REVIEW, O.REVIEWED)
# Motivos de moderación que indican manipulación a favor del técnico.
FRAUD_REASONS = ("FAKE_REVIEW", "FRAUD_SIGNALS")


def _q(value: float, places: str) -> Decimal:
    return Decimal(str(value)).quantize(Decimal(places))


def recompute(db: Session, technician_id: uuid.UUID, now: datetime | None = None) -> TechnicianReputation:
    s = get_settings()
    now = now or datetime.now(timezone.utc)

    completed = db.scalar(select(func.count()).select_from(ServiceOrder).where(
        ServiceOrder.technician_id == technician_id, ServiceOrder.status.in_(COMPLETED_STATES))) or 0

    reviews = db.execute(select(Review.client_id, Review.rating, Review.weight, Review.created_at).where(
        Review.technician_id == technician_id, Review.status == ReviewStatus.PUBLISHED)).all()
    published = len(reviews)
    simple_avg = sum(r.rating for r in reviews) / published if published else 0.0

    per_client: dict[uuid.UUID, list[tuple[float, float]]] = defaultdict(list)
    for r in reviews:
        age_days = max(0.0, (now - r.created_at).total_seconds() / 86400)
        w = float(r.weight) * 0.5 ** (age_days / s.REPUTATION_HALF_LIFE_DAYS)
        per_client[r.client_id].append((float(r.rating), w))
    num = s.REPUTATION_PRIOR_WEIGHT * s.REPUTATION_PRIOR_MEAN
    den = s.REPUTATION_PRIOR_WEIGHT
    for items in per_client.values():
        total_w = sum(w for _, w in items)
        if total_w <= 0:
            continue
        mean = sum(r * w for r, w in items) / total_w
        cap = min(1.0, total_w)
        num += cap * mean
        den += cap
    bayes = num / den if den else s.REPUTATION_PRIOR_MEAN

    cat_rows = db.execute(select(ReviewRating.category, func.avg(ReviewRating.score)).join(
        Review, Review.id == ReviewRating.review_id).where(
        Review.technician_id == technician_id, Review.status == ReviewStatus.PUBLISHED)
        .group_by(ReviewRating.category)).all()
    categories = {c.value: round(float(avg), 2) for c, avg in cat_rows}
    for c in ReviewCategory:
        categories.setdefault(c.value, None)

    withdrawals = db.scalar(select(func.count()).select_from(OrderStatusHistory).where(
        OrderStatusHistory.technician_id == technician_id, OrderStatusHistory.actor_type == ActorType.TECHNICIAN,
        OrderStatusHistory.from_status.in_((O.ACCEPTED, O.SCHEDULED)),
        OrderStatusHistory.to_status == O.REQUESTED)) or 0
    disputes_lost = db.scalar(select(func.count()).select_from(OrderStatusHistory).where(
        OrderStatusHistory.technician_id == technician_id, OrderStatusHistory.from_status == O.DISPUTED,
        or_(OrderStatusHistory.to_status.in_((O.REFUNDED, O.CANCELLED)),
            OrderStatusHistory.reason_code == "DISPUTE_PARTIAL_REFUND"))) or 0
    strikes = db.scalar(select(func.count()).select_from(Review).where(
        Review.technician_id == technician_id, Review.rating >= 4,
        Review.status.in_((ReviewStatus.REMOVED, ReviewStatus.HIDDEN)),
        Review.moderation_reason.in_(FRAUD_REASONS), Review.moderated_at >= now - timedelta(days=180))) or 0

    denominator = completed + withdrawals + disputes_lost
    reliability = completed / denominator if denominator else 1.0
    experience = min(1.0, math.log(1 + completed) / math.log(101))
    approved_at = db.scalar(select(KycProfile.approved_at).where(KycProfile.technician_id == technician_id))
    months = (now - approved_at).days / 30 if approved_at else 0
    tenure = min(1.0, max(0.0, months / 24))
    score = 100 * (0.60 * (bayes - 1) / 4 + 0.20 * reliability + 0.12 * experience + 0.08 * tenure)
    score = max(0.0, min(100.0, score - min(30, 10 * strikes)))

    values = dict(completed_jobs=completed, verified_reviews=published, rating_avg=_q(simple_avg, "0.01"),
                  bayes_rating=_q(bayes, "0.001"), category_avgs=categories, technician_cancellations=withdrawals,
                  disputes_lost=disputes_lost, fraud_strikes=strikes, reliability=_q(reliability, "0.001"),
                  reputation_score=_q(score, "0.01"), computed_at=now)
    db.execute(insert(TechnicianReputation).values(technician_id=technician_id, **values)
               .on_conflict_do_update(index_elements=["technician_id"], set_=values))
    # Campos públicos del perfil (solo el sistema los escribe; el técnico no puede editarlos).
    profile = db.get(TechnicianProfile, technician_id)
    if profile is not None:
        profile.rating_avg, profile.rating_count, profile.jobs_completed = (
            values["rating_avg"], published, completed)
    db.flush()
    return db.get(TechnicianReputation, technician_id, populate_existing=True)

