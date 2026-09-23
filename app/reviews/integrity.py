"""
Firma de integridad de cada reseña: HMAC-SHA256 (INTEGRITY_KEY) sobre su contenido.

Protege contra "cambiar estrellas directamente en la base": quien tenga acceso SQL pero
no la llave no puede recalcular la firma, y verify_all() lo detecta. Las ediciones
legítimas pasan por el servicio, que actualiza la firma y deja rastro en review_audit_logs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from decimal import Decimal
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Review, ReviewRating


@lru_cache
def _key() -> bytes:
    raw = get_settings().INTEGRITY_KEY.get_secret_value()
    master = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    return hmac.new(master, b"review-integrity-v1", hashlib.sha256).digest()


def compute(review: Review, ratings: dict[str, int]) -> str:
    payload = {
        "id": str(review.id), "order": str(review.service_order_id), "client": str(review.client_id),
        "technician": str(review.technician_id), "rating": int(review.rating), "comment": review.comment,
        "ratings": dict(sorted(ratings.items())), "status": review.status.value,
        "weight": f"{Decimal(review.weight):.2f}",   # misma forma en memoria (Decimal("1")) y leída (1.00)
        "reply": review.technician_reply, "version": int(review.version),
        "moderation_reason": review.moderation_reason, "risk_flags": sorted(review.risk_flags or []),
        "edit_count": int(review.edit_count), "editable_until": int(review.editable_until.timestamp()),
    }
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(_key(), data, hashlib.sha256).hexdigest()


def ratings_of(db: Session, review: Review) -> dict[str, int]:
    rows = db.execute(select(ReviewRating.category, ReviewRating.score)
                      .where(ReviewRating.review_id == review.id)).all()
    return {c.value: int(s) for c, s in rows}


def sign(db: Session, review: Review) -> None:
    db.flush()
    review.integrity_mac = compute(review, ratings_of(db, review))


def verify_all(db: Session, limit: int = 10_000) -> list[str]:
    """IDs de reseñas cuya firma no coincide (alteradas fuera de la aplicación)."""
    bad = []
    for review in db.scalars(select(Review).order_by(Review.created_at).limit(limit)):
        expected = compute(review, ratings_of(db, review))
        if not hmac.compare_digest(expected, review.integrity_mac):
            bad.append(str(review.id))
    return bad
