"""
Calificaciones verificadas, reportes, bitácora de reseñas, reputación y señales antifraude.

Regla absoluta (la impone también un trigger de PostgreSQL): una reseña solo puede
existir ligada a una orden real del mismo cliente y técnico, en READY_FOR_REVIEW y con
el pago confirmado. Las reseñas nunca se borran: se ocultan o se marcan REMOVED.
"""
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import (
    ActorType,
    ReportReason,
    ReportResolution,
    ReportStatus,
    ReviewCategory,
    ReviewStatus,
    SignalKind,
    pg_enum,
)

VERIFIED_SERVICE = "VERIFIED_SERVICE"


class Review(Base):
    __tablename__ = "reviews"
    __table_args__ = (
        CheckConstraint("rating BETWEEN 1 AND 5", name="rating_range"),
        CheckConstraint(f"verification = '{VERIFIED_SERVICE}'", name="only_verified"),
        CheckConstraint("comment IS NULL OR char_length(comment) BETWEEN 1 AND 1000", name="comment_length"),
        CheckConstraint("technician_reply IS NULL OR char_length(technician_reply) BETWEEN 1 AND 500",
                        name="reply_length"),
        CheckConstraint("weight >= 0 AND weight <= 1", name="weight_range"),
        CheckConstraint("edit_count >= 0", name="edit_count_non_negative"),
        CheckConstraint("client_id <> technician_id", name="not_self_review"),
        Index("ix_reviews_technician_public", "technician_id", "created_at",
              postgresql_where=text("status = 'PUBLISHED'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    service_order_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_orders.id", ondelete="RESTRICT"), unique=True, nullable=False
    )
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
                                                 index=True)
    technician_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"),
                                                     nullable=False)
    rating: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ReviewStatus] = mapped_column(pg_enum(ReviewStatus, "review_status"), nullable=False,
                                                 server_default=ReviewStatus.PUBLISHED.value)
    verification: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text(f"'{VERIFIED_SERVICE}'"))
    # Antifraude: señales detectadas y peso en la reputación (0 = no cuenta).
    risk_flags: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True))
    weight: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False, server_default=text("1"))
    edit_count: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("0"))
    editable_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    technician_reply: Mapped[str | None] = mapped_column(Text)
    technician_reply_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    moderation_reason: Mapped[str | None] = mapped_column(String(40))
    moderated_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    moderated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # HMAC del contenido: detecta estrellas o textos cambiados directamente en la base.
    integrity_mac: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    ratings: Mapped[list["ReviewRating"]] = relationship(back_populates="review", cascade="save-update, merge",
                                                         lazy="selectin", order_by="ReviewRating.category")


class ReviewRating(Base):
    """Calificación opcional por categoría (calidad, puntualidad, ...)."""

    __tablename__ = "review_ratings"
    __table_args__ = (CheckConstraint("score BETWEEN 1 AND 5", name="score_range"),)

    review_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("reviews.id", ondelete="RESTRICT"),
                                                 primary_key=True)
    category: Mapped[ReviewCategory] = mapped_column(pg_enum(ReviewCategory, "review_category"), primary_key=True)
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    review: Mapped[Review] = relationship(back_populates="ratings")


class ReviewAuditLog(Base):
    """Historia completa de cada reseña (solo inserción): valor anterior, nuevo, quién, cuándo y por qué."""

    __tablename__ = "review_audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    review_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("reviews.id", ondelete="RESTRICT"),
                                                 nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_type: Mapped[ActorType] = mapped_column(pg_enum(ActorType, "actor_type"), nullable=False)
    old_values: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    new_values: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    reason: Mapped[str | None] = mapped_column(String(300))
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReviewReport(Base):
    __tablename__ = "review_reports"
    __table_args__ = (
        UniqueConstraint("review_id", "reporter_id"),
        CheckConstraint("(status = 'OPEN') = (resolution IS NULL)", name="resolution_matches_status"),
        Index("ix_review_reports_open", "created_at", postgresql_where=text("status = 'OPEN'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    review_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("reviews.id", ondelete="RESTRICT"), nullable=False,
                                                 index=True)
    reporter_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    reason: Mapped[ReportReason] = mapped_column(pg_enum(ReportReason, "report_reason"), nullable=False)
    note: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[ReportStatus] = mapped_column(pg_enum(ReportStatus, "report_status"), nullable=False,
                                                 server_default=ReportStatus.OPEN.value)
    resolution: Mapped[ReportResolution | None] = mapped_column(pg_enum(ReportResolution, "report_resolution"))
    resolution_note: Mapped[str | None] = mapped_column(String(500))
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TechnicianReputation(Base):
    """Métricas calculadas por el sistema (nunca editables por el técnico). Ver app/reviews/reputation.py."""

    __tablename__ = "technician_reputation"
    __table_args__ = (CheckConstraint("reputation_score BETWEEN 0 AND 100", name="score_range"),)

    technician_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"),
                                                     primary_key=True)
    completed_jobs: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    verified_reviews: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    rating_avg: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False, server_default=text("0"))
    bayes_rating: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False, server_default=text("0"))
    category_avgs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    technician_cancellations: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    disputes_lost: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    fraud_strikes: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    reliability: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False, server_default=text("1"))
    reputation_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, server_default=text("0"))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class UserSignal(Base):
    """
    Dispositivos e IP vistos por usuario, SEUDONIMIZADOS (HMAC con INTEGRITY_KEY): permiten
    detectar que un cliente y un técnico comparten equipo o red sin guardar la IP en claro.
    """

    __tablename__ = "user_signals"
    __table_args__ = (
        UniqueConstraint("user_id", "kind", "value_hash"),
        Index("ix_user_signals_lookup", "kind", "value_hash"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[SignalKind] = mapped_column(pg_enum(SignalKind, "signal_kind"), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
