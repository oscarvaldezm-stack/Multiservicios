"""
Schemas de decisiones KYC, órdenes y reseñas. Entradas con extra="forbid": un campo no
previsto ("status", "client_id", "verification", "weight"...) produce 422, así un
cliente no puede "colar" valores que solo el servidor decide.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import (
    DocumentDecision,
    KycStatus,
    OrderStatus,
    ReportReason,
    ReportResolution,
    ReviewCategory,
    ReviewDecision,
    ReviewStatus,
)


Score = Annotated[int, Field(ge=1, le=5, strict=True)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# =============================================================================
# KYC: decisiones
# =============================================================================
class VersionIn(_In):
    expected_version: int | None = Field(default=None, ge=1)


class DocumentDecisionIn(_In):
    decision: DocumentDecision
    reason_code: str | None = Field(default=None, max_length=40, pattern=r"^[A-Z_]+$")
    note: str | None = Field(default=None, max_length=500)


class CaseDecisionIn(_In):
    decision: ReviewDecision
    reason_code: str | None = Field(default=None, max_length=40, pattern=r"^[A-Z_]+$")
    note: str | None = Field(default=None, max_length=1000)
    expected_version: int | None = Field(default=None, ge=1)


class SuspendIn(_In):
    reason_code: str = Field(max_length=40, pattern=r"^[A-Z_]+$")
    note: str | None = Field(default=None, max_length=1000)


class ReinstateIn(_In):
    note: str = Field(min_length=5, max_length=1000)


class CaseStateOut(BaseModel):
    case_id: uuid.UUID
    status: KycStatus
    version: int
    cycle: int
    assigned_reviewer_id: uuid.UUID | None


class DocumentDecisionOut(BaseModel):
    document_id: uuid.UUID
    status: str
    rejection_reason: str | None


# =============================================================================
# Órdenes
# =============================================================================
class OrderCreateIn(_In):
    category_id: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    address_line: str = Field(min_length=5, max_length=200)
    city: str = Field(min_length=2, max_length=80)
    latitude: Decimal | None = Field(default=None, ge=-90, le=90, max_digits=9, decimal_places=6)
    longitude: Decimal | None = Field(default=None, ge=-180, le=180, max_digits=9, decimal_places=6)
    requested_technician_id: uuid.UUID | None = None


class AcceptIn(_In):
    agreed_price: Decimal = Field(gt=0, le=Decimal("500000"), max_digits=10, decimal_places=2)


class ScheduleIn(_In):
    scheduled_at: datetime

    @model_validator(mode="after")
    def _aware(self) -> ScheduleIn:
        if self.scheduled_at.tzinfo is None:
            raise ValueError("scheduled_at debe incluir zona horaria (ISO 8601)")
        return self


class ReasonIn(_In):
    reason: str | None = Field(default=None, max_length=500)


class DisputeIn(_In):
    reason: str = Field(min_length=10, max_length=1000)


class DisputeResolutionIn(_In):
    outcome: Literal["RELEASE", "PARTIAL_REFUND", "FULL_REFUND"]
    refund_amount: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    note: str = Field(min_length=5, max_length=1000)


class OrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: OrderStatus
    category_id: int
    title: str
    description: str
    address_line: str
    city: str
    client_id: uuid.UUID
    technician_id: uuid.UUID | None
    agreed_price: Decimal | None
    scheduled_at: datetime | None
    departed_at: datetime | None = None
    accepted_at: datetime | None
    started_at: datetime | None
    work_finished_at: datetime | None
    completed_at: datetime | None
    paid_at: datetime | None
    cancelled_at: datetime | None
    version: int
    created_at: datetime


class FeedItemOut(BaseModel):
    """Lo que ve un técnico de una solicitud abierta: sin dirección exacta ni datos del cliente."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    category_id: int
    title: str
    description: str
    city: str
    created_at: datetime
    direct_request: bool = False


# =============================================================================
# Reseñas
# =============================================================================
class ReviewCreateIn(_In):
    service_order_id: uuid.UUID
    rating: int = Field(ge=1, le=5, strict=True)     # "5" (texto) o 4.5 no se convierten: 422
    comment: str | None = Field(default=None, max_length=1000)
    ratings: dict[ReviewCategory, Score] | None = None


class ReviewEditIn(_In):
    rating: int | None = Field(default=None, ge=1, le=5, strict=True)
    comment: str | None = Field(default=None, max_length=1000)
    ratings: dict[ReviewCategory, Score] | None = None
    reason: str = Field(min_length=3, max_length=200)

    @model_validator(mode="after")
    def _something(self) -> ReviewEditIn:
        if self.rating is None and "comment" not in self.model_fields_set and not self.ratings:
            raise ValueError("Indica qué quieres modificar")
        return self


class ReplyIn(_In):
    reply: str = Field(min_length=2, max_length=500)


class ReportIn(_In):
    reason: ReportReason
    note: str | None = Field(default=None, max_length=500)


class ModerationIn(_In):
    action: Literal["PUBLISH", "HIDE", "REMOVE"]
    reason: str = Field(max_length=40, pattern=r"^[A-Z_]+$")
    note: str | None = Field(default=None, max_length=1000)
    count_in_reputation: bool = True


class ReportResolutionIn(_In):
    resolution: ReportResolution
    note: str | None = Field(default=None, max_length=500)


class EligibilityOut(BaseModel):
    order_id: uuid.UUID
    can_review: bool
    reason_code: str | None
    message: str | None
    review_deadline: datetime | None


class OwnReviewOut(BaseModel):
    id: uuid.UUID
    service_order_id: uuid.UUID
    technician_id: uuid.UUID
    rating: int
    comment: str | None
    ratings: dict[str, int]
    status: ReviewStatus
    verification: str
    created_at: datetime
    updated_at: datetime
    editable_until: datetime
    can_edit: bool
    edits_left: int
    technician_reply: str | None


class PublicReviewOut(BaseModel):
    id: uuid.UUID
    rating: int
    comment: str | None
    ratings: dict[str, int]
    verification: str
    client_display: str
    created_at: datetime
    edited: bool
    technician_reply: str | None
    technician_reply_at: datetime | None


class ReputationOut(BaseModel):
    rating_avg: Decimal
    verified_reviews: int
    completed_jobs: int
    category_avgs: dict[str, float | None]
    reputation_score: Decimal
    has_background_check_badge: bool


class TechnicianReviewsOut(BaseModel):
    technician_id: uuid.UUID
    summary: ReputationOut
    items: list[PublicReviewOut]
    next_cursor: str | None


class ReportOut(BaseModel):
    id: uuid.UUID
    review_id: uuid.UUID
    reason: ReportReason
    status: str
    created_at: datetime


class AdminReviewOut(BaseModel):
    id: uuid.UUID
    service_order_id: uuid.UUID
    client_id: uuid.UUID
    technician_id: uuid.UUID
    rating: int
    comment: str | None
    status: ReviewStatus
    risk_flags: list[str] | None
    weight: Decimal
    open_reports: int
    moderation_reason: str | None
    created_at: datetime


class AdminReviewPageOut(BaseModel):
    items: list[AdminReviewOut]
    next_cursor: str | None


class ReviewLogOut(BaseModel):
    action: str
    actor_type: str
    actor_id: uuid.UUID | None
    old_values: dict | None
    new_values: dict | None
    reason: str | None
    created_at: datetime


class AdminReviewDetailOut(AdminReviewOut):
    ratings: dict[str, int]
    technician_reply: str | None
    edit_count: int
    integrity_ok: bool
    reports: list[dict]
    history: list[ReviewLogOut]


class IntegrityOut(BaseModel):
    checked: int
    tampered_ids: list[str]
