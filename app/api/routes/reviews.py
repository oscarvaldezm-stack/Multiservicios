"""
Calificaciones verificadas.

| Ruta                                   | Quién                         |
| POST /reviews                          | cliente dueño de la orden     |
| PUT  /reviews/{id}                     | autor, dentro de 24 h         |
| POST /reviews/{id}/reply               | técnico calificado            |
| POST /reviews/{id}/report              | técnico calificado o clientes |
| GET  /orders/{id}/review-eligibility   | cliente dueño                 |
| GET  /clients/me/reviews               | cliente                       |
| GET  /technicians/me/reviews           | técnico                       |
| GET  /technicians/{id}/reviews         | cualquier usuario autenticado |
| /admin/reviews...                      | moderación (permisos finos)   |
"""
from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import and_, func, or_, select

from app.api.deps import CurrentClient, CurrentTechnician, CurrentUser, DbSession, ReqCtx, actor_permissions, \
    require_permission, require_roles
from app.core.actor import Actor
from app.core.errors import DomainError
from app.kyc.permissions import Permission
from app.models import (
    KycProfile,
    Review,
    ReviewAuditLog,
    ReviewReport,
    ReviewStatus,
    ReportStatus,
    TechnicianReputation,
    User,
    UserRole,
)
from app.reviews import integrity, reputation, service
from app.schemas.marketplace import (
    AdminReviewDetailOut,
    AdminReviewPageOut,
    EligibilityOut,
    IntegrityOut,
    ModerationIn,
    OwnReviewOut,
    ReplyIn,
    ReportIn,
    ReportOut,
    ReportResolutionIn,
    ReviewCreateIn,
    ReviewEditIn,
    TechnicianReviewsOut,
)

router = APIRouter(tags=["calificaciones"])
admin_router = APIRouter(prefix="/admin", tags=["calificaciones (moderación)"],
                         dependencies=[Depends(require_roles(UserRole.ADMIN))])


def _encode(ts: datetime, rid: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{rid}".encode()).decode().rstrip("=")


def _decode(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, rid = raw.split("|", 1)
        return datetime.fromisoformat(ts), uuid.UUID(rid)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail={"code": "INVALID_CURSOR", "message": "Cursor inválido"}) from None


# =============================================================================
# Cliente
# =============================================================================
@router.post("/reviews", response_model=OwnReviewOut, status_code=status.HTTP_201_CREATED,
             summary="Calificar un servicio completado y pagado")
def create_review(data: ReviewCreateIn, client: CurrentClient, db: DbSession, ctx: ReqCtx):
    review = service.create(db, client, order_id=data.service_order_id, rating=data.rating, comment=data.comment,
                            ratings=data.ratings, ctx=ctx)
    db.commit()
    return service.own_item(review)


@router.put("/reviews/{review_id}", response_model=OwnReviewOut, summary="Modificar mi reseña (periodo limitado)")
def edit_review(data: ReviewEditIn, client: CurrentClient, db: DbSession, ctx: ReqCtx,
                review_id: uuid.UUID = Path()):
    review = service.edit(db, client, review_id, rating=data.rating, comment=data.comment,
                          comment_set="comment" in data.model_fields_set, ratings=data.ratings, reason=data.reason,
                          ctx=ctx)
    db.commit()
    db.refresh(review)
    return service.own_item(review)


@router.get("/orders/{order_id}/review-eligibility", response_model=EligibilityOut,
            summary="¿Puedo calificar esta orden? (para mostrar u ocultar el botón; el backend valida igual)")
def review_eligibility(client: CurrentClient, db: DbSession, order_id: uuid.UUID = Path()):
    return service.check_eligibility(db, client, order_id)


@router.get("/clients/me/reviews", response_model=list[OwnReviewOut], summary="Mis reseñas (cliente)")
def my_reviews(client: CurrentClient, db: DbSession, limit: int = Query(50, ge=1, le=100)):
    rows = db.scalars(select(Review).where(Review.client_id == client.id)
                      .order_by(Review.created_at.desc()).limit(limit)).all()
    return [service.own_item(r) for r in rows]


# =============================================================================
# Técnico
# =============================================================================
@router.post("/reviews/{review_id}/reply", response_model=OwnReviewOut, summary="Responder una reseña (técnico)")
def reply_review(data: ReplyIn, tech: CurrentTechnician, db: DbSession, ctx: ReqCtx, review_id: uuid.UUID = Path()):
    review = service.reply(db, tech, review_id, data.reply, ctx)
    db.commit()
    return service.own_item(review)


@router.get("/technicians/me/reviews", response_model=TechnicianReviewsOut, summary="Mis calificaciones (técnico)")
def technician_own_reviews(tech: CurrentTechnician, db: DbSession, cursor: str | None = Query(None, max_length=200),
                           limit: int = Query(20, ge=1, le=50)):
    return _technician_reviews(db, tech.id, cursor, limit)


# =============================================================================
# Reportes y consulta pública
# =============================================================================
@router.post("/reviews/{review_id}/report", response_model=ReportOut, status_code=status.HTTP_201_CREATED,
             summary="Reportar una reseña")
def report_review(data: ReportIn, user: CurrentUser, db: DbSession, ctx: ReqCtx, review_id: uuid.UUID = Path()):
    if user.role == UserRole.ADMIN:
        raise DomainError("Los administradores moderan desde el panel", code="ADMIN_USE_MODERATION", http_status=403)
    rep = service.report(db, user, review_id, data.reason, data.note, ctx)
    db.commit()
    return ReportOut(id=rep.id, review_id=rep.review_id, reason=rep.reason, status=rep.status.value,
                     created_at=rep.created_at)


@router.get("/technicians/{technician_id}/reviews", response_model=TechnicianReviewsOut,
            summary="Reseñas verificadas y reputación de un técnico")
def technician_reviews(_: CurrentUser, db: DbSession, technician_id: uuid.UUID = Path(),
                       cursor: str | None = Query(None, max_length=200), limit: int = Query(20, ge=1, le=50)):
    tech = db.get(User, technician_id)
    if tech is None or tech.role != UserRole.TECHNICIAN or not tech.is_active:
        raise DomainError("Técnico no encontrado", code="TECHNICIAN_NOT_FOUND", http_status=404)
    return _technician_reviews(db, technician_id, cursor, limit)


def _technician_reviews(db, technician_id: uuid.UUID, cursor: str | None, limit: int) -> dict:
    rep = db.get(TechnicianReputation, technician_id) or reputation.recompute(db, technician_id)
    badge = db.scalar(select(KycProfile.has_background_check_badge).where(KycProfile.technician_id == technician_id))
    stmt = (select(Review, User.full_name).join(User, User.id == Review.client_id)
            .where(Review.technician_id == technician_id, Review.status == ReviewStatus.PUBLISHED))
    if cursor:
        ts, rid = _decode(cursor)
        stmt = stmt.where(or_(Review.created_at < ts, and_(Review.created_at == ts, Review.id < rid)))
    rows = db.execute(stmt.order_by(Review.created_at.desc(), Review.id.desc()).limit(limit + 1)).all()
    items = [service.public_item(r, name) for r, name in rows[:limit]]
    last = rows[limit - 1][0] if len(rows) > limit else None
    db.commit()
    return dict(technician_id=technician_id,
                summary=dict(rating_avg=rep.rating_avg, verified_reviews=rep.verified_reviews,
                             completed_jobs=rep.completed_jobs, category_avgs=rep.category_avgs,
                             reputation_score=rep.reputation_score, has_background_check_badge=bool(badge)),
                items=items, next_cursor=_encode(last.created_at, last.id) if last else None)


# =============================================================================
# Moderación
# =============================================================================
def _admin_item(db, r: Review) -> dict:
    open_reports = db.scalar(select(func.count()).select_from(ReviewReport).where(
        ReviewReport.review_id == r.id, ReviewReport.status == ReportStatus.OPEN))
    return dict(id=r.id, service_order_id=r.service_order_id, client_id=r.client_id, technician_id=r.technician_id,
                rating=r.rating, comment=r.comment, status=r.status, risk_flags=r.risk_flags, weight=r.weight,
                open_reports=open_reports, moderation_reason=r.moderation_reason, created_at=r.created_at)


@admin_router.get("/reviews", response_model=AdminReviewPageOut, summary="Cola de moderación")
def admin_list_reviews(db: DbSession, status_: ReviewStatus | None = Query(None, alias="status"),
                       has_open_reports: bool | None = None, technician_id: uuid.UUID | None = None,
                       cursor: str | None = Query(None, max_length=200), limit: int = Query(25, ge=1, le=100),
                       _: Actor = Depends(require_permission(Permission.REVIEWS_READ))):
    stmt = select(Review)
    if status_:
        stmt = stmt.where(Review.status == status_)
    if technician_id:
        stmt = stmt.where(Review.technician_id == technician_id)
    if has_open_reports is not None:
        sub = select(ReviewReport.review_id).where(ReviewReport.status == ReportStatus.OPEN)
        stmt = stmt.where(Review.id.in_(sub) if has_open_reports else Review.id.not_in(sub))
    if cursor:
        ts, rid = _decode(cursor)
        stmt = stmt.where(or_(Review.created_at > ts, and_(Review.created_at == ts, Review.id > rid)))
    rows = db.scalars(stmt.order_by(Review.created_at, Review.id).limit(limit + 1)).all()
    last = rows[limit - 1] if len(rows) > limit else None
    return {"items": [_admin_item(db, r) for r in rows[:limit]],
            "next_cursor": _encode(last.created_at, last.id) if last else None}


@admin_router.get("/reviews/integrity", response_model=IntegrityOut,
                  summary="Verificar firmas: detecta reseñas alteradas directamente en la base")
def admin_reviews_integrity(db: DbSession, limit: int = Query(10_000, ge=1, le=100_000),
                            _: Actor = Depends(require_permission(Permission.REVIEWS_READ))):
    bad = integrity.verify_all(db, limit)
    checked = min(limit, db.scalar(select(func.count()).select_from(Review)))
    return {"checked": checked, "tampered_ids": bad}


@admin_router.get("/reviews/{review_id}", response_model=AdminReviewDetailOut,
                  summary="Detalle con señales, reportes e historial completo")
def admin_get_review(db: DbSession, ctx: ReqCtx, review_id: uuid.UUID = Path(),
                     admin: Actor = Depends(require_permission(Permission.REVIEWS_READ))):
    r = db.get(Review, review_id)
    if r is None:
        raise DomainError("Reseña no encontrada", code="REVIEW_NOT_FOUND", http_status=404)
    ratings = integrity.ratings_of(db, r)
    reports = [dict(id=str(p.id), reporter_id=str(p.reporter_id), reason=p.reason.value, note=p.note,
                    status=p.status.value, resolution=p.resolution.value if p.resolution else None,
                    created_at=p.created_at.isoformat())
               for p in db.scalars(select(ReviewReport).where(ReviewReport.review_id == r.id)
                                   .order_by(ReviewReport.created_at))]
    history = [dict(action=h.action, actor_type=h.actor_type.value, actor_id=h.actor_id, old_values=h.old_values,
                    new_values=h.new_values, reason=h.reason, created_at=h.created_at)
               for h in db.scalars(select(ReviewAuditLog).where(ReviewAuditLog.review_id == r.id)
                                   .order_by(ReviewAuditLog.id))]
    return dict(**_admin_item(db, r), ratings=ratings, technician_reply=r.technician_reply, edit_count=r.edit_count,
                integrity_ok=integrity.compute(r, ratings) == r.integrity_mac, reports=reports, history=history)


@admin_router.post("/reviews/{review_id}/moderation", response_model=AdminReviewDetailOut,
                   summary="Publicar, ocultar o eliminar una reseña")
def admin_moderate(data: ModerationIn, db: DbSession, ctx: ReqCtx, review_id: uuid.UUID = Path(),
                   admin: Actor = Depends(require_permission(Permission.REVIEWS_MODERATE))):
    service.moderate(db, admin, review_id, data.action, data.reason, data.note, actor_permissions(admin), ctx,
                     count_in_reputation=data.count_in_reputation)
    db.commit()
    return admin_get_review(db, ctx, review_id, admin)


@admin_router.post("/review-reports/{report_id}/resolution", response_model=ReportOut,
                   summary="Resolver un reporte: mantener, ocultar o eliminar")
def admin_resolve_report(data: ReportResolutionIn, db: DbSession, ctx: ReqCtx, report_id: uuid.UUID = Path(),
                         admin: Actor = Depends(require_permission(Permission.REVIEWS_MODERATE))):
    rep = service.resolve_report(db, admin, report_id, data.resolution, data.note, actor_permissions(admin), ctx)
    db.commit()
    return ReportOut(id=rep.id, review_id=rep.review_id, reason=rep.reason, status=rep.status.value,
                     created_at=rep.created_at)
