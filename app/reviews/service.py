"""
Calificaciones verificadas: crear, editar, responder, reportar y moderar.

Cadena de validación al crear (backend, nunca solo la app):
  usuario autenticado con rol cliente → la orden existe y es SUYA (si no: 404, sin IDOR)
  → tiene técnico → orden READY_FOR_REVIEW → pago confirmado por el proveedor
  → dentro de la ventana → no hay reseña previa (UNIQUE en la base) → correo verificado
  → límite diario → texto saneado → señales antifraude → reseña + firma + bitácora.
El trigger `review_insert_guard` repite en PostgreSQL las condiciones de orden y pago.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.kyc.permissions import Permission
from app.models import (
    PAYMENT_CONFIRMED,
    OrderStatus,
    OutboxEvent,
    ReportReason,
    ReportResolution,
    ReportStatus,
    Review,
    ReviewAuditLog,
    ReviewCategory,
    ReviewRating,
    ReviewReport,
    ReviewStatus,
    ServiceOrder,
    User,
    UserRole,
)
from app.orders.state_machine import lock_order, transition
from app.payments.service import active_payment
from app.reviews import antifraud, integrity, reputation, signals
from app.reviews.content import clean_text, is_offensive

O = OrderStatus
RS = ReviewStatus
MODERATION_REASONS = frozenset({"OFFENSIVE_CONTENT", "FAKE_REVIEW", "FRAUD_SIGNALS", "SPAM", "NOT_RELATED",
                                "PERSONAL_DATA", "VERIFIED_OK", "OTHER"})
_NOT_FOUND = DomainError("Reseña no encontrada", code="REVIEW_NOT_FOUND", http_status=404)
_PAID_STATES = (O.PAID, O.READY_FOR_REVIEW, O.REVIEWED)


class ReviewError(DomainError):
    http_status = 409
    code = "REVIEW_ERROR"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _log(db: Session, review: Review, action: str, actor: Actor, *, old: dict | None = None,
         new: dict | None = None, reason: str | None = None, ctx: RequestContext | None = None) -> None:
    db.add(ReviewAuditLog(review_id=review.id, action=action, actor_id=actor.user_id, actor_type=actor.actor_type,
                          old_values=old, new_values=new, reason=(reason or None) and reason[:300],
                          request_id=ctx.request_id if ctx else None))


def _snapshot(review: Review, ratings: dict[str, int]) -> dict[str, Any]:
    return {"rating": review.rating, "comment": review.comment, "ratings": ratings, "status": review.status.value}


def _save(db: Session, review: Review, *, bump: bool = True) -> None:
    if bump:
        review.version += 1
    review.updated_at = _now()
    integrity.sign(db, review)
    db.flush()


# =============================================================================
# Elegibilidad
# =============================================================================
def eligibility(db: Session, client: User, order: ServiceOrder) -> tuple[bool, str | None]:
    """(puede_calificar, código_si_no). La orden ya fue validada como del cliente."""
    s = get_settings()
    if order.technician_id is None:
        return False, "REVIEW_NO_TECHNICIAN"
    if db.scalar(select(func.count()).select_from(Review).where(Review.service_order_id == order.id)):
        return False, "REVIEW_ALREADY_EXISTS"
    if order.status == O.DISPUTED:
        return False, "REVIEW_ORDER_DISPUTED"
    if order.status in (O.CANCELLED, O.FAILED, O.REFUNDED):
        return False, "REVIEW_ORDER_NOT_REVIEWABLE"
    if order.status != O.READY_FOR_REVIEW:
        return False, "REVIEW_ORDER_NOT_COMPLETED" if order.status not in (O.COMPLETED, O.PAID) \
            else "REVIEW_PAYMENT_NOT_CONFIRMED"
    payment = active_payment(db, order.id)
    if payment is None or payment.status not in PAYMENT_CONFIRMED:
        return False, "REVIEW_PAYMENT_NOT_CONFIRMED"
    if order.paid_at is None:
        return False, "REVIEW_PAYMENT_NOT_CONFIRMED"
    if _now() > order.paid_at + timedelta(days=s.REVIEW_WINDOW_DAYS):
        return False, "REVIEW_WINDOW_CLOSED"
    if s.REVIEW_REQUIRE_VERIFIED_EMAIL and not client.is_email_verified:
        return False, "EMAIL_NOT_VERIFIED"
    return True, None


_ELIGIBILITY_MESSAGES = {
    "REVIEW_NO_TECHNICIAN": "La orden no tiene técnico asignado",
    "REVIEW_ALREADY_EXISTS": "Esta orden ya tiene una calificación registrada",
    "REVIEW_ORDER_DISPUTED": "La orden está en disputa; podrás calificar cuando se resuelva",
    "REVIEW_ORDER_NOT_REVIEWABLE": "Esta orden no se puede calificar (cancelada, fallida o reembolsada)",
    "REVIEW_ORDER_NOT_COMPLETED": "Solo puedes calificar servicios completados",
    "REVIEW_PAYMENT_NOT_CONFIRMED": "El pago de este servicio aún no está confirmado",
    "REVIEW_WINDOW_CLOSED": "El plazo para calificar este servicio ya venció",
    "EMAIL_NOT_VERIFIED": "Verifica tu correo para poder calificar",
}


def _client_order(db: Session, client: User, order_id: uuid.UUID, *, lock: bool) -> ServiceOrder:
    order = lock_order(db, order_id) if lock else db.get(ServiceOrder, order_id)
    if order is None or client.role != UserRole.CLIENT or order.client_id != client.id:
        raise DomainError("Orden no encontrada", code="ORDER_NOT_FOUND", http_status=404)
    return order


def check_eligibility(db: Session, client: User, order_id: uuid.UUID) -> dict:
    order = _client_order(db, client, order_id, lock=False)
    ok, code = eligibility(db, client, order)
    deadline = order.paid_at + timedelta(days=get_settings().REVIEW_WINDOW_DAYS) if order.paid_at else None
    return {"order_id": order.id, "can_review": ok, "reason_code": code,
            "message": _ELIGIBILITY_MESSAGES.get(code) if code else None, "review_deadline": deadline}


# =============================================================================
# Cliente
# =============================================================================
def _validate_ratings(ratings: dict[ReviewCategory, int] | None) -> dict[ReviewCategory, int]:
    ratings = ratings or {}
    for cat, score in ratings.items():
        if not isinstance(score, int) or not 1 <= score <= 5:
            raise DomainError("Cada categoría se califica de 1 a 5", code="REVIEW_INVALID_RATING", http_status=422,
                              extra={"category": cat.value})
    return ratings


def create(db: Session, client: User, *, order_id: uuid.UUID, rating: int, comment: str | None,
           ratings: dict[ReviewCategory, int] | None, ctx: RequestContext | None) -> Review:
    s = get_settings()
    actor = Actor.of(client)
    order = _client_order(db, client, order_id, lock=True)       # FOR UPDATE: sin carreras de doble reseña
    ok, code = eligibility(db, client, order)
    if not ok:
        status = 403 if code == "EMAIL_NOT_VERIFIED" else 409
        raise ReviewError(_ELIGIBILITY_MESSAGES[code], code=code, http_status=status)
    today = db.scalar(select(func.count()).select_from(Review).where(
        Review.client_id == client.id, Review.created_at >= _now() - timedelta(hours=24)))
    if today >= s.REVIEW_MAX_PER_DAY:
        raise ReviewError("Alcanzaste el límite de calificaciones por día", code="REVIEW_RATE_LIMITED", http_status=429)
    if not 1 <= rating <= 5:
        raise DomainError("La calificación va de 1 a 5 estrellas", code="REVIEW_INVALID_RATING", http_status=422)
    ratings = _validate_ratings(ratings)
    text = clean_text(comment, max_len=1000)

    signals.record(db, client.id, ctx)
    payment = active_payment(db, order.id)
    verdict = antifraud.assess(db, client, order, payment, offensive=is_offensive(text))

    now = _now()
    review = Review(id=uuid.uuid4(), service_order_id=order.id, client_id=client.id,
                    technician_id=order.technician_id, rating=rating, comment=text, status=verdict.status,
                    risk_flags=verdict.flags or None, weight=verdict.weight,
                    editable_until=now + timedelta(hours=s.REVIEW_EDIT_HOURS), integrity_mac="-", version=1,
                    created_at=now, updated_at=now)
    db.add(review)
    try:
        db.flush()                           # trigger: orden READY_FOR_REVIEW + pago confirmado + mismas partes
    except IntegrityError as exc:
        db.rollback()
        if "uq_reviews_service_order_id" in str(exc.orig):
            raise ReviewError("Esta orden ya tiene una calificación registrada", code="REVIEW_ALREADY_EXISTS") from None
        raise                                  # el manejador global traduce el código del trigger
    for cat, score in ratings.items():
        db.add(ReviewRating(review_id=review.id, category=cat, score=score))
    _save(db, review, bump=False)
    _log(db, review, "CREATED", actor, new=_snapshot(review, {c.value: v for c, v in ratings.items()}), ctx=ctx)
    if review.status == RS.PENDING_MODERATION:
        _log(db, review, "HELD_FOR_MODERATION", Actor.system(), reason=",".join(verdict.flags))
    transition(db, order, O.REVIEWED, actor, ctx=ctx)
    if review.status == RS.PUBLISHED:
        db.add(OutboxEvent(event_type="review.published", aggregate_type="review", aggregate_id=review.id,
                           recipient_user_id=review.technician_id, payload={"rating": rating}))
    reputation.recompute(db, review.technician_id)
    return review


def edit(db: Session, client: User, review_id: uuid.UUID, *, rating: int | None, comment: str | None,
         comment_set: bool, ratings: dict[ReviewCategory, int] | None, reason: str,
         ctx: RequestContext | None) -> Review:
    s = get_settings()
    review = db.execute(select(Review).where(Review.id == review_id).with_for_update()).scalar_one_or_none()
    if review is None or review.client_id != client.id:
        raise _NOT_FOUND
    if review.status not in (RS.PUBLISHED, RS.PENDING_MODERATION):
        raise ReviewError("Esta reseña no se puede modificar", code="REVIEW_LOCKED")
    if _now() > review.editable_until:
        raise ReviewError("El periodo para modificar la reseña terminó", code="REVIEW_EDIT_WINDOW_CLOSED")
    if review.edit_count >= s.REVIEW_MAX_EDITS:
        raise ReviewError("Alcanzaste el número máximo de modificaciones", code="REVIEW_EDIT_LIMIT")
    order = db.get(ServiceOrder, review.service_order_id)
    if order.status in (O.DISPUTED, O.REFUNDED):
        raise ReviewError("La orden está en disputa o reembolsada; la reseña está congelada", code="REVIEW_FROZEN")
    reason_text = clean_text(reason, max_len=200, field="reason")
    if not reason_text:
        raise DomainError("Indica el motivo de la modificación", code="REVIEW_EDIT_REASON_REQUIRED", http_status=422)

    before_ratings = integrity.ratings_of(db, review)
    before = _snapshot(review, before_ratings)
    # Va en el mismo UPDATE que el cambio de estrellas o comentario: el trigger lo exige.
    review.edit_count += 1
    if rating is not None:
        if not 1 <= rating <= 5:
            raise DomainError("La calificación va de 1 a 5 estrellas", code="REVIEW_INVALID_RATING", http_status=422)
        review.rating = rating
    if comment_set:
        review.comment = clean_text(comment, max_len=1000)
    for cat, score in _validate_ratings(ratings).items():
        row = db.get(ReviewRating, (review.id, cat))
        if row is None:
            db.add(ReviewRating(review_id=review.id, category=cat, score=score))
        else:
            row.score = score
    db.flush()

    # El lenguaje se vuelve a revisar; las demás señales antifraude (del momento de crear) se conservan.
    flags = set(review.risk_flags or []) - {"OFFENSIVE_LANGUAGE"}
    if is_offensive(review.comment):
        flags.add("OFFENSIVE_LANGUAGE")
    verdict = antifraud.decide(flags)
    review.risk_flags = verdict.flags or None
    if review.moderated_by_id is None:
        review.status, review.weight = verdict.status, verdict.weight
    elif "OFFENSIVE_LANGUAGE" in flags and review.status == RS.PUBLISHED:
        # Ya la decidió un moderador: una edición no cambia su peso ni su estado, salvo que
        # agregue lenguaje ofensivo (vuelve a moderación y no cuenta mientras tanto).
        review.status, review.weight = RS.PENDING_MODERATION, Decimal("0")
    _save(db, review)
    after = _snapshot(review, integrity.ratings_of(db, review))
    _log(db, review, "EDITED", Actor.of(client), old=before, new=after, reason=reason_text, ctx=ctx)
    reputation.recompute(db, review.technician_id)
    return review


# =============================================================================
# Técnico
# =============================================================================
def reply(db: Session, technician: User, review_id: uuid.UUID, text: str, ctx: RequestContext | None) -> Review:
    if not get_settings().REVIEW_REPLIES_ENABLED:
        raise ReviewError("Las respuestas no están habilitadas", code="REVIEW_REPLIES_DISABLED", http_status=403)
    review = db.execute(select(Review).where(Review.id == review_id).with_for_update()).scalar_one_or_none()
    if review is None or review.technician_id != technician.id or review.status != RS.PUBLISHED:
        raise _NOT_FOUND
    if review.technician_reply is not None:
        raise ReviewError("Ya respondiste esta reseña", code="REVIEW_ALREADY_REPLIED")
    clean = clean_text(text, max_len=500, field="reply")
    if not clean:
        raise DomainError("La respuesta está vacía", code="REVIEW_REPLY_EMPTY", http_status=422)
    if is_offensive(clean):
        raise DomainError("La respuesta contiene lenguaje no permitido", code="CONTENT_OFFENSIVE", http_status=422)
    review.technician_reply, review.technician_reply_at = clean, _now()
    _save(db, review)
    _log(db, review, "REPLIED", Actor.of(technician), new={"reply": clean}, ctx=ctx)
    db.add(OutboxEvent(event_type="review.replied", aggregate_type="review", aggregate_id=review.id,
                       recipient_user_id=review.client_id, payload={}))
    return review


# =============================================================================
# Reportes
# =============================================================================
def report(db: Session, user: User, review_id: uuid.UUID, reason: ReportReason, note: str | None,
           ctx: RequestContext | None) -> ReviewReport:
    s = get_settings()
    review = db.execute(select(Review).where(Review.id == review_id).with_for_update()).scalar_one_or_none()
    visible = review is not None and review.status == RS.PUBLISHED
    allowed = visible and (
        (user.role == UserRole.TECHNICIAN and review.technician_id == user.id)
        or (user.role == UserRole.CLIENT and review.client_id != user.id))
    if not allowed:
        raise _NOT_FOUND
    count = db.scalar(select(func.count()).select_from(ReviewReport).where(
        ReviewReport.reporter_id == user.id, ReviewReport.created_at >= _now() - timedelta(hours=24)))
    if count >= s.REVIEW_REPORTS_PER_DAY:
        raise ReviewError("Alcanzaste el límite de reportes por día", code="REPORT_RATE_LIMITED", http_status=429)
    if db.scalar(select(func.count()).select_from(ReviewReport).where(ReviewReport.review_id == review.id,
                                                                      ReviewReport.reporter_id == user.id)):
        raise ReviewError("Ya reportaste esta reseña", code="REPORT_ALREADY_EXISTS")
    rep = ReviewReport(review_id=review.id, reporter_id=user.id, reason=reason,
                       note=clean_text(note, max_len=500, field="note"))
    db.add(rep)
    db.flush()
    _log(db, review, "REPORTED", Actor.of(user), new={"reason": reason.value}, ctx=ctx)

    # Ocultamiento preventivo: N clientes distintos, con correo verificado, lo reportan.
    # Los reportes del propio técnico no cuentan (conflicto de interés).
    # Solo cuentan clientes "creíbles": correo verificado, cuenta con antigüedad mínima y al menos un
    # servicio pagado en la plataforma. Así un grupo de cuentas recién creadas no oculta reseñas ajenas.
    paid_client = select(ServiceOrder.client_id).where(ServiceOrder.status.in_(_PAID_STATES))
    reporters = db.scalar(
        select(func.count(func.distinct(ReviewReport.reporter_id))).join(User, User.id == ReviewReport.reporter_id)
        .where(ReviewReport.review_id == review.id, ReviewReport.status == ReportStatus.OPEN,
               User.role == UserRole.CLIENT, User.is_email_verified.is_(True),
               User.created_at <= _now() - timedelta(days=s.REVIEW_REPORTER_MIN_AGE_DAYS),
               User.id.in_(paid_client)))
    if reporters >= s.REVIEW_AUTO_HIDE_REPORTS:
        review.status, review.moderation_reason, review.moderated_at = RS.HIDDEN, "AUTO_HIDDEN_REPORTS", _now()
        _save(db, review)
        _log(db, review, "AUTO_HIDDEN", Actor.system(), old={"status": "PUBLISHED"}, new={"status": "HIDDEN"},
             reason=f"{reporters} reportes de clientes distintos")
        reputation.recompute(db, review.technician_id)
    return rep


# =============================================================================
# Moderación (administradores)
# =============================================================================
def _check_reason(reason: str, note: str | None, *, note_required: bool) -> None:
    if reason not in MODERATION_REASONS:
        raise DomainError("Motivo de moderación inválido", code="MODERATION_REASON_INVALID", http_status=422)
    if note_required and not (note and note.strip()):
        raise DomainError("Esta acción requiere una nota", code="MODERATION_NOTE_REQUIRED", http_status=422)


def _apply_moderation(db: Session, admin: Actor, review: Review, to: ReviewStatus, reason: str, note: str | None,
                      ctx: RequestContext | None, *, count_in_reputation: bool = True) -> None:
    if to == RS.PUBLISHED:
        order = db.get(ServiceOrder, review.service_order_id)
        if order.status == O.REFUNDED:
            raise ReviewError("No se publica la reseña de una orden reembolsada", code="REVIEW_ORDER_REFUNDED")
    before = {"status": review.status.value, "weight": str(review.weight)}
    review.status, review.moderation_reason = to, reason
    review.moderated_by_id, review.moderated_at = admin.user_id, _now()
    if to == RS.PUBLISHED and review.weight == 0 and count_in_reputation:
        # Un moderador liberó una reseña retenida: cuenta, con el peso de las señales medias que tenga.
        review.weight = antifraud.decide(set(review.risk_flags or []) - antifraud.HIGH).weight
    if not count_in_reputation:
        review.weight = Decimal("0")
    _save(db, review)
    after = {"status": review.status.value, "weight": str(review.weight)}
    _log(db, review, f"MODERATED_{to.value}", admin, old=before, new=after, reason=f"{reason}: {note or ''}", ctx=ctx)
    write_audit(db, action=f"review.moderated.{to.value.lower()}", actor=admin, technician_id=review.technician_id,
                target_type="review", target_id=str(review.id), reason_code=reason, reason_note=note,
                changes={"status": {"from": before["status"], "to": after["status"]}}, ctx=ctx)
    if to in (RS.HIDDEN, RS.REMOVED):
        resolution = ReportResolution.HIDE if to == RS.HIDDEN else ReportResolution.REMOVE
        for rep in db.scalars(select(ReviewReport).where(ReviewReport.review_id == review.id,
                                                         ReviewReport.status == ReportStatus.OPEN)):
            rep.status, rep.resolution = ReportStatus.RESOLVED, resolution
            rep.resolved_by_id, rep.resolved_at, rep.resolution_note = admin.user_id, _now(), "Moderación directa"
    reputation.recompute(db, review.technician_id)


def _forbidden(message: str) -> DomainError:
    return DomainError(message, code="PERMISSION_DENIED", http_status=403)


def moderate(db: Session, admin: Actor, review_id: uuid.UUID, action: str, reason: str, note: str | None,
             perms: frozenset[Permission], ctx: RequestContext | None, *,
             count_in_reputation: bool = True) -> Review:
    """
    Separación de funciones: soporte (REVIEWS_MODERATE) solo OCULTA. Publicar, liberar una
    reseña retenida o decidir que no cuente en la reputación es de moderación de contenido
    (REVIEWS_PUBLISH); eliminar, de quien tenga REVIEWS_REMOVE.
    """
    review = db.execute(select(Review).where(Review.id == review_id).with_for_update()).scalar_one_or_none()
    if review is None:
        raise _NOT_FOUND
    if review.status == RS.REMOVED:
        raise ReviewError("La reseña ya fue eliminada", code="REVIEW_ALREADY_REMOVED")
    target = {"PUBLISH": RS.PUBLISHED, "HIDE": RS.HIDDEN, "REMOVE": RS.REMOVED}.get(action)
    if target is None:
        raise DomainError("Acción inválida", code="MODERATION_ACTION_INVALID", http_status=422)
    if target == RS.REMOVED and Permission.REVIEWS_REMOVE not in perms:
        raise _forbidden("No tienes permiso para eliminar reseñas")
    if (target == RS.PUBLISHED or not count_in_reputation) and Permission.REVIEWS_PUBLISH not in perms:
        raise _forbidden("Solo moderación de contenido publica reseñas o decide su peso")
    if target == review.status:
        raise ReviewError("La reseña ya está en ese estado", code="REVIEW_SAME_STATUS")
    _check_reason(reason, note, note_required=target != RS.PUBLISHED)
    _apply_moderation(db, admin, review, target, reason, note, ctx, count_in_reputation=count_in_reputation)
    return review


def resolve_report(db: Session, admin: Actor, report_id: uuid.UUID, resolution: ReportResolution, note: str | None,
                   perms: frozenset[Permission], ctx: RequestContext | None) -> ReviewReport:
    rep = db.execute(select(ReviewReport).where(ReviewReport.id == report_id).with_for_update()).scalar_one_or_none()
    if rep is None:
        raise DomainError("Reporte no encontrado", code="REPORT_NOT_FOUND", http_status=404)
    if rep.status != ReportStatus.OPEN:
        raise ReviewError("El reporte ya fue resuelto", code="REPORT_ALREADY_RESOLVED")
    if resolution == ReportResolution.REMOVE and Permission.REVIEWS_REMOVE not in perms:
        raise _forbidden("No tienes permiso para eliminar reseñas")
    review = db.execute(select(Review).where(Review.id == rep.review_id).with_for_update()).scalar_one()
    if resolution == ReportResolution.KEEP and review.status != RS.PUBLISHED \
            and Permission.REVIEWS_PUBLISH not in perms:
        # "Mantener" una reseña oculta equivale a volver a publicarla: decisión de moderación de contenido.
        raise _forbidden("Solo moderación de contenido puede mantener (republicar) una reseña oculta")
    reason = {ReportReason.OFFENSIVE: "OFFENSIVE_CONTENT", ReportReason.FALSE: "FAKE_REVIEW",
              ReportReason.SPAM: "SPAM", ReportReason.NOT_RELATED: "NOT_RELATED"}.get(rep.reason, "OTHER")
    rep.status, rep.resolution = ReportStatus.RESOLVED, resolution
    rep.resolved_by_id, rep.resolved_at, rep.resolution_note = admin.user_id, _now(), note
    db.flush()                      # la sesión no hace autoflush: el conteo de abajo debe ver este cambio
    if resolution == ReportResolution.KEEP:
        _log(db, review, "REPORT_DISMISSED", admin, reason=note, ctx=ctx)
        others_open = db.scalar(select(func.count()).select_from(ReviewReport).where(
            ReviewReport.review_id == review.id, ReviewReport.status == ReportStatus.OPEN))
        order = db.get(ServiceOrder, review.service_order_id)
        if review.status == RS.HIDDEN and review.moderation_reason == "AUTO_HIDDEN_REPORTS" and not others_open \
                and order.status != O.REFUNDED:
            _apply_moderation(db, admin, review, RS.PUBLISHED, "VERIFIED_OK", note, ctx)
        write_audit(db, action="review.report.dismissed", actor=admin, technician_id=review.technician_id,
                    target_type="review_report", target_id=str(rep.id), reason_note=note, ctx=ctx)
    else:
        target = RS.HIDDEN if resolution == ReportResolution.HIDE else RS.REMOVED
        _check_reason(reason, note, note_required=True)
        if review.status != target and review.status != RS.REMOVED:
            _apply_moderation(db, admin, review, target, reason, note, ctx)
    db.flush()
    return rep


def hide_for_refund(db: Session, review: Review) -> None:
    """Reembolso total: el servicio dejó de estar 'completado y pagado'; la reseña deja de ser pública y de contar."""
    if review.status == RS.REMOVED:
        return
    before = {"status": review.status.value, "weight": str(review.weight)}
    # Cualquier estado (incluida una ocultación previa por reportes): el motivo pasa a ORDER_REFUNDED,
    # así ninguna resolución de reportes posterior la vuelve a publicar.
    review.status, review.moderation_reason, review.moderated_at = RS.HIDDEN, "ORDER_REFUNDED", _now()
    review.weight = Decimal("0")
    _save(db, review)
    _log(db, review, "HIDDEN_ORDER_REFUNDED", Actor.system(), old=before,
         new={"status": "HIDDEN", "weight": "0.00"})


# =============================================================================
# Lectura
# =============================================================================
def display_name(full_name: str) -> str:
    parts = full_name.split()
    if not parts:
        return "Cliente"
    return parts[0] + (f" {parts[1][0]}." if len(parts) > 1 else "")


def public_item(review: Review, client_name: str) -> dict:
    return dict(id=review.id, rating=review.rating, comment=review.comment,
                ratings={r.category.value: r.score for r in review.ratings}, verification=review.verification,
                client_display=display_name(client_name), created_at=review.created_at,
                edited=review.edit_count > 0, technician_reply=review.technician_reply,
                technician_reply_at=review.technician_reply_at)


def own_item(review: Review) -> dict:
    s = get_settings()
    return dict(id=review.id, service_order_id=review.service_order_id, technician_id=review.technician_id,
                rating=review.rating, comment=review.comment,
                ratings={r.category.value: r.score for r in review.ratings}, status=review.status,
                verification=review.verification, created_at=review.created_at, updated_at=review.updated_at,
                editable_until=review.editable_until,
                can_edit=review.status in (RS.PUBLISHED, RS.PENDING_MODERATION)
                and _now() <= review.editable_until and review.edit_count < s.REVIEW_MAX_EDITS,
                edits_left=max(0, s.REVIEW_MAX_EDITS - review.edit_count),
                technician_reply=review.technician_reply)
