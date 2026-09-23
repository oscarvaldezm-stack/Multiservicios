"""
Visualización de documentos KYC por administradores, tickets temporales y consulta de auditoría.

Cada visualización:
  permiso + asignación del caso (o supervisor)  ->  límite de visualizaciones por hora
  ->  descifrado en memoria  ->  marca de agua con quién y cuándo  ->  auditoría  ->  respuesta sin caché.
Nunca se entrega el archivo original ni una URL al bucket.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, ReqCtx, require_permission, require_roles
from app.api.responses import document_image
from app.audit.writer import verify_chain, write_audit, write_audit_detached
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.kyc import documents, view_tickets
from app.kyc.access import can_read_case
from app.kyc.permissions import Permission
from app.models import AuditLog, AuditResult, KycDocument, KycDocumentFile, KycProfile, User, UserRole
from app.schemas.kyc import AuditIntegrityOut, AuditPageOut, ViewTicketOut
from app.storage.object_storage import get_storage

security_log = logging.getLogger("security")

router = APIRouter(prefix="/admin", tags=["kyc (administración)"],
                   dependencies=[Depends(require_roles(UserRole.ADMIN))])
public_router = APIRouter(prefix="/kyc", tags=["kyc (visualización con ticket)"])

_NOT_FOUND = HTTPException(status_code=404, detail={"code": "FILE_NOT_FOUND", "message": "Archivo no encontrado"})


def _authorize_file(db: Session, actor: Actor, case_id: uuid.UUID, document_id: uuid.UUID,
                    file_id: uuid.UUID, ctx: RequestContext) -> tuple[KycProfile, KycDocumentFile]:
    profile = db.get(KycProfile, case_id)
    f = documents.load_file(db, file_id, document_id, case_id) if profile else None
    if profile is None or f is None or not can_read_case(db, actor, profile):
        write_audit_detached(action="kyc.file.access_denied", actor=actor, result=AuditResult.DENIED,
                             technician_id=profile.technician_id if profile else None,
                             kyc_profile_id=case_id if profile else None, document_id=document_id,
                             target_type="kyc_document_file", target_id=str(file_id), ctx=ctx)
        raise _NOT_FOUND
    return profile, f


def _enforce_view_rate(db: Session, actor: Actor, ctx: RequestContext) -> None:
    limit = get_settings().KYC_FILE_VIEWS_PER_HOUR
    if documents.views_last_hour(db, actor.user_id) >= limit:
        write_audit_detached(action="kyc.file.view_rate_limited", actor=actor, result=AuditResult.DENIED,
                             target_type="user", target_id=str(actor.user_id), ctx=ctx)
        # Alerta: patrón típico de extracción masiva por alguien con acceso legítimo.
        security_log.warning("ALERTA: administrador %s superó %s visualizaciones de documentos por hora",
                             actor.user_id, limit)
        raise HTTPException(status_code=429, detail={"code": "VIEW_RATE_LIMITED",
                                                     "message": "Demasiadas visualizaciones; intenta más tarde"})


def _serve(db: Session, actor: Actor, profile: KycProfile, f: KycDocumentFile, ctx: RequestContext,
           via: str) -> Response:
    _enforce_view_rate(db, actor, ctx)
    image = documents.render_preview(db, get_storage(), profile, f, documents.watermark_label(actor))
    write_audit(db, action="kyc.file.viewed", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, document_id=f.document_id, target_type="kyc_document_file",
                target_id=str(f.id), changes={"via": via}, ctx=ctx)
    db.commit()
    return document_image(image)


@router.get("/kyc/cases/{case_id}/documents/{document_id}/files/{file_id}/content", response_class=Response,
            summary="Ver un documento (imagen con marca de agua; revisor asignado o supervisor)")
def get_file_content(db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = Path(), document_id: uuid.UUID = Path(),
                     file_id: uuid.UUID = Path(),
                     actor: Actor = Depends(require_permission(Permission.KYC_QUEUE_READ))):
    profile, f = _authorize_file(db, actor, case_id, document_id, file_id, ctx)
    return _serve(db, actor, profile, f, ctx, via="api")


@router.post("/kyc/cases/{case_id}/documents/{document_id}/files/{file_id}/view-ticket",
             response_model=ViewTicketOut, status_code=status.HTTP_201_CREATED,
             summary="Ticket de un solo uso (60 s) para mostrar el documento en un <img>")
def post_view_ticket(db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = Path(), document_id: uuid.UUID = Path(),
                     file_id: uuid.UUID = Path(),
                     actor: Actor = Depends(require_permission(Permission.KYC_QUEUE_READ))):
    profile, f = _authorize_file(db, actor, case_id, document_id, file_id, ctx)
    token, expires = view_tickets.issue(db, actor.user_id, f.id)
    write_audit(db, action="kyc.file.view_ticket_issued", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, document_id=document_id, target_type="kyc_document_file",
                target_id=str(file_id), ctx=ctx)
    db.commit()
    return {"url": f"{get_settings().API_V1_PREFIX}/kyc/file-views/{token}", "expires_at": expires}


@public_router.get("/file-views/{token}", response_class=Response,
                   summary="Canjear un ticket de visualización (un solo uso)")
def redeem_view_ticket(db: DbSession, ctx: ReqCtx, token: str = Path(min_length=40, max_length=64,
                                                                           pattern=r"^[A-Za-z0-9_-]+$")):
    redeemed = view_tickets.redeem(db, token)
    if redeemed is None:
        db.rollback()
        raise _NOT_FOUND                                  # falso, vencido o ya usado: misma respuesta
    user_id, file_id = redeemed
    db.commit()                                           # el ticket queda quemado aunque lo demás falle
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.role != UserRole.ADMIN:
        raise _NOT_FOUND
    actor = Actor.from_user(user)
    f = db.get(KycDocumentFile, file_id)
    doc = db.get(KycDocument, f.document_id) if f else None
    doc_profile = db.get(KycProfile, doc.kyc_profile_id) if doc else None
    # Los permisos se vuelven a comprobar al canjear: si le quitaron el caso, ya no ve nada.
    if f is None or doc_profile is None or not can_read_case(db, actor, doc_profile):
        write_audit_detached(action="kyc.file.access_denied", actor=actor, result=AuditResult.DENIED,
                             target_type="kyc_document_file", target_id=str(file_id), ctx=ctx)
        raise _NOT_FOUND
    return _serve(db, actor, doc_profile, f, ctx, via="ticket")


# ---------------------------------------------------------------------------
# Auditoría
# ---------------------------------------------------------------------------
@router.get("/audit-logs", response_model=AuditPageOut, summary="Consultar la bitácora de auditoría")
def list_audit_logs(
    db: DbSession, ctx: ReqCtx,
    technician_id: uuid.UUID | None = None, actor_id: uuid.UUID | None = None,
    action: str | None = Query(default=None, max_length=80, pattern=r"^[a-z_.]+$"),
    result: AuditResult | None = None,
    limit: int = Query(default=50, ge=1, le=200), before_id: int | None = Query(default=None, ge=1),
    actor: Actor = Depends(require_permission(Permission.AUDIT_READ)),
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit + 1)
    if technician_id:
        stmt = stmt.where(AuditLog.technician_id == technician_id)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)
    rows = db.scalars(stmt).all()
    # Consultar la auditoría también se audita (quién revisó a quién).
    write_audit(db, action="audit.queried", actor=actor, technician_id=technician_id, target_type="audit_log",
                changes={"action": action, "actor_id": str(actor_id) if actor_id else None}, ctx=ctx)
    db.commit()
    items = [dict(id=r.id, occurred_at=r.occurred_at, actor_id=r.actor_id, actor_type=r.actor_type.value,
                  actor_roles=r.actor_roles, action=r.action, result=r.result.value, target_type=r.target_type,
                  target_id=r.target_id, technician_id=r.technician_id, document_id=r.document_id,
                  reason_code=r.reason_code, ip=str(r.ip) if r.ip else None) for r in rows[:limit]]
    return {"items": items, "next_cursor": rows[limit - 1].id if len(rows) > limit else None}


@router.get("/audit-logs/integrity", response_model=AuditIntegrityOut,
            summary="Verificar que la cadena de auditoría no fue alterada")
def audit_integrity(db: DbSession, _: Actor = Depends(require_permission(Permission.AUDIT_READ))):
    broken = verify_chain(db)
    return {"intact": not broken, "broken_ids": broken[:100]}
