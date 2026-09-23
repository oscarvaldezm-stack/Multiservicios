"""
Decisiones sobre expedientes KYC (Fase 4). Cada ruta exige su permiso; la capa de
servicio (app/kyc/decisions.py) valida además la asignación, la región, el estado, la
versión y los motivos. Todo queda en historial + auditoría + notificación al técnico.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Path

from app.api.deps import DbSession, ReqCtx, require_permission, require_roles
from app.core.actor import Actor
from app.kyc import decisions
from app.kyc.permissions import Permission
from app.models import RejectionReason, UserRole
from app.schemas.marketplace import (
    CaseDecisionIn,
    CaseStateOut,
    DocumentDecisionIn,
    DocumentDecisionOut,
    ReinstateIn,
    SuspendIn,
    VersionIn,
)

router = APIRouter(prefix="/admin/kyc/cases", tags=["kyc (decisiones)"],
                   dependencies=[Depends(require_roles(UserRole.ADMIN))])
CaseId = Path(description="ID del expediente")


def _state(p) -> CaseStateOut:
    return CaseStateOut(case_id=p.id, status=p.status, version=p.version, cycle=p.cycle,
                        assigned_reviewer_id=p.assigned_reviewer_id)


@router.post("/{case_id}/claim", response_model=CaseStateOut, summary="Tomar un caso de la cola")
def claim(db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
          actor: Actor = Depends(require_permission(Permission.KYC_CASE_CLAIM))):
    p = decisions.claim(db, actor, case_id, ctx)
    db.commit()
    return _state(p)


@router.post("/{case_id}/release", response_model=CaseStateOut, summary="Liberar un caso tomado")
def release(data: VersionIn, db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
            actor: Actor = Depends(require_permission(Permission.KYC_CASE_CLAIM))):
    p = decisions.release(db, actor, case_id, data.expected_version, ctx)
    db.commit()
    return _state(p)


@router.put("/{case_id}/documents/{document_id}/decision", response_model=DocumentDecisionOut,
            summary="Aprobar o rechazar un documento")
def decide_document(data: DocumentDecisionIn, db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
                    document_id: uuid.UUID = Path(),
                    actor: Actor = Depends(require_permission(Permission.KYC_DOCUMENT_DECIDE))):
    doc = decisions.decide_document(db, actor, case_id, document_id, data.decision, data.reason_code, data.note, ctx)
    label = db.get(RejectionReason, doc.rejection_reason_id).label if doc.rejection_reason_id else None
    db.commit()
    return DocumentDecisionOut(document_id=doc.id, status=doc.status.value, rejection_reason=label)


@router.post("/{case_id}/decision", response_model=CaseStateOut,
             summary="Decidir el expediente: aprobar, pedir corrección o rechazar")
def decide_case(data: CaseDecisionIn, db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
                actor: Actor = Depends(require_permission(Permission.KYC_QUEUE_READ))):
    # El permiso específico (aprobar / corrección / rechazo definitivo) lo valida el servicio según la decisión.
    p = decisions.decide(db, actor, case_id, data.decision, reason_code=data.reason_code, note=data.note,
                         expected_version=data.expected_version, ctx=ctx)
    db.commit()
    return _state(p)


@router.post("/{case_id}/suspend", response_model=CaseStateOut, summary="Suspender a un técnico aprobado")
def suspend(data: SuspendIn, db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
            actor: Actor = Depends(require_permission(Permission.KYC_SUSPEND))):
    p = decisions.suspend(db, actor, case_id, data.reason_code, data.note, ctx)
    db.commit()
    return _state(p)


@router.post("/{case_id}/reinstate", response_model=CaseStateOut, summary="Reactivar (abre una revisión nueva)")
def reinstate(data: ReinstateIn, db: DbSession, ctx: ReqCtx, case_id: uuid.UUID = CaseId,
              actor: Actor = Depends(require_permission(Permission.KYC_REINSTATE))):
    p = decisions.reinstate(db, actor, case_id, data.note, ctx)
    db.commit()
    return _state(p)
