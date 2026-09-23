"""
Administración del KYC: lectura de la cola y del expediente, y gestión de roles.

Autorización en dos niveles:
1. Permiso (require_permission): ¿este rol puede hacer esto en general?
2. Objeto: ¿puede hacerlo sobre ESTE expediente? (asignado a él o supervisor, y dentro de
   su región si tiene regiones asignadas). Si no, se responde 404 —no 403— para no
   confirmar que el expediente existe, y el intento se audita.

Las decisiones (tomar caso, aprobar, rechazar, corrección, suspensión) llegan en la Fase 4.
"""
from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, ReqCtx, require_permission, require_roles
from app.audit.writer import write_audit, write_audit_detached
from app.core.actor import Actor
from app.kyc import identity, service
from app.kyc.access import can_read_case, region_scope
from app.kyc.permissions import Permission, check_role_set, permissions_for
from app.models import (
    AdminRole,
    AdminRoleAssignment,
    AuditResult,
    KycAddress,
    KycProfile,
    KycStatus,
    KycStatusHistory,
    MxState,
    User,
    UserRole,
)
from app.schemas.kyc import CaseDetailOut, QueuePageOut, RolesIn, RolesOut

router = APIRouter(prefix="/admin", tags=["kyc (administración)"],
                   dependencies=[Depends(require_roles(UserRole.ADMIN))])

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                           detail={"code": "KYC_CASE_NOT_FOUND", "message": "Expediente no encontrado"})
_DEFAULT_QUEUE = (KycStatus.SUBMITTED, KycStatus.UNDER_REVIEW)


def _encode_cursor(ts: datetime, case_id: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{case_id}".encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, cid = raw.split("|", 1)
        return datetime.fromisoformat(ts), uuid.UUID(cid)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail={"code": "INVALID_CURSOR", "message": "Cursor inválido"}) from None


# ---------------------------------------------------------------------------
# Cola
# ---------------------------------------------------------------------------
@router.get("/kyc/cases", response_model=QueuePageOut, summary="Cola de expedientes (datos enmascarados)")
def list_cases(
    db: DbSession,
    actor: Actor = Depends(require_permission(Permission.KYC_QUEUE_READ)),
    status_: list[KycStatus] | None = Query(default=None, alias="status"),
    assigned: str = Query(default="any", pattern="^(any|me|unassigned)$"),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=200),
):
    statuses = status_ or list(_DEFAULT_QUEUE)
    stmt = (
        select(KycProfile, KycAddress.state_id, MxState.name)
        .outerjoin(KycAddress, KycAddress.id == KycProfile.current_address_id)
        .outerjoin(MxState, MxState.id == KycAddress.state_id)
        .where(KycProfile.status.in_(statuses), KycProfile.submitted_at.isnot(None))
    )
    if assigned == "me":
        stmt = stmt.where(KycProfile.assigned_reviewer_id == actor.user_id)
    elif assigned == "unassigned":
        stmt = stmt.where(KycProfile.assigned_reviewer_id.is_(None))
    regions = region_scope(db, actor)
    if regions:
        stmt = stmt.where(KycAddress.state_id.in_(regions))
    if cursor:  # paginación por llave (FIFO: el más antiguo primero), estable aunque lleguen casos nuevos
        ts, cid = _decode_cursor(cursor)
        stmt = stmt.where(or_(KycProfile.submitted_at > ts,
                              and_(KycProfile.submitted_at == ts, KycProfile.id > cid)))
    rows = db.execute(stmt.order_by(KycProfile.submitted_at, KycProfile.id).limit(limit + 1)).all()

    items = []
    for p, _state_id, state_name in rows[:limit]:
        initial = f" {p.paternal_surname[0]}." if p.paternal_surname else ""
        first = (p.first_names or "").split(" ")[0]
        items.append(dict(case_id=p.id, status=p.status, cycle=p.cycle, submitted_at=p.submitted_at,
                          technician_display=(first + initial) or "—", state=state_name,
                          assigned_to_me=p.assigned_reviewer_id == actor.user_id,
                          assigned=p.assigned_reviewer_id is not None))
    last = rows[limit - 1][0] if len(rows) > limit else None
    return {"items": items, "next_cursor": _encode_cursor(last.submitted_at, last.id) if last else None}


# ---------------------------------------------------------------------------
# Expediente completo
# ---------------------------------------------------------------------------
@router.get("/kyc/cases/{case_id}", response_model=CaseDetailOut,
            summary="Expediente completo (solo revisor asignado o supervisor)")
def get_case(
    db: DbSession,
    ctx: ReqCtx,
    case_id: uuid.UUID = Path(),
    actor: Actor = Depends(require_permission(Permission.KYC_QUEUE_READ)),
):
    profile = db.get(KycProfile, case_id)
    if profile is None or not can_read_case(db, actor, profile):
        write_audit_detached(action="kyc.case.access_denied", actor=actor, result=AuditResult.DENIED,
                             technician_id=profile.technician_id if profile else None,
                             kyc_profile_id=case_id if profile else None,
                             target_type="kyc_profile", target_id=str(case_id), ctx=ctx)
        raise _NOT_FOUND

    user = db.get(User, profile.technician_id)
    curp, rfc = identity.read_identifiers(profile) if profile.anonymized_at is None else (None, None)
    history = db.scalars(select(KycStatusHistory).where(KycStatusHistory.kyc_profile_id == profile.id)
                         .order_by(KycStatusHistory.id)).all()
    address = db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None

    # Cada apertura del expediente completo queda auditada (quién vio datos de quién).
    write_audit(db, action="kyc.case.viewed", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, target_type="kyc_profile", target_id=str(profile.id), ctx=ctx)
    db.commit()

    return dict(
        case_id=profile.id, version=profile.version, status=profile.status, cycle=profile.cycle,
        technician_id=profile.technician_id, email=user.email, phone=user.phone,
        first_names=profile.first_names, paternal_surname=profile.paternal_surname,
        maternal_surname=profile.maternal_surname, birth_date=profile.birth_date, curp=curp, rfc=rfc,
        address=service.address_view(db, address), documents=service.documents_view(db, profile, reviewer=True),
        history=[dict(from_status=h.from_status, to_status=h.to_status, actor_type=h.actor_type.value,
                      reason_code=h.reason_code, note=h.note, at=h.created_at) for h in history],
        assigned_reviewer_id=profile.assigned_reviewer_id, submitted_at=profile.submitted_at,
        has_background_check_badge=profile.has_background_check_badge,
    )


# ---------------------------------------------------------------------------
# Roles de administradores
# ---------------------------------------------------------------------------
def _admin_or_404(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=404, detail={"code": "ADMIN_NOT_FOUND", "message": "Administrador no encontrado"})
    return user


def _roles_out(user_id: uuid.UUID, roles: set[AdminRole]) -> dict:
    return {"user_id": user_id, "roles": sorted(roles, key=lambda r: r.value),
            "permissions": sorted(p.value for p in permissions_for(roles))}


@router.get("/users/{user_id}/roles", response_model=RolesOut)
def get_roles(db: DbSession, user_id: uuid.UUID = Path(),
              _: Actor = Depends(require_permission(Permission.ADMIN_ROLES_MANAGE))):
    user = _admin_or_404(db, user_id)
    return _roles_out(user.id, {a.role for a in user.admin_roles})


@router.put("/users/{user_id}/roles", response_model=RolesOut)
def put_roles(data: RolesIn, db: DbSession, ctx: ReqCtx, user_id: uuid.UUID = Path(),
              actor: Actor = Depends(require_permission(Permission.ADMIN_ROLES_MANAGE))):
    if user_id == actor.user_id:
        write_audit_detached(action="admin.roles.self_change_denied", actor=actor, result=AuditResult.DENIED,
                             target_type="user", target_id=str(user_id), ctx=ctx)
        raise HTTPException(status_code=403, detail={"code": "SELF_ROLE_CHANGE",
                                                     "message": "Nadie puede modificar sus propios roles"})
    target = _admin_or_404(db, user_id)
    new = set(data.roles)
    try:
        check_role_set(new)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "ROLE_CONFLICT", "message": str(exc)}) from None

    before = {a.role for a in target.admin_roles}
    if AdminRole.SUPERADMIN in before and AdminRole.SUPERADMIN not in new:
        # Serializa cambios de superadmin para que dos peticiones no dejen el sistema sin ninguno.
        others = db.scalars(
            select(AdminRoleAssignment.user_id).where(AdminRoleAssignment.role == AdminRole.SUPERADMIN,
                                                      AdminRoleAssignment.user_id != target.id).with_for_update()
        ).all()
        if not others:
            raise HTTPException(status_code=409, detail={"code": "LAST_SUPERADMIN",
                                                         "message": "No se puede quitar el último superadmin"})

    for a in list(target.admin_roles):
        if a.role not in new:
            target.admin_roles.remove(a)
    for r in new - before:
        target.admin_roles.append(AdminRoleAssignment(user_id=target.id, role=r, granted_by_id=actor.user_id))
    if before - new:
        target.token_version += 1   # al reducir privilegios, se cierran sus sesiones activas

    write_audit(db, action="admin.roles.updated", actor=actor, target_type="user", target_id=str(target.id),
                changes={"before": sorted(r.value for r in before), "after": sorted(r.value for r in new)}, ctx=ctx)
    db.commit()
    return _roles_out(target.id, new)
