"""Regla de acceso a un expediente (y sus documentos) por parte de un administrador."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.actor import Actor
from app.kyc.permissions import Permission, permissions_for
from app.models import AdminRegionScope, KycAddress, KycProfile


def region_scope(db: Session, actor: Actor) -> set[int]:
    return set(db.scalars(select(AdminRegionScope.state_id).where(AdminRegionScope.user_id == actor.user_id)))


def can_read_case(db: Session, actor: Actor, profile: KycProfile) -> bool:
    """Supervisor: cualquier caso. Revisor: solo el asignado a él y dentro de sus regiones (si tiene)."""
    perms = permissions_for(actor.admin_roles)
    allowed = (Permission.KYC_CASE_READ_ANY in perms
               or (Permission.KYC_CASE_READ_ASSIGNED in perms and profile.assigned_reviewer_id == actor.user_id))
    if not allowed:
        return False
    regions = region_scope(db, actor)
    if regions and Permission.KYC_CASE_READ_ANY not in perms:
        addr = db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None
        return addr is not None and addr.state_id in regions
    return True
