"""
Rutas de ejemplo que demuestran la separación de roles.
Cada router aplica su restricción de rol a TODAS sus rutas, de modo que
agregar un endpoint nuevo sin protección es difícil por accidente.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import (
    CurrentClient,
    CurrentTechnician,
    CurrentUser,
    DbSession,
    ReqCtx,
    require_permission,
    require_roles,
)
from app.audit.writer import write_audit
from app.core.actor import Actor
from app.kyc.permissions import Permission
from app.models import KycProfile, KycStatus, User, UserRole
from app.schemas.auth import (
    ClientProfileOut,
    TechnicianProfileOut,
    TechnicianProfileUpdate,
    UserOut,
)

# --- Cualquier usuario autenticado ------------------------------------------
me_router = APIRouter(prefix="/users", tags=["users"])


@me_router.get("/me", response_model=UserOut)
def read_me(user: CurrentUser) -> User:
    return user


# --- Solo CLIENTES -----------------------------------------------------------
client_router = APIRouter(
    prefix="/clients",
    tags=["clients"],
    dependencies=[Depends(require_roles(UserRole.CLIENT))],
)


@client_router.get("/me/profile", response_model=ClientProfileOut)
def read_client_profile(user: CurrentClient):
    return user.client_profile


# --- Solo TÉCNICOS -----------------------------------------------------------
technician_router = APIRouter(
    prefix="/technicians",
    tags=["technicians"],
    dependencies=[Depends(require_roles(UserRole.TECHNICIAN))],
)


@technician_router.get("/me/profile", response_model=TechnicianProfileOut)
def read_technician_profile(user: CurrentTechnician):
    return user.technician_profile


@technician_router.patch("/me/profile", response_model=TechnicianProfileOut)
def update_technician_profile(data: TechnicianProfileUpdate, user: CurrentTechnician, db: DbSession):
    profile = user.technician_profile
    changes = data.model_dump(exclude_unset=True)
    if changes.get("is_available"):
        # Se valida aquí para dar un error claro; un trigger en la base lo impone de todos modos.
        kyc_status = db.scalar(select(KycProfile.status).where(KycProfile.technician_id == user.id))
        if kyc_status != KycStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "KYC_NOT_APPROVED",
                        "message": "No puedes marcarte disponible hasta que tu verificación esté aprobada"},
            )
    # Solo se aplican los campos permitidos del esquema (lista blanca), nunca setattr con el body crudo.
    for field, value in changes.items():
        setattr(profile, field, value)
    db.commit()
    return profile


# La bolsa de trabajo (/technicians/me/jobs-feed) vive en app/api/routes/orders.py.


# --- Solo ADMINISTRADORES ----------------------------------------------------
admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_roles(UserRole.ADMIN))],
)


@admin_router.get("/users", response_model=list[UserOut])
def list_users(
    db: DbSession,
    _: Actor = Depends(require_permission(Permission.USERS_READ)),
    role: UserRole | None = None,
    limit: int = Query(default=50, ge=1, le=200),   # paginación acotada: evita volcados masivos
    offset: int = Query(default=0, ge=0),
):
    stmt = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    if role is not None:
        stmt = stmt.where(User.role == role)
    return db.scalars(stmt).all()


# La aprobación de técnicos se hace con el flujo de revisión KYC (app/api/routes/admin_kyc_decisions.py).


@admin_router.post("/users/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(user_id: uuid.UUID, db: DbSession, ctx: ReqCtx,
                    admin: Actor = Depends(require_permission(Permission.USERS_DEACTIVATE))) -> None:
    if user_id == admin.user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No puedes desactivarte a ti mismo")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    user.is_active = False
    user.token_version += 1  # corta sus sesiones de inmediato
    if user.role == UserRole.TECHNICIAN:
        from app.orders.service import release_technician_orders
        release_technician_orders(db, user.id, "TECHNICIAN_DEACTIVATED")
    write_audit(db, action="admin.user.deactivated", actor=admin, target_type="user", target_id=str(user.id),
                technician_id=user.id if user.role == UserRole.TECHNICIAN else None, ctx=ctx)
    db.commit()
