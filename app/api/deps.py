"""
Dependencias de FastAPI para autenticación y autorización.

Principios:
1. El token solo PRUEBA IDENTIDAD. El rol y el estado de la cuenta se leen
   SIEMPRE de la base de datos en cada petición (si un admin suspende o cambia
   el rol de alguien, surte efecto de inmediato, sin esperar a que expire el token).
2. Negar por defecto: cada ruta protegida declara explícitamente qué roles acepta.
"""
import uuid
from collections.abc import Callable
from typing import Annotated

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit_detached
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.security import TokenError, decode_access_token
from app.db.session import get_db
from app.kyc.permissions import Permission, permissions_for
from app.models import AuditResult, KycProfile, KycStatus, User, UserRole

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/token")

DbSession = Annotated[Session, Depends(get_db)]

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="No se pudieron validar las credenciales",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(db: DbSession, token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    try:
        payload = decode_access_token(token)
    except TokenError:
        raise _CREDENTIALS_EXC from None

    # Consulta 100 % parametrizada por el ORM (sin concatenar strings).
    user = db.execute(select(User).where(User.id == uuid.UUID(payload["sub"]))).scalar_one_or_none()

    if user is None or not user.is_active:
        raise _CREDENTIALS_EXC
    # Token emitido antes de un "logout global" / cambio de contraseña -> inválido.
    if int(payload["ver"]) != user.token_version:
        raise _CREDENTIALS_EXC
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*allowed: UserRole) -> Callable[[User], User]:
    """
    Fábrica de dependencias:  Depends(require_roles(UserRole.ADMIN))
    Devuelve 403 (autenticado pero sin permiso), distinto de 401 (no autenticado).
    """
    allowed_set = frozenset(allowed)

    def _checker(user: CurrentUser) -> User:
        if user.role not in allowed_set:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes permiso para este recurso")
        return user

    return _checker


CurrentClient = Annotated[User, Depends(require_roles(UserRole.CLIENT))]
CurrentTechnician = Annotated[User, Depends(require_roles(UserRole.TECHNICIAN))]
CurrentAdmin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


def require_kyc_approved(user: CurrentTechnician, db: DbSession) -> User:
    """
    Regla crítica: un técnico solo recibe órdenes con el KYC en APPROVED.

    Lee el estado desde la base en ESTA transacción con FOR SHARE: si un supervisor
    suspende al técnico en el mismo instante, una operación espera a la otra y no hay
    ventana de carrera. Un trigger en service_requests repite la validación en la base.
    """
    status_ = db.scalar(
        select(KycProfile.status).where(KycProfile.technician_id == user.id).with_for_update(read=True)
    )
    if status_ != KycStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "KYC_NOT_APPROVED", "message": "Tu verificación de identidad aún no está aprobada"},
        )
    return user


VerifiedTechnician = Annotated[User, Depends(require_kyc_approved)]


# ---------------------------------------------------------------------------
# Contexto de la petición y actor (para auditoría)
# ---------------------------------------------------------------------------
def get_request_context(request: Request) -> RequestContext:
    # Detrás de Nginx, configurar uvicorn con --proxy-headers y --forwarded-allow-ips
    # para que request.client.host sea la IP real y no la del proxy.
    rid = request.headers.get("x-request-id") or secrets.token_hex(8)
    return RequestContext(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=rid[:64],
        device_id=request.headers.get("x-device-id"),
    )


ReqCtx = Annotated[RequestContext, Depends(get_request_context)]


def get_actor(user: CurrentUser) -> Actor:
    try:
        return Actor.from_user(user)
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes permiso para este recurso") from None


CurrentActor = Annotated[Actor, Depends(get_actor)]


def require_permission(*needed: Permission) -> Callable[..., Actor]:
    """
    Exige que el administrador tenga TODOS los permisos indicados.
    Un intento sin permiso se audita (transacción aparte) y responde 403.
    """
    needed_set = frozenset(needed)

    def _checker(user: CurrentAdmin, ctx: ReqCtx) -> Actor:
        actor = Actor.from_user(user)
        missing = needed_set - permissions_for(actor.admin_roles)
        if missing:
            write_audit_detached(
                action="admin.permission.denied", actor=actor, result=AuditResult.DENIED,
                target_type="permission", target_id=",".join(sorted(p.value for p in missing))[:64], ctx=ctx,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "PERMISSION_DENIED", "message": "No tienes permiso para esta acción"},
            )
        return actor

    return _checker


def actor_permissions(actor: Actor) -> frozenset[Permission]:
    return permissions_for(actor.admin_roles)
