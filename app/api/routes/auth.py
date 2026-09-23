import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, DbSession
from app.core.actor import RequestContext
from app.reviews.signals import record as record_signals
from app.core.config import get_settings
from app.kyc.identity import create_kyc_profile
from app.core.security import (
    create_access_token,
    dummy_verify,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.models import (
    ClientProfile,
    RefreshToken,
    ServiceCategory,
    TechnicianProfile,
    TechnicianService,
    User,
    UserRole,
)
from app.schemas.auth import ClientRegister, RefreshRequest, TechnicianRegister, TokenPair, UserOut

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_LOGIN = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Correo o contraseña incorrectos",  # mensaje genérico: no revela si el correo existe
    headers={"WWW-Authenticate": "Bearer"},
)
_INVALID_REFRESH = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _issue_tokens(db: Session, user: User, request: Request, family_id: uuid.UUID | None = None) -> tuple[TokenPair, RefreshToken]:
    raw_refresh = generate_refresh_token()
    rt = RefreshToken(
        user_id=user.id,
        family_id=family_id or uuid.uuid4(),
        token_hash=hash_refresh_token(raw_refresh),
        expires_at=refresh_token_expiry(),
        created_ip=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(rt)
    pair = TokenPair(
        access_token=create_access_token(user_id=user.id, role=user.role.value, token_version=user.token_version),
        refresh_token=raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return pair, rt


def _create_user(db: Session, data: ClientRegister | TechnicianRegister, role: UserRole) -> User:
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        role=role,  # <- lo fija el servidor, jamás el cliente
        full_name=data.full_name,
        phone=data.phone,
    )
    db.add(user)
    return user


def _commit_new_user(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Nota: responder 409 permite saber si un correo ya existe. Cuando se
        # agregue verificación por email, conviene responder siempre 202 y
        # avisar por correo al dueño de la cuenta.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No se pudo completar el registro") from None


# ---------------------------------------------------------------------------
# Registro (rol determinado por la ruta)
# ---------------------------------------------------------------------------
@router.post("/register/client", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_client(data: ClientRegister, db: DbSession) -> User:
    user = _create_user(db, data, UserRole.CLIENT)
    user.client_profile = ClientProfile(city=data.city)
    _commit_new_user(db)
    return user


@router.post("/register/technician", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_technician(data: TechnicianRegister, request: Request, db: DbSession) -> User:
    category_ids = sorted(set(data.category_ids))
    if category_ids:
        found = db.scalars(
            select(ServiceCategory.id).where(
                ServiceCategory.id.in_(category_ids),  # IN parametrizado, no string armado a mano
                ServiceCategory.is_active.is_(True),
            )
        ).all()
        if len(found) != len(category_ids):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Categoría inválida")

    user = _create_user(db, data, UserRole.TECHNICIAN)
    user.technician_profile = TechnicianProfile(
        bio=data.bio,
        years_experience=data.years_experience,
        base_city=data.base_city,
        services=[TechnicianService(category_id=cid) for cid in category_ids],
    )
    try:
        db.flush()  # necesita el id del técnico para crear su expediente
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No se pudo completar el registro") from None
    # Todo técnico nace con su expediente KYC en NOT_STARTED y su propia llave de cifrado.
    create_kyc_profile(db, user.id, RequestContext(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    ))
    _commit_new_user(db)
    return user


# ---------------------------------------------------------------------------
# Login OAuth2 (password flow) -> access JWT + refresh opaco
# ---------------------------------------------------------------------------
@router.post("/token", response_model=TokenPair)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
) -> TokenPair:
    email = form.username.strip().lower()
    if len(email) > 254 or len(form.password.encode("utf-8")) > 72:
        dummy_verify()
        raise _INVALID_LOGIN

    # FOR UPDATE: evita que peticiones concurrentes se salten el contador de intentos.
    user = db.execute(select(User).where(User.email == email).with_for_update()).scalar_one_or_none()

    if user is None:
        dummy_verify()  # mismo tiempo de respuesta exista o no el usuario
        raise _INVALID_LOGIN

    now = _now()
    if user.locked_until and user.locked_until > now:
        dummy_verify()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.",
        )

    valid, new_hash = verify_password(form.password, user.hashed_password)
    if not valid:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
        db.commit()
        raise _INVALID_LOGIN

    if not user.is_active:
        db.rollback()
        raise _INVALID_LOGIN

    if new_hash:  # los parámetros de bcrypt cambiaron -> se actualiza el hash
        user.hashed_password = new_hash
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    pair, _ = _issue_tokens(db, user, request)
    # Señales antifraude (dispositivo / red), seudonimizadas.
    record_signals(db, user.id, RequestContext(ip=request.client.host if request.client else None,
                                               device_id=request.headers.get("x-device-id")))
    db.commit()
    return pair


# ---------------------------------------------------------------------------
# Refresh con rotación + detección de reuso
# ---------------------------------------------------------------------------
@router.post("/refresh", response_model=TokenPair)
def refresh_tokens(body: RefreshRequest, request: Request, db: DbSession) -> TokenPair:
    token_hash = hash_refresh_token(body.refresh_token)
    stored = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
    ).scalar_one_or_none()
    if stored is None:
        raise _INVALID_REFRESH

    now = _now()
    user = db.get(User, stored.user_id, with_for_update=True)

    if stored.revoked_at is not None:
        # ¡Reuso! Alguien usó un token que ya se había rotado: posible robo.
        # Se revoca toda la familia y se invalidan también los access tokens.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == stored.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        if user is not None:
            user.token_version += 1
        db.commit()
        raise _INVALID_REFRESH

    if stored.expires_at <= now or user is None or not user.is_active:
        raise _INVALID_REFRESH

    pair, new_rt = _issue_tokens(db, user, request, family_id=stored.family_id)
    db.flush()  # para obtener new_rt.id
    stored.revoked_at = now
    stored.replaced_by_id = new_rt.id
    db.commit()
    return pair


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, db: DbSession) -> None:
    """Cierra la sesión de ESTE dispositivo (revoca la familia del refresh token)."""
    stored = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(body.refresh_token))
    ).scalar_one_or_none()
    if stored is not None:
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == stored.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
        db.commit()
    # 204 siempre: no se revela si el token existía.


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(user: CurrentUser, db: DbSession) -> None:
    """Cierra sesión en todos los dispositivos: invalida access y refresh tokens."""
    user.token_version += 1
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    db.commit()
