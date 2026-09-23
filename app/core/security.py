"""
Primitivas criptográficas: hashing de contraseñas (Passlib + bcrypt),
emisión/validación de JWT de acceso y generación de refresh tokens opacos.
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------
# deprecated="auto": si en el futuro subes los rounds o cambias de esquema,
# verify_and_update() devuelve un hash nuevo y se re-hashea al hacer login.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
    bcrypt__ident="2b",
)


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> tuple[bool, str | None]:
    """Devuelve (es_valida, hash_nuevo_si_hay_que_actualizar)."""
    return pwd_context.verify_and_update(plain_password, hashed_password)


def dummy_verify() -> None:
    """
    Gasta el mismo tiempo que una verificación real. Se llama cuando el email
    no existe para que el tiempo de respuesta no revele qué correos están
    registrados (enumeración de usuarios por timing).
    """
    pwd_context.dummy_verify()


# ---------------------------------------------------------------------------
# JWT de acceso (vida corta)
# ---------------------------------------------------------------------------
class TokenError(Exception):
    """Token inválido, expirado o manipulado."""


def create_access_token(*, user_id: uuid.UUID, role: str, token_version: int) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,          # informativo para el frontend; el backend usa el rol de la BD
        "ver": token_version,  # permite invalidar todos los tokens de un usuario
        "type": "access",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],  # lista fija: bloquea "alg: none" y confusión de algoritmos
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]},
            leeway=10,
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc

    if payload.get("type") != "access":
        raise TokenError("Tipo de token incorrecto")
    try:
        uuid.UUID(payload["sub"])
        int(payload["ver"])
    except (KeyError, ValueError, TypeError) as exc:
        raise TokenError("Claims inválidos") from exc
    return payload


# ---------------------------------------------------------------------------
# Refresh tokens (opacos, vida larga, rotados en cada uso)
# ---------------------------------------------------------------------------
def generate_refresh_token() -> str:
    """Token aleatorio de 384 bits. Se entrega al cliente UNA sola vez."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    """En la BD solo se guarda el SHA-256: si la BD se filtra, los tokens no sirven."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
