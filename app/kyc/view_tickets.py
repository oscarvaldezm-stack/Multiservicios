"""
Tickets de visualización: acceso temporal a UN archivo, de UN solo uso, ligado a UN usuario.

Para qué: un <img src="..."> del panel no puede mandar el encabezado Authorization, y
poner el JWT en la URL lo filtraría a logs e historial. El ticket vive segundos, se
invalida al primer uso y, al canjearse, se vuelven a verificar los permisos.

Por qué no una URL prefirmada de S3: los objetos están cifrados por la aplicación; una URL
prefirmada solo entregaría texto cifrado. Ver un documento siempre pasa por la API.

Formato: base64url( jti[16 bytes] + HMAC-SHA256(jti)[16 bytes] ). Los datos (archivo,
usuario, vencimiento) viven en la base; el token solo prueba que lo emitimos nosotros.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import FileViewTicket


def _mac_key() -> bytes:
    secret = get_settings().JWT_SECRET_KEY.get_secret_value().encode()
    return hmac.new(secret, b"kyc-file-view-ticket-v1", hashlib.sha256).digest()


def _mac(jti: uuid.UUID) -> bytes:
    return hmac.new(_mac_key(), jti.bytes, hashlib.sha256).digest()[:16]


def issue(db: Session, user_id: uuid.UUID, file_id: uuid.UUID) -> tuple[str, datetime]:
    ttl = get_settings().KYC_VIEW_TICKET_TTL_SECONDS
    jti = uuid.uuid4()
    expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    db.add(FileViewTicket(jti=jti, file_id=file_id, user_id=user_id, expires_at=expires))
    db.flush()
    token = base64.urlsafe_b64encode(jti.bytes + _mac(jti)).decode().rstrip("=")
    return token, expires


def redeem(db: Session, token: str) -> tuple[uuid.UUID, uuid.UUID] | None:
    """Devuelve (user_id, file_id) si el ticket es auténtico, vigente y no usado; lo marca usado."""
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    jti = uuid.UUID(bytes=raw[:16])
    if not hmac.compare_digest(raw[16:], _mac(jti)):
        return None
    # Canje atómico: dos peticiones simultáneas con el mismo ticket, solo una gana.
    row = db.execute(text(
        "UPDATE file_view_tickets SET used_at = now() "
        "WHERE jti = :j AND used_at IS NULL AND expires_at > now() RETURNING user_id, file_id"
    ), {"j": jti}).first()
    return (row.user_id, row.file_id) if row else None


def purge_expired(db: Session) -> int:
    return db.execute(text("DELETE FROM file_view_tickets WHERE expires_at < now() - interval '1 day'")).rowcount
