"""
Encabezado Idempotency-Key en los POST de pagos (sección 8 del doc de pagos).

Evita que un doble clic o un reintento de red repitan una operación de dinero:
- Se guarda (usuario, endpoint, llave, hash del cuerpo) junto con la respuesta, en la MISMA
  transacción que la operación: o quedan las dos, o ninguna.
- La misma llave con el mismo cuerpo devuelve la respuesta guardada, sin repetir nada.
- La misma llave con OTRO cuerpo → 422 (la llave no se reutiliza para otra cosa).
- Dos peticiones simultáneas con la misma llave: la segunda espera en el índice único y,
  cuando la primera confirma, recibe su respuesta.
- Las llaves vencen a las 24 h (un trabajo del worker las borra).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import IdempotencyKey

TTL = timedelta(hours=24)
_KEY = re.compile(r"^[A-Za-z0-9_-]{8,100}$")


class IdempotencyError(DomainError):
    http_status = 422
    code = "IDEMPOTENCY_KEY_INVALID"


def request_hash(body: Any) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def run(db: Session, *, user_id: uuid.UUID, endpoint: str, key: str | None, body: Any,
        operation: Callable[[], dict[str, Any]], status_code: int = 200) -> tuple[int, dict[str, Any], bool]:
    """
    Ejecuta `operation` una sola vez por (usuario, endpoint, llave). Devuelve
    (código, cuerpo JSON, repetida). No hace commit: lo hace la ruta, junto con la operación.
    """
    if not key or not _KEY.fullmatch(key):
        raise IdempotencyError("Falta el encabezado Idempotency-Key (8 a 100 caracteres: letras, números, - y _)",
                               code="IDEMPOTENCY_KEY_REQUIRED" if not key else "IDEMPOTENCY_KEY_INVALID")
    digest = request_hash(body)
    now = datetime.now(timezone.utc)
    inserted = db.execute(
        insert(IdempotencyKey).values(key=key, user_id=user_id, endpoint=endpoint, request_hash=digest,
                                      expires_at=now + TTL)
        .on_conflict_do_nothing(constraint="uq_idempotency_keys_user_endpoint_key")
        .returning(IdempotencyKey.id)
    ).scalar_one_or_none()
    row = db.scalar(select(IdempotencyKey).where(IdempotencyKey.user_id == user_id,
                                                 IdempotencyKey.endpoint == endpoint, IdempotencyKey.key == key)
                    .with_for_update().execution_options(populate_existing=True))
    if inserted is None:
        if row.request_hash != digest:
            raise IdempotencyError("Esta Idempotency-Key ya se usó con otros datos", code="IDEMPOTENCY_KEY_REUSED")
        if row.response_code is None:                    # la otra petición falló y no se guardó nada
            raise IdempotencyError("Operación en curso con esta llave", code="IDEMPOTENCY_IN_PROGRESS",
                                   http_status=409)
        return row.response_code, row.response_body or {}, True
    body_out = operation()
    row.response_code, row.response_body = status_code, json.loads(json.dumps(body_out, default=str))
    db.flush()
    return status_code, body_out, False


def purge_expired(db: Session, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    return db.execute(delete(IdempotencyKey).where(IdempotencyKey.expires_at < now)).rowcount or 0
