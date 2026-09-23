"""
Escritor de auditoría con cadena de hashes.

Cada fila guarda `prev_hash` (el `row_hash` de la fila anterior) y su propio `row_hash`
= SHA-256 del contenido canónico + prev_hash. Si alguien modifica o borra una fila
(por ejemplo con acceso directo a la base, saltándose los triggers), verify_chain()
lo detecta. Un advisory lock serializa las escrituras para que la cadena no se bifurque.

Regla: nunca pasar aquí contraseñas, tokens ni identificadores completos
(usar app.core.crypto.mask_identifier).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.actor import Actor, RequestContext
from app.models.enums import AuditResult
from app.models.kyc import AuditLog

_AUDIT_CHAIN_LOCK = 0x4B59_4341  # "KYCA": clave del advisory lock de la cadena

_FORBIDDEN_KEYS = {"password", "hashed_password", "token", "access_token", "refresh_token",
                   "curp", "rfc", "document_number", "secret"}


def _check_changes(changes: dict[str, Any] | None) -> None:
    if not changes:
        return
    stack = [changes]
    while stack:
        cur = stack.pop()
        for k, v in cur.items():
            if k.lower() in _FORBIDDEN_KEYS:
                raise ValueError(f"El campo '{k}' no puede registrarse en auditoría; usa una versión enmascarada")
            if isinstance(v, dict):
                stack.append(v)


def _canonical(row: dict[str, Any]) -> bytes:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _hash_fields(entry: AuditLog) -> dict[str, Any]:
    def s(v):  # normaliza UUID / IP / enums a texto
        return None if v is None else str(getattr(v, "value", v))

    return {
        "occurred_at": entry.occurred_at.astimezone(timezone.utc).isoformat(),
        "actor_id": s(entry.actor_id),
        "actor_type": s(entry.actor_type),
        "actor_roles": entry.actor_roles,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "technician_id": s(entry.technician_id),
        "kyc_profile_id": s(entry.kyc_profile_id),
        "document_id": s(entry.document_id),
        "result": s(entry.result),
        "reason_code": entry.reason_code,
        "reason_note": entry.reason_note,
        "changes": entry.changes,
        "ip": s(entry.ip),
        "user_agent": entry.user_agent,
        "request_id": entry.request_id,
        "prev_hash": entry.prev_hash,
    }


def compute_row_hash(entry: AuditLog) -> str:
    return hashlib.sha256(_canonical(_hash_fields(entry))).hexdigest()


def write_audit(
    db: Session,
    *,
    action: str,
    actor: Actor,
    result: AuditResult = AuditResult.SUCCESS,
    technician_id: uuid.UUID | None = None,
    kyc_profile_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    reason_code: str | None = None,
    reason_note: str | None = None,
    changes: dict[str, Any] | None = None,
    ctx: RequestContext | None = None,
) -> AuditLog:
    """Escribe en la transacción actual: si la operación hace rollback, la auditoría también."""
    _check_changes(changes)
    ctx = ctx or RequestContext()
    db.execute(select(func.pg_advisory_xact_lock(_AUDIT_CHAIN_LOCK)))
    prev_hash = db.scalar(select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1))

    entry = AuditLog(
        occurred_at=datetime.now(timezone.utc),
        actor_id=actor.user_id,
        actor_type=actor.actor_type,
        actor_roles=actor.roles_for_audit or None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        technician_id=technician_id,
        kyc_profile_id=kyc_profile_id,
        document_id=document_id,
        result=result,
        reason_code=reason_code,
        reason_note=reason_note,
        changes=changes,
        ip=ctx.ip,
        user_agent=(ctx.user_agent or "")[:255] or None,
        request_id=ctx.request_id,
        prev_hash=prev_hash,
    )
    entry.row_hash = compute_row_hash(entry)
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session, batch_size: int = 1000) -> list[int]:
    """Recalcula la cadena completa. Devuelve los IDs donde se rompe (lista vacía = íntegra)."""
    broken: list[int] = []
    prev: str | None = None
    last_id = 0
    while True:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.id > last_id).order_by(AuditLog.id).limit(batch_size)
        ).all()
        if not rows:
            return broken
        for row in rows:
            if row.prev_hash != prev or compute_row_hash(row) != row.row_hash:
                broken.append(row.id)
            prev = row.row_hash
            last_id = row.id


def write_audit_detached(**kwargs: Any) -> None:
    """
    Escribe un registro en una transacción PROPIA y la confirma de inmediato.

    Se usa para intentos denegados (IDOR, permisos insuficientes, regla crítica): la
    petición que los provoca termina en error y hace rollback, y sin esto el intento
    desaparecería. Nunca lanza: si la auditoría falla, se registra en el log de
    seguridad y la respuesta al usuario no cambia.
    """
    import logging

    from app.db.session import SessionLocal

    try:
        with SessionLocal() as s:
            # Si la transacción principal de la misma petición ya tiene el candado de la
            # cadena, esperar sería un interbloqueo: se limita la espera y se registra el fallo.
            s.execute(text("SET LOCAL lock_timeout = '3s'"))
            write_audit(s, **kwargs)
            s.commit()
    except Exception:  # noqa: BLE001
        logging.getLogger("security").exception("No se pudo escribir auditoría de acceso denegado: %s",
                                                kwargs.get("action"))
