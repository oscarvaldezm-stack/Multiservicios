"""
Señales de dispositivo e IP para antifraude, seudonimizadas.

Se guarda HMAC(INTEGRITY_KEY, tipo + valor): permite saber si dos cuentas comparten
dispositivo o red sin almacenar la IP ni el identificador en claro (minimización de
datos, LFPDPPP). Se registran al iniciar sesión, al crear/aceptar órdenes y al calificar.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, aliased

from app.core.actor import RequestContext
from app.core.config import get_settings
from app.models import SignalKind, UserSignal


@lru_cache
def _signal_key() -> bytes:
    raw = get_settings().INTEGRITY_KEY.get_secret_value()
    master = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    return hmac.new(master, b"user-signal-v1", hashlib.sha256).digest()


def _network(ip: str) -> str:
    """IPv4 exacta; IPv6 por prefijo /64 (una casa suele rotar la parte baja)."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return ip


def signal_hash(kind: SignalKind, value: str) -> str:
    return hmac.new(_signal_key(), f"{kind.value}:{value}".encode(), hashlib.sha256).hexdigest()


def record(db: Session, user_id: uuid.UUID, ctx: RequestContext | None) -> None:
    if ctx is None:
        return
    values = []
    if ctx.ip:
        values.append((SignalKind.IP, signal_hash(SignalKind.IP, _network(ctx.ip))))
    if ctx.device_id:
        values.append((SignalKind.DEVICE, signal_hash(SignalKind.DEVICE, ctx.device_id)))
    for kind, h in values:
        stmt = insert(UserSignal).values(user_id=user_id, kind=kind, value_hash=h)
        db.execute(stmt.on_conflict_do_update(
            index_elements=["user_id", "kind", "value_hash"],
            set_={"last_seen": func.now(), "hits": UserSignal.hits + 1},
        ))


def shared_signals(db: Session, user_a: uuid.UUID, user_b: uuid.UUID, *, ip_days: int = 30) -> set[SignalKind]:
    """Qué tipos de señal comparten dos usuarios (IP solo si ambas se vieron en los últimos días)."""
    a, b = aliased(UserSignal), aliased(UserSignal)
    since = datetime.now(timezone.utc) - timedelta(days=ip_days)
    rows = db.execute(
        select(a.kind).join(b, (a.kind == b.kind) & (a.value_hash == b.value_hash))
        .where(a.user_id == user_a, b.user_id == user_b)
        .where((a.kind == SignalKind.DEVICE) | ((a.last_seen >= since) & (b.last_seen >= since)))
        .distinct()
    ).scalars().all()
    return set(rows)
