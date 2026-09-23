"""Quién ejecuta una acción y desde dónde. Se pasa explícito a toda operación auditable."""
from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field

from app.models.enums import ActorType, AdminRole, UserRole


def _normalize_ip(value: str | None) -> str | None:
    """Solo IPs válidas llegan a la columna INET; cualquier otra cosa se descarta."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


_DEVICE_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{8,128}$")


@dataclass(frozen=True)
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    # Identificador de instalación que manda la app (X-Device-Id). Solo se guarda seudonimizado.
    device_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip", _normalize_ip(self.ip))
        if self.device_id is not None and not _DEVICE_RE.match(self.device_id):
            object.__setattr__(self, "device_id", None)


@dataclass(frozen=True)
class Actor:
    user_id: uuid.UUID | None
    actor_type: ActorType
    admin_roles: frozenset[AdminRole] = field(default_factory=frozenset)

    @classmethod
    def system(cls) -> Actor:
        return cls(user_id=None, actor_type=ActorType.SYSTEM)

    @classmethod
    def from_user(cls, user) -> Actor:  # user: app.models.User
        if user.role == UserRole.ADMIN:
            roles = frozenset(a.role for a in user.admin_roles)
            return cls(user_id=user.id, actor_type=ActorType.ADMIN, admin_roles=roles)
        if user.role == UserRole.TECHNICIAN:
            return cls(user_id=user.id, actor_type=ActorType.TECHNICIAN)
        raise PermissionError("Los clientes no ejecutan acciones sobre expedientes KYC")

    @classmethod
    def of(cls, user) -> Actor:
        """Cualquier usuario (incluye clientes). Para órdenes y reseñas; el KYC usa from_user."""
        if user.role == UserRole.CLIENT:
            return cls(user_id=user.id, actor_type=ActorType.CLIENT)
        return cls.from_user(user)

    def has_role(self, role: AdminRole) -> bool:
        return role in self.admin_roles

    @property
    def roles_for_audit(self) -> list[str]:
        return sorted(r.value for r in self.admin_roles)
