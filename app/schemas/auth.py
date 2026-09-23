"""
Esquemas Pydantic = la frontera de validación. Todo lo que entra se valida
aquí antes de tocar la BD.

REGLA CLAVE contra escalada de privilegios (mass assignment):
- Los esquemas de registro usan extra="forbid" y NO tienen campo `role`.
  El rol lo decide el endpoint (/register/client o /register/technician),
  nunca el cuerpo de la petición. Un admin jamás se crea por la API pública.
"""
import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.enums import KycStatus, UserRole

_PHONE_RE = re.compile(r"^\+?[0-9]{10,15}$")


class _StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _validate_password_strength(v: str) -> str:
    # bcrypt solo usa los primeros 72 BYTES; más allá se truncaría en silencio.
    if len(v.encode("utf-8")) > 72:
        raise ValueError("La contraseña no puede exceder 72 bytes")
    if len(v) < 10:
        raise ValueError("La contraseña debe tener al menos 10 caracteres")
    checks = [r"[a-z]", r"[A-Z]", r"[0-9]"]
    if not all(re.search(p, v) for p in checks):
        raise ValueError("La contraseña debe incluir mayúsculas, minúsculas y números")
    return v


class _RegisterBase(_StrictInput):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)
    full_name: str = Field(min_length=2, max_length=120)
    phone: str | None = Field(default=None, max_length=20)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.replace(" ", "").replace("-", "")
        if not _PHONE_RE.fullmatch(v):
            raise ValueError("Teléfono inválido (10 a 15 dígitos, opcionalmente con +)")
        return v


class ClientRegister(_RegisterBase):
    city: str | None = Field(default=None, max_length=80)


class TechnicianRegister(_RegisterBase):
    bio: str | None = Field(default=None, max_length=2000)
    years_experience: int = Field(default=0, ge=0, le=70)
    base_city: str | None = Field(default=None, max_length=80)
    category_ids: list[int] = Field(default_factory=list, max_length=20)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos de vida del access token


class RefreshRequest(_StrictInput):
    refresh_token: str = Field(min_length=20, max_length=200)


class UserOut(BaseModel):
    """Salida pública: NUNCA incluye hashed_password, token_version, etc."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    phone: str | None
    role: UserRole
    is_active: bool
    is_email_verified: bool
    created_at: datetime


class ClientProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    address_line: str | None
    city: str | None
    state: str | None
    postal_code: str | None


class TechnicianProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bio: str | None
    years_experience: int
    kyc_status: KycStatus | None
    rating_avg: float
    rating_count: int
    jobs_completed: int
    base_city: str | None
    coverage_radius_km: int
    is_available: bool


class TechnicianProfileUpdate(_StrictInput):
    """
    Lo que un técnico puede editar de sí mismo. Nótese lo que NO está:
    kyc_status, rating_avg, jobs_completed -> extra="forbid" los rechaza.
    """

    bio: str | None = Field(default=None, max_length=2000)
    years_experience: int | None = Field(default=None, ge=0, le=70)
    base_city: str | None = Field(default=None, max_length=80)
    coverage_radius_km: int | None = Field(default=None, gt=0, le=200)
    is_available: bool | None = None

