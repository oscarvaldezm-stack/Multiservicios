"""
Schemas del módulo de pagos. Las entradas usan extra="forbid": ningún importe, estado ni id
de cuenta del proveedor puede venir del cliente. Las salidas no exponen ids del proveedor.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import PaymentAccountStatus


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmptyIn(_In):
    """Cuerpo vacío: cualquier campo (amount, status, account...) se rechaza con 422."""


class PaymentAccountOut(BaseModel):
    status: PaymentAccountStatus
    can_receive_payments: bool
    transfers_active: bool = False
    payouts_enabled: bool = False
    requirements_due: list[str] = []
    in_review: bool = False              # bloqueada por la plataforma (sin detallar el motivo al técnico)
    updated_at: datetime | None = None


class OnboardingLinkOut(BaseModel):
    url: str
    expires_at: datetime


class CardSetupOut(BaseModel):
    client_secret: str                   # para el componente oficial del proveedor; vence con el SetupIntent
    publishable_key: str | None


class SavedCardOut(BaseModel):
    id: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int


class NameReviewIn(_In):
    approve: bool
    note: str = Field(min_length=5, max_length=500)
