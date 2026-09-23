"""
Schemas del módulo de pagos. Las entradas usan extra="forbid": ningún importe, estado ni id
de cuenta del proveedor puede venir del cliente. Las salidas no exponen ids del proveedor.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import PaymentAccountStatus, PaymentStatus


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


# ------------------------------------------------------------------ Fase 3: pago de una orden
class PaymentMethodIn(_In):
    """Solo el id de una tarjeta guardada del propio cliente. Nunca un monto."""

    payment_method_id: str = Field(pattern=r"^pm_[A-Za-z0-9_]{3,100}$")


class OrderPaymentClientOut(BaseModel):
    """Lo que ve el cliente: el total y el desglose del servicio, no la división interna."""

    status: PaymentStatus
    currency: str
    total: Decimal
    service_price: Decimal
    service_tax: Decimal
    discount: Decimal
    payment_method_selected: bool
    authorized_at: datetime | None
    captured_at: datetime | None
    refunded: Decimal
    client_secret: str | None = None      # solo en REQUIRES_ACTION, para completar 3D Secure en la app


class OrderPaymentTechnicianOut(BaseModel):
    """Lo que ve el técnico: cuánto recibe y por qué (comisión y retenciones)."""

    status: PaymentStatus
    currency: str
    service_price: Decimal
    commission: Decimal
    commission_tax: Decimal
    withholding_isr: Decimal
    withholding_iva: Decimal
    net: Decimal
    authorized_at: datetime | None
    captured_at: datetime | None
    capture_deadline: datetime | None


class DepartOut(BaseModel):
    order_id: str
    payment_status: PaymentStatus
    can_start: bool
    failure_code: str | None = None
