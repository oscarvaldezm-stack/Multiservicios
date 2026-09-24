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


# ------------------------------------------------------------------ Fase 5: reembolsos, disputas, técnico
class RefundRequestIn(_In):
    """Solicitud del cliente. El monto es opcional (sin monto = lo que queda por reembolsar)."""

    reason_code: str = Field(pattern=r"^[A-Z_]{3,40}$")
    amount: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    note: str | None = Field(default=None, max_length=500)


class FinanceRefundIn(_In):
    reason_code: str = Field(pattern=r"^[A-Z_]{3,40}$")
    amount: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    note: str = Field(min_length=5, max_length=500)


class NoteIn(_In):
    note: str = Field(min_length=5, max_length=500)


class EvidenceIn(_In):
    note: str | None = Field(default=None, max_length=2000)


class RefundClientOut(BaseModel):
    """Lo que ve el cliente de su reembolso (sin el reparto interno)."""

    id: str
    status: str
    amount: Decimal
    reason_code: str
    created_at: datetime
    succeeded_at: datetime | None


class RefundFinanceOut(RefundClientOut):
    payment_id: str
    request_source: str
    reverse_transfer: bool
    refund_application_fee: bool
    technician_recovered: Decimal
    commission_returned: Decimal
    vat_returned: Decimal
    withholding_returned: Decimal
    platform_absorbed: Decimal
    needs_second_approval: bool
    failure_code: str | None


class DisputeOut(BaseModel):
    id: str
    payment_id: str
    amount: Decimal
    reason: str | None
    status: str
    evidence_due_by: datetime | None
    evidence_submitted_at: datetime | None
    technician_recovered: Decimal
    opened_at: datetime
    closed_at: datetime | None


class CancellationPolicyIn(_In):
    scenario: str = Field(pattern=r"^(CLIENT_LATE_CANCEL|CLIENT_CANCEL_ON_SITE)$")
    fee_type: str = Field(pattern=r"^(NONE|FIXED|PERCENT)$")
    fee_value: int = Field(ge=0, le=50_000_000)          # centavos (FIXED, sin IVA) o puntos base (PERCENT)
    technician_share_bp: int = Field(ge=0, le=10_000)


class CancellationPolicyOut(BaseModel):
    id: int
    scenario: str
    fee_type: str
    fee_value: int
    technician_share_bp: int
    platform_share_bp: int
    valid_from: datetime
    valid_to: datetime | None


class PayoutOut(BaseModel):
    id: str
    amount: Decimal
    currency: str
    status: str
    arrival_date: str | None
    failure_code: str | None
    created_at: datetime


class BalanceOut(BaseModel):
    available: Decimal
    pending: Decimal
    currency: str


class EarningOut(BaseModel):
    order_id: str
    status: str
    captured_at: datetime | None
    service_price: Decimal
    commission: Decimal
    commission_tax: Decimal
    withholding_isr: Decimal
    withholding_iva: Decimal
    net: Decimal
    adjustments: Decimal                  # lo que se le recuperó por reembolsos o contracargos perdidos
    net_after_adjustments: Decimal


class EarningsOut(BaseModel):
    items: list[EarningOut]
    total_net: Decimal
    total_adjustments: Decimal
    total_net_after_adjustments: Decimal
