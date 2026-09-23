"""
Contrato PaymentProvider (sección 3 del doc de pagos).

La lógica de negocio (comisiones, estados, reglas) NO importa nada de Stripe: habla con
esta interfaz, y cada proveedor es un adaptador que traduce sus objetos a los tipos propios
de este módulo. Agregar Mercado Pago = un adaptador nuevo, sin tocar tablas ni reglas.

Fase 2: cuentas conectadas del técnico, cliente del proveedor y guardado de tarjeta.
Las fases 3 a 5 agregan authorize / capture / cancel_authorization / refund / get_payment /
verify_webhook / payouts / disputes a este mismo contrato.
"""
from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime

from app.core.errors import DomainError


class ProviderError(DomainError):
    """Error del proveedor ya traducido: nunca lleva el mensaje crudo (puede traer datos personales)."""

    http_status = 502
    code = "PAYMENT_PROVIDER_ERROR"

    def __init__(self, message: str, code: str | None = None, http_status: int | None = None, *,
                 retryable: bool = False, provider_code: str | None = None):
        super().__init__(message, code=code, http_status=http_status,
                         extra={"retryable": retryable} if retryable else None)
        self.retryable = retryable
        self.provider_code = provider_code


@dataclass(frozen=True)
class Capabilities:
    """Lo que el adaptador soporta; PaymentService elige el flujo según esto, sin fingir funciones."""

    manual_capture: bool
    partial_fee_refund: bool
    connected_accounts: bool
    saved_cards: bool


@dataclass(frozen=True)
class AccountPrefill:
    """Datos del expediente KYC que se precargan para que el técnico no los capture dos veces."""

    technician_id: uuid.UUID
    email: str
    first_names: str
    last_names: str
    birth_date: date | None = None
    phone: str | None = None                  # solo en formato E.164 (+52...)
    address_line1: str | None = None
    address_line2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None


@dataclass(frozen=True)
class AccountStatusInfo:
    provider_account_id: str
    transfers_active: bool
    payouts_enabled: bool
    details_submitted: bool
    requirements_due: tuple[str, ...] = ()
    disabled_reason: str | None = None
    # Nombre legal que tiene el proveedor (None si no lo expone para este tipo de cuenta).
    legal_first_name: str | None = None
    legal_last_name: str | None = None


@dataclass(frozen=True)
class OnboardingLink:
    url: str
    expires_at: datetime


@dataclass(frozen=True)
class SetupIntentInfo:
    provider_id: str
    client_secret: str = field(repr=False)     # nunca en logs


@dataclass(frozen=True)
class SavedCard:
    provider_id: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int


class PaymentProvider(abc.ABC):
    name: str
    capabilities: Capabilities

    # ---------------------------------------------------------------- cuenta del técnico
    @abc.abstractmethod
    def create_connected_account(self, prefill: AccountPrefill) -> str:
        """Crea la cuenta que recibirá las transferencias; devuelve su id en el proveedor. Idempotente por técnico."""

    @abc.abstractmethod
    def create_onboarding_link(self, provider_account_id: str) -> OnboardingLink:
        """URL de un solo uso para que el técnico complete sus datos (CLABE incluida) con el proveedor."""

    @abc.abstractmethod
    def get_account_status(self, provider_account_id: str) -> AccountStatusInfo:
        """Estado actual en el proveedor (fuente de verdad: nunca lo que diga la app)."""

    # ---------------------------------------------------------------- cliente y tarjetas
    @abc.abstractmethod
    def create_customer(self, user_id: uuid.UUID, email: str, name: str) -> str:
        """Cliente en el proveedor; devuelve su id. Idempotente por usuario."""

    @abc.abstractmethod
    def create_setup_intent(self, provider_customer_id: str, user_id: uuid.UUID) -> SetupIntentInfo:
        """Prepara el guardado de una tarjeta; la tarjeta viaja de la app al proveedor, nunca a nosotros."""

    @abc.abstractmethod
    def list_saved_cards(self, provider_customer_id: str) -> list[SavedCard]:
        """Tarjetas guardadas (solo marca, últimos 4 y vencimiento)."""
