"""
Contrato PaymentProvider (sección 3 del doc de pagos).

La lógica de negocio (comisiones, estados, reglas) NO importa nada de Stripe: habla con
esta interfaz, y cada proveedor es un adaptador que traduce sus objetos a los tipos propios
de este módulo. Agregar Mercado Pago = un adaptador nuevo, sin tocar tablas ni reglas.

Fase 2: cuentas conectadas del técnico, cliente del proveedor y guardado de tarjeta.
Fase 3: autorizar (captura manual con cargo de destino), capturar, anular y consultar un cobro.
Fase 4: verificar webhooks, consultar depósitos al técnico y listar cobros para la conciliación.
Fase 5: reembolsos (quién los absorbe), captura parcial con su comisión, contracargos (consulta,
evidencia), reversión de la transferencia al técnico y saldo de su cuenta.
"""
from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime

from app.core.errors import DomainError
from app.models.enums import PaymentStatus


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


@dataclass(frozen=True)
class AuthorizationRequest:
    """Todo lo calcula el backend: monto, comisión y cuenta destino nunca vienen de la app."""

    payment_id: uuid.UUID
    order_id: uuid.UUID
    amount_cents: int
    currency: str
    customer_id: str
    payment_method_id: str
    destination_account_id: str        # cuenta conectada del técnico (transfer_data[destination])
    application_fee_cents: int         # comisión + IVA + retenciones: lo que se queda la plataforma


@dataclass(frozen=True)
class ProviderPayment:
    """Estado de un cobro en el proveedor, ya traducido a los estados propios."""

    provider_payment_id: str | None
    status: PaymentStatus
    amount_cents: int = 0
    amount_capturable_cents: int = 0
    amount_received_cents: int = 0
    failure_code: str | None = None
    payment_method_fingerprint: str | None = None
    client_secret: str | None = field(default=None, repr=False)   # solo para que el dueño complete 3D Secure
    metadata_payment_id: str | None = None      # nuestro id de pago, guardado en el cobro al autorizar


@dataclass(frozen=True)
class WebhookEvent:
    """
    Evento ya verificado y reducido a lo mínimo. No se guarda el objeto completo (puede traer
    correos, nombres o datos de facturación): el worker vuelve a consultar el objeto al proveedor.
    """

    provider_event_id: str
    type: str
    object_id: str | None
    object_type: str | None
    account_id: str | None          # cuenta conectada (eventos de Connect)
    livemode: bool
    created: int


@dataclass(frozen=True)
class PayoutInfo:
    provider_payout_id: str
    amount_cents: int
    currency: str
    status: str                     # pending, in_transit, paid, failed, canceled
    arrival_date: date | None = None
    failure_code: str | None = None


@dataclass(frozen=True)
class RefundRequest:
    refund_id: uuid.UUID               # nuestro id: Idempotency-Key refund:{id}
    provider_payment_id: str
    amount_cents: int
    reverse_transfer: bool             # recuperar del técnico la parte proporcional de lo transferido
    refund_application_fee: bool       # devolver la parte proporcional de la comisión (exige reverse_transfer)
    duplicate: bool = False


@dataclass(frozen=True)
class RefundInfo:
    provider_refund_id: str
    provider_payment_id: str | None
    amount_cents: int
    status: str                        # pending, succeeded, failed, canceled, requires_action
    failure_reason: str | None = None
    transfer_reversed: bool = False
    metadata_refund_id: str | None = None


@dataclass(frozen=True)
class DisputeInfo:
    provider_dispute_id: str
    provider_payment_id: str | None
    amount_cents: int
    reason: str | None
    status: str                        # warning_needs_response, needs_response, under_review, won, lost...
    evidence_due_by: datetime | None = None


@dataclass(frozen=True)
class BalanceInfo:
    available_cents: int
    pending_cents: int
    currency: str


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

    # ---------------------------------------------------------------- cobros (Fase 3)
    @abc.abstractmethod
    def authorize(self, req: AuthorizationRequest) -> ProviderPayment:
        """
        Reserva el monto en la tarjeta guardada, sin el cliente presente, con su división.
        Idempotente por pago. Un rechazo NO es excepción: vuelve con status FAILED y su código;
        si el banco pide autenticación, vuelve REQUIRES_ACTION con el client_secret.
        """

    @abc.abstractmethod
    def capture(self, provider_payment_id: str, payment_id: uuid.UUID, amount_cents: int,
                application_fee_cents: int | None = None) -> ProviderPayment:
        """
        Cobra lo autorizado (idempotente por pago: nunca dos capturas). En una captura parcial se
        manda la comisión recalculada sobre lo capturado; el resto de la reserva se libera solo.
        """

    @abc.abstractmethod
    def cancel_authorization(self, provider_payment_id: str, payment_id: uuid.UUID) -> ProviderPayment:
        """Libera la reserva (idempotente)."""

    @abc.abstractmethod
    def get_payment(self, provider_payment_id: str) -> ProviderPayment:
        """Estado real del cobro en el proveedor (fuente de verdad)."""

    # ---------------------------------------------------------------- webhooks y conciliación (Fase 4)
    @abc.abstractmethod
    def verify_webhook(self, payload: bytes, signature: str | None, endpoint: str) -> WebhookEvent:
        """
        Verifica la firma sobre el cuerpo CRUDO con el secreto de ese endpoint ("platform" o "connect")
        y una tolerancia de 5 minutos (bloquea replays). Firma inválida → ProviderError WEBHOOK_SIGNATURE_INVALID.
        """

    @abc.abstractmethod
    def get_payout(self, provider_account_id: str, provider_payout_id: str) -> PayoutInfo:
        """Depósito de una cuenta conectada al banco del técnico."""

    @abc.abstractmethod
    def list_payments(self, created_from: datetime, created_to: datetime) -> list[ProviderPayment]:
        """Cobros creados en el periodo (para detectar los que existen solo en el proveedor)."""

    # ---------------------------------------------------------------- reembolsos, disputas y saldo (Fase 5)
    @abc.abstractmethod
    def refund(self, req: RefundRequest) -> RefundInfo:
        """Reembolso total o parcial. Idempotente por reembolso (refund:{id})."""

    @abc.abstractmethod
    def get_refund(self, provider_refund_id: str) -> RefundInfo:
        """Estado real de un reembolso."""

    @abc.abstractmethod
    def get_dispute(self, provider_dispute_id: str) -> DisputeInfo:
        """Estado real de un contracargo."""

    @abc.abstractmethod
    def submit_dispute_evidence(self, provider_dispute_id: str, evidence: dict[str, str]) -> DisputeInfo:
        """Envía el expediente de evidencia (texto; los archivos van por referencia)."""

    @abc.abstractmethod
    def reverse_transfer(self, provider_payment_id: str, amount_cents: int, key: str) -> str:
        """Recupera de la cuenta del técnico parte de lo transferido. Idempotente por `key`."""

    @abc.abstractmethod
    def get_balance(self, provider_account_id: str) -> BalanceInfo:
        """Saldo disponible y pendiente de la cuenta conectada del técnico."""
