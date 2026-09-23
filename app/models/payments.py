"""
Módulo de pagos (Fase 1): pagos en centavos, reglas de comisión, desglose congelado por
pago, libro contable de partida doble y las tablas que usarán las fases 2 a 6
(cuentas del técnico, reembolsos, disputas, depósitos, webhooks, idempotencia).

Reglas que se repiten en la base (migración 0006):
- Todo importe es BIGINT en centavos; nada de float ni de Numeric para dinero nuevo.
- Ninguna tabla tiene columnas para tarjeta, CVV, vencimiento ni CLABE: solo IDs del proveedor.
- Un solo pago SERVICE activo por orden (índice único parcial): evita el doble cobro.
- commission_transactions cuadra al centavo (CHECK) y no se modifica (trigger).
- ledger_entries es solo inserción y cada grupo de asientos suma cero (trigger diferido).
- Dos reglas de comisión del mismo alcance no pueden traslaparse en fechas (EXCLUDE).
"""
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import (
    CommissionScope,
    CommissionType,
    DisputeStatus,
    LedgerAccount,
    PaymentAccountStatus,
    PaymentKind,
    PaymentStatus,
    PaymentTransactionType,
    PayoutStatus,
    RefundStatus,
    WebhookEventStatus,
    pg_enum,
)


class TechnicianPaymentAccount(TimestampMixin, Base):
    """Cuenta conectada del técnico en el proveedor. La CLABE la guarda el proveedor, no nosotros."""

    __tablename__ = "technician_payment_accounts"
    __table_args__ = (
        UniqueConstraint("technician_id", "provider", name="uq_technician_payment_accounts_technician_provider"),
        CheckConstraint("status = 'NOT_CREATED' OR provider_account_id IS NOT NULL", name="account_id_when_created"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    technician_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_account_id: Mapped[str | None] = mapped_column(String(120), unique=True)
    status: Mapped[PaymentAccountStatus] = mapped_column(
        pg_enum(PaymentAccountStatus, "payment_account_status"), nullable=False,
        server_default=PaymentAccountStatus.NOT_CREATED.value,
    )
    transfers_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    payouts_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    requirements_due: Mapped[list[str] | None] = mapped_column(JSONB)
    name_matches_kyc: Mapped[bool | None] = mapped_column(Boolean)
    blocked_reason: Mapped[str | None] = mapped_column(String(60))


class PaymentCustomer(Base):
    """ID de cliente en el proveedor. Las tarjetas guardadas viven en el proveedor."""

    __tablename__ = "payment_customers"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(30), primary_key=True)
    provider_customer_id: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Payment(TimestampMixin, Base):
    """
    Un cobro al cliente. Con cargos de destino, el proveedor cobra, separa la comisión y
    transfiere el resto al técnico; aquí solo se guardan referencias e importes.
    El desglose (comisión, impuestos, parte del técnico) vive en commission_transactions.
    La huella del método de pago la entrega el proveedor (no revela la tarjeta) y sirve
    para detectar cuentas múltiples de una misma persona.
    """

    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        CheckConstraint("captured_cents >= 0 AND captured_cents <= amount_cents", name="captured_within_amount"),
        CheckConstraint("refunded_cents >= 0 AND refunded_cents <= captured_cents", name="refunded_within_captured"),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="currency_iso4217"),
        CheckConstraint("version >= 1", name="version_positive"),
        # Un solo pago SERVICE vivo por orden. Si el técnico se retira, el pago queda CANCELLED
        # y al reasignarse se crea otro.
        Index("uq_payments_active_service", "service_order_id", unique=True,
              postgresql_where=text("kind = 'SERVICE' AND status NOT IN ('CANCELLED', 'FAILED')")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    service_order_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_orders.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    payer_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    technician_account_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("technician_payment_accounts.id", ondelete="RESTRICT"), index=True
    )
    kind: Mapped[PaymentKind] = mapped_column(
        pg_enum(PaymentKind, "payment_kind"), nullable=False, server_default=PaymentKind.SERVICE.value
    )
    status: Mapped[PaymentStatus] = mapped_column(
        pg_enum(PaymentStatus, "payment_status"), nullable=False, server_default=PaymentStatus.PENDING.value,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_payment_id: Mapped[str | None] = mapped_column(String(120), unique=True)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default=text("'MXN'"))
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)       # lo que se cobra al cliente
    captured_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    refunded_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    payment_method_fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    failure_code: Mapped[str | None] = mapped_column(String(60))
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    capture_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # vence la autorización
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refunded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    order: Mapped["ServiceOrder"] = relationship(back_populates="payments")  # noqa: F821
    breakdown: Mapped["CommissionTransaction | None"] = relationship(back_populates="payment", uselist=False)


class PaymentTransaction(Base):
    """Solo inserción: el historial de lo que ocurrió en el proveedor para cada pago."""

    __tablename__ = "payment_transactions"
    __table_args__ = (
        UniqueConstraint("type", "provider_object_id", name="uq_payment_transactions_type_object"),
        CheckConstraint("amount_cents >= 0", name="amount_non_negative"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    payment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    type: Mapped[PaymentTransactionType] = mapped_column(
        pg_enum(PaymentTransactionType, "payment_transaction_type"), nullable=False
    )
    provider_object_id: Mapped[str | None] = mapped_column(String(120))
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(60))
    raw_status: Mapped[str | None] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CommissionRule(Base):
    """
    Regla de comisión. Se elige la primera vigente en la fecha de la cotización:
    PROMOTION → TECHNICIAN → CATEGORY → GLOBAL. Las reglas no se editan ni se borran:
    para cambiar una se cierra (valid_to) y se crea otra, así los pagos viejos conservan la suya.
    """

    __tablename__ = "commission_rules"
    __table_args__ = (
        CheckConstraint("rate_bp >= 0 AND rate_bp <= 10000", name="rate_bp_range"),
        CheckConstraint("fixed_cents >= 0", name="fixed_non_negative"),
        CheckConstraint("min_cents IS NULL OR min_cents >= 0", name="min_non_negative"),
        CheckConstraint("max_cents IS NULL OR max_cents >= coalesce(min_cents, 0)", name="max_at_least_min"),
        CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="valid_range"),
        CheckConstraint("(scope = 'GLOBAL') = (scope_ref IS NULL)", name="scope_ref_matches_scope"),
        CheckConstraint(
            "(type = 'PERCENT' AND fixed_cents = 0) OR (type = 'FIXED' AND rate_bp = 0) "
            "OR type = 'PERCENT_PLUS_FIXED'", name="type_matches_values"),
        # La restricción EXCLUDE (sin traslapes por alcance) se crea en la migración 0006.
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    scope: Mapped[CommissionScope] = mapped_column(pg_enum(CommissionScope, "commission_scope"), nullable=False)
    # GLOBAL: NULL · CATEGORY: id de categoría · TECHNICIAN: id del técnico · PROMOTION: código
    scope_ref: Mapped[str | None] = mapped_column(String(64))
    type: Mapped[CommissionType] = mapped_column(pg_enum(CommissionType, "commission_type"), nullable=False)
    rate_bp: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))   # 1500 = 15 %
    fixed_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    min_cents: Mapped[int | None] = mapped_column(BigInteger)
    max_cents: Mapped[int | None] = mapped_column(BigInteger)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(String(200))
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CommissionTransaction(Base):
    """
    Desglose congelado de un pago, con copia de la regla y de las tasas aplicadas.
    Invariante (CHECK): técnico + comisión + IVA de la comisión + retenciones = bruto − descuento.
    """

    __tablename__ = "commission_transactions"
    __table_args__ = (
        CheckConstraint(
            "price_cents > 0 AND service_tax_cents >= 0 AND discount_cents >= 0 AND commission_cents >= 0 "
            "AND commission_tax_cents >= 0 AND withholding_isr_cents >= 0 AND withholding_iva_cents >= 0 "
            "AND technician_cents >= 0", name="amounts_non_negative"),
        CheckConstraint("gross_cents = price_cents + service_tax_cents", name="gross_is_price_plus_tax"),
        CheckConstraint("discount_cents < gross_cents", name="discount_below_gross"),
        CheckConstraint(
            "technician_cents + commission_cents + commission_tax_cents + withholding_isr_cents "
            "+ withholding_iva_cents = gross_cents - discount_cents", name="split_adds_up"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    payment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    rule_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("commission_rules.id", ondelete="RESTRICT"))
    # Copia de la regla (LEGACY = pago anterior al motor de comisiones).
    rule_scope: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_type: Mapped[str | None] = mapped_column(String(20))
    rate_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    fixed_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    min_cents: Mapped[int | None] = mapped_column(BigInteger)
    max_cents: Mapped[int | None] = mapped_column(BigInteger)
    # Copia de las tasas fiscales vigentes (puntos base).
    service_tax_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    commission_tax_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    isr_withholding_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    iva_withholding_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    technician_has_rfc: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # Importes
    price_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)          # precio sin IVA
    service_tax_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    gross_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    discount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    commission_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    commission_tax_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    withholding_isr_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    withholding_iva_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    technician_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    payment: Mapped[Payment] = relationship(back_populates="breakdown")

    @property
    def application_fee_cents(self) -> int:
        """Lo que se queda la plataforma en un cargo de destino (comisión + IVA + retenciones)."""
        return self.commission_cents + self.commission_tax_cents + self.withholding_isr_cents \
            + self.withholding_iva_cents


class LedgerEntry(Base):
    """Libro de partida doble. Solo inserción; cada transaction_group_id suma cero."""

    __tablename__ = "ledger_entries"
    __table_args__ = (
        CheckConstraint("amount_cents <> 0", name="amount_not_zero"),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="currency_iso4217"),
        Index("ix_ledger_entries_account_created", "account", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    transaction_group_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    payment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    entry_type: Mapped[str] = mapped_column(String(40), nullable=False)       # CAPTURE, REFUND, ...
    account: Mapped[LedgerAccount] = mapped_column(pg_enum(LedgerAccount, "ledger_account"), nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)     # con signo
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default=text("'MXN'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PaymentRefund(TimestampMixin, Base):
    __tablename__ = "payment_refunds"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        CheckConstraint("technician_recovered_cents >= 0 AND commission_returned_cents >= 0",
                        name="split_non_negative"),
        # Stripe solo devuelve la comisión si también se revierte la transferencia.
        CheckConstraint("NOT refund_application_fee OR reverse_transfer", name="fee_refund_needs_reversal"),
        CheckConstraint("approved_by IS NULL OR approved_by <> requested_by", name="four_eyes"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    payment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    provider_refund_id: Mapped[str | None] = mapped_column(String(120), unique=True)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(40), nullable=False)
    reverse_transfer: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    refund_application_fee: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    technician_recovered_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    commission_returned_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    status: Mapped[RefundStatus] = mapped_column(
        pg_enum(RefundStatus, "refund_status"), nullable=False, server_default=RefundStatus.REQUESTED.value
    )
    failure_code: Mapped[str | None] = mapped_column(String(60))
    requested_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))


class PaymentDispute(TimestampMixin, Base):
    __tablename__ = "payment_disputes"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        Index("ix_payment_disputes_inbox", "status", "evidence_due_by"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    payment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    provider_dispute_id: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(60))
    status: Mapped[DisputeStatus] = mapped_column(
        pg_enum(DisputeStatus, "dispute_status"), nullable=False, server_default=DisputeStatus.NEEDS_RESPONSE.value
    )
    evidence_due_by: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)   # referencias a archivos privados
    transfer_reversal_id: Mapped[str | None] = mapped_column(String(120))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Payout(TimestampMixin, Base):
    """Depósitos del proveedor a la cuenta bancaria del técnico (webhooks payout.*)."""

    __tablename__ = "payouts"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="currency_iso4217"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    technician_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("technician_payment_accounts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    provider_payout_id: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default=text("'MXN'"))
    status: Mapped[PayoutStatus] = mapped_column(
        pg_enum(PayoutStatus, "payout_status"), nullable=False, server_default=PayoutStatus.PENDING.value
    )
    arrival_date: Mapped[date | None] = mapped_column(Date)
    failure_code: Mapped[str | None] = mapped_column(String(60))


class PaymentWebhookEvent(Base):
    """Bandeja de eventos del proveedor. El mismo evento no se procesa dos veces (UNIQUE)."""

    __tablename__ = "payment_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "provider_event_id", name="uq_payment_webhook_events_provider_event"),
        Index("ix_payment_webhook_events_pending", "next_attempt_at",
              postgresql_where=text("status IN ('PENDING', 'FAILED')")),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(120), nullable=False)
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(120))        # cuenta conectada (Connect)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[WebhookEventStatus] = mapped_column(
        pg_enum(WebhookEventStatus, "webhook_event_status"), nullable=False,
        server_default=WebhookEventStatus.PENDING.value,
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(String(500))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                      nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IdempotencyKey(Base):
    """Encabezado Idempotency-Key de los POST de pagos y reembolsos; se borran a las 24 h."""

    __tablename__ = "idempotency_keys"
    __table_args__ = (
        UniqueConstraint("user_id", "endpoint", "key", name="uq_idempotency_keys_user_endpoint_key"),
        Index("ix_idempotency_keys_expires_at", "expires_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    key: Mapped[str] = mapped_column(String(100), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(120), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CancellationPolicy(Base):
    """Políticas comerciales de cancelación que edita el administrador; el código solo las aplica."""

    __tablename__ = "cancellation_policies"
    __table_args__ = (
        CheckConstraint("fee_type IN ('NONE', 'FIXED', 'PERCENT')", name="fee_type_valid"),
        CheckConstraint("fee_value >= 0", name="fee_value_non_negative"),
        CheckConstraint("fee_type <> 'PERCENT' OR fee_value <= 10000", name="percent_fee_range"),
        CheckConstraint("technician_share_bp >= 0 AND platform_share_bp >= 0 "
                        "AND technician_share_bp + platform_share_bp = 10000", name="shares_add_up"),
        CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="valid_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(40), nullable=False)
    fee_type: Mapped[str] = mapped_column(String(10), nullable=False)
    fee_value: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))  # centavos o bp
    technician_share_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    platform_share_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
