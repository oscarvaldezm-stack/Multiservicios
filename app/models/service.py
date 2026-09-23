"""
Órdenes de servicio y pagos.

Flujo: REQUESTED → ACCEPTED → SCHEDULED → IN_PROGRESS → AWAITING_APPROVAL → COMPLETED
       → PAID → READY_FOR_REVIEW → REVIEWED   (más CANCELLED, FAILED, DISPUTED, REFUNDED)

La máquina de estados (app/orders/state_machine.py) es la única vía para cambiar
`status`; un trigger de PostgreSQL repite la tabla de transiciones permitidas y otro
impide que un técnico sin KYC aprobado quede asignado o avance una orden.
"""
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.catalog import ServiceCategory
from app.models.enums import ActorType, OrderStatus, PaymentStatus, pg_enum
from app.models.user import User


class ServiceOrder(TimestampMixin, Base):
    __tablename__ = "service_orders"
    __table_args__ = (
        CheckConstraint("agreed_price IS NULL OR agreed_price > 0", name="agreed_price_positive"),
        CheckConstraint("technician_id IS NULL OR technician_id <> client_id", name="client_is_not_technician"),
        CheckConstraint("requested_technician_id IS NULL OR requested_technician_id <> client_id",
                        name="client_is_not_requested_technician"),
        # Una solicitud abierta no tiene técnico; a partir de ACCEPTED siempre lo tiene.
        CheckConstraint(
            "(status = 'REQUESTED' AND technician_id IS NULL) OR status = 'CANCELLED' OR technician_id IS NOT NULL",
            name="technician_matches_status",
        ),
        CheckConstraint("status = 'REQUESTED' OR status = 'CANCELLED' OR agreed_price IS NOT NULL",
                        name="price_after_acceptance"),
        Index("ix_service_orders_open", "category_id", "created_at", postgresql_where=text("status = 'REQUESTED'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    technician_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    # Reserva directa a un técnico concreto: solo él puede aceptarla.
    requested_technician_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    category_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("service_categories.id", ondelete="RESTRICT"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    address_line: Mapped[str] = mapped_column(String(200), nullable=False)
    city: Mapped[str] = mapped_column(String(80), nullable=False)
    latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))
    longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))

    status: Mapped[OrderStatus] = mapped_column(
        pg_enum(OrderStatus, "order_status"), nullable=False, server_default=OrderStatus.REQUESTED.value, index=True,
    )
    agreed_price: Mapped[Decimal | None] = mapped_column(Numeric(10, 2))
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    work_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # aceptación del cliente
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disputed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_before_dispute: Mapped[OrderStatus | None] = mapped_column(pg_enum(OrderStatus, "order_status"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    client: Mapped[User] = relationship(foreign_keys=[client_id])
    technician: Mapped[User | None] = relationship(foreign_keys=[technician_id])
    category: Mapped[ServiceCategory] = relationship()
    payments: Mapped[list["Payment"]] = relationship(back_populates="order", order_by="Payment.created_at")


class OrderStatusHistory(Base):
    """Solo inserción (trigger). Una fila por transición; también sirve para medir cancelaciones."""

    __tablename__ = "order_status_history"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    order_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_orders.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    from_status: Mapped[OrderStatus | None] = mapped_column(pg_enum(OrderStatus, "order_status"))
    to_status: Mapped[OrderStatus] = mapped_column(pg_enum(OrderStatus, "order_status"), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_type: Mapped[ActorType] = mapped_column(pg_enum(ActorType, "actor_type"), nullable=False)
    # Técnico afectado (p. ej. el que se retiró de la orden): para métricas de reputación.
    technician_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    reason_code: Mapped[str | None] = mapped_column(String(40))
    note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Payment(TimestampMixin, Base):
    """
    Pago en custodia (escrow). El cobro lo hace el proveedor (Stripe); aquí solo se
    guardan referencias. Nunca números de tarjeta ni CVV (PCI-DSS). La huella del
    método de pago es la que entrega el proveedor (no revela la tarjeta) y sirve para
    detectar cuentas múltiples de una misma persona.
    """

    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("platform_fee >= 0 AND technician_payout >= 0", name="split_non_negative"),
        # La comisión + lo que recibe el técnico debe cuadrar exactamente con lo cobrado.
        CheckConstraint("platform_fee + technician_payout = amount", name="split_matches_amount"),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="currency_iso4217"),
        CheckConstraint("amount_refunded >= 0 AND amount_refunded <= amount", name="refund_within_amount"),
        # Un solo pago vivo por orden (si el técnico se retira, el pago anterior queda CANCELED
        # y al reasignarse se crea otro).
        Index("uq_payments_active_order", "service_order_id", unique=True,
              postgresql_where=text("status NOT IN ('CANCELED', 'FAILED')")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    service_order_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_orders.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    platform_fee: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    technician_payout: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    amount_refunded: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False, server_default=text("0"))
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default=text("'MXN'"))

    status: Mapped[PaymentStatus] = mapped_column(
        pg_enum(PaymentStatus, "payment_status"), nullable=False, server_default=PaymentStatus.PENDING.value,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_payment_id: Mapped[str | None] = mapped_column(String(120), unique=True)
    payment_method_fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    failure_code: Mapped[str | None] = mapped_column(String(60))
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refunded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    order: Mapped[ServiceOrder] = relationship(back_populates="payments")
