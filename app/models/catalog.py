import uuid
from decimal import Decimal

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, Numeric, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.user import TechnicianProfile


class ServiceCategory(TimestampMixin, Base):
    """Plomería, Electricidad, Carpintería, Aire acondicionado..."""

    __tablename__ = "service_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    # La comisión ya no vive aquí: la definen las reglas de commission_rules (alcance CATEGORY).


class TechnicianService(TimestampMixin, Base):
    """Qué categorías ofrece cada técnico y su tarifa base (N:M con datos extra)."""

    __tablename__ = "technician_services"
    __table_args__ = (
        CheckConstraint("base_rate IS NULL OR base_rate >= 0", name="base_rate_non_negative"),
    )

    technician_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("technician_profiles.user_id", ondelete="CASCADE"), primary_key=True
    )
    category_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("service_categories.id", ondelete="RESTRICT"), primary_key=True
    )
    base_rate: Mapped[Decimal | None] = mapped_column(Numeric(10, 2))  # MXN por visita/hora

    technician: Mapped[TechnicianProfile] = relationship(back_populates="services")
    category: Mapped[ServiceCategory] = relationship()
