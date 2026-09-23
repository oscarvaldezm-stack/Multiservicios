import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import UserRole, pg_enum

if TYPE_CHECKING:
    from app.models.catalog import TechnicianService
    from app.models.kyc import AdminRoleAssignment, KycProfile


class User(TimestampMixin, Base):
    """
    Identidad y credenciales. Un solo registro por persona; el rol decide qué
    perfil (cliente o técnico) tiene asociado. Los datos del perfil viven en
    tablas separadas para no mezclar credenciales con datos de negocio.
    """

    __tablename__ = "users"
    __table_args__ = (
        # El email se guarda normalizado en minúsculas; esto lo garantiza en la BD.
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("failed_login_attempts >= 0", name="failed_attempts_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(pg_enum(UserRole, "user_role"), nullable=False, index=True)

    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(20))

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    is_email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    # Protección contra fuerza bruta
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Al incrementarlo se invalidan TODOS los access tokens emitidos
    # (cambio de contraseña, "cerrar sesión en todos los dispositivos", robo detectado).
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    client_profile: Mapped["ClientProfile | None"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    technician_profile: Mapped["TechnicianProfile | None"] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="TechnicianProfile.user_id",
    )
    admin_roles: Mapped[list["AdminRoleAssignment"]] = relationship(
        cascade="all, delete-orphan", foreign_keys="AdminRoleAssignment.user_id", lazy="selectin"
    )

    def __repr__(self) -> str:  # nunca incluir el hash en logs
        return f"<User id={self.id} role={self.role.value}>"


class ClientProfile(TimestampMixin, Base):
    __tablename__ = "client_profiles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    address_line: Mapped[str | None] = mapped_column(String(200))
    city: Mapped[str | None] = mapped_column(String(80))
    state: Mapped[str | None] = mapped_column(String(80))
    postal_code: Mapped[str | None] = mapped_column(String(10))
    latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))
    longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))

    user: Mapped[User] = relationship(back_populates="client_profile")


class TechnicianProfile(TimestampMixin, Base):
    __tablename__ = "technician_profiles"
    __table_args__ = (
        CheckConstraint("rating_avg >= 0 AND rating_avg <= 5", name="rating_avg_range"),
        CheckConstraint("rating_count >= 0", name="rating_count_non_negative"),
        CheckConstraint("jobs_completed >= 0", name="jobs_completed_non_negative"),
        CheckConstraint("years_experience >= 0 AND years_experience <= 70", name="years_experience_range"),
        CheckConstraint("coverage_radius_km > 0 AND coverage_radius_km <= 200", name="coverage_radius_range"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    bio: Mapped[str | None] = mapped_column(Text)
    years_experience: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("0"))

    # El estado de verificación vive en kyc_profiles.status (ver app/models/kyc.py).

    # Métricas públicas (calculadas por el sistema, nunca editables por el técnico)
    rating_avg: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False, server_default=text("0"))
    rating_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    jobs_completed: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    # Zona de servicio
    base_city: Mapped[str | None] = mapped_column(String(80))
    base_latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))
    base_longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))
    coverage_radius_km: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("15"))
    # Un trigger de PostgreSQL impide ponerlo en true si el KYC no está APPROVED,
    # y lo regresa a false cuando el KYC sale de APPROVED.
    is_available: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    # Referencia a la cuenta del proveedor de pagos (módulo de pagos). Nunca CLABE.
    payout_account_ref: Mapped[str | None] = mapped_column(String(120))

    user: Mapped[User] = relationship(back_populates="technician_profile", foreign_keys=[user_id])
    services: Mapped[list["TechnicianService"]] = relationship(
        back_populates="technician", cascade="all, delete-orphan"
    )
    kyc_profile: Mapped["KycProfile | None"] = relationship(
        back_populates="technician", uselist=False, foreign_keys="KycProfile.technician_id"
    )

    @property
    def kyc_status(self):
        return self.kyc_profile.status if self.kyc_profile else None
