"""
Modelo de datos del KYC de técnicos.

Principios:
- PostgreSQL guarda metadatos y llaves de objeto; los archivos viven en un bucket privado.
- CURP, RFC y números de documento: cifrados (BYTEA) + índice ciego HMAC (CHAR 64).
- Historial y auditoría son solo-inserción (triggers en la migración 0002).
- Las transiciones de estado solo ocurren por app.kyc.state_machine.transition(),
  y un trigger rechaza cualquier par no permitido aunque se use SQL directo.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

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
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import (
    ActorType,
    AdminRole,
    AuditResult,
    DocumentCategory,
    DocumentDecision,
    DocumentSide,
    KeyPurpose,
    KeyStatus,
    KycDocumentStatus,
    KycStatus,
    ReasonScope,
    RetentionAction,
    ReviewDecision,
    ScanStatus,
    pg_enum,
)

if TYPE_CHECKING:
    from app.models.user import TechnicianProfile

HASH_LEN = 64  # SHA-256 / HMAC-SHA256 en hex
MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_MIME = ("image/jpeg", "image/png", "application/pdf")


# =============================================================================
# Catálogos geográficos (INEGI / SEPOMEX)
# =============================================================================
class Country(Base):
    __tablename__ = "countries"

    code: Mapped[str] = mapped_column(String(2), primary_key=True)  # ISO 3166-1 alfa-2
    name: Mapped[str] = mapped_column(String(80), nullable=False)


class MxState(Base):
    __tablename__ = "mx_states"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)  # clave INEGI 1-32
    curp_code: Mapped[str] = mapped_column(String(2), unique=True, nullable=False)       # 'NL', 'DF'...
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)


class MxMunicipality(Base):
    __tablename__ = "mx_municipalities"
    __table_args__ = (UniqueConstraint("state_id", "inegi_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    state_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("mx_states.id"), nullable=False, index=True)
    inegi_code: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # clave municipal dentro del estado
    name: Mapped[str] = mapped_column(String(120), nullable=False)


class MxPostalSettlement(Base):
    """Asentamiento (colonia) del catálogo SEPOMEX. Se carga con scripts/load_sepomex.py."""

    __tablename__ = "mx_postal_settlements"
    __table_args__ = (
        UniqueConstraint("postal_code", "municipality_id", "sepomex_id"),
        CheckConstraint("postal_code ~ '^[0-9]{5}$'", name="postal_code_format"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    postal_code: Mapped[str] = mapped_column(String(5), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    settlement_type: Mapped[str] = mapped_column(String(60), nullable=False)
    municipality_id: Mapped[int] = mapped_column(Integer, ForeignKey("mx_municipalities.id"), nullable=False)
    city: Mapped[str | None] = mapped_column(String(120))
    sepomex_id: Mapped[int] = mapped_column(Integer, nullable=False)  # id_asenta_cpcons


# =============================================================================
# Catálogos de negocio
# =============================================================================
class DocumentType(Base):
    __tablename__ = "document_types"
    __table_args__ = (
        CheckConstraint("max_files BETWEEN 1 AND 5", name="max_files_range"),
        CheckConstraint("sides_required BETWEEN 1 AND max_files", name="sides_within_max"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[DocumentCategory] = mapped_column(pg_enum(DocumentCategory, "document_category"), nullable=False)
    sides_required: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("1"))
    max_files: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("1"))
    requires_number: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    requires_issue_date: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    requires_expiry: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    max_age_days: Mapped[int | None] = mapped_column(SmallInteger)  # antigüedad máxima (comprobantes)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sort_order: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("0"))


class RejectionReason(Base):
    __tablename__ = "rejection_reasons"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[ReasonScope] = mapped_column(pg_enum(ReasonScope, "reason_scope"), nullable=False)
    requires_note: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


# =============================================================================
# Expediente
# =============================================================================
class KycProfile(TimestampMixin, Base):
    __tablename__ = "kyc_profiles"
    __table_args__ = (
        CheckConstraint(f"curp_hash IS NULL OR length(curp_hash) = {HASH_LEN}", name="curp_hash_len"),
        CheckConstraint(f"rfc_hash IS NULL OR length(rfc_hash) = {HASH_LEN}", name="rfc_hash_len"),
        CheckConstraint("(curp_enc IS NULL) = (curp_hash IS NULL)", name="curp_enc_and_hash_together"),
        CheckConstraint("(rfc_enc IS NULL) = (rfc_hash IS NULL)", name="rfc_enc_and_hash_together"),
        # Desde que se envía, el expediente debe tener datos completos (salvo que se haya anonimizado).
        CheckConstraint(
            "status IN ('NOT_STARTED', 'PENDING_DOCUMENTS') OR anonymized_at IS NOT NULL OR ("
            "first_names IS NOT NULL AND paternal_surname IS NOT NULL AND birth_date IS NOT NULL "
            "AND curp_hash IS NOT NULL AND rfc_hash IS NOT NULL AND current_address_id IS NOT NULL)",
            name="complete_data_after_submission",
        ),
        # Mayor de edad a la fecha de envío.
        CheckConstraint(
            "submitted_at IS NULL OR birth_date IS NULL "
            "OR birth_date <= (timezone('UTC', submitted_at) - interval '18 years')::date",
            name="adult_at_submission",
        ),
        # Solo hay revisor asignado mientras el caso está en revisión.
        CheckConstraint(
            "(status = 'UNDER_REVIEW') = (assigned_reviewer_id IS NOT NULL)",
            name="reviewer_only_under_review",
        ),
        CheckConstraint("cycle >= 0", name="cycle_non_negative"),
        Index("ix_kyc_profiles_queue", "status", "submitted_at"),
        Index("ix_kyc_profiles_expires_at", "expires_at", postgresql_where=text("status = 'APPROVED'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    technician_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("technician_profiles.user_id", ondelete="RESTRICT"), unique=True, nullable=False
    )
    status: Mapped[KycStatus] = mapped_column(
        pg_enum(KycStatus, "kyc_status"), nullable=False, server_default=KycStatus.NOT_STARTED.value
    )

    # Nombre legal (el nombre visible en la app sigue siendo users.full_name)
    first_names: Mapped[str | None] = mapped_column(String(80))
    paternal_surname: Mapped[str | None] = mapped_column(String(80))
    maternal_surname: Mapped[str | None] = mapped_column(String(80))  # opcional: no todas las personas lo tienen
    birth_date: Mapped[date | None] = mapped_column(Date)

    # Identificadores cifrados + índice ciego
    curp_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    curp_hash: Mapped[str | None] = mapped_column(String(HASH_LEN), unique=True)
    rfc_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    rfc_hash: Mapped[str | None] = mapped_column(String(HASH_LEN), unique=True)
    # DEK del expediente envuelta con la llave maestra. NULL = borrado criptográfico.
    data_key_enc: Mapped[bytes | None] = mapped_column(LargeBinary)

    current_address_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("kyc_addresses.id", use_alter=True, name="fk_kyc_profiles_current_address_id_kyc_addresses")
    )

    # Revisión
    assigned_reviewer_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cycle: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))  # nº de envíos

    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revalidation_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    has_background_check_badge: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    anonymized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Bloqueo optimista: dos administradores no pueden decidir sobre el mismo caso a la vez.
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    technician: Mapped[TechnicianProfile] = relationship(back_populates="kyc_profile", foreign_keys=[technician_id])
    addresses: Mapped[list[KycAddress]] = relationship(
        back_populates="profile", foreign_keys="KycAddress.kyc_profile_id"
    )
    current_address: Mapped[KycAddress | None] = relationship(foreign_keys=[current_address_id], post_update=True)
    documents: Mapped[list[KycDocument]] = relationship(back_populates="profile")

    def __repr__(self) -> str:  # sin datos personales
        return f"<KycProfile id={self.id} status={self.status.value}>"


class KycAddress(Base):
    """Domicilio declarado. Una fila por versión; se congela (locked_at) al enviarse a revisión."""

    __tablename__ = "kyc_addresses"
    __table_args__ = (CheckConstraint("postal_code ~ '^[0-9]{5}$'", name="postal_code_format"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kyc_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    street: Mapped[str] = mapped_column(String(150), nullable=False)
    exterior_number: Mapped[str] = mapped_column(String(20), nullable=False)
    interior_number: Mapped[str | None] = mapped_column(String(20))
    settlement: Mapped[str] = mapped_column(String(150), nullable=False)  # colonia
    postal_settlement_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("mx_postal_settlements.id"))
    postal_code: Mapped[str] = mapped_column(String(5), nullable=False)
    city: Mapped[str | None] = mapped_column(String(120))
    municipality_id: Mapped[int] = mapped_column(Integer, ForeignKey("mx_municipalities.id"), nullable=False)
    state_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("mx_states.id"), nullable=False)
    country_code: Mapped[str] = mapped_column(
        String(2), ForeignKey("countries.code"), nullable=False, server_default=text("'MX'")
    )
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    profile: Mapped[KycProfile] = relationship(back_populates="addresses", foreign_keys=[kyc_profile_id])


class KycDocument(TimestampMixin, Base):
    __tablename__ = "kyc_documents"
    __table_args__ = (
        CheckConstraint("expires_at IS NULL OR issued_at IS NULL OR expires_at > issued_at",
                        name="expiry_after_issue"),
        CheckConstraint("(number_enc IS NULL) = (number_hash IS NULL)", name="number_enc_and_hash_together"),
        CheckConstraint("supersedes_id IS NULL OR supersedes_id <> id", name="not_self_superseding"),
        Index("ix_kyc_documents_expiring", "expires_at", postgresql_where=text("status = 'APPROVED'")),
        Index("ix_kyc_documents_number_hash", "number_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kyc_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    document_type_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("document_types.id"), nullable=False)
    address_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("kyc_addresses.id"))  # comprobantes
    status: Mapped[KycDocumentStatus] = mapped_column(
        pg_enum(KycDocumentStatus, "kyc_document_status"),
        nullable=False, server_default=KycDocumentStatus.UPLOADING.value,
    )
    number_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    number_hash: Mapped[str | None] = mapped_column(String(HASH_LEN))  # sin UNIQUE: el mismo técnico re-sube
    issued_at: Mapped[date | None] = mapped_column(Date)
    expires_at: Mapped[date | None] = mapped_column(Date)
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("kyc_documents.id"))
    review_cycle: Mapped[int | None] = mapped_column(Integer)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    rejection_reason_id: Mapped[int | None] = mapped_column(SmallInteger, ForeignKey("rejection_reasons.id"))
    rejection_note: Mapped[str | None] = mapped_column(String(500))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # descartado antes de enviar
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Señales para el revisor: número de documento o archivo idéntico en OTRO expediente.
    risk_flags: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True))

    profile: Mapped[KycProfile] = relationship(back_populates="documents")
    document_type: Mapped[DocumentType] = relationship()
    files: Mapped[list[KycDocumentFile]] = relationship(back_populates="document")


class KycDocumentFile(Base):
    __tablename__ = "kyc_document_files"
    __table_args__ = (
        CheckConstraint(f"size_bytes > 0 AND size_bytes <= {MAX_FILE_BYTES}", name="size_range"),
        CheckConstraint("detected_mime IN ('image/jpeg', 'image/png', 'application/pdf')", name="mime_allowed"),
        CheckConstraint(f"length(sha256) = {HASH_LEN}", name="sha256_len"),
        CheckConstraint("object_key !~ '[^a-z0-9/_-]'", name="object_key_safe_chars"),
        # Todo archivo vivo tiene su llave; al purgarlo se destruye (borrado criptográfico por archivo).
        CheckConstraint("file_key_enc IS NOT NULL OR purged_at IS NOT NULL", name="key_or_purged"),
        CheckConstraint("scan_attempts >= 0", name="scan_attempts_non_negative"),
        Index("ix_kyc_document_files_sha256", "sha256"),
        Index("ix_kyc_document_files_pending", "created_at", postgresql_where=text("scan_status = 'PENDING'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    side: Mapped[DocumentSide] = mapped_column(pg_enum(DocumentSide, "document_side"), nullable=False)
    page_number: Mapped[int | None] = mapped_column(SmallInteger)
    bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    object_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)  # uuid, sin datos personales
    detected_mime: Mapped[str] = mapped_column(String(40), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(HASH_LEN), nullable=False)
    scan_status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"), nullable=False, server_default=ScanStatus.PENDING.value
    )
    scan_engine: Mapped[str | None] = mapped_column(String(60))
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    preview_key: Mapped[str | None] = mapped_column(String(200))  # imagen re-codificada que ve el revisor
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    page_count: Mapped[int | None] = mapped_column(SmallInteger)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Llave del archivo (FEK) envuelta con la DEK del expediente.
    file_key_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    scan_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    scan_detail: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    document: Mapped[KycDocument] = relationship(back_populates="files")


# =============================================================================
# Revisión e historial
# =============================================================================
class KycReview(Base):
    """Un registro por ciclo de revisión (cada envío del expediente abre un ciclo)."""

    __tablename__ = "kyc_reviews"
    __table_args__ = (UniqueConstraint("kyc_profile_id", "cycle"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kyc_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_profiles.id", ondelete="CASCADE"), nullable=False
    )
    cycle: Mapped[int] = mapped_column(Integer, nullable=False)
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision: Mapped[ReviewDecision | None] = mapped_column(pg_enum(ReviewDecision, "review_decision"))
    reason_id: Mapped[int | None] = mapped_column(SmallInteger, ForeignKey("rejection_reasons.id"))
    notes: Mapped[str | None] = mapped_column(Text)
    address_check: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KycDocumentReview(Base):
    __tablename__ = "kyc_document_reviews"
    __table_args__ = (
        UniqueConstraint("review_id", "document_id"),
        CheckConstraint("decision = 'APPROVED' OR reason_id IS NOT NULL", name="rejection_needs_reason"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    review_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("kyc_reviews.id", ondelete="CASCADE"), nullable=False)
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_documents.id", ondelete="CASCADE"), nullable=False
    )
    decision: Mapped[DocumentDecision] = mapped_column(pg_enum(DocumentDecision, "document_decision"), nullable=False)
    reason_id: Mapped[int | None] = mapped_column(SmallInteger, ForeignKey("rejection_reasons.id"))
    note: Mapped[str | None] = mapped_column(String(500))
    reviewer_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KycStatusHistory(Base):
    """Solo inserción (trigger). Una fila por transición de estado."""

    __tablename__ = "kyc_status_history"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kyc_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("kyc_profiles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    from_status: Mapped[KycStatus | None] = mapped_column(pg_enum(KycStatus, "kyc_status"))
    to_status: Mapped[KycStatus] = mapped_column(pg_enum(KycStatus, "kyc_status"), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    actor_type: Mapped[ActorType] = mapped_column(pg_enum(ActorType, "actor_type"), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(40))
    note: Mapped[str | None] = mapped_column(String(1000))
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# =============================================================================
# Auditoría, consentimientos, permisos, retención, notificaciones
# =============================================================================
class AuditLog(Base):
    """
    Solo inserción (trigger). Cada fila guarda el hash de la anterior (prev_hash) y el
    suyo (row_hash): alterar o borrar una fila rompe la cadena y se detecta con
    app.audit.writer.verify_chain(). Nunca guarda contraseñas, tokens ni identificadores completos.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_technician", "technician_id", "occurred_at"),
        Index("ix_audit_logs_action", "action", "occurred_at"),
        Index("ix_audit_logs_actor_action", "actor_id", "action", "occurred_at"),
        CheckConstraint(f"length(row_hash) = {HASH_LEN}", name="row_hash_len"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # sin FK: el registro sobrevive a la baja del usuario
    actor_type: Mapped[ActorType] = mapped_column(pg_enum(ActorType, "actor_type"), nullable=False)
    actor_roles: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    technician_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    kyc_profile_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    document_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    result: Mapped[AuditResult] = mapped_column(pg_enum(AuditResult, "audit_result"), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(40))
    reason_note: Mapped[str | None] = mapped_column(String(1000))
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str | None] = mapped_column(String(HASH_LEN))
    row_hash: Mapped[str] = mapped_column(String(HASH_LEN), nullable=False)


class Consent(Base):
    __tablename__ = "consents"
    __table_args__ = (UniqueConstraint("user_id", "notice_version", "purpose"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    notice_version: Mapped[str] = mapped_column(String(20), nullable=False)
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)  # KYC_IDENTITY, BIOMETRIC_SELFIE, ...
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(255))


class AdminRoleAssignment(Base):
    __tablename__ = "admin_role_assignments"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[AdminRole] = mapped_column(pg_enum(AdminRole, "admin_role"), primary_key=True)
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AdminRegionScope(Base):
    """Opcional: limita a un revisor a expedientes de ciertos estados."""

    __tablename__ = "admin_region_scopes"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    state_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("mx_states.id"), primary_key=True)


class RetentionPolicy(Base):
    """Reglas de retención. Se siembran DESHABILITADAS: nada se borra hasta que legal las valide."""

    __tablename__ = "retention_policies"
    __table_args__ = (CheckConstraint("retain_days >= 0", name="retain_days_non_negative"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    data_category: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    trigger_event: Mapped[str] = mapped_column(String(60), nullable=False)
    retain_days: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[RetentionAction] = mapped_column(pg_enum(RetentionAction, "retention_action"), nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(300), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OutboxEvent(Base):
    """Eventos para notificaciones, escritos en la misma transacción que el cambio de estado."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        Index("ix_outbox_pending", "created_at", postgresql_where=text("processed_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(40), nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(String(500))


class FileViewTicket(Base):
    """
    Permiso temporal de UN solo uso para ver UN archivo (p. ej. en un <img> del panel, que
    no puede mandar el encabezado Authorization). Ligado al usuario; expira en segundos;
    al canjearlo se vuelven a verificar los permisos.
    """

    __tablename__ = "file_view_tickets"

    jti: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    file_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("kyc_document_files.id", ondelete="CASCADE"),
                                               nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EncryptionKeyMetadata(Base):
    """
    Metadatos de llaves de cifrado. JAMÁS contiene material de llave: solo id, propósito,
    estado, referencia externa (ARN de KMS) y una huella para detectar llaves mal configuradas.
    """

    __tablename__ = "encryption_keys_metadata"
    __table_args__ = (
        Index("uq_encryption_keys_one_active", "purpose", unique=True, postgresql_where=text("status = 'ACTIVE'")),
        CheckConstraint("key_id BETWEEN 1 AND 255", name="key_id_range"),
        CheckConstraint("status <> 'REVOKED' OR revoked_at IS NOT NULL", name="revoked_has_date"),
    )

    purpose: Mapped[KeyPurpose] = mapped_column(pg_enum(KeyPurpose, "key_purpose"), primary_key=True)
    key_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)
    status: Mapped[KeyStatus] = mapped_column(pg_enum(KeyStatus, "key_status"), nullable=False)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)       # local | aws-kms
    external_ref: Mapped[str | None] = mapped_column(String(255))            # ARN / alias (no es secreto)
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(String(300))
