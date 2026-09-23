"""
Schemas del KYC. Todas las entradas usan extra="forbid": un campo no previsto
(por ejemplo "status" o "approved_by") produce 422 en lugar de ignorarse en silencio.
"""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.kyc.requirements import ConsentPurpose, Missing
from app.models.enums import AdminRole, DocumentCategory, DocumentSide, KycDocumentStatus, KycStatus, ScanStatus

# Letras (incluye acentos, ñ, ü), espacios, apóstrofo, guion y punto. Sin dígitos ni símbolos.
_NAME_RE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .\-]+$")
_STREET_RE = re.compile(r"^[0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ#'°º .,\-/]+$")
_NUMBER_RE = re.compile(r"^[0-9A-Za-z\- /]+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _clean_text(v: str | None, pattern: re.Pattern[str], field: str) -> str | None:
    if v is None:
        return None
    if _CONTROL_RE.search(v):
        raise ValueError(f"{field} contiene caracteres no permitidos")
    v = re.sub(r"\s+", " ", v).strip()
    if not v:
        return None
    if not pattern.fullmatch(v):
        raise ValueError(f"{field} contiene caracteres no permitidos")
    return v


# ---------------------------------------------------------------------------
# Técnico: entradas
# ---------------------------------------------------------------------------
class ConsentIn(_In):
    notice_version: str = Field(min_length=1, max_length=20)
    purposes: list[ConsentPurpose] = Field(min_length=1, max_length=3)

    @field_validator("purposes")
    @classmethod
    def _unique(cls, v: list[ConsentPurpose]) -> list[ConsentPurpose]:
        return sorted(set(v), key=lambda p: p.value)


class PersonalDataIn(_In):
    first_names: str = Field(min_length=1, max_length=80)
    paternal_surname: str = Field(min_length=1, max_length=80)
    maternal_surname: str | None = Field(default=None, max_length=80)
    birth_date: date
    curp: str = Field(min_length=18, max_length=18)
    rfc: str = Field(min_length=13, max_length=13)

    @field_validator("first_names", "paternal_surname", "maternal_surname")
    @classmethod
    def _names(cls, v: str | None, info) -> str | None:
        return _clean_text(v, _NAME_RE, info.field_name)

    @field_validator("curp", "rfc")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


class AddressIn(_In):
    """
    Dos formas de capturar la colonia:
    - `postal_settlement_id`: la colonia elegida del catálogo SEPOMEX (recomendado); el backend
      deriva CP, municipio, estado y ciudad.
    - Manual (`postal_code` + `settlement` + `municipality_id`): solo si la colonia no aparece
      en el catálogo. El backend verifica que ese CP exista y pertenezca a ese municipio.
    """

    street: str = Field(min_length=2, max_length=150)
    exterior_number: str = Field(min_length=1, max_length=20)
    interior_number: str | None = Field(default=None, max_length=20)
    postal_settlement_id: int | None = Field(default=None, gt=0)
    postal_code: str | None = Field(default=None, pattern=r"^\d{5}$")
    settlement: str | None = Field(default=None, min_length=2, max_length=150)
    municipality_id: int | None = Field(default=None, gt=0)

    @field_validator("street", "settlement")
    @classmethod
    def _street(cls, v: str | None, info) -> str | None:
        return _clean_text(v, _STREET_RE, info.field_name)

    @field_validator("exterior_number", "interior_number")
    @classmethod
    def _number(cls, v: str | None, info) -> str | None:
        return _clean_text(v, _NUMBER_RE, info.field_name)

    @model_validator(mode="after")
    def _one_way(self) -> AddressIn:
        manual = (self.postal_code, self.settlement, self.municipality_id)
        if self.postal_settlement_id is not None:
            if any(x is not None for x in manual):
                raise ValueError("Usa postal_settlement_id o la captura manual, no ambas")
        elif not all(x is not None for x in manual):
            raise ValueError("Indica postal_settlement_id, o bien postal_code, settlement y municipality_id")
        return self


# ---------------------------------------------------------------------------
# Técnico: salidas
# ---------------------------------------------------------------------------
class PersonalDataOut(BaseModel):
    first_names: str | None
    paternal_surname: str | None
    maternal_surname: str | None
    birth_date: date | None
    curp_masked: str | None
    rfc_masked: str | None


class AddressOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    street: str
    exterior_number: str
    interior_number: str | None
    settlement: str
    postal_code: str
    city: str | None
    municipality_id: int
    municipality: str
    state_id: int
    state: str
    country_code: str
    locked: bool


class FileOut(BaseModel):
    id: uuid.UUID
    side: DocumentSide
    page_number: int | None
    scan_status: ScanStatus
    mime: str
    width: int | None
    height: int | None
    page_count: int | None
    uploaded_at: datetime


class DocumentSummaryOut(BaseModel):
    id: uuid.UUID
    type_code: str
    type_name: str
    category: DocumentCategory
    status: KycDocumentStatus
    issued_at: date | None
    expires_at: date | None
    files: int
    file_items: list[FileOut] = []
    allowed_sides: list[DocumentSide] = []
    number_masked: str | None = None
    rejection_reason: str | None = None
    rejection_note: str | None = None
    risk_flags: list[str] | None = None      # solo en la vista del revisor


class DocumentCreateIn(_In):
    type_code: str = Field(min_length=2, max_length=40, pattern=r"^[A-Z0-9_]+$")
    document_number: str | None = Field(default=None, max_length=30)
    issued_at: date | None = None
    expires_at: date | None = None


class ViewTicketOut(BaseModel):
    url: str
    expires_at: datetime


class AuditEntryOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_id: uuid.UUID | None
    actor_type: str
    actor_roles: list[str] | None
    action: str
    result: str
    target_type: str | None
    target_id: str | None
    technician_id: uuid.UUID | None
    document_id: uuid.UUID | None
    reason_code: str | None
    ip: str | None


class AuditPageOut(BaseModel):
    items: list[AuditEntryOut]
    next_cursor: int | None


class AuditIntegrityOut(BaseModel):
    intact: bool
    broken_ids: list[int]


class CorrectionOut(BaseModel):
    reason_code: str | None
    reason_label: str | None
    note: str | None
    can_edit_personal_data: bool
    can_edit_address: bool
    rejected_documents: list[DocumentSummaryOut]


class ConsentStatusOut(BaseModel):
    notice_version: str
    granted: list[str]
    required: list[str]


class KycStatusOut(BaseModel):
    status: KycStatus
    cycle: int
    submitted_at: datetime | None
    can_submit: bool
    missing: list[Missing]
    next_step: str


class TechnicianKycOut(KycStatusOut):
    personal_data: PersonalDataOut
    address: AddressOut | None
    documents: list[DocumentSummaryOut]
    consents: ConsentStatusOut
    correction: CorrectionOut | None
    has_background_check_badge: bool
    editable: dict[str, bool]


# ---------------------------------------------------------------------------
# Catálogos
# ---------------------------------------------------------------------------
class StateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


class DocumentTypeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    code: str
    name: str
    category: DocumentCategory
    sides_required: int
    max_files: int
    requires_number: bool
    requires_issue_date: bool
    requires_expiry: bool
    max_age_days: int | None


class SettlementOut(BaseModel):
    id: int
    name: str
    settlement_type: str
    city: str | None
    municipality_id: int
    municipality: str
    state_id: int
    state: str


class PostalCodeOut(BaseModel):
    postal_code: str
    settlements: list[SettlementOut]


class PrivacyNoticeOut(BaseModel):
    version: str
    purposes: list[dict[str, object]]


# ---------------------------------------------------------------------------
# Administración
# ---------------------------------------------------------------------------
class QueueItemOut(BaseModel):
    case_id: uuid.UUID
    status: KycStatus
    cycle: int
    submitted_at: datetime | None
    technician_display: str       # "Gloria H." — nunca nombre completo ni identificadores en la cola
    state: str | None
    assigned_to_me: bool
    assigned: bool


class QueuePageOut(BaseModel):
    items: list[QueueItemOut]
    next_cursor: str | None


class HistoryItemOut(BaseModel):
    from_status: KycStatus | None
    to_status: KycStatus
    actor_type: str
    reason_code: str | None
    note: str | None
    at: datetime


class CaseDetailOut(BaseModel):
    case_id: uuid.UUID
    version: int                  # enviar como expected_version al decidir (Fase 4)
    status: KycStatus
    cycle: int
    technician_id: uuid.UUID
    email: str
    phone: str | None
    first_names: str | None
    paternal_surname: str | None
    maternal_surname: str | None
    birth_date: date | None
    curp: str | None
    rfc: str | None
    address: AddressOut | None
    documents: list[DocumentSummaryOut]
    history: list[HistoryItemOut]
    assigned_reviewer_id: uuid.UUID | None
    submitted_at: datetime | None
    has_background_check_badge: bool


class RolesIn(_In):
    roles: list[AdminRole] = Field(max_length=len(AdminRole))


class RolesOut(BaseModel):
    user_id: uuid.UUID
    roles: list[AdminRole]
    permissions: list[str]
