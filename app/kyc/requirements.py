"""
Qué le falta a un expediente para poder enviarse a revisión.

Se usa en dos lugares: la pantalla "Completa tu verificación" (checklist) y el envío
(POST /submission), que rechaza con la lista exacta de pendientes. Los documentos se
suben en la Fase 3; aquí ya se valida su presencia, escaneo, vigencia y antigüedad.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.models import (
    Consent,
    DocumentCategory,
    KycDocument,
    KycDocumentStatus,
    KycProfile,
    ScanStatus,
    User,
)


class ConsentPurpose(str, enum.Enum):
    KYC_IDENTITY = "KYC_IDENTITY"            # tratamiento de datos de identidad y domicilio
    BIOMETRIC_SELFIE = "BIOMETRIC_SELFIE"    # dato biométrico: consentimiento expreso separado
    BACKGROUND_CHECK = "BACKGROUND_CHECK"    # opcional: solo si sube carta de antecedentes


REQUIRED_CONSENTS = (ConsentPurpose.KYC_IDENTITY, ConsentPurpose.BIOMETRIC_SELFIE)
REQUIRED_CATEGORIES = (DocumentCategory.IDENTITY, DocumentCategory.ADDRESS, DocumentCategory.SELFIE)

# Estados de documento que cuentan para enviar (aprobados en ciclos anteriores o pendientes de revisión).
_COUNTING = {KycDocumentStatus.PENDING_REVIEW, KycDocumentStatus.APPROVED}


class Missing(str, enum.Enum):
    CONSENT_KYC_IDENTITY = "CONSENT_KYC_IDENTITY"
    CONSENT_BIOMETRIC_SELFIE = "CONSENT_BIOMETRIC_SELFIE"
    EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED"
    PERSONAL_DATA = "PERSONAL_DATA"
    ADDRESS = "ADDRESS"
    DOC_IDENTITY = "DOC_IDENTITY"
    DOC_IDENTITY_EXPIRED = "DOC_IDENTITY_EXPIRED"
    DOC_ADDRESS_PROOF = "DOC_ADDRESS_PROOF"
    DOC_ADDRESS_PROOF_TOO_OLD = "DOC_ADDRESS_PROOF_TOO_OLD"
    DOC_ADDRESS_PROOF_OTHER_ADDRESS = "DOC_ADDRESS_PROOF_OTHER_ADDRESS"
    DOC_SELFIE = "DOC_SELFIE"
    DOC_FILES_PENDING_SCAN = "DOC_FILES_PENDING_SCAN"


@dataclass
class RequirementsReport:
    missing: list[Missing] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing


def active_consents(db: Session, user_id, notice_version: str) -> set[str]:
    rows = db.scalars(select(Consent.purpose).where(
        Consent.user_id == user_id, Consent.notice_version == notice_version, Consent.revoked_at.is_(None),
    )).all()
    return set(rows)


def _doc_usable(doc: KycDocument) -> tuple[bool, bool]:
    """(cuenta_para_enviar, tiene_archivos_sin_escanear)"""
    if doc.deleted_at is not None:
        return False, False
    live = [f for f in doc.files if f.purged_at is None]
    pending = any(f.scan_status == ScanStatus.PENDING for f in live)
    if doc.status not in _COUNTING or not doc.document_type.is_active:
        return False, pending
    clean = [f for f in live if f.scan_status == ScanStatus.CLEAN]
    return len(clean) >= doc.document_type.sides_required, pending


def evaluate(db: Session, profile: KycProfile, user: User, today: date | None = None) -> RequirementsReport:
    s = get_settings()
    today = today or date.today()
    rep = RequirementsReport()

    consents = active_consents(db, user.id, s.KYC_PRIVACY_NOTICE_VERSION)
    if ConsentPurpose.KYC_IDENTITY.value not in consents:
        rep.missing.append(Missing.CONSENT_KYC_IDENTITY)
    if ConsentPurpose.BIOMETRIC_SELFIE.value not in consents:
        rep.missing.append(Missing.CONSENT_BIOMETRIC_SELFIE)
    if s.KYC_REQUIRE_VERIFIED_EMAIL and not user.is_email_verified:
        rep.missing.append(Missing.EMAIL_NOT_VERIFIED)
    if not (profile.first_names and profile.paternal_surname and profile.birth_date
            and profile.curp_hash and profile.rfc_hash):
        rep.missing.append(Missing.PERSONAL_DATA)
    if profile.current_address_id is None:
        rep.missing.append(Missing.ADDRESS)

    docs = db.scalars(
        select(KycDocument).where(KycDocument.kyc_profile_id == profile.id)
        .options(selectinload(KycDocument.files), selectinload(KycDocument.document_type))
    ).all()

    any_pending_scan = False
    found: dict[DocumentCategory, list[KycDocument]] = {c: [] for c in REQUIRED_CATEGORIES}
    for d in docs:
        ok, pending = _doc_usable(d)
        any_pending_scan |= pending and d.deleted_at is None
        if ok and d.document_type.category in found:
            found[d.document_type.category].append(d)

    ids = found[DocumentCategory.IDENTITY]
    if not ids:
        rep.missing.append(Missing.DOC_IDENTITY)
    elif not any(d.expires_at is None or d.expires_at > today for d in ids):
        rep.missing.append(Missing.DOC_IDENTITY_EXPIRED)

    proofs = found[DocumentCategory.ADDRESS]
    if not proofs:
        rep.missing.append(Missing.DOC_ADDRESS_PROOF)
    else:
        for_current = [d for d in proofs if d.address_id == profile.current_address_id]
        if not for_current:
            rep.missing.append(Missing.DOC_ADDRESS_PROOF_OTHER_ADDRESS)
        else:
            def fresh(d: KycDocument) -> bool:
                max_age = d.document_type.max_age_days or s.KYC_ADDRESS_PROOF_MAX_AGE_DAYS
                return d.issued_at is not None and d.issued_at >= today - timedelta(days=max_age)
            if not any(fresh(d) for d in for_current):
                rep.missing.append(Missing.DOC_ADDRESS_PROOF_TOO_OLD)

    if not found[DocumentCategory.SELFIE]:
        rep.missing.append(Missing.DOC_SELFIE)
    if any_pending_scan:
        rep.missing.append(Missing.DOC_FILES_PENDING_SCAN)
    return rep
