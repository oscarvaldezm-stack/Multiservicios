"""
Casos de uso del técnico sobre su expediente KYC.

Reglas centrales:
- Nada se captura sin el consentimiento vigente (aviso de privacidad).
- Qué se puede editar depende del estado y, en CORRECTION_REQUIRED, de lo que el
  revisor pidió corregir (alcance de la corrección).
- El envío valida la lista completa de requisitos, congela el domicilio y abre un ciclo.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, selectinload

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.crypto import mask_identifier
from app.core.errors import DomainError
from app.kyc import identity
from app.kyc.requirements import REQUIRED_CONSENTS, ConsentPurpose, Missing, active_consents, evaluate
from app.kyc.state_machine import transition
from app.models import (
    Consent,
    KycAddress,
    KycDocument,
    KycProfile,
    KycStatus,
    KycStatusHistory,
    MxMunicipality,
    MxPostalSettlement,
    MxState,
    RejectionReason,
    User,
)
from app.schemas.kyc import AddressIn, ConsentIn, PersonalDataIn

S = KycStatus


class Scope(str, enum.Enum):
    PERSONAL_DATA = "PERSONAL_DATA"
    ADDRESS = "ADDRESS"
    DOCUMENTS = "DOCUMENTS"


# Qué desbloquea cada motivo de corrección.
CORRECTION_SCOPES: dict[str, frozenset[Scope]] = {
    "CORRECCION_DATOS_PERSONALES": frozenset({Scope.PERSONAL_DATA, Scope.ADDRESS, Scope.DOCUMENTS}),
    "CORRECCION_DOMICILIO": frozenset({Scope.ADDRESS, Scope.DOCUMENTS}),
    "CORRECCION_DOCUMENTOS": frozenset({Scope.DOCUMENTS}),
}

# Qué se puede editar en cada estado (sin contar correcciones).
STATE_SCOPES: dict[KycStatus, frozenset[Scope]] = {
    S.NOT_STARTED: frozenset(Scope),
    S.PENDING_DOCUMENTS: frozenset(Scope),
    # Revalidación: puede actualizar domicilio y documentos, no su identidad.
    S.EXPIRED: frozenset({Scope.ADDRESS, Scope.DOCUMENTS}),
}

SUBMITTABLE_FROM = frozenset({S.PENDING_DOCUMENTS, S.CORRECTION_REQUIRED, S.EXPIRED})


# ---------------------------------------------------------------------------
def get_technician_profile(db: Session, technician_id: uuid.UUID, *, lock: bool = False) -> KycProfile:
    stmt = select(KycProfile).where(KycProfile.technician_id == technician_id)
    if lock:
        stmt = stmt.with_for_update()
    profile = db.scalar(stmt)
    if profile is None:  # no debería ocurrir: el registro crea el expediente
        raise DomainError("Expediente no encontrado", code="KYC_NOT_FOUND", http_status=404)
    return profile


@dataclass(frozen=True)
class CorrectionInfo:
    reason_code: str | None
    note: str | None
    scopes: frozenset[Scope]


def correction_info(db: Session, profile: KycProfile) -> CorrectionInfo | None:
    if profile.status != S.CORRECTION_REQUIRED:
        return None
    last = db.scalar(
        select(KycStatusHistory)
        .where(KycStatusHistory.kyc_profile_id == profile.id, KycStatusHistory.to_status == S.CORRECTION_REQUIRED)
        .order_by(KycStatusHistory.id.desc()).limit(1)
    )
    code = last.reason_code if last else None
    return CorrectionInfo(code, last.note if last else None,
                          CORRECTION_SCOPES.get(code or "", frozenset({Scope.DOCUMENTS})))


def editable_scopes(db: Session, profile: KycProfile) -> frozenset[Scope]:
    if profile.status == S.CORRECTION_REQUIRED:
        info = correction_info(db, profile)
        return info.scopes if info else frozenset()
    return STATE_SCOPES.get(profile.status, frozenset())


def _require_scope(db: Session, profile: KycProfile, scope: Scope) -> None:
    if scope not in editable_scopes(db, profile):
        raise DomainError(
            "Esta sección no se puede modificar en el estado actual de tu verificación",
            code="KYC_NOT_EDITABLE", http_status=409, extra={"status": profile.status.value},
        )


def _require_consent(db: Session, user: User, purpose: ConsentPurpose) -> None:
    version = get_settings().KYC_PRIVACY_NOTICE_VERSION
    if purpose.value not in active_consents(db, user.id, version):
        raise DomainError(
            "Debes aceptar el aviso de privacidad vigente antes de continuar",
            code="KYC_CONSENT_REQUIRED", http_status=409,
            extra={"purpose": purpose.value, "notice_version": version},
        )


def _start_if_needed(db: Session, profile: KycProfile, actor: Actor, ctx: RequestContext | None) -> None:
    if profile.status == S.NOT_STARTED:
        transition(db, profile.id, S.PENDING_DOCUMENTS, actor, ctx=ctx)


# ---------------------------------------------------------------------------
# Consentimientos
# ---------------------------------------------------------------------------
def record_consents(db: Session, user: User, actor: Actor, data: ConsentIn,
                    ctx: RequestContext | None = None) -> list[str]:
    version = get_settings().KYC_PRIVACY_NOTICE_VERSION
    if data.notice_version != version:
        raise DomainError("El aviso de privacidad cambió; revisa la versión vigente",
                          code="KYC_NOTICE_OUTDATED", http_status=409, extra={"notice_version": version})
    already = active_consents(db, user.id, version)
    new = [p for p in data.purposes if p.value not in already]
    for p in new:
        db.add(Consent(user_id=user.id, notice_version=version, purpose=p.value,
                       ip=ctx.ip if ctx else None, user_agent=((ctx.user_agent or "")[:255] or None) if ctx else None))
    if new:
        write_audit(db, action="kyc.consent.granted", actor=actor, technician_id=user.id,
                    target_type="consent", target_id=version,
                    changes={"purposes": [p.value for p in new], "notice_version": version}, ctx=ctx)
    db.flush()
    return sorted(already | {p.value for p in new})


# ---------------------------------------------------------------------------
# Datos personales
# ---------------------------------------------------------------------------
def save_personal_data(db: Session, user: User, actor: Actor, data: PersonalDataIn,
                       ctx: RequestContext | None = None) -> KycProfile:
    _require_consent(db, user, ConsentPurpose.KYC_IDENTITY)
    profile = get_technician_profile(db, user.id, lock=True)
    _require_scope(db, profile, Scope.PERSONAL_DATA)
    identity.set_identity(
        db, profile, actor, first_names=data.first_names, paternal_surname=data.paternal_surname,
        maternal_surname=data.maternal_surname, birth_date=data.birth_date, curp=data.curp, rfc=data.rfc, ctx=ctx,
    )
    _start_if_needed(db, profile, actor, ctx)
    return profile


# ---------------------------------------------------------------------------
# Domicilio
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _ResolvedAddress:
    postal_code: str
    settlement: str
    postal_settlement_id: int | None
    municipality_id: int
    state_id: int
    city: str | None


def _resolve_address(db: Session, data: AddressIn) -> _ResolvedAddress:
    if data.postal_settlement_id is not None:
        row = db.execute(
            select(MxPostalSettlement, MxMunicipality)
            .join(MxMunicipality, MxMunicipality.id == MxPostalSettlement.municipality_id)
            .where(MxPostalSettlement.id == data.postal_settlement_id)
        ).one_or_none()
        if row is None:
            raise DomainError("La colonia seleccionada no existe", code="ADDRESS_SETTLEMENT_UNKNOWN", http_status=422)
        sett, muni = row
        return _ResolvedAddress(sett.postal_code, sett.name, sett.id, muni.id, muni.state_id,
                                sett.city or muni.name)

    muni = db.get(MxMunicipality, data.municipality_id)
    if muni is None:
        raise DomainError("El municipio no existe", code="ADDRESS_MUNICIPALITY_UNKNOWN", http_status=422)
    munis_for_cp = set(db.scalars(
        select(MxPostalSettlement.municipality_id).where(MxPostalSettlement.postal_code == data.postal_code)
    ).all())
    if munis_for_cp:
        if muni.id not in munis_for_cp:
            raise DomainError("El código postal no corresponde a ese municipio",
                              code="ADDRESS_POSTAL_CODE_MISMATCH", http_status=422)
    elif db.scalar(select(exists().where(MxPostalSettlement.id.isnot(None)))):
        # El catálogo está cargado y ese CP no existe en él.
        raise DomainError("El código postal no existe", code="ADDRESS_POSTAL_CODE_UNKNOWN", http_status=422)
    return _ResolvedAddress(data.postal_code, data.settlement, None, muni.id, muni.state_id, muni.name)


def save_address(db: Session, user: User, actor: Actor, data: AddressIn,
                 ctx: RequestContext | None = None) -> KycAddress:
    _require_consent(db, user, ConsentPurpose.KYC_IDENTITY)
    profile = get_technician_profile(db, user.id, lock=True)
    _require_scope(db, profile, Scope.ADDRESS)
    r = _resolve_address(db, data)
    values = dict(street=data.street, exterior_number=data.exterior_number, interior_number=data.interior_number,
                  settlement=r.settlement, postal_settlement_id=r.postal_settlement_id, postal_code=r.postal_code,
                  city=r.city, municipality_id=r.municipality_id, state_id=r.state_id, country_code="MX")

    current = db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None
    # Un comprobante prueba UNA dirección concreta. Si ya hay documentos ligados a este
    # domicilio (o ya se envió a revisión), editarlo en su lugar haría que un comprobante
    # de la dirección anterior "validara" la nueva: en ese caso se crea una versión nueva.
    referenced = current is not None and db.scalar(
        select(exists().where(KycDocument.address_id == current.id))
    )
    if current is not None and current.locked_at is None and not referenced:
        for k, v in values.items():          # borrador sin documentos: se actualiza en su lugar
            setattr(current, k, v)
        address = current
    else:                                     # congelado o con comprobante ligado: versión nueva
        address = KycAddress(kyc_profile_id=profile.id, **values)
        db.add(address)
        db.flush()
        profile.current_address_id = address.id

    write_audit(db, action="kyc.address.updated", actor=actor, technician_id=user.id,
                kyc_profile_id=profile.id, target_type="kyc_address", target_id=str(address.id),
                changes={"postal_code": r.postal_code, "state_id": r.state_id,
                         "municipality_id": r.municipality_id, "new_version": address is not current}, ctx=ctx)
    _start_if_needed(db, profile, actor, ctx)
    db.flush()
    return address


# ---------------------------------------------------------------------------
# Envío a revisión
# ---------------------------------------------------------------------------
def submit(db: Session, user: User, actor: Actor, ctx: RequestContext | None = None) -> KycProfile:
    profile = get_technician_profile(db, user.id, lock=True)
    if profile.status not in SUBMITTABLE_FROM:
        raise DomainError("Tu expediente no se puede enviar en su estado actual",
                          code="KYC_NOT_SUBMITTABLE", http_status=409, extra={"status": profile.status.value})
    report = evaluate(db, profile, user)
    if not report.complete:
        raise DomainError("Faltan requisitos para enviar tu verificación", code="KYC_REQUIREMENTS_MISSING",
                          http_status=422, extra={"missing": [m.value for m in report.missing]})

    now = datetime.now(timezone.utc)
    address = db.get(KycAddress, profile.current_address_id)
    if address.locked_at is None:
        address.locked_at = now               # desde aquí el trigger impide modificarlo
    transition(db, profile.id, S.SUBMITTED, actor, ctx=ctx)
    return profile


# ---------------------------------------------------------------------------
# Vistas (lectura)
# ---------------------------------------------------------------------------
NEXT_STEP: dict[KycStatus, str] = {
    S.NOT_STARTED: "Acepta el aviso de privacidad y captura tus datos personales.",
    S.PENDING_DOCUMENTS: "Completa los datos y documentos pendientes y envía tu verificación.",
    S.SUBMITTED: "Recibimos tu documentación. Un revisor la tomará pronto.",
    S.UNDER_REVIEW: "Tu expediente está en revisión.",
    S.APPROVED: "Tu identidad está verificada. Ya puedes recibir servicios.",
    S.REJECTED: "Tu verificación fue rechazada. Contacta a soporte si crees que es un error.",
    S.CORRECTION_REQUIRED: "Corrige lo que se indica y vuelve a enviar tu verificación.",
    S.SUSPENDED: "Tu cuenta está suspendida. Contacta a soporte.",
    S.EXPIRED: "Un documento venció. Sube el documento vigente y vuelve a enviar.",
}


def address_view(db: Session, address: KycAddress | None) -> dict | None:
    if address is None:
        return None
    muni = db.get(MxMunicipality, address.municipality_id)
    state = db.get(MxState, address.state_id)
    return dict(id=address.id, street=address.street, exterior_number=address.exterior_number,
                interior_number=address.interior_number, settlement=address.settlement,
                postal_code=address.postal_code, city=address.city, municipality_id=address.municipality_id,
                municipality=muni.name if muni else "", state_id=address.state_id,
                state=state.name if state else "", country_code=address.country_code,
                locked=address.locked_at is not None)


def documents_view(db: Session, profile: KycProfile, *, include_superseded: bool = False,
                   reviewer: bool = False) -> list[dict]:
    from app.kyc.documents import allowed_sides

    docs = db.scalars(
        select(KycDocument)
        .where(KycDocument.kyc_profile_id == profile.id, KycDocument.deleted_at.is_(None))
        .options(selectinload(KycDocument.files), selectinload(KycDocument.document_type))
        .order_by(KycDocument.created_at)
    ).all()
    reasons = {r.id: r for r in db.scalars(select(RejectionReason)).all()}
    c = None
    out = []
    for d in docs:
        if d.status.value == "SUPERSEDED" and not include_superseded:
            continue
        reason = reasons.get(d.rejection_reason_id)
        live = [f for f in d.files if f.purged_at is None]
        number_masked = None
        if d.number_enc is not None and profile.anonymized_at is None:
            c = c or identity.cipher_for_profile(profile.id, profile.data_key_enc)
            number_masked = mask_identifier(c.decrypt("kyc_documents", d.id, "number", d.number_enc))
        out.append(dict(
            id=d.id, type_code=d.document_type.code, type_name=d.document_type.name,
            category=d.document_type.category, status=d.status, issued_at=d.issued_at, expires_at=d.expires_at,
            files=len(live), allowed_sides=allowed_sides(d.document_type), number_masked=number_masked,
            file_items=[dict(id=f.id, side=f.side, page_number=f.page_number, scan_status=f.scan_status,
                             mime=f.detected_mime, width=f.width, height=f.height, page_count=f.page_count,
                             uploaded_at=f.created_at)
                        for f in sorted(live, key=lambda x: (x.side.value, x.page_number or 0))],
            rejection_reason=reason.label if reason else None, rejection_note=d.rejection_note,
            risk_flags=d.risk_flags if reviewer else None,
        ))
    return out


def status_view(db: Session, profile: KycProfile, user: User) -> dict:
    report = evaluate(db, profile, user)
    can_submit = profile.status in SUBMITTABLE_FROM and report.complete
    missing = report.missing if profile.status in (SUBMITTABLE_FROM | {S.NOT_STARTED}) else []
    return dict(status=profile.status, cycle=profile.cycle, submitted_at=profile.submitted_at,
                can_submit=can_submit, missing=missing, next_step=NEXT_STEP[profile.status])


def technician_view(db: Session, profile: KycProfile, user: User) -> dict:
    s = get_settings()
    curp, rfc = identity.read_identifiers(profile) if profile.anonymized_at is None else (None, None)
    docs = documents_view(db, profile)
    scopes = editable_scopes(db, profile)
    info = correction_info(db, profile)
    correction = None
    if info is not None:
        label = db.scalar(select(RejectionReason.label).where(RejectionReason.code == info.reason_code))
        correction = dict(reason_code=info.reason_code, reason_label=label, note=info.note,
                          can_edit_personal_data=Scope.PERSONAL_DATA in info.scopes,
                          can_edit_address=Scope.ADDRESS in info.scopes,
                          rejected_documents=[d for d in docs if d["status"].value == "REJECTED"])
    return dict(
        **status_view(db, profile, user),
        personal_data=dict(first_names=profile.first_names, paternal_surname=profile.paternal_surname,
                           maternal_surname=profile.maternal_surname, birth_date=profile.birth_date,
                           curp_masked=mask_identifier(curp), rfc_masked=mask_identifier(rfc)),
        address=address_view(db, db.get(KycAddress, profile.current_address_id) if profile.current_address_id else None),
        documents=docs,
        consents=dict(notice_version=s.KYC_PRIVACY_NOTICE_VERSION,
                      granted=sorted(active_consents(db, user.id, s.KYC_PRIVACY_NOTICE_VERSION)),
                      required=[c.value for c in REQUIRED_CONSENTS]),
        correction=correction,
        has_background_check_badge=profile.has_background_check_badge,
        editable={sc.value.lower(): sc in scopes for sc in Scope},
    )


__all__ = ["Missing", "Scope", "record_consents", "save_personal_data", "save_address", "submit",
           "technician_view", "status_view", "get_technician_profile", "correction_info"]
