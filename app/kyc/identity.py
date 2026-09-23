"""
Creación del expediente y manejo de identificadores cifrados (CURP, RFC).

La API de la Fase 2 usará estas funciones; nunca se escribe curp_enc/rfc_enc a mano.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.crypto import blind_index, cipher_for_profile, mask_identifier, new_wrapped_dek
from app.kyc.validators import validate_adult, validate_curp_matches, validate_rfc_persona_fisica
from app.models.enums import KycStatus
from app.models.kyc import KycProfile, KycStatusHistory

_TABLE = "kyc_profiles"

# Estados en los que el técnico puede capturar o corregir su identidad.
IDENTITY_EDITABLE_STATES = frozenset({
    KycStatus.NOT_STARTED, KycStatus.PENDING_DOCUMENTS, KycStatus.CORRECTION_REQUIRED,
})


class IdentityError(Exception):
    http_status = 422
    code = "KYC_IDENTITY_ERROR"


class NotEditable(IdentityError):
    http_status = 409
    code = "KYC_NOT_EDITABLE"


class DuplicateIdentity(IdentityError):
    """
    La CURP o el RFC ya pertenecen a otro expediente. El mensaje al usuario es genérico
    (no confirma que la CURP exista); el detalle queda en auditoría para revisión.
    """

    http_status = 409
    code = "KYC_IDENTITY_CONFLICT"

    def __init__(self, message: str, conflicting_profile_id: uuid.UUID | None = None):
        super().__init__(message)
        self.conflicting_profile_id = conflicting_profile_id


def create_kyc_profile(db: Session, technician_id: uuid.UUID, ctx: RequestContext | None = None) -> KycProfile:
    """Crea el expediente vacío (NOT_STARTED) con su propia llave de datos. No hace commit."""
    profile_id = uuid.uuid4()
    profile = KycProfile(id=profile_id, technician_id=technician_id, data_key_enc=new_wrapped_dek(profile_id))
    db.add(profile)
    db.flush()
    system = Actor.system()
    db.add(KycStatusHistory(kyc_profile_id=profile_id, from_status=None, to_status=KycStatus.NOT_STARTED,
                            actor_type=system.actor_type, note="Expediente creado al registrar al técnico"))
    write_audit(db, action="kyc.profile.created", actor=system, technician_id=technician_id,
                kyc_profile_id=profile_id, target_type="kyc_profile", target_id=str(profile_id), ctx=ctx)
    return profile


def set_identity(
    db: Session,
    profile: KycProfile,
    actor: Actor,
    *,
    first_names: str,
    paternal_surname: str,
    maternal_surname: str | None,
    birth_date: date,
    curp: str,
    rfc: str,
    ctx: RequestContext | None = None,
) -> None:
    """Valida, detecta duplicados, cifra y guarda los datos de identidad. No hace commit."""
    if profile.status not in IDENTITY_EDITABLE_STATES:
        raise NotEditable("Los datos de identidad no se pueden modificar en el estado actual")
    if actor.user_id != profile.technician_id:
        raise PermissionError("Solo el titular captura sus datos de identidad")

    validate_adult(birth_date)
    curp_info = validate_curp_matches(curp, birth_date)
    rfc_norm = validate_rfc_persona_fisica(rfc, birth_date)
    # El RFC y la CURP de una persona física comparten las 4 letras iniciales en la mayoría
    # de los casos, pero hay excepciones legítimas (palabras altisonantes, homónimos): no se bloquea.

    curp_h, rfc_h = blind_index("curp", curp_info.curp), blind_index("rfc", rfc_norm)
    clash = db.scalar(
        select(KycProfile.id).where(
            KycProfile.id != profile.id,
            (KycProfile.curp_hash == curp_h) | (KycProfile.rfc_hash == rfc_h),
        ).limit(1)
    )
    if clash is not None:
        write_audit(db, action="kyc.identity.duplicate_detected", actor=actor,
                    technician_id=profile.technician_id, kyc_profile_id=profile.id,
                    target_type="kyc_profile", target_id=str(profile.id),
                    changes={"conflicting_profile_id": str(clash)}, ctx=ctx)
        db.flush()
        raise DuplicateIdentity("No pudimos validar tus datos. Contacta a soporte.", conflicting_profile_id=clash)

    cipher = cipher_for_profile(profile.id, profile.data_key_enc)
    profile.first_names = first_names.strip()
    profile.paternal_surname = paternal_surname.strip()
    profile.maternal_surname = maternal_surname.strip() if maternal_surname else None
    profile.birth_date = birth_date
    profile.curp_enc = cipher.encrypt(_TABLE, profile.id, "curp", curp_info.curp)
    profile.curp_hash = curp_h
    profile.rfc_enc = cipher.encrypt(_TABLE, profile.id, "rfc", rfc_norm)
    profile.rfc_hash = rfc_h

    write_audit(db, action="kyc.identity.updated", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, target_type="kyc_profile", target_id=str(profile.id),
                changes={"curp_masked": mask_identifier(curp_info.curp),
                         "rfc_masked": mask_identifier(rfc_norm)}, ctx=ctx)
    db.flush()


def read_identifiers(profile: KycProfile) -> tuple[str | None, str | None]:
    """Descifra CURP y RFC. Solo para el titular o un revisor con el caso asignado (lo valida la API)."""
    if profile.curp_enc is None:
        return None, None
    cipher = cipher_for_profile(profile.id, profile.data_key_enc)
    return (cipher.decrypt(_TABLE, profile.id, "curp", profile.curp_enc),
            cipher.decrypt(_TABLE, profile.id, "rfc", profile.rfc_enc))


def crypto_shred(db: Session, profile: KycProfile, actor: Actor, ctx: RequestContext | None = None) -> None:
    """
    Borrado criptográfico: destruye la llave del expediente. CURP, RFC y números de
    documento quedan ilegibles para siempre, incluso en respaldos. Lo usará el job de
    retención (Fase 5); respeta legal_hold.
    """
    if profile.legal_hold:
        raise PermissionError("El expediente tiene retención legal activa")
    profile.data_key_enc = None
    profile.anonymized_at = datetime.now(timezone.utc)
    write_audit(db, action="kyc.profile.crypto_shredded", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, target_type="kyc_profile", target_id=str(profile.id), ctx=ctx)
    db.flush()
