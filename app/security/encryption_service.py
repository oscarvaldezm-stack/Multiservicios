"""
EncryptionService: punto único para cifrar, descifrar, enmascarar, rotar llaves y validar
acceso a datos sensibles. El resto del código no usa AES ni llaves directamente.

Jerarquía de llaves (envelope encryption):

    KEK (KMS / entorno, versionada)            -> nunca sale del proveedor de llaves
     └─ DEK por expediente (kyc_profiles.data_key_enc)
         ├─ campos: CURP, RFC, número de documento
         └─ FEK por archivo (kyc_document_files.file_key_enc)
             └─ bytes del documento y su vista previa (en el bucket)

Rotar la KEK = re-envolver las DEK (rápido; ni campos ni archivos se tocan).
Si una DEK se compromete = re-key del expediente (DEK nueva; se re-cifran campos y FEK;
los archivos no se tocan porque su FEK sigue siendo secreta).
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor
from app.core.config import get_settings
from app.core.crypto import (
    FILE_TABLE,
    CryptoError,
    FieldCipher,
    KeyProvider,
    _b64_key,
    blind_index,
    cipher_for_profile,
    decrypt_file,
    encrypt_file,
    get_key_provider,
    key_fingerprint,
    mask_identifier,
    new_file_key,
    new_wrapped_dek,
)
from app.kyc.permissions import Permission, permissions_for
from app.models import (
    EncryptionKeyMetadata,
    KeyPurpose,
    KeyStatus,
    KycDocument,
    KycDocumentFile,
    KycProfile,
)

PROFILE_TABLE = "kyc_profiles"
DOCUMENT_TABLE = "kyc_documents"


class KeyConfigurationError(Exception):
    """La configuración de llaves del entorno no coincide con lo registrado en la base."""


# =============================================================================
# Cifrado de campos y archivos
# =============================================================================
def cipher(profile: KycProfile, provider: KeyProvider | None = None) -> FieldCipher:
    return cipher_for_profile(profile.id, profile.data_key_enc, provider)


def encrypt_data(profile: KycProfile, table: str, row_id: uuid.UUID, field: str, value: str) -> bytes:
    return cipher(profile).encrypt(table, row_id, field, value)


def decrypt_data(profile: KycProfile, table: str, row_id: uuid.UUID, field: str, blob: bytes) -> str:
    return cipher(profile).decrypt(table, row_id, field, blob)


def new_encrypted_file(profile: KycProfile, file_id: uuid.UUID, data: bytes) -> tuple[bytes, bytes]:
    """Genera la FEK del archivo. Devuelve (fek_envuelta_con_la_DEK, bytes_cifrados)."""
    fek = new_file_key()
    wrapped = cipher(profile).encrypt_bytes(FILE_TABLE, file_id, "fek", fek)
    return wrapped, encrypt_file(fek, file_id, "original", data)


def file_key(profile: KycProfile, f: KycDocumentFile) -> bytes:
    if f.file_key_enc is None:
        raise CryptoError("El archivo fue purgado: su llave ya no existe")
    return cipher(profile).decrypt_bytes(FILE_TABLE, f.id, "fek", f.file_key_enc)


def encrypt_file_variant(profile: KycProfile, f: KycDocumentFile, variant: str, data: bytes) -> bytes:
    return encrypt_file(file_key(profile, f), f.id, variant, data)


def decrypt_file_variant(profile: KycProfile, f: KycDocumentFile, variant: str, blob: bytes) -> bytes:
    return decrypt_file(file_key(profile, f), f.id, variant, blob)


# =============================================================================
# Enmascarado
# =============================================================================
def mask_sensitive_data(kind: str, value: str | None) -> str | None:
    """
    clabe / account / card / phone: solo los últimos 4 dígitos.
    curp / rfc / document_number: primeros 4 y últimos 2.
    email: primera letra del usuario y dominio completo.
    """
    if value is None:
        return None
    v = re.sub(r"\s|-", "", value)
    if kind in {"clabe", "account", "card", "phone"}:
        return "*" * max(0, len(v) - 4) + v[-4:]
    if kind in {"curp", "rfc", "document_number"}:
        return mask_identifier(v)
    if kind == "email":
        user, _, domain = value.partition("@")
        return (user[:1] + "***@" + domain) if domain else "***"
    raise ValueError(f"Tipo de dato desconocido para enmascarar: {kind}")


# =============================================================================
# Control de acceso
# =============================================================================
def validate_access(actor: Actor, permission: Permission, *, owner_id: uuid.UUID | None = None,
                    assigned_to: uuid.UUID | None = None) -> bool:
    """
    Regla común para datos sensibles:
    - el titular accede a lo suyo;
    - un administrador necesita el permiso y, si el permiso es "de caso asignado", la asignación.
    """
    if owner_id is not None and actor.user_id == owner_id:
        return True
    perms = permissions_for(actor.admin_roles)
    if permission not in perms:
        return False
    if permission == Permission.KYC_CASE_READ_ASSIGNED:
        return assigned_to is not None and assigned_to == actor.user_id
    return True


# =============================================================================
# Gestión y rotación de llaves
# =============================================================================
def verify_key_configuration(db: Session, provider: KeyProvider | None = None) -> None:
    """
    Verifica al arrancar (worker, scripts) que:
    - la KEK activa del entorno está registrada como ACTIVE y su huella coincide;
    - ninguna llave configurada está REVOCADA;
    - la llave de índice ciego coincide con la registrada.
    Así una llave equivocada o revocada se detecta antes de escribir datos ilegibles.
    """
    provider = provider or get_key_provider()
    meta = {(m.purpose, m.key_id): m for m in db.scalars(select(EncryptionKeyMetadata))}
    for kid, fp in provider.fingerprints().items():
        m = meta.get((KeyPurpose.KYC_KEK, kid))
        if m is None:
            raise KeyConfigurationError(f"La llave maestra {kid} no está registrada")
        if m.fingerprint != fp:
            raise KeyConfigurationError(f"La llave maestra {kid} no coincide con la registrada")
        if m.status == KeyStatus.REVOKED:
            raise KeyConfigurationError(f"La llave maestra {kid} está REVOCADA: retírala de la configuración")
    active = meta.get((KeyPurpose.KYC_KEK, provider.active_key_id))
    if active is None or active.status != KeyStatus.ACTIVE:
        raise KeyConfigurationError("La llave maestra configurada como activa no está ACTIVE en la base")
    bi_fp = key_fingerprint(_b64_key(get_settings().KYC_BLIND_INDEX_KEY.get_secret_value(), "KYC_BLIND_INDEX_KEY"))
    bi = [m for (p, _), m in meta.items() if p == KeyPurpose.BLIND_INDEX and m.status == KeyStatus.ACTIVE]
    if not bi or bi[0].fingerprint != bi_fp:
        raise KeyConfigurationError("La llave de índice ciego no coincide con la registrada")


def register_active_kek(db: Session, actor: Actor, provider: KeyProvider | None = None,
                        external_ref: str | None = None) -> EncryptionKeyMetadata:
    """Paso 1 de la rotación: la KEK nueva (ya configurada como activa) pasa a ACTIVE y la anterior a DECRYPT_ONLY."""
    provider = provider or get_key_provider()
    kid = provider.active_key_id
    fp = provider.fingerprints()[kid]
    now = datetime.now(timezone.utc)
    existing = db.get(EncryptionKeyMetadata, (KeyPurpose.KYC_KEK, kid))
    if existing is not None:
        if existing.fingerprint != fp:
            raise KeyConfigurationError(f"El id {kid} ya existe con otra llave; usa un id nuevo")
        if existing.status == KeyStatus.REVOKED:
            raise KeyConfigurationError("No se puede reactivar una llave revocada")
    db.execute(update(EncryptionKeyMetadata)
               .where(EncryptionKeyMetadata.purpose == KeyPurpose.KYC_KEK,
                      EncryptionKeyMetadata.status == KeyStatus.ACTIVE, EncryptionKeyMetadata.key_id != kid)
               .values(status=KeyStatus.DECRYPT_ONLY, retired_at=now))
    db.flush()
    if existing is None:
        existing = EncryptionKeyMetadata(purpose=KeyPurpose.KYC_KEK, key_id=kid, status=KeyStatus.ACTIVE,
                                         provider="local", external_ref=external_ref, fingerprint=fp,
                                         activated_at=now)
        db.add(existing)
    else:
        existing.status, existing.activated_at = KeyStatus.ACTIVE, now
    write_audit(db, action="security.key.activated", actor=actor, target_type="encryption_key",
                target_id=f"KYC_KEK:{kid}", changes={"fingerprint": fp})
    db.flush()
    return existing


def rotate_keys(db: Session, actor: Actor, provider: KeyProvider | None = None, batch_size: int = 500) -> int:
    """
    Paso 2: re-envuelve con la KEK activa toda DEK envuelta con otra versión. Idempotente
    y por lotes (se puede interrumpir y reanudar). Devuelve cuántas DEK se re-envolvieron.
    """
    provider = provider or get_key_provider()
    active = provider.active_key_id
    total = 0
    while True:
        rows = db.scalars(
            select(KycProfile)
            .where(KycProfile.data_key_enc.isnot(None),
                   func.get_byte(KycProfile.data_key_enc, 1) != active)
            .limit(batch_size).with_for_update(skip_locked=True)
        ).all()
        if not rows:
            break
        for p in rows:
            p.data_key_enc = provider.rewrap(p.data_key_enc, str(p.id).encode())
        total += len(rows)
        write_audit(db, action="security.key.rewrapped", actor=actor, target_type="encryption_key",
                    target_id=f"KYC_KEK:{active}", changes={"profiles": len(rows)})
        db.commit()
    return total


def count_wrapped_with(db: Session, key_id: int) -> int:
    return db.scalar(select(func.count()).select_from(KycProfile).where(
        KycProfile.data_key_enc.isnot(None), func.get_byte(KycProfile.data_key_enc, 1) == key_id))


def revoke_kek(db: Session, actor: Actor, key_id: int, reason: str) -> None:
    """Paso 3: revoca una KEK. Se niega si todavía hay DEK envueltas con ella (se perderían datos)."""
    m = db.get(EncryptionKeyMetadata, (KeyPurpose.KYC_KEK, key_id))
    if m is None:
        raise KeyConfigurationError("Llave no registrada")
    if m.status == KeyStatus.ACTIVE:
        raise KeyConfigurationError("No se puede revocar la llave activa; activa otra primero")
    pending = count_wrapped_with(db, key_id)
    if pending:
        raise KeyConfigurationError(f"Aún hay {pending} expedientes con esta llave: ejecuta rotate_keys primero")
    m.status, m.revoked_at, m.notes = KeyStatus.REVOKED, datetime.now(timezone.utc), reason[:300]
    write_audit(db, action="security.key.revoked", actor=actor, target_type="encryption_key",
                target_id=f"KYC_KEK:{key_id}", reason_note=reason[:1000])
    db.flush()


def rekey_profile(db: Session, actor: Actor, profile: KycProfile) -> None:
    """
    Si se sospecha que la DEK de UN expediente se filtró: genera una DEK nueva y re-cifra
    CURP, RFC, números de documento y las FEK de sus archivos. Los archivos del bucket no
    se tocan (su FEK no cambia, solo cómo está envuelta).
    """
    old = cipher(profile)
    new_wrapped = new_wrapped_dek(profile.id)
    new = cipher_for_profile(profile.id, new_wrapped)

    for field in ("curp", "rfc"):
        blob = getattr(profile, f"{field}_enc")
        if blob is not None:
            setattr(profile, f"{field}_enc",
                    new.encrypt_bytes(PROFILE_TABLE, profile.id, field,
                                      old.decrypt_bytes(PROFILE_TABLE, profile.id, field, blob)))
    for doc in db.scalars(select(KycDocument).where(KycDocument.kyc_profile_id == profile.id)):
        if doc.number_enc is not None:
            doc.number_enc = new.encrypt_bytes(DOCUMENT_TABLE, doc.id, "number",
                                               old.decrypt_bytes(DOCUMENT_TABLE, doc.id, "number", doc.number_enc))
        for f in db.scalars(select(KycDocumentFile).where(KycDocumentFile.document_id == doc.id)):
            if f.file_key_enc is not None:
                f.file_key_enc = new.encrypt_bytes(FILE_TABLE, f.id, "fek",
                                                   old.decrypt_bytes(FILE_TABLE, f.id, "fek", f.file_key_enc))
    profile.data_key_enc = new_wrapped
    write_audit(db, action="security.profile.rekeyed", actor=actor, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, target_type="kyc_profile", target_id=str(profile.id))
    db.flush()


def reindex_blind_indexes(db: Session, actor: Actor, new_key: bytes, batch_size: int = 500) -> int:
    """
    Rotación de la llave de índices ciegos: descifra cada CURP / RFC / número de documento y
    recalcula su HMAC con la llave nueva. Correr en ventana de mantenimiento y, al terminar,
    cambiar KYC_BLIND_INDEX_KEY y registrar la huella nueva.
    """
    total = 0
    last_id = None
    while True:
        stmt = select(KycProfile).where(KycProfile.data_key_enc.isnot(None)).order_by(KycProfile.id).limit(batch_size)
        if last_id is not None:
            stmt = stmt.where(KycProfile.id > last_id)
        profiles = db.scalars(stmt).all()
        if not profiles:
            break
        # Un HMAC con la llave nueva no puede chocar con uno viejo de otro expediente
        # (256 bits), así que los UNIQUE no estorban durante el recálculo.
        for p in profiles:
            c = cipher(p)
            if p.curp_enc is not None:
                p.curp_hash = blind_index("curp", c.decrypt(PROFILE_TABLE, p.id, "curp", p.curp_enc), new_key)
                p.rfc_hash = blind_index("rfc", c.decrypt(PROFILE_TABLE, p.id, "rfc", p.rfc_enc), new_key)
            for doc in db.scalars(select(KycDocument).where(KycDocument.kyc_profile_id == p.id,
                                                            KycDocument.number_enc.isnot(None))):
                code = doc.document_type.code
                doc.number_hash = blind_index(f"docnum:{code}",
                                              c.decrypt(DOCUMENT_TABLE, doc.id, "number", doc.number_enc), new_key)
            last_id = p.id
        total += len(profiles)
        db.flush()
    fp = key_fingerprint(new_key)
    now = datetime.now(timezone.utc)
    db.execute(update(EncryptionKeyMetadata)
               .where(EncryptionKeyMetadata.purpose == KeyPurpose.BLIND_INDEX,
                      EncryptionKeyMetadata.status == KeyStatus.ACTIVE)
               .values(status=KeyStatus.REVOKED, revoked_at=now, notes="Reemplazada por reindexado"))
    db.flush()
    next_id = (db.scalar(select(func.max(EncryptionKeyMetadata.key_id))
                         .where(EncryptionKeyMetadata.purpose == KeyPurpose.BLIND_INDEX)) or 0) + 1
    db.add(EncryptionKeyMetadata(purpose=KeyPurpose.BLIND_INDEX, key_id=next_id, status=KeyStatus.ACTIVE,
                                 provider="local", fingerprint=fp, activated_at=now))
    write_audit(db, action="security.blind_index.reindexed", actor=actor, target_type="encryption_key",
                target_id=f"BLIND_INDEX:{next_id}", changes={"profiles": total, "fingerprint": fp})
    db.flush()
    return total
