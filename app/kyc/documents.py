"""
Documentos KYC: alta, subida, procesamiento en cuarentena, borrado seguro y visualización.

Flujo de un archivo:
  1. API: valida tamaño / tipo real / extensión / dimensiones  ->  cifra con una FEK nueva
     ->  guarda en el bucket de CUARENTENA  ->  scan_status = PENDING (202).
  2. Worker (aislado): descifra -> antivirus -> sanea (imagen re-codificada sin metadatos;
     PDF revisado y convertido a imagen) -> cifra original y vista previa -> bucket LIMPIO
     -> borra de cuarentena -> CLEAN.  Si algo falla: INVALID / INFECTED y se purga.
  3. Solo archivos CLEAN cuentan para enviar el expediente y solo ellos se pueden ver.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.crypto import blind_index
from app.core.errors import DomainError
from app.kyc import files as fx
from app.kyc.requirements import ConsentPurpose
from app.kyc.service import Scope, _require_consent, _require_scope, get_technician_profile
from app.models import (
    ActorType,
    AuditResult,
    DocumentCategory,
    DocumentSide,
    DocumentType,
    KycDocument,
    KycDocumentFile,
    KycDocumentStatus,
    KycProfile,
    KycStatus,
    OutboxEvent,
    ScanStatus,
    User,
)
from app.security import encryption_service as enc
from app.security.scanner import Scanner, ScannerUnavailable
from app.storage.object_storage import ObjectNotFound, ObjectStorage

D = KycDocumentStatus
# Documentos que se pueden completar o reemplazar archivo por archivo.
_OPEN_FOR_FILES = {D.UPLOADING, D.INVALID}
# Documentos "vivos": impiden crear otro de la misma categoría.
_LIVE = {D.UPLOADING, D.SCANNING, D.PENDING_REVIEW, D.APPROVED, D.INVALID}
_DOC_NUMBER_RULES: dict[str, re.Pattern[str]] = {
    "INE": re.compile(r"^[A-Z]{6}\d{8}[HM]\d{3}$"),          # clave de elector (18)
    "PASSPORT_MX": re.compile(r"^[A-Z]\d{8}$"),
    "CURP_BIOMETRIC": re.compile(r"^[A-Z0-9]{18}$"),
}
_GENERIC_NUMBER = re.compile(r"^[A-Z0-9]{5,20}$")


# =============================================================================
# Reglas por tipo
# =============================================================================
def allowed_sides(dt: DocumentType) -> list[DocumentSide]:
    if dt.category == DocumentCategory.SELFIE:
        return [DocumentSide.SELFIE]
    if dt.sides_required == 2:
        return [DocumentSide.FRONT, DocumentSide.BACK]
    return [DocumentSide.PAGE]


def allowed_mimes(dt: DocumentType) -> frozenset[str]:
    # Selfie e identificaciones de dos caras: foto. Pasaporte y comprobantes: foto o PDF.
    if dt.category == DocumentCategory.SELFIE or dt.sides_required == 2:
        return fx.IMAGE_MIME
    return fx.ALLOWED_MIME


@dataclass(frozen=True)
class DocumentCreate:
    type_code: str
    document_number: str | None
    issued_at: date | None
    expires_at: date | None


def _validate_metadata(dt: DocumentType, data: DocumentCreate, today: date) -> str | None:
    number = None
    if dt.requires_number:
        if not data.document_number:
            raise DomainError("Captura el número del documento", code="DOC_NUMBER_REQUIRED", http_status=422)
        number = re.sub(r"[\s-]", "", data.document_number).upper()
        if not _DOC_NUMBER_RULES.get(dt.code, _GENERIC_NUMBER).fullmatch(number):
            raise DomainError("El número del documento no tiene un formato válido",
                              code="DOC_NUMBER_FORMAT", http_status=422)
    elif data.document_number:
        raise DomainError("Este documento no lleva número", code="DOC_NUMBER_NOT_EXPECTED", http_status=422)

    if dt.requires_expiry:
        if data.expires_at is None:
            raise DomainError("Captura la fecha de vencimiento", code="DOC_EXPIRY_REQUIRED", http_status=422)
        if data.expires_at <= today:
            raise DomainError("El documento está vencido", code="DOC_EXPIRED", http_status=422)
    if dt.requires_issue_date:
        if data.issued_at is None:
            raise DomainError("Captura la fecha de emisión", code="DOC_ISSUE_DATE_REQUIRED", http_status=422)
        if data.issued_at > today:
            raise DomainError("La fecha de emisión no puede ser futura", code="DOC_ISSUE_DATE_FUTURE", http_status=422)
        if dt.max_age_days and data.issued_at < today - timedelta(days=dt.max_age_days):
            raise DomainError(f"El documento debe tener {dt.max_age_days} días de antigüedad como máximo",
                              code="DOC_TOO_OLD", http_status=422)
    if data.expires_at and data.issued_at and data.expires_at <= data.issued_at:
        raise DomainError("La vigencia debe ser posterior a la emisión", code="DOC_DATES_INVALID", http_status=422)
    return number


def _own_document(db: Session, profile: KycProfile, document_id: uuid.UUID, *, lock: bool = False) -> KycDocument:
    stmt = (select(KycDocument)
            .where(KycDocument.id == document_id, KycDocument.kyc_profile_id == profile.id,
                   KycDocument.deleted_at.is_(None))
            .options(selectinload(KycDocument.files), selectinload(KycDocument.document_type)))
    if lock:
        stmt = stmt.with_for_update(of=KycDocument)
    doc = db.scalar(stmt)
    if doc is None:  # ajeno o inexistente: misma respuesta
        raise DomainError("Documento no encontrado", code="DOC_NOT_FOUND", http_status=404)
    return doc


# =============================================================================
# Alta de documento
# =============================================================================
def create_document(db: Session, user: User, actor: Actor, data: DocumentCreate,
                    ctx: RequestContext | None = None, today: date | None = None) -> KycDocument:
    today = today or date.today()
    _require_consent(db, user, ConsentPurpose.KYC_IDENTITY)
    profile = get_technician_profile(db, user.id, lock=True)
    _require_scope(db, profile, Scope.DOCUMENTS)
    dt = db.scalar(select(DocumentType).where(DocumentType.code == data.type_code, DocumentType.is_active.is_(True)))
    if dt is None:
        raise DomainError("Tipo de documento no disponible", code="DOC_TYPE_UNKNOWN", http_status=422)
    if dt.category == DocumentCategory.SELFIE:
        _require_consent(db, user, ConsentPurpose.BIOMETRIC_SELFIE)
    if dt.category == DocumentCategory.BACKGROUND_CHECK:
        _require_consent(db, user, ConsentPurpose.BACKGROUND_CHECK)
    if dt.category == DocumentCategory.ADDRESS and profile.current_address_id is None:
        raise DomainError("Captura tu domicilio antes de subir el comprobante",
                          code="ADDRESS_REQUIRED_FIRST", http_status=409)
    number = _validate_metadata(dt, data, today)

    # Un solo documento vivo por categoría. Uno rechazado, vencido o de otro domicilio se reemplaza.
    same_cat = db.scalars(
        select(KycDocument).join(DocumentType).where(
            KycDocument.kyc_profile_id == profile.id, KycDocument.deleted_at.is_(None),
            DocumentType.category == dt.category, KycDocument.status.in_([*_LIVE, D.REJECTED, D.EXPIRED]),
        ).with_for_update(of=KycDocument)
    ).all()
    supersedes = None
    for old in same_cat:
        replaceable = (old.status in {D.REJECTED, D.EXPIRED}
                       or (old.status == D.APPROVED and old.expires_at is not None and old.expires_at <= today)
                       or (old.status == D.APPROVED and profile.status == KycStatus.EXPIRED)   # revalidación
                       or (dt.category == DocumentCategory.ADDRESS and old.address_id != profile.current_address_id))
        if not replaceable:
            raise DomainError("Ya tienes un documento de este tipo; elimínalo antes de subir otro",
                              code="DOC_ALREADY_EXISTS", http_status=409, extra={"document_id": str(old.id)})
        old.status = D.SUPERSEDED
        supersedes = old.id

    doc = KycDocument(id=uuid.uuid4(), kyc_profile_id=profile.id, document_type_id=dt.id,
                      address_id=profile.current_address_id if dt.category == DocumentCategory.ADDRESS else None,
                      issued_at=data.issued_at, expires_at=data.expires_at, supersedes_id=supersedes,
                      status=D.UPLOADING)
    flags: list[str] = []
    if number:
        doc.number_enc = enc.encrypt_data(profile, enc.DOCUMENT_TABLE, doc.id, "number", number)
        doc.number_hash = blind_index(f"docnum:{dt.code}", number)
        elsewhere = db.scalar(select(func.count()).select_from(KycDocument).where(
            KycDocument.number_hash == doc.number_hash, KycDocument.kyc_profile_id != profile.id))
        if elsewhere:
            flags.append("DOCUMENT_NUMBER_IN_OTHER_PROFILE")   # no se bloquea: lo decide el revisor
    doc.risk_flags = flags or None
    db.add(doc)
    db.flush()
    write_audit(db, action="kyc.document.created", actor=actor, technician_id=user.id, kyc_profile_id=profile.id,
                document_id=doc.id, target_type="kyc_document", target_id=str(doc.id),
                changes={"type": dt.code, "supersedes": str(supersedes) if supersedes else None,
                         "number_masked": enc.mask_sensitive_data("document_number", number) if number else None,
                         "risk_flags": flags or None}, ctx=ctx)
    return doc


# =============================================================================
# Subida de archivo
# =============================================================================
def _purge_file(storage: ObjectStorage, f: KycDocumentFile) -> None:
    """Borrado seguro: se borran los objetos y se destruye la FEK. Lo que pudiera quedar en el
    versionado del bucket o en respaldos queda ilegible."""
    targets = [(f.bucket, f.object_key)]
    if f.preview_key:
        targets.append((get_settings().KYC_CLEAN_BUCKET, f.preview_key))
    for bucket, key in targets:
        try:
            storage.delete(bucket, key)
        except ObjectNotFound:
            pass
    f.file_key_enc = None
    f.purged_at = datetime.now(timezone.utc)


def upload_file(db: Session, storage: ObjectStorage, user: User, actor: Actor, document_id: uuid.UUID,
                side: DocumentSide, data: bytes, filename: str | None, content_type: str | None,
                page_number: int | None = None, ctx: RequestContext | None = None) -> KycDocumentFile:
    s = get_settings()
    profile = get_technician_profile(db, user.id, lock=True)
    _require_scope(db, profile, Scope.DOCUMENTS)
    doc = _own_document(db, profile, document_id, lock=True)
    dt = doc.document_type
    if doc.status not in _OPEN_FOR_FILES:
        raise DomainError("Este documento ya está completo; elimínalo para subir otro",
                          code="DOC_NOT_OPEN", http_status=409, extra={"status": doc.status.value})
    if side not in allowed_sides(dt):
        raise DomainError("Lado no válido para este documento", code="DOC_SIDE_INVALID", http_status=422,
                          extra={"allowed": [x.value for x in allowed_sides(dt)]})
    if side == DocumentSide.PAGE:
        page_number = page_number or 1
        if not 1 <= page_number <= dt.max_files:
            raise DomainError("Número de página fuera de rango", code="DOC_PAGE_INVALID", http_status=422)
    else:
        page_number = None

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    uploads_today = db.scalar(select(func.count()).select_from(KycDocumentFile).join(KycDocument).where(
        KycDocument.kyc_profile_id == profile.id, KycDocumentFile.created_at >= since))
    if uploads_today >= s.KYC_MAX_UPLOADS_PER_DAY:
        raise DomainError("Alcanzaste el límite de archivos por día; intenta mañana",
                          code="UPLOAD_QUOTA_EXCEEDED", http_status=429)

    try:
        info = fx.validate_upload(data, filename, content_type, allowed=allowed_mimes(dt),
                                  max_bytes=s.KYC_MAX_FILE_BYTES, max_pixels=s.KYC_MAX_IMAGE_PIXELS)
    except fx.FileRejected as exc:
        raise DomainError(str(exc), code=exc.code, http_status=exc.http_status) from None

    # Reemplazo del mismo lado / página: el anterior se purga.
    for old in doc.files:
        if old.purged_at is None and old.side == side and old.page_number == page_number:
            _purge_file(storage, old)

    file_id = uuid.uuid4()
    wrapped_fek, blob = enc.new_encrypted_file(profile, file_id, data)
    key = f"kyc/{profile.id}/{file_id}"
    storage.put(s.KYC_QUARANTINE_BUCKET, key, blob)
    f = KycDocumentFile(id=file_id, document_id=doc.id, side=side, page_number=page_number,
                        bucket=s.KYC_QUARANTINE_BUCKET, object_key=key, detected_mime=info.mime,
                        size_bytes=info.size, sha256=info.sha256, width=info.width, height=info.height,
                        scan_status=ScanStatus.PENDING, file_key_enc=wrapped_fek)
    db.add(f)
    doc.files.append(f)
    live = [x for x in doc.files if x.purged_at is None]
    doc.status = D.SCANNING if len(live) >= dt.sides_required else D.UPLOADING
    db.flush()
    write_audit(db, action="kyc.document.file_uploaded", actor=actor, technician_id=user.id,
                kyc_profile_id=profile.id, document_id=doc.id, target_type="kyc_document_file",
                target_id=str(file_id), changes={"side": side.value, "mime": info.mime, "size": info.size}, ctx=ctx)
    return f


def delete_document(db: Session, storage: ObjectStorage, user: User, actor: Actor, document_id: uuid.UUID,
                    ctx: RequestContext | None = None) -> None:
    profile = get_technician_profile(db, user.id, lock=True)
    _require_scope(db, profile, Scope.DOCUMENTS)
    doc = _own_document(db, profile, document_id, lock=True)
    if doc.status == D.APPROVED:
        raise DomainError("Un documento aprobado no se puede eliminar", code="DOC_APPROVED", http_status=409)
    for f in doc.files:
        if f.purged_at is None:
            _purge_file(storage, f)
    doc.deleted_at = datetime.now(timezone.utc)
    write_audit(db, action="kyc.document.deleted", actor=actor, technician_id=user.id, kyc_profile_id=profile.id,
                document_id=doc.id, target_type="kyc_document", target_id=str(doc.id), ctx=ctx)
    db.flush()


# =============================================================================
# Worker: procesamiento de cuarentena
# =============================================================================
@dataclass
class ProcessStats:
    clean: int = 0
    rejected: int = 0
    retry: int = 0


def _reject(db: Session, storage: ObjectStorage, f: KycDocumentFile, doc: KycDocument, profile: KycProfile,
            status: ScanStatus, code: str, detail: str) -> None:
    system = Actor.system()
    f.scan_status, f.scan_detail = status, f"{code}: {detail}"[:200]
    f.scanned_at = datetime.now(timezone.utc)
    _purge_file(storage, f)
    doc.status = D.INVALID
    write_audit(db, action="kyc.file.rejected" if status != ScanStatus.INFECTED else "kyc.file.infected",
                actor=system, result=AuditResult.DENIED, technician_id=profile.technician_id,
                kyc_profile_id=profile.id, document_id=doc.id, target_type="kyc_document_file",
                target_id=str(f.id), reason_code=code, reason_note=detail[:1000])
    db.add(OutboxEvent(event_type="kyc.document.rejected", aggregate_type="kyc_document", aggregate_id=doc.id,
                       recipient_user_id=profile.technician_id, payload={"reason_code": code, "automatic": True}))


def process_pending(db: Session, storage: ObjectStorage, scanner: Scanner, limit: int = 20) -> ProcessStats:
    s = get_settings()
    stats = ProcessStats()
    files = db.scalars(
        select(KycDocumentFile).where(KycDocumentFile.scan_status == ScanStatus.PENDING,
                                      KycDocumentFile.purged_at.is_(None))
        .order_by(KycDocumentFile.created_at).limit(limit).with_for_update(skip_locked=True)
    ).all()
    for f in files:
        doc = db.get(KycDocument, f.document_id)
        profile = db.get(KycProfile, doc.kyc_profile_id)
        try:
            plain = enc.decrypt_file_variant(profile, f, "original", storage.get(f.bucket, f.object_key))
        except Exception as exc:  # noqa: BLE001  (objeto perdido o manipulado)
            _reject(db, storage, f, doc, profile, ScanStatus.ERROR, "FILE_UNREADABLE", exc.__class__.__name__)
            stats.rejected += 1
            continue

        try:
            result = scanner.scan(plain)
        except ScannerUnavailable as exc:
            f.scan_attempts += 1
            f.scan_detail = str(exc)[:200]
            if f.scan_attempts >= s.KYC_MAX_SCAN_ATTEMPTS:
                _reject(db, storage, f, doc, profile, ScanStatus.ERROR, "SCAN_UNAVAILABLE", str(exc))
                stats.rejected += 1
            else:
                stats.retry += 1        # falla cerrada: sigue PENDING, nunca se asume limpio
            continue
        if not result.clean:
            _reject(db, storage, f, doc, profile, ScanStatus.INFECTED, "FILE_INFECTED", result.signature or "")
            stats.rejected += 1
            continue

        try:
            if f.detected_mime in fx.IMAGE_MIME:
                stored, w, h = fx.sanitize_image(plain, s.KYC_MAX_IMAGE_PIXELS)
                preview, _, _ = fx.image_preview(stored)
                f.detected_mime, f.width, f.height = fx.JPEG, w, h
            else:
                f.page_count = fx.inspect_pdf(plain, s.KYC_MAX_PDF_PAGES)
                stored = plain                       # el PDF original se conserva (cifrado) como evidencia
                preview, w, h = fx.render_pdf_preview(plain, s.KYC_MAX_PDF_PAGES, s.KYC_MAX_IMAGE_PIXELS)
                f.width, f.height = w, h
        except fx.FileRejected as exc:
            _reject(db, storage, f, doc, profile, ScanStatus.INVALID, exc.code, str(exc))
            stats.rejected += 1
            continue

        quarantine_bucket, quarantine_key = f.bucket, f.object_key
        clean_key, preview_key = f"kyc/{profile.id}/{f.id}", f"kyc/{profile.id}/{f.id}-preview"
        storage.put(s.KYC_CLEAN_BUCKET, clean_key, enc.encrypt_file_variant(profile, f, "original", stored))
        storage.put(s.KYC_CLEAN_BUCKET, preview_key, enc.encrypt_file_variant(profile, f, "preview", preview))
        f.bucket, f.object_key, f.preview_key = s.KYC_CLEAN_BUCKET, clean_key, preview_key
        f.size_bytes = len(stored)
        f.scan_status, f.scan_engine, f.scan_detail = ScanStatus.CLEAN, result.engine, None
        f.scanned_at = datetime.now(timezone.utc)
        storage.delete(quarantine_bucket, quarantine_key)

        # Mismo archivo usado en OTRO expediente: señal de fraude para el revisor.
        reused = db.scalar(select(func.count()).select_from(KycDocumentFile).join(KycDocument).where(
            KycDocumentFile.sha256 == f.sha256, KycDocument.kyc_profile_id != profile.id))
        if reused:
            doc.risk_flags = sorted(set(doc.risk_flags or []) | {"FILE_REUSED_FROM_OTHER_PROFILE"})

        live = [x for x in doc.files if x.purged_at is None]
        if doc.status == D.SCANNING and len(live) >= doc.document_type.sides_required \
                and all(x.scan_status == ScanStatus.CLEAN for x in live):
            doc.status = D.PENDING_REVIEW
        write_audit(db, action="kyc.file.clean", actor=Actor.system(), technician_id=profile.technician_id,
                    kyc_profile_id=profile.id, document_id=doc.id, target_type="kyc_document_file",
                    target_id=str(f.id), changes={"engine": result.engine, "mime": f.detected_mime})
        stats.clean += 1
    db.flush()
    return stats


# =============================================================================
# Visualización
# =============================================================================
def load_file(db: Session, file_id: uuid.UUID, document_id: uuid.UUID, profile_id: uuid.UUID) -> KycDocumentFile | None:
    return db.scalar(
        select(KycDocumentFile).join(KycDocument)
        .where(KycDocumentFile.id == file_id, KycDocumentFile.document_id == document_id,
               KycDocument.kyc_profile_id == profile_id)
    )


def render_preview(db: Session, storage: ObjectStorage, profile: KycProfile, f: KycDocumentFile,
                   watermark_text: str) -> bytes:
    if f.scan_status != ScanStatus.CLEAN or f.purged_at is not None or not f.preview_key:
        raise DomainError("El archivo no está disponible", code="FILE_NOT_AVAILABLE", http_status=409)
    blob = storage.get(get_settings().KYC_CLEAN_BUCKET, f.preview_key)
    return fx.watermark(enc.decrypt_file_variant(profile, f, "preview", blob), watermark_text)


def views_last_hour(db: Session, actor_id: uuid.UUID) -> int:
    from app.models import AuditLog
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    return db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.actor_id == actor_id, AuditLog.action == "kyc.file.viewed", AuditLog.occurred_at >= since))


def watermark_label(actor: Actor) -> str:
    who = "TECNICO" if actor.actor_type == ActorType.TECHNICIAN else f"REVISOR {str(actor.user_id)[:8]}"
    return f"SOLO VERIFICACION KYC - {who} - {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"
