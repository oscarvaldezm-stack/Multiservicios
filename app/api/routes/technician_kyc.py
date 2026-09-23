"""
Endpoints del técnico sobre SU expediente. Todas las rutas son /me: el técnico nunca
envía el ID de un expediente, así que no hay forma de apuntar al de otra persona (IDOR).
"""
import uuid

from fastapi import APIRouter, Depends, File, Path, Query, Response, UploadFile, status

from app.api.deps import CurrentActor, CurrentTechnician, DbSession, ReqCtx, require_roles
from app.api.responses import document_image
from app.audit.writer import write_audit, write_audit_detached
from app.core.config import get_settings
from app.core.errors import DomainError
from app.kyc import documents, service
from app.kyc.identity import DuplicateIdentity
from app.kyc.requirements import REQUIRED_CONSENTS
from app.models import AuditResult, DocumentSide, UserRole
from app.schemas.kyc import (
    AddressIn,
    ConsentIn,
    ConsentStatusOut,
    DocumentCreateIn,
    DocumentSummaryOut,
    KycStatusOut,
    PersonalDataIn,
    TechnicianKycOut,
)
from app.storage.object_storage import get_storage

router = APIRouter(
    prefix="/technicians/me/kyc",
    tags=["kyc (técnico)"],
    dependencies=[Depends(require_roles(UserRole.TECHNICIAN))],
)


def _view(db, user) -> dict:
    return service.technician_view(db, service.get_technician_profile(db, user.id), user)


@router.get("", response_model=TechnicianKycOut, summary="Expediente completo del técnico")
def get_my_kyc(user: CurrentTechnician, db: DbSession):
    return _view(db, user)


@router.get("/status", response_model=KycStatusOut, summary="Estado y pendientes (ligero, para polling)")
def get_my_kyc_status(user: CurrentTechnician, db: DbSession):
    return service.status_view(db, service.get_technician_profile(db, user.id), user)


@router.post("/consents", response_model=ConsentStatusOut, status_code=status.HTTP_201_CREATED,
             summary="Aceptar el aviso de privacidad (y el consentimiento biométrico)")
def post_consents(data: ConsentIn, user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx):
    granted = service.record_consents(db, user, actor, data, ctx)
    db.commit()
    return {"notice_version": get_settings().KYC_PRIVACY_NOTICE_VERSION, "granted": granted,
            "required": [c.value for c in REQUIRED_CONSENTS]}


@router.put("/personal-data", response_model=TechnicianKycOut, summary="Capturar o corregir datos personales")
def put_personal_data(data: PersonalDataIn, user: CurrentTechnician, actor: CurrentActor, db: DbSession,
                      ctx: ReqCtx):
    try:
        service.save_personal_data(db, user, actor, data, ctx)
    except DuplicateIdentity as exc:
        db.rollback()
        # La petición falla y hace rollback: el intento se audita en una transacción aparte.
        write_audit_detached(action="kyc.identity.duplicate_detected", actor=actor, result=AuditResult.DENIED,
                             technician_id=user.id, target_type="kyc_profile",
                             changes={"conflicting_profile_id": str(exc.conflicting_profile_id)}, ctx=ctx)
        raise
    db.commit()
    return _view(db, user)


@router.put("/address", response_model=TechnicianKycOut, summary="Capturar o actualizar el domicilio")
def put_address(data: AddressIn, user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx):
    service.save_address(db, user, actor, data, ctx)
    db.commit()
    return _view(db, user)


@router.post("/submission", response_model=KycStatusOut, status_code=status.HTTP_202_ACCEPTED,
             summary="Enviar el expediente a revisión")
def post_submission(user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx):
    profile = service.submit(db, user, actor, ctx)
    db.commit()
    return service.status_view(db, profile, user)


# ---------------------------------------------------------------------------
# Documentos
# ---------------------------------------------------------------------------
@router.post("/documents", response_model=DocumentSummaryOut, status_code=status.HTTP_201_CREATED,
             summary="Dar de alta un documento (tipo, número, fechas)")
def post_document(data: DocumentCreateIn, user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx):
    doc = documents.create_document(db, user, actor, documents.DocumentCreate(
        type_code=data.type_code, document_number=data.document_number,
        issued_at=data.issued_at, expires_at=data.expires_at), ctx)
    db.commit()
    return _document(db, user, doc.id)


@router.put("/documents/{document_id}/files/{side}", response_model=DocumentSummaryOut,
            status_code=status.HTTP_202_ACCEPTED,
            summary="Subir un lado o página del documento (queda en cuarentena hasta el escaneo)")
async def put_document_file(
    user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx,
    document_id: uuid.UUID = Path(), side: DocumentSide = Path(),
    page_number: int | None = Query(default=None, ge=1, le=5),
    file: UploadFile = File(...),
):
    limit = get_settings().KYC_MAX_FILE_BYTES
    data = await file.read(limit + 1)           # nunca se lee más allá del límite + 1 byte
    await file.close()
    documents.upload_file(db, get_storage(), user, actor, document_id, side, data, file.filename,
                          file.content_type, page_number, ctx)
    db.commit()
    return _document(db, user, document_id)


@router.delete("/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Eliminar un documento no aprobado (borrado seguro de sus archivos)")
def delete_document(user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx,
                    document_id: uuid.UUID = Path()):
    documents.delete_document(db, get_storage(), user, actor, document_id, ctx)
    db.commit()


@router.get("/documents/{document_id}/files/{file_id}/preview", response_class=Response,
            summary="Ver la vista previa de un archivo propio (con marca de agua)")
def get_own_preview(user: CurrentTechnician, actor: CurrentActor, db: DbSession, ctx: ReqCtx,
                    document_id: uuid.UUID = Path(), file_id: uuid.UUID = Path()):
    profile = service.get_technician_profile(db, user.id)
    f = documents.load_file(db, file_id, document_id, profile.id)
    if f is None:
        raise DomainError("Archivo no encontrado", code="FILE_NOT_FOUND", http_status=404)
    image = documents.render_preview(db, get_storage(), profile, f, documents.watermark_label(actor))
    write_audit(db, action="kyc.file.viewed", actor=actor, technician_id=user.id, kyc_profile_id=profile.id,
                document_id=document_id, target_type="kyc_document_file", target_id=str(file_id), ctx=ctx)
    db.commit()
    return document_image(image)


def _document(db, user, document_id) -> dict:
    profile = service.get_technician_profile(db, user.id)
    for d in service.documents_view(db, profile, include_superseded=True):
        if d["id"] == document_id:
            return d
    raise DomainError("Documento no encontrado", code="DOC_NOT_FOUND", http_status=404)
