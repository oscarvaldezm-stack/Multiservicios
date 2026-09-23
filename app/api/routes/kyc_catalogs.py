"""Catálogos de solo lectura para los formularios del KYC. Requieren sesión (cualquier rol)."""
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import select

from app.api.deps import DbSession, get_current_user
from app.core.config import get_settings
from app.kyc.requirements import ConsentPurpose
from app.models import DocumentType, MxMunicipality, MxPostalSettlement, MxState
from app.schemas.kyc import DocumentTypeOut, PostalCodeOut, PrivacyNoticeOut, StateOut

router = APIRouter(prefix="/kyc/catalogs", tags=["kyc (catálogos)"], dependencies=[Depends(get_current_user)])

_PURPOSES = [
    {"code": ConsentPurpose.KYC_IDENTITY.value, "required": True,
     "title": "Verificación de identidad y domicilio",
     "summary": "Usamos tus datos y documentos para verificar tu identidad antes de que ofrezcas servicios."},
    {"code": ConsentPurpose.BIOMETRIC_SELFIE.value, "required": True,
     "title": "Selfie con tu identificación (dato biométrico)",
     "summary": "Un revisor compara tu selfie con la foto de tu identificación. Requiere tu consentimiento expreso."},
    {"code": ConsentPurpose.BACKGROUND_CHECK.value, "required": False,
     "title": "Carta de antecedentes no penales (opcional)",
     "summary": "Si la subes, mostramos una insignia de confianza en tu perfil."},
]


@router.get("/privacy-notice", response_model=PrivacyNoticeOut)
def privacy_notice():
    # El texto íntegro del aviso lo publica el área legal; aquí va la versión y las finalidades.
    return {"version": get_settings().KYC_PRIVACY_NOTICE_VERSION, "purposes": _PURPOSES}


@router.get("/document-types", response_model=list[DocumentTypeOut])
def document_types(db: DbSession):
    return db.scalars(select(DocumentType).where(DocumentType.is_active.is_(True))
                      .order_by(DocumentType.sort_order)).all()


@router.get("/states", response_model=list[StateOut])
def states(db: DbSession):
    return db.scalars(select(MxState).order_by(MxState.name)).all()


@router.get("/states/{state_id}/municipalities", response_model=list[StateOut])
def municipalities(db: DbSession, state_id: int = Path(ge=1, le=32)):
    return db.scalars(select(MxMunicipality).where(MxMunicipality.state_id == state_id)
                      .order_by(MxMunicipality.name)).all()


@router.get("/postal-codes/{postal_code}", response_model=PostalCodeOut)
def postal_code(db: DbSession, postal_code: str = Path(pattern=r"^\d{5}$"),
                limit: int = Query(default=200, ge=1, le=500)):
    rows = db.execute(
        select(MxPostalSettlement, MxMunicipality, MxState)
        .join(MxMunicipality, MxMunicipality.id == MxPostalSettlement.municipality_id)
        .join(MxState, MxState.id == MxMunicipality.state_id)
        .where(MxPostalSettlement.postal_code == postal_code)
        .order_by(MxPostalSettlement.name).limit(limit)
    ).all()
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"code": "POSTAL_CODE_NOT_FOUND", "message": "Código postal no encontrado"})
    return {"postal_code": postal_code, "settlements": [
        {"id": s.id, "name": s.name, "settlement_type": s.settlement_type, "city": s.city,
         "municipality_id": m.id, "municipality": m.name, "state_id": st.id, "state": st.name}
        for s, m, st in rows
    ]}
