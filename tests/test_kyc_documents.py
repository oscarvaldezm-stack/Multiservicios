"""Subida, procesamiento y borrado de documentos KYC, de punta a punta contra PostgreSQL real."""
import io
from datetime import date, timedelta

import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.kyc import documents
from app.models import (
    AuditLog,
    KycDocument,
    KycDocumentFile,
    KycDocumentStatus,
    OutboxEvent,
    ScanStatus,
    User,
)
from app.security import encryption_service as enc
from app.security.scanner import ClamdScanner, DevEicarScanner
from app.storage.object_storage import get_storage
from scripts.load_sepomex import iter_rows, load
from tests import filegen
from tests.conftest import API, auth, get_profile, login, register, valid_curp, valid_rfc, verify_email
from tests.test_sepomex import SAMPLE

KYC = f"{API}/technicians/me/kyc"
DOCS = f"{KYC}/documents"
S = get_settings()
TODAY = date.today()
INE_NUMBER = "HRGLGL56042730M500"


def _personal(n: int) -> dict:
    return {"first_names": "Gloria", "paternal_surname": "Hernández", "maternal_surname": "García",
            "birth_date": "1956-04-27", "curp": valid_curp(n), "rfc": valid_rfc(n)}


def onboard(client, db, category, email: str, n: int):
    register(client, "technician", email, category_ids=[category.id])
    uid = db.scalar(select(User.id).where(User.email == email))
    h = auth(login(client, email).json()["access_token"])
    client.post(f"{KYC}/consents", headers=h, json={"notice_version": "2026-09",
                                                    "purposes": ["KYC_IDENTITY", "BIOMETRIC_SELFIE"]})
    assert client.put(f"{KYC}/personal-data", headers=h, json=_personal(n)).status_code == 200
    from app.models import MxPostalSettlement
    sid = db.scalar(select(MxPostalSettlement.id).where(MxPostalSettlement.postal_code == "91700"))
    assert client.put(f"{KYC}/address", headers=h, json={"street": "Av. Independencia", "exterior_number": "100",
                                                         "postal_settlement_id": sid}).status_code == 200
    verify_email(db, uid)
    return uid, h


@pytest.fixture
def sepomex(db):
    load(db, iter_rows(io.StringIO(SAMPLE)))
    db.commit()


@pytest.fixture
def tech(client, db, category, sepomex):
    return onboard(client, db, category, "tec@example.com", 4)


def new_doc(client, h, code="INE", **kw):
    body = {"type_code": code}
    if code == "INE":
        body |= {"document_number": INE_NUMBER, "expires_at": str(TODAY + timedelta(days=900))}
    elif code in ("UTILITY_ELECTRICITY", "UTILITY_WATER"):
        body |= {"issued_at": str(TODAY - timedelta(days=10))}
    body |= kw
    return client.post(DOCS, headers=h, json=body)


def upload(client, h, doc_id, side, data, name="foto.jpg", ctype="image/jpeg"):
    return client.put(f"{DOCS}/{doc_id}/files/{side}", headers=h, files={"file": (name, data, ctype)})


def process(db, scanner=None):
    stats = documents.process_pending(db, get_storage(), scanner or DevEicarScanner())
    db.commit()
    db.expire_all()
    return stats


def raw_object(bucket, key) -> bytes:
    return get_storage().get(bucket, key)


# ------------------------------------------------------------------ alta
@pytest.mark.parametrize("body,code", [
    ({"document_number": None}, "DOC_NUMBER_REQUIRED"),
    ({"document_number": "123"}, "DOC_NUMBER_FORMAT"),
    ({"expires_at": str(TODAY - timedelta(days=1))}, "DOC_EXPIRED"),
    ({"expires_at": None}, "DOC_EXPIRY_REQUIRED"),
])
def test_alta_de_ine_valida_metadatos(body, code, client, tech):
    _, h = tech
    r = new_doc(client, h, **body)
    assert r.status_code == 422 and r.json()["detail"]["code"] == code


def test_comprobante_viejo_o_futuro_se_rechaza(client, tech):
    _, h = tech
    old = new_doc(client, h, "UTILITY_ELECTRICITY", issued_at=str(TODAY - timedelta(days=120)))
    assert old.json()["detail"]["code"] == "DOC_TOO_OLD"
    future = new_doc(client, h, "UTILITY_ELECTRICITY", issued_at=str(TODAY + timedelta(days=1)))
    assert future.json()["detail"]["code"] == "DOC_ISSUE_DATE_FUTURE"


def test_alta_ok_guarda_el_numero_cifrado(client, tech, db):
    _, h = tech
    r = new_doc(client, h)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "UPLOADING" and body["allowed_sides"] == ["FRONT", "BACK"]
    assert body["number_masked"] == "HRGL" + "•" * 12 + "00" and INE_NUMBER not in r.text
    doc = db.get(KycDocument, body["id"])
    assert doc.number_enc and INE_NUMBER.encode() not in doc.number_enc and len(doc.number_hash) == 64


def test_consentimientos_especificos(client, db, category, sepomex):
    register(client, "technician", "t2@example.com", category_ids=[category.id])
    h = auth(login(client, "t2@example.com").json()["access_token"])
    client.post(f"{KYC}/consents", headers=h, json={"notice_version": "2026-09", "purposes": ["KYC_IDENTITY"]})
    assert new_doc(client, h, "SELFIE_WITH_ID").json()["detail"]["code"] == "KYC_CONSENT_REQUIRED"
    r = new_doc(client, h, "CRIMINAL_RECORD_CERT", issued_at=str(TODAY))
    assert r.json()["detail"]["purpose"] == "BACKGROUND_CHECK"


def test_un_documento_vivo_por_categoria(client, tech, db):
    _, h = tech
    first = new_doc(client, h).json()["id"]
    dup = new_doc(client, h)
    assert dup.status_code == 409 and dup.json()["detail"]["code"] == "DOC_ALREADY_EXISTS"
    assert client.delete(f"{DOCS}/{first}", headers=h).status_code == 204
    assert new_doc(client, h).status_code == 201


def test_tipo_desconocido_o_inactivo(client, tech):
    _, h = tech
    assert new_doc(client, h, "CURP_BIOMETRIC").json()["detail"]["code"] == "DOC_TYPE_UNKNOWN"
    assert client.post(DOCS, headers=h, json={"type_code": "ine'; drop table--"}).status_code == 422


# ------------------------------------------------------------------ subida y cuarentena
def test_subida_cifra_y_deja_en_cuarentena(client, tech, db):
    _, h = tech
    doc_id = new_doc(client, h).json()["id"]
    original = filegen.jpeg()
    r = upload(client, h, doc_id, "FRONT", original)
    assert r.status_code == 202 and r.json()["status"] == "UPLOADING"
    f = db.scalar(select(KycDocumentFile).where(KycDocumentFile.document_id == doc_id))
    assert f.bucket == S.KYC_QUARANTINE_BUCKET and f.scan_status == ScanStatus.PENDING
    stored = raw_object(f.bucket, f.object_key)
    assert stored != original and not stored.startswith(b"\xff\xd8") and filegen.GPS_MARKER.encode() not in stored
    assert upload(client, h, doc_id, "BACK", filegen.jpeg(seed=2)).json()["status"] == "SCANNING"


def test_worker_escanea_sanea_y_mueve_al_bucket_limpio(client, tech, db):
    uid, h = tech
    doc_id = new_doc(client, h).json()["id"]
    upload(client, h, doc_id, "FRONT", filegen.jpeg())
    upload(client, h, doc_id, "BACK", filegen.jpeg(seed=3))
    q_keys = [(f.bucket, f.object_key) for f in db.scalars(select(KycDocumentFile))]
    assert process(db).clean == 2

    doc = db.get(KycDocument, doc_id)
    assert doc.status == KycDocumentStatus.PENDING_REVIEW
    profile = get_profile(db, uid)
    for f in doc.files:
        assert f.scan_status == ScanStatus.CLEAN and f.bucket == S.KYC_CLEAN_BUCKET and f.scan_engine == "dev-eicar"
        blob = raw_object(f.bucket, f.object_key)
        assert not blob.startswith(b"\xff\xd8")                       # cifrado en el bucket
        plain = enc.decrypt_file_variant(profile, f, "original", blob)
        assert plain.startswith(b"\xff\xd8") and filegen.GPS_MARKER.encode() not in plain   # sin EXIF / GPS
        assert raw_object(f.bucket, f.preview_key)
    for bucket, key in q_keys:
        assert not get_storage().exists(bucket, key)                  # cuarentena vacía


@pytest.mark.parametrize("data,name,ctype,status,code", [
    (filegen.pdf(), "ine.pdf", "application/pdf", 415, "FILE_TYPE_NOT_ALLOWED"),   # INE: solo foto
    (filegen.png(), "ine.pdf", "image/png", 415, "FILE_EXTENSION_MISMATCH"),
    (filegen.jpeg(), "ine.jpg", "image/png", 415, "FILE_CONTENT_TYPE_MISMATCH"),
    (b"GIF89a" + b"\x00" * 100, "ine.gif", "image/gif", 415, "FILE_TYPE_NOT_ALLOWED"),
    (b"<svg onload=alert(1)>", "ine.svg", "image/svg+xml", 415, "FILE_TYPE_NOT_ALLOWED"),
    (b"MZ\x90\x00", "ine.jpg", "image/jpeg", 415, "FILE_TYPE_NOT_ALLOWED"),         # ejecutable renombrado
    (filegen.jpeg(200, 200), "ine.jpg", "image/jpeg", 422, "IMAGE_TOO_SMALL"),
    (filegen.png_bomb_header(), "ine.png", "image/png", 413, "IMAGE_TOO_LARGE"),
    (b"\xff\xd8\xff" + b"\x00" * (10 * 1024 * 1024), "ine.jpg", "image/jpeg", 413, "FILE_TOO_LARGE"),
    (b"", "ine.jpg", "image/jpeg", 422, "FILE_EMPTY"),
])
def test_archivos_invalidos_se_rechazan_antes_de_guardar(data, name, ctype, status, code, client, tech, db):
    _, h = tech
    doc_id = new_doc(client, h).json()["id"]
    r = upload(client, h, doc_id, "FRONT", data, name, ctype)
    assert r.status_code == status and r.json()["detail"]["code"] == code
    assert db.scalar(select(func.count()).select_from(KycDocumentFile)) == 0


def test_lado_invalido_y_documento_ajeno(client, db, category, tech):
    _, h = tech
    doc_id = new_doc(client, h).json()["id"]
    assert upload(client, h, doc_id, "SELFIE", filegen.jpeg()).json()["detail"]["code"] == "DOC_SIDE_INVALID"
    _, h2 = onboard(client, db, category, "otro@example.com", 5)
    r = upload(client, h2, doc_id, "FRONT", filegen.jpeg())
    assert r.status_code == 404 and r.json()["detail"]["code"] == "DOC_NOT_FOUND"
    assert client.delete(f"{DOCS}/{doc_id}", headers=h2).status_code == 404


def test_archivo_infectado_se_purga_y_notifica(client, tech, db):
    uid, h = tech
    doc_id = new_doc(client, h).json()["id"]
    upload(client, h, doc_id, "FRONT", filegen.infected_jpeg())
    upload(client, h, doc_id, "BACK", filegen.jpeg(seed=4))
    f = db.scalar(select(KycDocumentFile).where(KycDocumentFile.side == "FRONT"))
    key = (f.bucket, f.object_key)
    stats = process(db)
    assert stats.rejected == 1
    f = db.get(KycDocumentFile, f.id)
    assert f.scan_status == ScanStatus.INFECTED and f.file_key_enc is None and f.purged_at is not None
    assert not get_storage().exists(*key)
    assert db.get(KycDocument, doc_id).status == KycDocumentStatus.INVALID
    assert db.scalar(select(AuditLog).where(AuditLog.action == "kyc.file.infected")) is not None
    assert db.scalar(select(OutboxEvent).where(OutboxEvent.event_type == "kyc.document.rejected"))
    # Documento INVALID: puede volver a subir ese lado.
    assert upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=9)).status_code == 202


@pytest.mark.parametrize("pdf_bytes,code", [
    (filegen.pdf(js=True), "PDF_ACTIVE_CONTENT"),
    (filegen.pdf(pages=6), "PDF_TOO_MANY_PAGES"),
    (filegen.pdf(encrypted=True), "PDF_ENCRYPTED"),
])
def test_pdf_peligroso_se_rechaza_en_el_worker(pdf_bytes, code, client, tech, db):
    _, h = tech
    doc_id = new_doc(client, h, "UTILITY_ELECTRICITY").json()["id"]
    assert upload(client, h, doc_id, "PAGE", pdf_bytes, "recibo.pdf", "application/pdf").status_code == 202
    process(db)
    f = db.scalar(select(KycDocumentFile))
    assert f.scan_status in (ScanStatus.INVALID, ScanStatus.ERROR) and code in f.scan_detail


def test_pdf_limpio_se_convierte_a_imagen_y_conserva_el_original(client, tech, db):
    uid, h = tech
    doc_id = new_doc(client, h, "UTILITY_ELECTRICITY").json()["id"]
    upload(client, h, doc_id, "PAGE", filegen.pdf(pages=2), "recibo.pdf", "application/pdf")
    process(db)
    f = db.scalar(select(KycDocumentFile))
    assert f.scan_status == ScanStatus.CLEAN and f.page_count == 2 and f.detected_mime == "application/pdf"
    profile = get_profile(db, uid)
    original = enc.decrypt_file_variant(profile, f, "original", raw_object(f.bucket, f.object_key))
    preview = enc.decrypt_file_variant(profile, f, "preview", raw_object(f.bucket, f.preview_key))
    assert original.startswith(b"%PDF-") and preview.startswith(b"\xff\xd8")


def test_antivirus_caido_falla_cerrado_y_reintenta(client, tech, db, monkeypatch):
    _, h = tech
    doc_id = new_doc(client, h, "SELFIE_WITH_ID").json()["id"]
    upload(client, h, doc_id, "SELFIE", filegen.jpeg())
    down = ClamdScanner("127.0.0.1", 1, timeout=0.5)       # puerto sin servicio
    assert process(db, down).retry == 1
    f = db.scalar(select(KycDocumentFile))
    assert f.scan_status == ScanStatus.PENDING and f.scan_attempts == 1   # nunca se asume limpio
    monkeypatch.setattr(S, "KYC_MAX_SCAN_ATTEMPTS", 2)
    process(db, down)
    f = db.scalar(select(KycDocumentFile))
    assert f.scan_status == ScanStatus.ERROR and f.purged_at is not None


def test_protocolo_clamd_instream():
    ok = filegen.FakeClamd(b"stream: OK\0")
    data = filegen.jpeg() * 3                              # varios bloques de 64 KB
    assert ClamdScanner("127.0.0.1", ok.port).scan(data).clean is True
    ok.thread.join(2)
    assert ok.received == data                             # el enmarcado reconstruye el archivo exacto
    bad = filegen.FakeClamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
    res = ClamdScanner("127.0.0.1", bad.port).scan(b"x" * 10)
    assert res.clean is False and res.signature == "Win.Test.EICAR_HDB-1"


def test_cuota_diaria_de_subidas(client, tech, monkeypatch):
    _, h = tech
    monkeypatch.setattr(S, "KYC_MAX_UPLOADS_PER_DAY", 2)
    doc_id = new_doc(client, h).json()["id"]
    upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=1))
    upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=2))     # reemplazo también cuenta
    r = upload(client, h, doc_id, "BACK", filegen.jpeg(seed=3))
    assert r.status_code == 429 and r.json()["detail"]["code"] == "UPLOAD_QUOTA_EXCEEDED"


def test_reemplazar_un_lado_purga_el_anterior(client, tech, db):
    _, h = tech
    doc_id = new_doc(client, h).json()["id"]
    upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=1))
    old = db.scalar(select(KycDocumentFile))
    key = (old.bucket, old.object_key)
    upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=2))
    db.expire_all()
    old = db.get(KycDocumentFile, old.id)
    assert old.purged_at is not None and old.file_key_enc is None and not get_storage().exists(*key)


def test_eliminar_documento_borra_objetos_y_llaves(client, tech, db):
    _, h = tech
    doc_id = new_doc(client, h).json()["id"]
    upload(client, h, doc_id, "FRONT", filegen.jpeg())
    upload(client, h, doc_id, "BACK", filegen.jpeg(seed=5))
    process(db)
    keys = [(f.bucket, f.object_key) for f in db.scalars(select(KycDocumentFile))] + \
           [(S.KYC_CLEAN_BUCKET, f.preview_key) for f in db.scalars(select(KycDocumentFile))]
    assert client.delete(f"{DOCS}/{doc_id}", headers=h).status_code == 204
    db.expire_all()
    assert all(not get_storage().exists(*k) for k in keys)
    assert all(f.file_key_enc is None for f in db.scalars(select(KycDocumentFile)))
    assert db.scalar(select(AuditLog).where(AuditLog.action == "kyc.document.deleted"))


# ------------------------------------------------------------------ señales de fraude
def test_mismo_archivo_o_numero_en_otro_expediente_se_marca(client, db, category, tech):
    _, h = tech
    shared = filegen.jpeg(seed=77)
    d1 = new_doc(client, h).json()["id"]
    upload(client, h, d1, "FRONT", shared)
    upload(client, h, d1, "BACK", filegen.jpeg(seed=78))
    process(db)
    _, h2 = onboard(client, db, category, "impostor@example.com", 6)
    r = new_doc(client, h2)                                          # mismo número de INE
    d2 = r.json()["id"]
    assert r.json()["risk_flags"] is None                            # el técnico no ve las señales
    upload(client, h2, d2, "FRONT", shared)                          # misma foto
    upload(client, h2, d2, "BACK", filegen.jpeg(seed=79))
    process(db)
    flags = set(db.get(KycDocument, d2).risk_flags)
    assert flags == {"DOCUMENT_NUMBER_IN_OTHER_PROFILE", "FILE_REUSED_FROM_OTHER_PROFILE"}


# ------------------------------------------------------------------ vista propia
def test_tecnico_ve_su_vista_previa_con_marca_de_agua(client, tech, db):
    uid, h = tech
    doc_id = new_doc(client, h, "SELFIE_WITH_ID").json()["id"]
    upload(client, h, doc_id, "SELFIE", filegen.jpeg())
    f = db.scalar(select(KycDocumentFile))
    url = f"{DOCS}/{doc_id}/files/{f.id}/preview"
    assert client.get(url, headers=h).json()["detail"]["code"] == "FILE_NOT_AVAILABLE"   # aún en cuarentena
    process(db)
    r = client.get(url, headers=h)
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
    assert r.headers["cache-control"].startswith("no-store") and "sandbox" in r.headers["content-security-policy"]
    f = db.get(KycDocumentFile, f.id)
    stored_preview = enc.decrypt_file_variant(get_profile(db, uid), f, "preview",
                                              raw_object(S.KYC_CLEAN_BUCKET, f.preview_key))
    assert r.content != stored_preview                                 # lleva marca de agua


def test_tecnico_no_ve_archivos_de_otro(client, db, category, tech):
    _, h = tech
    doc_id = new_doc(client, h, "SELFIE_WITH_ID").json()["id"]
    upload(client, h, doc_id, "SELFIE", filegen.jpeg())
    process(db)
    fid = db.scalar(select(KycDocumentFile.id))
    _, h2 = onboard(client, db, category, "otro@example.com", 5)
    r = client.get(f"{DOCS}/{doc_id}/files/{fid}/preview", headers=h2)
    assert r.status_code == 404


# ------------------------------------------------------------------ integración con el envío
def test_flujo_completo_con_documentos_reales_hasta_el_envio(client, tech, db):
    _, h = tech
    ine = new_doc(client, h).json()["id"]
    upload(client, h, ine, "FRONT", filegen.jpeg(seed=11))
    upload(client, h, ine, "BACK", filegen.jpeg(seed=12))
    bill = new_doc(client, h, "UTILITY_ELECTRICITY").json()["id"]
    upload(client, h, bill, "PAGE", filegen.pdf(), "recibo.pdf", "application/pdf")
    selfie = new_doc(client, h, "SELFIE_WITH_ID").json()["id"]
    upload(client, h, selfie, "SELFIE", filegen.jpeg(seed=13))

    pending = client.get(f"{KYC}/status", headers=h).json()["missing"]
    assert "DOC_FILES_PENDING_SCAN" in pending
    process(db)
    assert client.get(f"{KYC}/status", headers=h).json()["missing"] == []
    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 202 and r.json()["status"] == "SUBMITTED"
    # Enviado: ya no se agregan ni borran documentos.
    assert new_doc(client, h, "CRIMINAL_RECORD_CERT", issued_at=str(TODAY)).status_code == 409
    assert client.delete(f"{DOCS}/{ine}", headers=h).json()["detail"]["code"] == "KYC_NOT_EDITABLE"
