"""Visualización de documentos por administradores: acceso, tickets, límites y auditoría."""
import logging
import uuid

import pytest
from sqlalchemy import select

from app.core.actor import Actor
from app.core.config import get_settings
from app.kyc.state_machine import transition
from app.models import (
    AdminRole,
    AuditLog,
    AuditResult,
    FileViewTicket,
    KycDocument,
    KycDocumentFile,
    KycStatus,
)
from tests import filegen
from tests.conftest import API, auth, login, make_admin
from tests.test_kyc_documents import (  # noqa: F401  (fixtures)
    DOCS,
    KYC,
    new_doc,
    onboard,
    process,
    sepomex,
    tech,
    upload,
)

CASES = f"{API}/admin/kyc/cases"


def token(client, email: str) -> dict:
    return auth(login(client, email).json()["access_token"])


def audits(db, action: str) -> list[AuditLog]:
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == action)).all()


def submit_with_documents(client, db, h, seed: int = 0):
    ine = new_doc(client, h).json()["id"]
    upload(client, h, ine, "FRONT", filegen.jpeg(seed=seed + 1))
    upload(client, h, ine, "BACK", filegen.jpeg(seed=seed + 2))
    bill = new_doc(client, h, "UTILITY_ELECTRICITY").json()["id"]
    upload(client, h, bill, "PAGE", filegen.pdf(), "recibo.pdf", "application/pdf")
    selfie = new_doc(client, h, "SELFIE_WITH_ID").json()["id"]
    upload(client, h, selfie, "SELFIE", filegen.jpeg(seed=seed + 3))
    process(db)
    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 202, r.text
    return ine


@pytest.fixture
def case(client, db, tech, reviewer, supervisor):
    """Expediente real (documentos procesados) en revisión, asignado a `reviewer`."""
    uid, h = tech
    ine = submit_with_documents(client, db, h)
    doc = db.get(KycDocument, ine)
    transition(db, doc.kyc_profile_id, KycStatus.UNDER_REVIEW, Actor.from_user(reviewer))
    db.commit()
    f = db.scalars(select(KycDocumentFile).where(KycDocumentFile.document_id == doc.id)
                   .order_by(KycDocumentFile.side)).first()
    return {"case_id": doc.kyc_profile_id, "doc_id": doc.id, "file_id": f.id, "tech_uid": uid, "tech_h": h}


def content_url(c, file_id=None, doc_id=None, case_id=None) -> str:
    return (f"{CASES}/{case_id or c['case_id']}/documents/{doc_id or c['doc_id']}"
            f"/files/{file_id or c['file_id']}/content")


def ticket_url(c) -> str:
    return content_url(c).replace("/content", "/view-ticket")


# ------------------------------------------------------------------ ver contenido
def test_revisor_asignado_ve_imagen_con_marca_de_agua_y_queda_auditado(client, db, case, reviewer):
    r = client.get(content_url(case), headers=token(client, "revisor@example.com"))
    assert r.status_code == 200 and r.content.startswith(b"\xff\xd8\xff")
    assert r.headers["cache-control"].startswith("no-store")
    assert "sandbox" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert filegen.GPS_MARKER.encode() not in r.content          # nunca el original con metadatos
    viewed = audits(db, "kyc.file.viewed")
    assert len(viewed) == 1 and viewed[0].actor_id == reviewer.id and viewed[0].target_id == str(case["file_id"])


def test_supervisor_ve_cualquier_documento(client, db, case):
    assert client.get(content_url(case), headers=token(client, "supervisor@example.com")).status_code == 200


@pytest.mark.parametrize("roles", [
    (AdminRole.KYC_REVIEWER,),        # revisor NO asignado
    (AdminRole.SUPERADMIN,),          # el superadmin administra, no lee expedientes
    (AdminRole.SUPPORT,),
])
def test_quien_no_tiene_el_caso_recibe_404_y_se_audita(roles, client, db, case):
    make_admin(db, "otro@example.com", *roles)
    r = client.get(content_url(case), headers=token(client, "otro@example.com"))
    assert r.status_code == 404 and r.json()["detail"]["code"] == "FILE_NOT_FOUND"
    denied = audits(db, "kyc.file.access_denied")
    assert len(denied) == 1 and denied[0].result == AuditResult.DENIED
    assert audits(db, "kyc.file.viewed") == []


def test_finanzas_ni_siquiera_tiene_permiso(client, db, case):
    make_admin(db, "fin@example.com", AdminRole.FINANCE_ADMIN)
    assert client.get(content_url(case), headers=token(client, "fin@example.com")).status_code == 403


def test_tecnico_y_cliente_no_usan_rutas_de_administracion(client, db, case, client_tokens):
    assert client.get(content_url(case), headers=case["tech_h"]).status_code == 403
    assert client.get(content_url(case), headers=auth(client_tokens["access_token"])).status_code == 403
    assert client.get(content_url(case)).status_code == 401


def test_ids_cruzados_o_inexistentes_dan_el_mismo_404(client, db, case):
    h = token(client, "supervisor@example.com")
    other_doc = db.scalar(select(KycDocument.id).where(KycDocument.kyc_profile_id == case["case_id"],
                                                       KycDocument.id != case["doc_id"]))
    for url in (content_url(case, doc_id=other_doc),            # archivo que no es de ese documento
                content_url(case, case_id=uuid.uuid4()),
                content_url(case, file_id=uuid.uuid4())):
        r = client.get(url, headers=h)
        assert r.status_code == 404 and r.json()["detail"]["code"] == "FILE_NOT_FOUND"


def test_archivo_de_otro_expediente_no_se_alcanza_desde_mi_caso(client, db, category, case, supervisor):
    uid2, h2 = onboard(client, db, category, "tec2@example.com", 5)
    ine2 = new_doc(client, h2, document_number="HRGLGL56042730M501").json()["id"]
    upload(client, h2, ine2, "FRONT", filegen.jpeg(seed=91))
    process(db)
    foreign = db.scalar(select(KycDocumentFile.id).where(KycDocumentFile.document_id == ine2))
    r = client.get(content_url(case, file_id=foreign), headers=token(client, "supervisor@example.com"))
    assert r.status_code == 404


def test_limite_de_visualizaciones_por_hora_alerta_y_audita(client, db, case, monkeypatch, caplog):
    monkeypatch.setattr(get_settings(), "KYC_FILE_VIEWS_PER_HOUR", 2)
    h = token(client, "revisor@example.com")
    assert client.get(content_url(case), headers=h).status_code == 200
    assert client.get(content_url(case), headers=h).status_code == 200
    with caplog.at_level(logging.WARNING, logger="security"):
        r = client.get(content_url(case), headers=h)
    assert r.status_code == 429 and r.json()["detail"]["code"] == "VIEW_RATE_LIMITED"
    assert any("ALERTA" in rec.getMessage() for rec in caplog.records)
    assert len(audits(db, "kyc.file.view_rate_limited")) == 1
    assert len(audits(db, "kyc.file.viewed")) == 2


# ------------------------------------------------------------------ tickets de un solo uso
def issue_ticket(client, case, email="revisor@example.com") -> str:
    r = client.post(ticket_url(case), headers=token(client, email))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["url"].startswith(f"{API}/kyc/file-views/")
    return body["url"]


def test_ticket_funciona_sin_encabezado_y_solo_una_vez(client, db, case):
    url = issue_ticket(client, case)
    first = client.get(url)                                     # como <img src>: sin Authorization
    assert first.status_code == 200 and first.content.startswith(b"\xff\xd8\xff")
    assert first.headers["cache-control"].startswith("no-store")
    assert client.get(url).status_code == 404                   # segundo uso
    viewed = audits(db, "kyc.file.viewed")
    assert len(viewed) == 1 and viewed[0].changes["via"] == "ticket"
    assert len(audits(db, "kyc.file.view_ticket_issued")) == 1


def test_ticket_vencido_alterado_o_inventado_da_404(client, db, case):
    url = issue_ticket(client, case)
    db.execute(FileViewTicket.__table__.update().values(
        expires_at=FileViewTicket.__table__.c.created_at))      # vencerlo
    db.commit()
    assert client.get(url).status_code == 404
    good = issue_ticket(client, case)
    tok = good.rsplit("/", 1)[1]
    tampered = tok[:-2] + ("AA" if tok[-2:] != "AA" else "BB")
    assert client.get(good.replace(tok, tampered)).status_code == 404
    assert client.get(f"{API}/kyc/file-views/{'A' * 43}").status_code == 404
    assert client.get(f"{API}/kyc/file-views/corto").status_code == 422
    assert client.get(good).status_code == 200                  # el bueno sigue sirviendo


def test_ticket_se_invalida_si_pierde_la_asignacion(client, db, case, reviewer):
    url = issue_ticket(client, case)
    transition(db, case["case_id"], KycStatus.SUBMITTED, Actor.from_user(reviewer))   # libera el caso
    db.commit()
    assert client.get(url).status_code == 404
    assert len(audits(db, "kyc.file.access_denied")) == 1


def test_ticket_de_admin_desactivado_no_sirve(client, db, case, reviewer):
    url = issue_ticket(client, case)
    reviewer = db.merge(reviewer)
    reviewer.is_active = False
    db.commit()
    assert client.get(url).status_code == 404


def test_url_directa_al_almacenamiento_no_existe(client, db, case):
    f = db.get(KycDocumentFile, case["file_id"])
    for path in (f"/{f.bucket}/{f.object_key}", f"/storage/{f.object_key}", f"/var/storage/{f.bucket}/{f.object_key}",
                 f"{API}/{f.bucket}/{f.object_key}"):
        assert client.get(path).status_code == 404


# ------------------------------------------------------------------ bitácora
def test_bitacora_solo_para_quien_tiene_permiso_y_se_audita_su_consulta(client, db, case):
    client.get(content_url(case), headers=token(client, "revisor@example.com"))
    assert client.get(f"{API}/admin/audit-logs", headers=token(client, "revisor@example.com")).status_code == 403
    h = token(client, "supervisor@example.com")
    r = client.get(f"{API}/admin/audit-logs", headers=h, params={"action": "kyc.file.viewed"})
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["target_id"] == str(case["file_id"])
    assert "changes" not in items[0]                            # el detalle no se expone en el listado
    assert len(audits(db, "audit.queried")) == 1
    assert client.get(f"{API}/admin/audit-logs", headers=h,
                      params={"action": "x'; DROP TABLE audit_logs;--"}).status_code == 422


def test_cadena_de_auditoria_integra(client, db, case):
    h = token(client, "supervisor@example.com")
    r = client.get(f"{API}/admin/audit-logs/integrity", headers=h)
    assert r.status_code == 200 and r.json() == {"intact": True, "broken_ids": []}
