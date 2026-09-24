"""Fase 4 del KYC: tomar casos, decidir documentos y expedientes, suspender, reactivar y trabajos automáticos."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.kyc import decisions
from app.models import (
    AdminRole,
    AuditLog,
    KycDocument,
    KycDocumentStatus,
    KycProfile,
    KycStatus,
    OutboxEvent,
    User,
)
from tests.conftest import API, add_required_documents, auth, drive_to, login, make_admin, register
from tests.marketplace import ORDERS, approved_tech, create_order, new_client, order_status

CASES = f"{API}/admin/kyc/cases"
S = KycStatus


def token(client, email: str) -> dict:
    return auth(login(client, email).json()["access_token"])


@pytest.fixture
def case(client, db, category, reviewer, supervisor):
    """Expediente enviado con los tres documentos obligatorios pendientes de revisión."""
    assert register(client, "technician", "tec@example.com", category_ids=[category.id]).status_code == 201
    uid = db.scalar(select(User.id).where(User.email == "tec@example.com"))
    profile = drive_to(db, uid, S.SUBMITTED, reviewer, supervisor)
    add_required_documents(db, profile)
    return profile


def docs(db, profile) -> list[KycDocument]:
    db.expire_all()
    return db.scalars(select(KycDocument).where(KycDocument.kyc_profile_id == profile.id)).all()


def claim(client, profile, email="revisor@example.com"):
    return client.post(f"{CASES}/{profile.id}/claim", headers=token(client, email))


def decide_doc(client, profile, doc_id, decision="APPROVED", email="revisor@example.com", **kw):
    return client.put(f"{CASES}/{profile.id}/documents/{doc_id}/decision", headers=token(client, email),
                      json={"decision": decision, **kw})


def decide_case(client, profile, decision, email="revisor@example.com", **kw):
    return client.post(f"{CASES}/{profile.id}/decision", headers=token(client, email),
                       json={"decision": decision, **kw})


def approve_all_docs(client, db, profile, email="revisor@example.com"):
    for d in docs(db, profile):
        assert decide_doc(client, profile, d.id, email=email).status_code == 200


def audits(db, action):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == action)).all()


# ------------------------------------------------------------------ tomar y liberar
def test_revisor_toma_el_caso_y_nadie_mas_puede(client, db, case, reviewer):
    r = claim(client, case)
    assert r.status_code == 200 and r.json()["status"] == "UNDER_REVIEW"
    assert r.json()["assigned_reviewer_id"] == str(reviewer.id)
    make_admin(db, "revisor2@example.com", AdminRole.KYC_REVIEWER)
    again = claim(client, case, "revisor2@example.com")
    assert again.status_code == 409 and again.json()["detail"]["code"] == "KYC_CASE_NOT_CLAIMABLE"


@pytest.mark.parametrize("role", [AdminRole.SUPPORT, AdminRole.SUPERADMIN, AdminRole.FINANCE_ADMIN,
                                  AdminRole.CONTENT_MODERATOR])
def test_roles_sin_permiso_no_toman_ni_deciden(role, client, db, case):
    make_admin(db, "otro@example.com", role)
    assert claim(client, case, "otro@example.com").status_code == 403
    assert decide_case(client, case, "APPROVED", "otro@example.com").status_code == 403
    assert audits(db, "admin.permission.denied")


def test_tecnico_y_cliente_no_acceden(client, db, case, client_tokens):
    tech_h = token(client, "tec@example.com")
    assert client.post(f"{CASES}/{case.id}/claim", headers=tech_h).status_code == 403
    assert client.post(f"{CASES}/{case.id}/claim", headers=auth(client_tokens["access_token"])).status_code == 403


def test_limite_de_casos_tomados(client, db, case, monkeypatch):
    monkeypatch.setattr(get_settings(), "KYC_MAX_ACTIVE_CLAIMS", 1)
    assert claim(client, case).status_code == 200
    register(client, "technician", "tec2@example.com", category_ids=[])
    uid2 = db.scalar(select(User.id).where(User.email == "tec2@example.com"))
    reviewer = db.scalar(select(User).where(User.email == "revisor@example.com"))
    supervisor = db.scalar(select(User).where(User.email == "supervisor@example.com"))
    p2 = drive_to(db, uid2, S.SUBMITTED, reviewer, supervisor, n=5)
    r = claim(client, p2)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_TOO_MANY_CLAIMS"


def test_liberar_caso_vuelve_a_la_cola(client, db, case):
    v = claim(client, case).json()["version"]
    r = client.post(f"{CASES}/{case.id}/release", headers=token(client, "revisor@example.com"),
                    json={"expected_version": v})
    assert r.status_code == 200 and r.json()["status"] == "SUBMITTED" and r.json()["assigned_reviewer_id"] is None


def test_caso_inexistente_o_ajeno_da_404_y_se_audita(client, db, case):
    claim(client, case)
    make_admin(db, "revisor2@example.com", AdminRole.KYC_REVIEWER)
    d = docs(db, case)[0]
    r = decide_doc(client, case, d.id, email="revisor2@example.com")
    assert r.status_code == 404 and r.json()["detail"]["code"] == "KYC_CASE_NOT_FOUND"
    assert audits(db, "kyc.case.access_denied")
    assert client.post(f"{CASES}/{uuid.uuid4()}/claim", headers=token(client, "revisor@example.com")).status_code == 404


# ------------------------------------------------------------------ documentos
def test_rechazar_documento_exige_motivo_del_catalogo(client, db, case):
    claim(client, case)
    d = docs(db, case)[0]
    assert decide_doc(client, case, d.id, "REJECTED").json()["detail"]["code"] == "KYC_REASON_INVALID"
    wrong_scope = decide_doc(client, case, d.id, "REJECTED", reason_code="FRAUDE_IDENTIDAD")
    assert wrong_scope.json()["detail"]["code"] == "KYC_REASON_INVALID"
    no_note = decide_doc(client, case, d.id, "REJECTED", reason_code="OTRO")
    assert no_note.json()["detail"]["code"] == "KYC_NOTE_REQUIRED"
    ok = decide_doc(client, case, d.id, "REJECTED", reason_code="DOCUMENTO_ILEGIBLE")
    assert ok.status_code == 200 and ok.json()["status"] == "REJECTED" and ok.json()["rejection_reason"]
    assert audits(db, "kyc.document.rejected")


def test_no_se_decide_documento_de_otro_expediente(client, db, case, reviewer, supervisor):
    claim(client, case)
    register(client, "technician", "tec2@example.com", category_ids=[])
    uid2 = db.scalar(select(User.id).where(User.email == "tec2@example.com"))
    p2 = drive_to(db, uid2, S.SUBMITTED, reviewer, supervisor, n=5)
    add_required_documents(db, p2)
    foreign = docs(db, p2)[0]
    r = decide_doc(client, case, foreign.id)
    assert r.status_code == 404 and r.json()["detail"]["code"] == "KYC_DOCUMENT_NOT_FOUND"


def test_documento_sin_escaneo_limpio_no_se_aprueba(client, db, case):
    claim(client, case)
    d = docs(db, case)[0]
    for f in d.files:
        f.scan_status = "PENDING"
    db.commit()
    assert decide_doc(client, case, d.id).json()["detail"]["code"] == "KYC_DOCUMENT_NOT_CLEAN"


def test_decidir_documentos_solo_en_revision(client, db, case):
    d = docs(db, case)[0]
    r = decide_doc(client, case, d.id, email="supervisor@example.com")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_NOT_UNDER_REVIEW"


# ------------------------------------------------------------------ decisión del caso
def test_no_se_aprueba_con_documentos_sin_decidir(client, db, case):
    claim(client, case)
    r = decide_case(client, case, "APPROVED")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_DOCUMENTS_UNDECIDED"


def test_no_se_aprueba_si_falta_un_documento_obligatorio_aprobado(client, db, case):
    claim(client, case)
    d = docs(db, case)
    decide_doc(client, case, d[0].id)
    decide_doc(client, case, d[1].id)
    decide_doc(client, case, d[2].id, "REJECTED", reason_code="SELFIE_NO_COINCIDE")
    r = decide_case(client, case, "APPROVED")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_APPROVAL_BLOCKED"
    assert r.json()["detail"]["missing"]


def test_aprobar_habilita_recibir_ordenes(client, db, case, category):
    tech_h = token(client, "tec@example.com")
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=tech_h).status_code == 403
    v = claim(client, case).json()["version"]
    approve_all_docs(client, db, case)
    db.refresh(case)
    r = decide_case(client, case, "APPROVED", expected_version=case.version)
    assert r.status_code == 200 and r.json()["status"] == "APPROVED" and v < r.json()["version"]
    db.expire_all()
    p = db.get(KycProfile, case.id)
    assert p.approved_at and p.expires_at and p.revalidation_due_at
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=tech_h).status_code == 200
    assert db.scalar(select(OutboxEvent).where(OutboxEvent.event_type == "kyc.approved"))


def test_version_vieja_se_rechaza(client, db, case):
    claim(client, case)
    approve_all_docs(client, db, case)
    r = decide_case(client, case, "APPROVED", expected_version=1)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_STALE_VERSION"


def test_senales_de_riesgo_requieren_supervisor(client, db, case):
    claim(client, case)
    approve_all_docs(client, db, case)
    d = docs(db, case)[0]
    d.risk_flags = ["DOCUMENT_NUMBER_IN_OTHER_PROFILE"]
    db.commit()
    r = decide_case(client, case, "APPROVED")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "KYC_SUPERVISOR_REQUIRED"
    assert decide_case(client, case, "APPROVED", "supervisor@example.com").status_code == 200


def test_pedir_correccion_de_documentos(client, db, case):
    claim(client, case)
    d = docs(db, case)
    nothing = decide_case(client, case, "CORRECTION_REQUIRED", reason_code="CORRECCION_DOCUMENTOS")
    assert nothing.json()["detail"]["code"] == "KYC_NOTHING_TO_CORRECT"
    decide_doc(client, case, d[0].id, "REJECTED", reason_code="DOCUMENTO_ILEGIBLE")
    r = decide_case(client, case, "CORRECTION_REQUIRED", reason_code="CORRECCION_DOCUMENTOS")
    assert r.status_code == 200 and r.json()["status"] == "CORRECTION_REQUIRED"


def test_rechazo_definitivo_solo_supervisor_y_con_nota(client, db, case):
    claim(client, case)
    assert decide_case(client, case, "REJECTED", reason_code="FRAUDE_IDENTIDAD", note="x").status_code == 403
    no_note = decide_case(client, case, "REJECTED", "supervisor@example.com", reason_code="FRAUDE_IDENTIDAD")
    assert no_note.json()["detail"]["code"] == "KYC_NOTE_REQUIRED"
    r = decide_case(client, case, "REJECTED", "supervisor@example.com", reason_code="FRAUDE_IDENTIDAD",
                    note="La CURP pertenece a otra persona")
    assert r.status_code == 200 and r.json()["status"] == "REJECTED"


def test_campos_extra_en_la_decision_se_rechazan(client, db, case):
    claim(client, case)
    r = client.post(f"{CASES}/{case.id}/decision", headers=token(client, "revisor@example.com"),
                    json={"decision": "APPROVED", "status": "APPROVED"})
    assert r.status_code == 422


# ------------------------------------------------------------------ suspender y reactivar
def test_suspender_quita_ordenes_no_iniciadas_y_bloquea(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    _, ch = new_client(client, db)
    oid = create_order(client, ch, category)["id"]
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "500"}).status_code == 200
    other = create_order(client, ch, category)["id"]
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))

    sup = token(client, "supervisor@example.com")
    assert client.post(f"{CASES}/{profile.id}/suspend", headers=sup,
                       json={"reason_code": "INVESTIGACION_EN_CURSO"}).json()["detail"]["code"] == "KYC_NOTE_REQUIRED"
    r = client.post(f"{CASES}/{profile.id}/suspend", headers=sup,
                    json={"reason_code": "INVESTIGACION_EN_CURSO", "note": "Queja formal de un cliente"})
    assert r.status_code == 200 and r.json()["status"] == "SUSPENDED"
    assert order_status(db, oid) == "REQUESTED"                      # volvió a la bolsa
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=th).status_code == 403
    blocked = client.post(f"{ORDERS}/{other}/accept", headers=th, json={"agreed_price": "500"})
    assert blocked.status_code == 403 and blocked.json()["detail"]["code"] == "KYC_NOT_APPROVED"

    # Reactivar abre una revisión nueva; solo al aprobarla vuelve a recibir órdenes.
    re = client.post(f"{CASES}/{profile.id}/reinstate", headers=sup, json={"note": "Investigación cerrada"})
    assert re.status_code == 200 and re.json()["status"] == "UNDER_REVIEW" and re.json()["cycle"] > profile.cycle
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=th).status_code == 403
    # Este técnico se aprobó sin documentos (atajo de prueba): la nueva revisión exige tenerlos.
    again = decide_case(client, profile, "APPROVED", "supervisor@example.com")
    assert again.status_code == 409 and again.json()["detail"]["code"] == "KYC_APPROVAL_BLOCKED"


def test_revisor_no_suspende(client, db, category, reviewer, supervisor):
    tid, _ = approved_tech(client, db, category, reviewer, supervisor)
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    r = client.post(f"{CASES}/{profile.id}/suspend", headers=token(client, "revisor@example.com"),
                    json={"reason_code": "INVESTIGACION_EN_CURSO", "note": "x"})
    assert r.status_code == 403


# ------------------------------------------------------------------ trabajos automáticos
def test_casos_abandonados_vuelven_a_la_cola(client, db, case):
    claim(client, case)
    db.expire_all()
    p = db.get(KycProfile, case.id)
    p.assigned_at = datetime.now(timezone.utc) - timedelta(hours=get_settings().KYC_REVIEW_CLAIM_TIMEOUT_HOURS + 1)
    db.commit()
    assert decisions.release_stale_claims(db) == 1
    db.commit()
    db.expire_all()
    assert db.get(KycProfile, case.id).status == S.SUBMITTED


def test_aprobacion_vencida_expira_y_suelta_ordenes(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    _, ch = new_client(client, db)
    oid = create_order(client, ch, category)["id"]
    client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "500"})
    p = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    p.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()
    assert decisions.expire_approvals(db) == 1
    db.commit()
    db.expire_all()
    assert db.get(KycProfile, p.id).status == S.EXPIRED and order_status(db, oid) == "REQUESTED"


def test_programador_de_trabajos_corre_todo(db):
    from worker.jobs import run_once
    result = run_once()
    assert set(result) == {"kyc.release_stale_claims", "kyc.expire_approvals", "orders.auto_approve",
                           "orders.expire_requests", "payments.enforce_capture_deadline",
                           "payments.capture_due", "payments.purge_idempotency_keys", "payments.process_webhooks",
                           "payments.retry_voids", "payments.reconcile"}
    assert all(v == 0 for v in result.values())


def test_documentos_aprobados_quedan_con_ciclo_y_revisor(client, db, case, reviewer):
    claim(client, case)
    approve_all_docs(client, db, case)
    for d in docs(db, case):
        assert d.status == KycDocumentStatus.APPROVED and d.reviewed_by_id == reviewer.id
