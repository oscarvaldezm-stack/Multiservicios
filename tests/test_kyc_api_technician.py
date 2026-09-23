"""API del técnico sobre su expediente, de punta a punta contra PostgreSQL real."""
import io
from datetime import date, timedelta

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, AuditResult, Consent, KycAddress, KycStatus, User
from scripts.load_sepomex import iter_rows, load
from tests.conftest import (
    API,
    add_document,
    add_required_documents,
    auth,
    get_profile,
    login,
    register,
    valid_curp,
    valid_rfc,
    verify_email,
)
from tests.test_sepomex import SAMPLE

KYC = f"{API}/technicians/me/kyc"
NOTICE = "2026-09"
PERSONAL = {"first_names": "Gloria", "paternal_surname": "Hernández", "maternal_surname": "García",
            "birth_date": "1956-04-27", "curp": valid_curp(), "rfc": valid_rfc()}


@pytest.fixture
def tech(client, category, db):
    register(client, "technician", "tec@example.com", category_ids=[category.id])
    uid = db.scalar(select(User.id).where(User.email == "tec@example.com"))
    return uid, auth(login(client, "tec@example.com").json()["access_token"])


@pytest.fixture
def sepomex(db):
    load(db, iter_rows(io.StringIO(SAMPLE)))
    db.commit()


def consent(client, h, purposes=("KYC_IDENTITY", "BIOMETRIC_SELFIE")):
    return client.post(f"{KYC}/consents", headers=h, json={"notice_version": NOTICE, "purposes": list(purposes)})


def settlement_id(db, cp="91700") -> int:
    from app.models import MxPostalSettlement
    return db.scalar(select(MxPostalSettlement.id).where(MxPostalSettlement.postal_code == cp))


def address_body(db, cp="91700"):
    return {"street": "Av. Independencia", "exterior_number": "100", "postal_settlement_id": settlement_id(db, cp)}


def ready_to_submit(client, db, tech):
    uid, h = tech
    assert consent(client, h).status_code == 201
    assert client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL).status_code == 200
    assert client.put(f"{KYC}/address", headers=h, json=address_body(db)).status_code == 200
    verify_email(db, uid)
    add_required_documents(db, get_profile(db, uid))


# ------------------------------------------------------------------ lectura inicial
def test_expediente_nuevo_muestra_pendientes(client, tech):
    _, h = tech
    r = client.get(KYC, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "NOT_STARTED" and body["can_submit"] is False
    assert {"CONSENT_KYC_IDENTITY", "CONSENT_BIOMETRIC_SELFIE", "PERSONAL_DATA", "ADDRESS",
            "DOC_IDENTITY", "DOC_ADDRESS_PROOF", "DOC_SELFIE", "EMAIL_NOT_VERIFIED"} <= set(body["missing"])
    assert body["editable"] == {"personal_data": True, "address": True, "documents": True}
    assert client.get(f"{KYC}/status", headers=h).json()["status"] == "NOT_STARTED"


@pytest.mark.parametrize("who", ["client", "admin"])
def test_solo_tecnicos_acceden(who, client, client_tokens, admin_tokens):
    tok = client_tokens if who == "client" else admin_tokens
    assert client.get(KYC, headers=auth(tok["access_token"])).status_code == 403


def test_sin_sesion_401(client):
    assert client.get(KYC).status_code == 401


# ------------------------------------------------------------------ consentimiento
def test_no_se_capturan_datos_sin_consentimiento(client, tech):
    _, h = tech
    r = client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_CONSENT_REQUIRED"


def test_consentimiento_de_version_vieja_se_rechaza(client, tech):
    _, h = tech
    r = client.post(f"{KYC}/consents", headers=h, json={"notice_version": "2020-01", "purposes": ["KYC_IDENTITY"]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_NOTICE_OUTDATED"


def test_consentimiento_idempotente_y_auditado(client, tech, db):
    uid, h = tech
    assert consent(client, h).json()["granted"] == ["BIOMETRIC_SELFIE", "KYC_IDENTITY"]
    assert consent(client, h).status_code == 201
    assert db.scalar(select(func.count()).select_from(Consent).where(Consent.user_id == uid)) == 2
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "kyc.consent.granted")) == 1


def test_proposito_de_consentimiento_inventado_422(client, tech):
    _, h = tech
    r = client.post(f"{KYC}/consents", headers=h, json={"notice_version": NOTICE, "purposes": ["MARKETING"]})
    assert r.status_code == 422


# ------------------------------------------------------------------ datos personales
def test_datos_personales_validos_inician_el_expediente(client, tech):
    _, h = tech
    consent(client, h)
    r = client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "PENDING_DOCUMENTS"
    assert body["personal_data"]["curp_masked"] == "HEGG" + "•" * 12 + valid_curp()[-2:]
    assert valid_curp() not in r.text and valid_rfc() not in r.text     # nunca en claro en la respuesta
    assert "PERSONAL_DATA" not in body["missing"]


@pytest.mark.parametrize("change,code", [
    ({"birth_date": "1956-04-28"}, "CURP_BIRTHDATE_MISMATCH"),
    ({"curp": "HEGG560427MVZRRL05"}, "CURP_CHECK_DIGIT"),
    ({"rfc": "XAXX010101000"}, "RFC_GENERIC"),
])
def test_datos_inconsistentes_devuelven_codigo(change, code, client, tech):
    _, h = tech
    consent(client, h)
    r = client.put(f"{KYC}/personal-data", headers=h, json={**PERSONAL, **change})
    assert r.status_code == 422 and r.json()["detail"]["code"] == code


@pytest.mark.parametrize("change", [
    {"status": "APPROVED"},                                  # asignación masiva de campos
    {"first_names": "Gloria2"},                              # dígitos en el nombre
    {"first_names": "<script>alert(1)</script>"},            # marcado
    {"paternal_surname": "Pérez\x00"},                       # caracteres de control
    {"curp": "HEGG560427MVZRRL0"},                           # longitud
])
def test_entradas_maliciosas_o_mal_formadas_422(change, client, tech):
    _, h = tech
    consent(client, h)
    assert client.put(f"{KYC}/personal-data", headers=h, json={**PERSONAL, **change}).status_code == 422


def test_curp_de_otro_tecnico_se_rechaza_y_se_audita(client, tech, category, db):
    _, h = tech
    consent(client, h)
    assert client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL).status_code == 200
    register(client, "technician", "impostor@example.com", category_ids=[category.id])
    h2 = auth(login(client, "impostor@example.com").json()["access_token"])
    consent(client, h2)
    r = client.put(f"{KYC}/personal-data", headers=h2, json={**PERSONAL, "rfc": valid_rfc(7)})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_IDENTITY_CONFLICT"
    assert "CURP" not in r.text                                          # no confirma qué coincidió
    denied = db.scalar(select(AuditLog).where(AuditLog.action == "kyc.identity.duplicate_detected"))
    assert denied is not None and denied.result == AuditResult.DENIED    # sobrevive al rollback


# ------------------------------------------------------------------ domicilio
def test_domicilio_desde_catalogo_deriva_cp_municipio_y_estado(client, tech, db, sepomex):
    _, h = tech
    consent(client, h)
    r = client.put(f"{KYC}/address", headers=h, json=address_body(db))
    assert r.status_code == 200
    a = r.json()["address"]
    assert (a["postal_code"], a["municipality"], a["state"], a["settlement"]) == (
        "91700", "Veracruz", "Veracruz de Ignacio de la Llave", "Veracruz Centro")
    assert a["locked"] is False


def test_domicilio_manual_debe_coincidir_con_el_catalogo(client, tech, db, sepomex):
    from app.models import MxMunicipality
    _, h = tech
    consent(client, h)
    mty = db.scalar(select(MxMunicipality.id).where(MxMunicipality.name == "Monterrey"))
    base = {"street": "Calle 1", "exterior_number": "5", "settlement": "Colonia Nueva"}
    wrong = client.put(f"{KYC}/address", headers=h, json={**base, "postal_code": "91700", "municipality_id": mty})
    assert wrong.status_code == 422 and wrong.json()["detail"]["code"] == "ADDRESS_POSTAL_CODE_MISMATCH"
    unknown = client.put(f"{KYC}/address", headers=h, json={**base, "postal_code": "99999", "municipality_id": mty})
    assert unknown.json()["detail"]["code"] == "ADDRESS_POSTAL_CODE_UNKNOWN"
    ok = client.put(f"{KYC}/address", headers=h, json={**base, "postal_code": "64010", "municipality_id": mty})
    assert ok.status_code == 200 and ok.json()["address"]["state"] == "Nuevo León"


def test_domicilio_ambiguo_o_incompleto_422(client, tech, db, sepomex):
    _, h = tech
    consent(client, h)
    both = {**address_body(db), "postal_code": "91700"}
    assert client.put(f"{KYC}/address", headers=h, json=both).status_code == 422
    assert client.put(f"{KYC}/address", headers=h, json={"street": "Calle", "exterior_number": "1"}).status_code == 422
    missing = {**address_body(db), "postal_settlement_id": 999999}
    assert client.put(f"{KYC}/address", headers=h, json=missing).json()["detail"]["code"] == "ADDRESS_SETTLEMENT_UNKNOWN"


# ------------------------------------------------------------------ envío
def test_envio_incompleto_lista_lo_que_falta(client, tech):
    _, h = tech
    consent(client, h)
    client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL)
    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "KYC_REQUIREMENTS_MISSING"
    assert {"ADDRESS", "DOC_IDENTITY", "DOC_SELFIE", "EMAIL_NOT_VERIFIED"} <= set(r.json()["detail"]["missing"])


def test_no_se_envia_sin_haber_empezado(client, tech):
    _, h = tech
    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "KYC_NOT_SUBMITTABLE"


def test_flujo_completo_envia_y_congela(client, tech, db, sepomex):
    uid, h = tech
    ready_to_submit(client, db, tech)
    status_ = client.get(f"{KYC}/status", headers=h).json()
    assert status_["can_submit"] is True and status_["missing"] == []

    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 202 and r.json()["status"] == "SUBMITTED" and r.json()["cycle"] == 1
    profile = get_profile(db, uid)
    assert db.get(KycAddress, profile.current_address_id).locked_at is not None

    # Ya enviado: nada es editable y un segundo envío no procede.
    assert client.put(f"{KYC}/address", headers=h, json=address_body(db)).json()["detail"]["code"] == "KYC_NOT_EDITABLE"
    assert client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL).status_code == 409
    assert client.post(f"{KYC}/submission", headers=h).status_code == 409
    assert client.get(KYC, headers=h).json()["editable"] == {"personal_data": False, "address": False,
                                                             "documents": False}


@pytest.mark.parametrize("problem,expected", [
    ("old_proof", "DOC_ADDRESS_PROOF_TOO_OLD"),
    ("expired_id", "DOC_IDENTITY_EXPIRED"),
    ("pending_scan", "DOC_FILES_PENDING_SCAN"),
    ("one_side_ine", "DOC_IDENTITY"),
    ("infected_selfie", "DOC_SELFIE"),
])
def test_documentos_invalidos_bloquean_el_envio(problem, expected, client, tech, db, sepomex):
    from app.models import ScanStatus
    uid, h = tech
    consent(client, h)
    client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL)
    client.put(f"{KYC}/address", headers=h, json=address_body(db))
    verify_email(db, uid)
    p = get_profile(db, uid)
    today = date.today()
    ine_kw = {"expires_at": today + timedelta(days=900)}
    if problem == "expired_id":
        ine_kw["expires_at"] = today - timedelta(days=1)
    if problem == "one_side_ine":
        ine_kw["files"] = 1
    add_document(db, p, "INE", **ine_kw)
    add_document(db, p, "UTILITY_WATER", address_id=p.current_address_id,
                 issued_at=today - timedelta(days=200 if problem == "old_proof" else 5),
                 scan=ScanStatus.PENDING if problem == "pending_scan" else None)
    add_document(db, p, "SELFIE_WITH_ID", scan=ScanStatus.INFECTED if problem == "infected_selfie" else None)
    db.commit()
    r = client.post(f"{KYC}/submission", headers=h)
    assert r.status_code == 422 and expected in r.json()["detail"]["missing"]


def test_cambiar_domicilio_invalida_el_comprobante_anterior(client, tech, db, sepomex):
    uid, h = tech
    ready_to_submit(client, db, tech)
    before = get_profile(db, uid).current_address_id
    # Se muda antes de enviar: el comprobante subido era de la dirección anterior.
    assert client.put(f"{KYC}/address", headers=h, json=address_body(db, "64000")).status_code == 200
    db.expire_all()
    assert get_profile(db, uid).current_address_id != before          # versión nueva, no edición en su lugar
    status_ = client.get(f"{KYC}/status", headers=h).json()
    assert "DOC_ADDRESS_PROOF_OTHER_ADDRESS" in status_["missing"] and status_["can_submit"] is False


def test_borrador_sin_documentos_se_edita_en_su_lugar(client, tech, db, sepomex):
    uid, h = tech
    consent(client, h)
    client.put(f"{KYC}/address", headers=h, json=address_body(db))
    first = get_profile(db, uid).current_address_id
    client.put(f"{KYC}/address", headers=h, json=address_body(db, "64000"))
    db.expire_all()
    assert get_profile(db, uid).current_address_id == first
    assert db.scalar(select(func.count()).select_from(KycAddress)) == 1


# ------------------------------------------------------------------ correcciones
@pytest.mark.parametrize("reason,can_personal,can_address", [
    ("CORRECCION_DOCUMENTOS", False, False),
    ("CORRECCION_DOMICILIO", False, True),
    ("CORRECCION_DATOS_PERSONALES", True, True),
])
def test_alcance_de_la_correccion(reason, can_personal, can_address, client, tech, db, sepomex,
                                  reviewer, supervisor):
    from app.core.actor import Actor
    from app.kyc.state_machine import transition
    uid, h = tech
    ready_to_submit(client, db, tech)
    assert client.post(f"{KYC}/submission", headers=h).status_code == 202
    p = get_profile(db, uid)
    transition(db, p.id, KycStatus.UNDER_REVIEW, Actor.from_user(reviewer))
    transition(db, p.id, KycStatus.CORRECTION_REQUIRED, Actor.from_user(reviewer), reason_code=reason,
               note="Revisa lo indicado")
    db.commit()
    old_address = p.current_address_id

    view = client.get(KYC, headers=h).json()
    assert view["correction"]["reason_code"] == reason
    assert view["correction"]["can_edit_personal_data"] is can_personal
    assert view["editable"]["documents"] is True

    r_personal = client.put(f"{KYC}/personal-data", headers=h, json=PERSONAL)
    assert (r_personal.status_code == 200) is can_personal
    r_addr = client.put(f"{KYC}/address", headers=h, json=address_body(db, "64000"))
    assert (r_addr.status_code == 200) is can_address
    if can_address:
        db.expire_all()
        p = get_profile(db, uid)
        assert p.current_address_id != old_address                       # versión nueva
        assert db.get(KycAddress, old_address).locked_at is not None     # la anterior queda intacta
        assert "DOC_ADDRESS_PROOF_OTHER_ADDRESS" in client.get(f"{KYC}/status", headers=h).json()["missing"]


# ------------------------------------------------------------------ catálogos
def test_catalogo_de_codigos_postales(client, tech, sepomex):
    _, h = tech
    r = client.get(f"{API}/kyc/catalogs/postal-codes/64000", headers=h)
    assert r.status_code == 200 and r.json()["settlements"][0]["municipality"] == "Monterrey"
    assert client.get(f"{API}/kyc/catalogs/postal-codes/00000", headers=h).status_code == 404
    assert client.get(f"{API}/kyc/catalogs/postal-codes/64OOO", headers=h).status_code == 422
    assert client.get(f"{API}/kyc/catalogs/postal-codes/64000").status_code == 401


def test_catalogos_basicos(client, tech):
    _, h = tech
    states = client.get(f"{API}/kyc/catalogs/states", headers=h).json()
    assert len(states) == 32
    types = {t["code"] for t in client.get(f"{API}/kyc/catalogs/document-types", headers=h).json()}
    assert {"INE", "PASSPORT_MX", "SELFIE_WITH_ID", "CRIMINAL_RECORD_CERT"} <= types
    assert "CURP_BIOMETRIC" not in types                                  # inactivo
    notice = client.get(f"{API}/kyc/catalogs/privacy-notice", headers=h).json()
    assert notice["version"] == NOTICE and len(notice["purposes"]) == 3
