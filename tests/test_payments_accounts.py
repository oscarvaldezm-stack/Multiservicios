"""Pagos, Fase 2: cuenta de pagos del técnico, bloqueo por KYC o nombre distinto, y tarjetas del cliente."""
import re
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.core.actor import Actor
from app.kyc import decisions
from app.models import (
    AdminRole,
    AuditLog,
    KycProfile,
    KycStatus,
    OutboxEvent,
    PaymentAccountStatus,
    PaymentCustomer,
    TechnicianPaymentAccount,
    User,
)
from app.payments import accounts
from app.payments.accounts import ALLOWED_ACCOUNT_TRANSITIONS
from app.payments.providers import get_provider
from app.payments.providers.base import ProviderError
from tests.conftest import API, add_required_documents, auth, drive_to, login, make_admin, register
from tests.marketplace import approved_tech, new_client

ACCOUNT = f"{API}/technicians/me/payment-account"
CARDS = f"{API}/clients/me/payment-methods"
CASES = f"{API}/admin/kyc/cases"
S = PaymentAccountStatus


@pytest.fixture
def fake():
    return get_provider()


@pytest.fixture
def tech(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor, payment_account=False)
    return tid, th


def err(r) -> str:
    return r.json()["detail"]["code"]


def row(db, tid) -> TechnicianPaymentAccount:
    db.expire_all()
    return db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == tid))


def enabled_account(client, db, fake, tid, th) -> TechnicianPaymentAccount:
    assert client.post(ACCOUNT, headers=th, json={}).status_code == 201
    fake.complete_onboarding(row(db, tid).provider_account_id)
    assert client.post(f"{ACCOUNT}/refresh", headers=th, json={}).json()["status"] == "ENABLED"
    return row(db, tid)


# ------------------------------------------------------------------ app = trigger
def test_transiciones_de_la_cuenta_coinciden_con_el_trigger(db):
    src = db.scalar(text("SELECT pg_get_functiondef('payment_account_guard'::regproc)"))
    in_db = set(re.findall(r"'([A-Z_]+>[A-Z_]+)'", src))
    assert in_db == {f"{a.value}>{b.value}" for a, b in ALLOWED_ACCOUNT_TRANSITIONS}


# ------------------------------------------------------------------ alta
def test_sin_kyc_aprobado_no_hay_cuenta(client, db, category, fake):
    assert register(client, "technician", "nuevo@example.com", category_ids=[category.id]).status_code == 201
    h = auth(login(client, "nuevo@example.com").json()["access_token"])
    r = client.post(ACCOUNT, headers=h, json={})
    assert r.status_code == 403 and err(r) == "KYC_NOT_APPROVED"
    assert fake.calls == [] and db.scalar(select(func.count()).select_from(TechnicianPaymentAccount)) == 0


def test_alta_precarga_datos_del_kyc_sin_curp_ni_rfc(client, db, tech, fake):
    tid, th = tech
    assert client.get(ACCOUNT, headers=th).json()["status"] == "NOT_CREATED"
    r = client.post(ACCOUNT, headers=th, json={})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "ONBOARDING" and not body["can_receive_payments"]
    assert "provider_account_id" not in body and "acct_" not in r.text      # no se expone el id del proveedor
    acc = row(db, tid)
    prefill = fake.prefills[acc.provider_account_id]
    assert (prefill.first_names, prefill.last_names) == ("Gloria", "Hernández García")
    assert (prefill.postal_code, prefill.city) == ("91700", "Veracruz") and prefill.state   # estado del catálogo INEGI
    assert prefill.address_line1 == "Av. Independencia 100" and prefill.birth_date is not None
    assert not any(hasattr(prefill, f) for f in ("curp", "rfc"))
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "payment_account.created"))


def test_segunda_alta_da_409_y_no_crea_otra_cuenta(client, db, tech, fake):
    _, th = tech
    assert client.post(ACCOUNT, headers=th, json={}).status_code == 201
    r = client.post(ACCOUNT, headers=th, json={})
    assert r.status_code == 409 and err(r) == "PAYMENT_ACCOUNT_EXISTS"
    assert fake.calls.count("accounts.create") == 1


@pytest.mark.parametrize("body", [{"status": "ENABLED"}, {"account_id": "acct_123"}, {"payouts_enabled": True}])
def test_el_cliente_no_puede_colar_campos(client, tech, body):
    _, th = tech
    assert client.post(ACCOUNT, headers=th, json=body).status_code == 422
    assert client.post(f"{ACCOUNT}/refresh", headers=th, json=body).status_code == 422


def test_proveedor_caido_no_deja_filas_a_medias(client, db, tech, fake):
    tid, th = tech
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", http_status=503,
                                   retryable=True)
    r = client.post(ACCOUNT, headers=th, json={})
    assert r.status_code == 503 and err(r) == "PAYMENT_PROVIDER_UNAVAILABLE"
    assert row(db, tid) is None
    assert client.post(ACCOUNT, headers=th, json={}).status_code == 201     # el reintento funciona


def test_roles_separados(client, db, tech, client_tokens):
    ch = auth(client_tokens["access_token"])
    assert client.post(ACCOUNT, headers=ch, json={}).status_code == 403
    _, th = tech
    assert client.post(f"{CARDS}/setup-intent", headers=th, json={}).status_code == 403
    assert client.get(ACCOUNT).status_code == 401


# ------------------------------------------------------------------ formulario del proveedor
def test_enlace_de_alta(client, db, tech, fake):
    _, th = tech
    r = client.post(f"{ACCOUNT}/onboarding-link", headers=th, json={})
    assert r.status_code == 404 and err(r) == "PAYMENT_ACCOUNT_NOT_FOUND"
    client.post(ACCOUNT, headers=th, json={})
    r = client.post(f"{ACCOUNT}/onboarding-link", headers=th, json={})
    assert r.status_code == 200 and r.json()["url"].startswith("https://connect.stripe.com/")
    assert datetime.fromisoformat(r.json()["expires_at"]) > datetime.now(timezone.utc)


# ------------------------------------------------------------------ estado (siempre desde el proveedor)
def test_estados_segun_el_proveedor(client, db, tech, fake):
    tid, th = tech
    client.post(ACCOUNT, headers=th, json={})
    acct = row(db, tid).provider_account_id

    def refresh():
        db.execute(text("UPDATE technician_payment_accounts SET last_synced_at = NULL"))
        db.commit()
        return client.post(f"{ACCOUNT}/refresh", headers=th, json={}).json()

    fake.set_account(acct, details_submitted=True)
    assert refresh()["status"] == "PENDING_VERIFICATION"
    fake.complete_onboarding(acct)
    out = refresh()
    assert out["status"] == "ENABLED" and out["can_receive_payments"] and out["requirements_due"] == []
    assert row(db, tid).enabled_at is not None
    fake.set_account(acct, requirements_due=("individual.verification.document",))
    out = refresh()
    assert out["status"] == "RESTRICTED" and not out["can_receive_payments"]
    fake.set_account(acct, disabled_reason="rejected.fraud")
    assert refresh()["status"] == "DISABLED"
    r = client.post(f"{ACCOUNT}/onboarding-link", headers=th, json={})
    assert r.status_code == 409 and err(r) == "PAYMENT_ACCOUNT_DISABLED"
    events = db.scalars(select(OutboxEvent.event_type).where(OutboxEvent.recipient_user_id == tid)).all()
    assert {"payment_account.enabled", "payment_account.restricted", "payment_account.disabled"} <= set(events)


def test_consulta_repetida_no_martillea_al_proveedor(client, db, tech, fake):
    _, th = tech
    client.post(ACCOUNT, headers=th, json={})
    for _ in range(3):
        client.post(f"{ACCOUNT}/refresh", headers=th, json={})
    assert fake.calls.count("accounts.retrieve") == 1


# ------------------------------------------------------------------ nombre distinto al del KYC
def test_nombre_distinto_bloquea_y_alerta(client, db, tech, fake, supervisor):
    tid, th = tech
    client.post(ACCOUNT, headers=th, json={})
    acc = row(db, tid)
    fake.complete_onboarding(acc.provider_account_id)
    fake.set_account(acc.provider_account_id, legal_first_name="Roberto", legal_last_name="Pérez")
    out = client.post(f"{ACCOUNT}/refresh", headers=th, json={}).json()
    assert out["status"] == "ENABLED" and out["in_review"] and not out["can_receive_payments"]
    acc = row(db, tid)
    assert acc.blocked_reason == "NAME_MISMATCH" and acc.name_matches_kyc is False
    assert db.scalar(select(func.count()).select_from(OutboxEvent)
                     .where(OutboxEvent.event_type == "payment_account.name_mismatch")) == 1

    url = f"{API}/admin/payment-accounts/{acc.id}/name-review"
    fin = make_admin(db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(url, headers=auth(login(client, fin.email).json()["access_token"]),
                    json={"approve": True, "note": "Verificado por teléfono"})
    assert r.status_code == 403
    sup = auth(login(client, "supervisor@example.com").json()["access_token"])
    r = client.post(url, headers=sup, json={"approve": True, "note": "Es su nombre de casada, verificado"})
    assert r.status_code == 200 and r.json()["can_receive_payments"]
    r = client.post(url, headers=sup, json={"approve": True, "note": "Otra vez"})
    assert r.status_code == 409 and err(r) == "PAYMENT_ACCOUNT_NOT_IN_REVIEW"


def test_nombre_rechazado_no_se_libera_con_el_kyc(client, db, tech, fake, supervisor):
    tid, th = tech
    client.post(ACCOUNT, headers=th, json={})
    acc = row(db, tid)
    fake.complete_onboarding(acc.provider_account_id)
    fake.set_account(acc.provider_account_id, legal_first_name="Otra", legal_last_name="Persona")
    client.post(f"{ACCOUNT}/refresh", headers=th, json={})
    accounts.resolve_name_review(db, Actor.from_user(supervisor), acc.id, approve=False, note="No es el titular")
    accounts.unblock_for_kyc(db, tid)
    db.commit()
    assert row(db, tid).blocked_reason == "NAME_REJECTED" and not row(db, tid).can_receive_payments


@pytest.mark.parametrize("first,last,expected", [
    ("GLORIA", "HERNANDEZ", True),                   # sin acentos y solo apellido paterno
    ("gloria", "Hernández García", True),
    ("Glória", "Hernández-García", True),
    ("Gloria", "García", False),
    ("Roberto", "Hernández", False),
    (None, None, None),                              # el proveedor no expone el nombre
])
def test_comparacion_de_nombre(db, tech, first, last, expected):
    from app.payments.providers.base import AccountStatusInfo
    tid, _ = tech
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    info = AccountStatusInfo(provider_account_id="acct_x", transfers_active=True, payouts_enabled=True,
                             details_submitted=True, legal_first_name=first, legal_last_name=last)
    assert accounts.name_matches(profile, info) is expected


# ------------------------------------------------------------------ regla crítica: KYC
def test_suspension_del_kyc_bloquea_la_cuenta_sin_borrarla(client, db, tech, fake, supervisor):
    tid, th = tech
    enabled_account(client, db, fake, tid, th)
    assert accounts.can_receive_payments(db, tid, fake.name)
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    decisions.suspend(db, Actor.from_user(supervisor), profile.id, "INVESTIGACION_EN_CURSO", "Queja formal")
    db.commit()
    acc = row(db, tid)
    assert acc.status == S.ENABLED and acc.blocked_reason == "KYC_SUSPENDED"
    assert not accounts.can_receive_payments(db, tid, fake.name)
    assert client.get(ACCOUNT, headers=th).json()["in_review"]
    with pytest.raises(DBAPIError) as exc:
        db.execute(text("DELETE FROM technician_payment_accounts WHERE technician_id = :t"), {"t": tid})
    db.rollback()
    assert "PAYMENT_ACCOUNT_IMMUTABLE" in str(exc.value.orig)


def test_vencimiento_del_kyc_bloquea_la_cuenta(client, db, tech, fake):
    tid, th = tech
    enabled_account(client, db, fake, tid, th)
    db.execute(text("UPDATE kyc_profiles SET expires_at = now() - interval '1 day' WHERE technician_id = :t"),
               {"t": tid})
    db.commit()
    assert decisions.expire_approvals(db) == 1
    db.commit()
    assert row(db, tid).blocked_reason == "KYC_EXPIRED"


def test_reaprobacion_del_kyc_libera_la_cuenta(client, db, category, reviewer, supervisor, fake):
    """Camino real: aprobación por la API, suspensión, reactivación y nueva aprobación."""
    assert register(client, "technician", "tec2@example.com", category_ids=[category.id]).status_code == 201
    uid = db.scalar(select(User.id).where(User.email == "tec2@example.com"))
    profile = drive_to(db, uid, KycStatus.SUBMITTED, reviewer, supervisor)
    add_required_documents(db, profile)
    db.commit()
    sup = auth(login(client, "supervisor@example.com").json()["access_token"])

    def approve():
        assert client.post(f"{CASES}/{profile.id}/claim", headers=sup).status_code in (200, 409)
        for d in db.scalars(text("SELECT id FROM kyc_documents WHERE kyc_profile_id = :p AND status = 'PENDING_REVIEW'"),
                            {"p": profile.id}).all():
            client.put(f"{CASES}/{profile.id}/documents/{d}/decision", headers=sup, json={"decision": "APPROVED"})
        r = client.post(f"{CASES}/{profile.id}/decision", headers=sup, json={"decision": "APPROVED"})
        assert r.status_code == 200, r.text

    approve()
    th = auth(login(client, "tec2@example.com").json()["access_token"])
    enabled_account(client, db, fake, uid, th)
    assert client.post(f"{CASES}/{profile.id}/suspend", headers=sup,
                       json={"reason_code": "INVESTIGACION_EN_CURSO", "note": "Queja formal"}).status_code == 200
    assert row(db, uid).blocked_reason == "KYC_SUSPENDED"
    assert client.post(f"{CASES}/{profile.id}/reinstate", headers=sup,
                       json={"note": "Investigación cerrada"}).status_code == 200
    assert row(db, uid).blocked_reason == "KYC_SUSPENDED"          # reactivar no basta: falta aprobar
    approve()
    assert row(db, uid).blocked_reason is None and row(db, uid).can_receive_payments


def test_trigger_protege_la_cuenta(client, db, tech, fake):
    tid, th = tech
    client.post(ACCOUNT, headers=th, json={})
    for sql, code in (
        ("UPDATE technician_payment_accounts SET status = 'RESTRICTED' WHERE technician_id = :t",
         "PAYMENT_ACCOUNT_INVALID_TRANSITION"),
        ("UPDATE technician_payment_accounts SET provider_account_id = 'acct_otra' WHERE technician_id = :t",
         "PAYMENT_ACCOUNT_IMMUTABLE"),
        ("UPDATE technician_payment_accounts SET technician_id = gen_random_uuid() WHERE technician_id = :t",
         "PAYMENT_ACCOUNT_IMMUTABLE"),
    ):
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(sql), {"t": tid})
        db.rollback()
        assert code in str(exc.value.orig)


# ------------------------------------------------------------------ tarjetas del cliente
def test_guardar_tarjeta_entrega_solo_el_client_secret(client, db, fake):
    cid, ch = new_client(client, db)
    r = client.post(f"{CARDS}/setup-intent", headers=ch, json={})
    assert r.status_code == 201
    secret = r.json()["client_secret"]
    assert secret.startswith("seti_") and "_secret_" in secret
    assert "cus_" not in r.text                                     # sin id de cliente del proveedor
    assert r.headers.get("cache-control") == "no-store"
    assert client.post(f"{CARDS}/setup-intent", headers=ch, json={}).status_code == 201
    assert fake.calls.count("customers.create") == 1               # un solo cliente en el proveedor
    assert db.scalar(select(func.count()).select_from(PaymentCustomer).where(PaymentCustomer.user_id == cid)) == 1
    assert client.post(f"{CARDS}/setup-intent", headers=ch, json={"amount": 1}).status_code == 422


def test_listar_tarjetas(client, db, fake):
    cid, ch = new_client(client, db)
    assert client.get(CARDS, headers=ch).json() == []
    client.post(f"{CARDS}/setup-intent", headers=ch, json={})
    customer = db.scalar(select(PaymentCustomer.provider_customer_id).where(PaymentCustomer.user_id == cid))
    fake.add_card(customer, "mastercard", "5454")
    cards = client.get(CARDS, headers=ch).json()
    assert [(c["brand"], c["last4"]) for c in cards] == [("mastercard", "5454")]
    assert set(cards[0]) == {"id", "brand", "last4", "exp_month", "exp_year"}


def test_cada_cliente_ve_solo_sus_tarjetas(client, db, fake):
    a, ha = new_client(client, db, "a@example.com")
    _, hb = new_client(client, db, "b@example.com")
    client.post(f"{CARDS}/setup-intent", headers=ha, json={})
    fake.add_card(db.scalar(select(PaymentCustomer.provider_customer_id).where(PaymentCustomer.user_id == a)))
    assert len(client.get(CARDS, headers=ha).json()) == 1
    assert client.get(CARDS, headers=hb).json() == []
