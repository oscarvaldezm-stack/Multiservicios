"""
Pagos, Fase 7: regresiones de la revisión de seguridad independiente.

1. Reembolso confirmado con un contracargo abierto: el pago sigue en DISPUTED y el contracargo
   perdido se procesa (reversión al técnico y asiento), descontando lo ya reembolsado.
2. Doble firma (D8) sobre el acumulado: partir un reembolso no la evita; tampoco resolver una
   disputa antes de capturar.
3. "En camino" solo cerca de la cita.
4. Se asienta lo que el proveedor capturó de verdad; la conciliación compara lo capturado.
5. Límite por usuario en las rutas que llaman al proveedor, aunque la petición falle.
6. 3D Secure pendiente no se da por rechazo; una autorización tardía sobre un pago muerto se anula.
7. Aprobar la revisión de nombre no quita un bloqueo del KYC que estaba detrás.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.core.actor import Actor
from app.kyc import decisions
from app.models import (
    AdminRole,
    CommissionTransaction,
    KycProfile,
    LedgerAccount,
    OutboxEvent,
    PaymentDispute,
    PaymentStatus,
    RateLimitHit,
    RefundStatus,
)
from app.payments import ledger, webhooks
from app.payments import service as payments
from app.payments.providers import get_provider
from app.payments.providers.stripe_provider import StripePaymentProvider
from tests.conftest import API
from tests.marketplace import (
    ORDERS,
    approved_tech,
    choose_card,
    new_client,
    order_status,
    payment_of,
    run_order,
)
from tests.test_payments_accounts import ACCOUNT, row
from tests.test_payments_refunds import admin, err, events, idem, refund_row
from tests.test_payments_webhooks import PLATFORM, event, post, reconcile, work

P, R, A = PaymentStatus, RefundStatus, LedgerAccount


@pytest.fixture
def fake():
    return get_provider()


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


@pytest.fixture
def tech(client, db, category, reviewer, supervisor):
    return approved_tech(client, db, category, reviewer, supervisor, payment_account=False)


def _dispute(client, db, fake, p, amount_cents: int) -> str:
    did = fake.open_dispute(p.provider_payment_id, amount_cents)
    post(client, PLATFORM, event("charge.dispute.created", did, object_type="dispute"))
    work(db)
    return did


def _close(client, db, fake, did: str, *, won: bool) -> None:
    fake.close_dispute(did, won=won)
    post(client, PLATFORM, event("charge.dispute.closed", did, object_type="dispute"))
    work(db)


def _confirm_refund(client, db, fake, rid) -> None:
    provider_refund_id = refund_row(db, rid).provider_refund_id
    fake.set_refund(provider_refund_id, "succeeded")
    post(client, PLATFORM, event("refund.updated", provider_refund_id, object_type="refund"))
    work(db)


# ------------------------------------------------------------------ 1. reembolso durante un contracargo
def test_reembolso_confirmado_durante_contracargo_no_evita_el_contracargo(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")                  # cobro 1,160.00
    p = payment_of(db, oid)
    fake.refund_status_next = "pending"
    op = admin(client, db, "op@example.com", AdminRole.FINANCE_OPERATOR)
    rid = client.post(f"{API}/admin/payments/{p.id}/refunds", headers=op | idem(),
                      json={"reason_code": "COURTESY", "amount": "100.00", "note": "Cortesía por demora"}).json()["id"]
    assert refund_row(db, rid).status == R.PENDING
    did = _dispute(client, db, fake, p, 106_000)
    assert payment_of(db, oid).status == P.DISPUTED

    _confirm_refund(client, db, fake, rid)
    p = payment_of(db, oid)
    assert refund_row(db, rid).status == R.SUCCEEDED
    assert p.status == P.DISPUTED and p.refunded_cents == 10_000                   # sigue en disputa

    _close(client, db, fake, did, won=False)
    p = payment_of(db, oid)
    d = db.scalar(select(PaymentDispute).where(PaymentDispute.provider_dispute_id == did))
    assert p.status == P.CHARGED_BACK
    assert d.technician_recovered_cents > 0 and fake.reversals                     # D9: se le revirtió al técnico
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == 0                    # 116,000 − 10,000 − 106,000
    assert ledger.balance(db, A.TECHNICIAN_PAYABLE, payment_id=p.id) >= 0


def test_contracargo_ganado_con_todo_reembolsado_termina_en_refunded(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    p = payment_of(db, oid)
    fake.refund_status_next = "pending"
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    rid = client.post(f"{API}/admin/payments/{p.id}/refunds", headers=boss | idem(),
                      json={"reason_code": "COURTESY", "note": "Reembolso completo"}).json()["id"]
    did = _dispute(client, db, fake, p, 116_000)
    _confirm_refund(client, db, fake, rid)
    assert payment_of(db, oid).status == P.DISPUTED
    _close(client, db, fake, did, won=True)
    assert payment_of(db, oid).status == P.REFUNDED
    assert order_status(db, oid) == "REFUNDED"


def test_no_se_aprueba_ni_envia_un_reembolso_con_contracargo_abierto(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="3000.00")                  # cobro 3,480 > umbral
    p = payment_of(db, oid)
    op = admin(client, db, "op@example.com", AdminRole.FINANCE_OPERATOR)
    rid = client.post(f"{API}/admin/payments/{p.id}/refunds", headers=op | idem(),
                      json={"reason_code": "COURTESY", "note": "Espera segunda firma"}).json()["id"]
    assert refund_row(db, rid).status == R.REQUESTED
    _dispute(client, db, fake, p, 348_000)
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    r = client.post(f"{API}/admin/refunds/{rid}/approve", headers=boss, json={})
    assert r.status_code == 409 and err(r) == "REFUND_PAYMENT_NOT_REFUNDABLE"
    assert not fake.refunds


# ------------------------------------------------------------------ 2. D8 sobre el acumulado
def test_partir_un_reembolso_no_evita_la_segunda_firma(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="3000.00")                  # cobro 3,480
    p = payment_of(db, oid)
    op = admin(client, db, "op@example.com", AdminRole.FINANCE_OPERATOR)
    first = client.post(f"{API}/admin/payments/{p.id}/refunds", headers=op | idem(),
                        json={"reason_code": "COURTESY", "amount": "2000.00", "note": "Primera parte"}).json()
    assert first["status"] == "SUCCEEDED"                                           # justo en el umbral
    second = client.post(f"{API}/admin/payments/{p.id}/refunds", headers=op | idem(),
                         json={"reason_code": "COURTESY", "amount": "1480.00", "note": "Segunda parte"}).json()
    assert second["status"] == "REQUESTED" and second["needs_second_approval"]
    op2 = admin(client, db, "op2@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/refunds/{second['id']}/approve", headers=op2, json={})
    assert r.status_code == 403
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    assert client.post(f"{API}/admin/refunds/{second['id']}/approve", headers=boss, json={}).json()["status"] \
        == "SUCCEEDED"


@pytest.mark.parametrize("outcome,amount", [("PARTIAL_REFUND", "2100.00"), ("FULL_REFUND", None)])
def test_resolver_disputa_antes_de_capturar_respeta_el_umbral(client, db, category, people, fake, outcome, amount):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL", price="3000.00")
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "No quedó bien el trabajo"})
    body = {"outcome": outcome, "note": "Resolución de la disputa"} | ({"refund_amount": amount} if amount else {})
    op = admin(client, db, "op@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=op, json=body)
    assert r.status_code == 403
    assert payment_of(db, oid).status == P.AUTHORIZED
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    assert client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=boss, json=body).status_code == 200


def test_resolver_disputa_chica_no_pide_segunda_firma(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL", price="3000.00")
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Faltó un detalle menor"})
    op = admin(client, db, "op@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=op,
                    json={"outcome": "PARTIAL_REFUND", "refund_amount": "300.00", "note": "Descuento menor"})
    assert r.status_code == 200


# ------------------------------------------------------------------ 3. "En camino" cerca de la cita
def test_no_se_sale_dias_antes_de_la_cita(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="ACCEPTED")
    client.post(f"{ORDERS}/{oid}/schedule", headers=th,
                json={"scheduled_at": (datetime.now(timezone.utc) + timedelta(days=4)).isoformat()})
    choose_card(client, db, ch, oid)
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 409 and err(r) == "ORDER_DEPART_TOO_EARLY"
    assert payment_of(db, oid).status == P.PENDING and not fake.intents          # la tarjeta no se toca


# ------------------------------------------------------------------ 4. lo capturado de verdad
def test_captura_parcial_perdida_se_asienta_por_lo_que_cobro_el_proveedor(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL", price="850.00")   # autorizado 986.00
    p = payment_of(db, oid)
    # El proveedor capturó 485.99 pero la respuesta se perdió (timeout → rollback del desglose).
    fake.set_intent(p.provider_payment_id, status=P.PAID, received=48_599)
    post(client, PLATFORM, event("payment_intent.succeeded", p.provider_payment_id))
    work(db)
    p = payment_of(db, oid)
    cap = db.scalar(select(CommissionTransaction).where(CommissionTransaction.payment_id == p.id,
                                                        CommissionTransaction.stage == "CAPTURE"))
    assert p.status == P.PAID and p.captured_cents == 48_599
    assert cap is not None and cap.gross_cents - cap.discount_cents == 48_599
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == -48_599


def test_captura_que_no_cuadra_con_ningun_desglose_alerta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL", price="850.00")
    p = payment_of(db, oid)
    fake.set_intent(p.provider_payment_id, status=P.PAID, received=50_000)          # ningún precio da 500.00 con IVA
    post(client, PLATFORM, event("payment_intent.succeeded", p.provider_payment_id))
    work(db)
    assert events(db, "payment.capture_amount_mismatch") == 1


def test_conciliacion_compara_lo_capturado(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    fake.set_intent(payment_of(db, oid).provider_payment_id, received=1_000)
    reconcile(db)
    kinds = [e.payload["kind"] for e in db.scalars(select(OutboxEvent).where(
        OutboxEvent.event_type == "payment.reconciliation_mismatch"))]
    assert kinds == ["CAPTURE_MISMATCH"]


# ------------------------------------------------------------------ 5. límite por usuario hacia el proveedor
def test_los_intentos_fallidos_tambien_cuentan(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    codes = [client.post(f"{ORDERS}/{oid}/payment-method", headers=ch | idem(),
                         json={"payment_method_id": f"pm_inventado{i}"}).status_code for i in range(11)]
    assert codes[:10] == [422] * 10 and codes[10] == 429
    assert db.scalar(select(func.count()).select_from(RateLimitHit).where(RateLimitHit.action == "payment-method")) \
        == 10


def test_rutas_que_llaman_al_proveedor_tienen_cuota_por_usuario(client, db, category, people, fake, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "RATE_PROVIDER_CALLS_PER_MINUTE", 3)
    _, _, _, ch = people
    codes = [client.post(f"{API}/clients/me/payment-methods/setup-intent", headers=ch, json={}).status_code
             for _ in range(4)]
    assert codes == [201, 201, 201, 429]
    assert client.get(f"{API}/clients/me/payment-methods", headers=ch).status_code == 429


def test_purga_de_intentos_viejos(db, people):
    from app.payments import panel

    _, _, cid, _ = people
    db.add(RateLimitHit(user_id=uuid.UUID(str(cid)), action="provider",
                        created_at=datetime.now(timezone.utc) - timedelta(days=2)))
    db.add(RateLimitHit(user_id=uuid.UUID(str(cid)), action="provider"))
    db.commit()
    assert panel.purge_rate_hits(db) == 1


# ------------------------------------------------------------------ 6. 3D Secure
@pytest.mark.parametrize("code,expected", [("authentication_required", P.REQUIRES_ACTION),
                                           ("card_declined", P.FAILED)])
def test_stripe_distingue_autenticacion_pendiente_de_rechazo(code, expected):
    pi = {"id": "pi_x", "status": "requires_payment_method", "amount": 1000, "amount_capturable": 0,
          "amount_received": 0, "last_payment_error": {"code": code}, "latest_charge": None, "metadata": {}}
    assert StripePaymentProvider._to_payment(pi).status == expected


def test_autorizacion_tardia_sobre_pago_muerto_se_anula(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    choose_card(client, db, ch, oid)
    fake.decline_next = "authentication_required"
    client.post(f"{ORDERS}/{oid}/depart", headers=th)
    old = payment_of(db, oid)
    pid = old.provider_payment_id
    fake.set_intent(pid, status=P.FAILED)
    payments.apply_provider_state(db, old, fake.get_payment(pid))                   # se da por fallido
    db.commit()
    fake.complete_authentication(pid)                                              # el cliente autentica tarde
    assert payments.apply_provider_state(db, old, fake.get_payment(pid)) is False
    payments.apply_provider_state(db, old, fake.get_payment(pid))                  # repetido: una sola anulación
    db.commit()
    assert events(db, "payment.void_requested") == 1
    assert webhooks.retry_voids(db) == 1
    db.commit()
    assert fake.intents[pid]["status"] == P.CANCELLED


# ------------------------------------------------------------------ 7. revisión de nombre y KYC
def test_aprobar_el_nombre_no_libera_un_kyc_suspendido(client, db, tech, fake, supervisor):
    from tests.conftest import auth, login

    tid, th = tech
    client.post(ACCOUNT, headers=th, json={})
    acc = row(db, tid)
    fake.complete_onboarding(acc.provider_account_id)
    fake.set_account(acc.provider_account_id, legal_first_name="Roberto", legal_last_name="Pérez")
    client.post(f"{ACCOUNT}/refresh", headers=th, json={})
    assert row(db, tid).blocked_reason == "NAME_MISMATCH"
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    decisions.suspend(db, Actor.from_user(supervisor), profile.id, "INVESTIGACION_EN_CURSO", "Queja formal")
    db.commit()
    sup = auth(login(client, "supervisor@example.com").json()["access_token"])
    r = client.post(f"{API}/admin/payment-accounts/{acc.id}/name-review", headers=sup,
                    json={"approve": True, "note": "Es su nombre, verificado"})
    assert r.status_code == 200 and not r.json()["can_receive_payments"]
    assert row(db, tid).blocked_reason == "KYC_SUSPENDED"


# ------------------------------------------------------------------ Docker: generador de .env
def test_generador_de_env_no_deja_marcadores_y_usa_secretos_distintos():
    from pathlib import Path

    from scripts.dev_env import render

    template = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")
    values = dict(line.split("=", 1) for line in render(template).splitlines()
                  if "=" in line and not line.startswith("#"))
    assert not any(v.startswith(("GENERA", "CAMBIA")) or "CAMBIA_ESTA" in v for v in values.values())
    keys = [values[k] for k in ("JWT_SECRET_KEY", "KYC_MASTER_KEY", "KYC_BLIND_INDEX_KEY", "INTEGRITY_KEY")]
    assert len(set(keys)) == 4
    assert f":{values['POSTGRES_APP_PASSWORD']}@" in values["DATABASE_URL"]
    assert values["POSTGRES_PASSWORD"] != values["POSTGRES_APP_PASSWORD"]
