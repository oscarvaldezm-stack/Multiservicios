"""Pagos, Fase 4: recepción de webhooks firmados, worker que re-consulta al proveedor, reintentos y conciliación."""
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select, text

from app.models import (
    AuditLog,
    OutboxEvent,
    PaymentStatus,
    PaymentTransaction,
    PaymentWebhookEvent,
    Payout,
    PayoutStatus,
    TechnicianPaymentAccount,
    WebhookEventStatus,
)
from app.payments import reconciliation, webhooks
from app.payments.providers import get_provider
from app.payments.providers.base import ProviderError
from tests.conftest import API
from tests.marketplace import ORDERS, approved_tech, new_client, order_status, payment_of, run_order

P, W = PaymentStatus, WebhookEventStatus
PLATFORM, CONNECT = f"{API}/webhooks/stripe", f"{API}/webhooks/stripe-connect"
SECRETS = {PLATFORM: os.environ["STRIPE_WEBHOOK_SECRET"], CONNECT: os.environ["STRIPE_CONNECT_WEBHOOK_SECRET"]}


@pytest.fixture
def fake():
    return get_provider()


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


def event(type_: str, object_id: str, *, object_type: str = "payment_intent", account: str | None = None,
          livemode: bool = False, extra: dict | None = None) -> dict:
    ev = {"id": f"evt_{uuid.uuid4().hex[:16]}", "object": "event", "type": type_, "livemode": livemode,
          "created": int(time.time()), "data": {"object": {"id": object_id, "object": object_type, **(extra or {})}}}
    if account:
        ev["account"] = account
    return ev


def post(client, url: str, ev: dict, *, secret: str | None = None, ts: int | None = None, raw: bytes | None = None):
    body = raw if raw is not None else json.dumps(ev).encode()
    ts = ts or int(time.time())
    sig = hmac.new((secret or SECRETS[url]).encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return client.post(url, content=body, headers={"Stripe-Signature": f"t={ts},v1={sig}",
                                                   "Content-Type": "application/json"})


def work(db) -> int:
    done = webhooks.process_pending(db)
    db.commit()
    db.expire_all()
    return done


def stored(db, provider_event_id: str) -> PaymentWebhookEvent:
    db.expire_all()
    return db.scalar(select(PaymentWebhookEvent).where(PaymentWebhookEvent.provider_event_id == provider_event_id))


def outbox(db, event_type: str) -> int:
    return db.scalar(select(func.count()).select_from(OutboxEvent).where(OutboxEvent.event_type == event_type))


# ------------------------------------------------------------------ recepción
def test_evento_firmado_se_guarda_minimo_y_responde_de_inmediato(client, db):
    ev = event("payment_intent.succeeded", "pi_123", extra={"receipt_email": "cliente@example.com",
                                                            "shipping": {"name": "Gloria"}})
    r = post(client, PLATFORM, ev)
    assert r.status_code == 200 and r.json() == {"received": True, "duplicate": False}
    row = stored(db, ev["id"])
    assert row.status == W.PENDING and row.signature_valid and row.type == "payment_intent.succeeded"
    assert "cliente@example.com" not in json.dumps(row.payload) and "Gloria" not in json.dumps(row.payload)
    assert row.payload["object_id"] == "pi_123" and row.payload["endpoint"] == "platform"


def test_evento_repetido_se_neutraliza(client, db):
    ev = event("payment_intent.succeeded", "pi_123")
    assert post(client, PLATFORM, ev).json()["duplicate"] is False
    assert post(client, PLATFORM, ev).json()["duplicate"] is True
    assert db.scalar(select(func.count()).select_from(PaymentWebhookEvent)) == 1


@pytest.mark.parametrize("case", ["firma_falsa", "sin_firma", "secreto_del_otro_endpoint", "replay_viejo",
                                  "cuerpo_alterado"])
def test_firmas_invalidas_se_rechazan_sin_guardar_nada(client, db, case, caplog):
    ev = event("payment_intent.succeeded", "pi_123")
    if case == "firma_falsa":
        r = client.post(PLATFORM, content=json.dumps(ev), headers={"Stripe-Signature": f"t={int(time.time())},v1=00"})
    elif case == "sin_firma":
        r = client.post(PLATFORM, content=json.dumps(ev))
    elif case == "secreto_del_otro_endpoint":
        r = post(client, PLATFORM, ev, secret=SECRETS[CONNECT])
    elif case == "replay_viejo":
        r = post(client, PLATFORM, ev, ts=int(time.time()) - 600)
    else:
        body = json.dumps(ev).encode()
        ts = int(time.time())
        sig = hmac.new(SECRETS[PLATFORM].encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        r = client.post(PLATFORM, content=body.replace(b"pi_123", b"pi_999"),
                        headers={"Stripe-Signature": f"t={ts},v1={sig}"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "WEBHOOK_SIGNATURE_INVALID"
    assert db.scalar(select(func.count()).select_from(PaymentWebhookEvent)) == 0


def test_cuerpo_demasiado_grande(client, db):
    ev = event("payment_intent.succeeded", "pi_123", extra={"relleno": "x" * (600 * 1024)})
    assert post(client, PLATFORM, ev).status_code == 413


def test_endpoint_de_connect_usa_su_propio_secreto(client, db):
    ev = event("account.updated", "acct_1", object_type="account", account="acct_1")
    assert post(client, CONNECT, ev).status_code == 200
    assert post(client, CONNECT, event("account.updated", "acct_1", object_type="account"),
                secret=SECRETS[PLATFORM]).status_code == 400


# ------------------------------------------------------------------ worker: pagos
def test_cobro_hecho_fuera_de_la_app_se_refleja_por_webhook(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    pid = payment_of(db, oid).provider_payment_id
    fake.set_intent(pid, status=P.PAID, received=payment_of(db, oid).amount_cents)   # capturado desde el panel
    ev = event("payment_intent.succeeded", pid)
    post(client, PLATFORM, ev)
    assert work(db) == 1
    assert stored(db, ev["id"]).status == W.PROCESSED
    assert payment_of(db, oid).status == P.PAID and order_status(db, oid) == "READY_FOR_REVIEW"
    kinds = db.scalars(select(PaymentTransaction.type).where(
        PaymentTransaction.provider_object_id == pid)).all()
    assert {k.value for k in kinds} == {"AUTHORIZATION", "CAPTURE"}


def test_evento_falso_con_firma_valida_no_cambia_nada(client, db, category, people):
    """El worker re-consulta al proveedor: el contenido del evento no manda."""
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    ev = event("payment_intent.succeeded", payment_of(db, oid).provider_payment_id, extra={"status": "succeeded"})
    post(client, PLATFORM, ev)
    work(db)
    assert payment_of(db, oid).status == P.AUTHORIZED and order_status(db, oid) == "COMPLETED"


def test_autenticacion_completada_llega_sola_por_webhook(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    from tests.marketplace import choose_card
    choose_card(client, db, ch, oid)
    fake.decline_next = "authentication_required"
    client.post(f"{ORDERS}/{oid}/depart", headers=th)
    pid = payment_of(db, oid).provider_payment_id
    fake.complete_authentication(pid)
    post(client, PLATFORM, event("payment_intent.amount_capturable_updated", pid))
    work(db)
    assert payment_of(db, oid).status == P.AUTHORIZED
    assert client.post(f"{ORDERS}/{oid}/start", headers=th).status_code == 200


def test_cobro_desconocido_se_ignora(client, db):
    ev = event("payment_intent.succeeded", "pi_no_existe")
    get_provider().intents["pi_no_existe"] = {"status": P.PAID, "amount": 1, "received": 1, "request": None,
                                              "failure_code": None, "fingerprint": None, "client_secret": "x",
                                              "captures": 1, "created": datetime.now(timezone.utc)}
    post(client, PLATFORM, ev)
    work(db)
    row = stored(db, ev["id"])
    assert row.status == W.IGNORED and row.last_error == "UNKNOWN_PAYMENT"


def test_modo_distinto_al_de_las_claves_se_ignora(client, db):
    ev = event("payment_intent.succeeded", "pi_1", livemode=True)
    post(client, PLATFORM, ev)
    work(db)
    assert stored(db, ev["id"]).last_error == "LIVEMODE_MISMATCH"


@pytest.mark.parametrize("type_,note", [("charge.refunded", "NOT_NEEDED"), ("transfer.reversed", "NOT_NEEDED"),
                                        ("customer.created", "UNHANDLED_EVENT_TYPE")])
def test_eventos_que_no_hace_falta_procesar(client, db, type_, note):
    ev = event(type_, "obj_1", object_type="x")
    post(client, PLATFORM, ev)
    work(db)
    row = stored(db, ev["id"])
    assert row.status == W.IGNORED and row.last_error == note


def test_reintentos_con_espera_creciente_y_dead(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    ev = event("payment_intent.succeeded", payment_of(db, oid).provider_payment_id)
    post(client, PLATFORM, ev)
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", retryable=True)
    assert work(db) == 0
    row = stored(db, ev["id"])
    assert row.status == W.FAILED and row.attempts == 1 and row.last_error == "PAYMENT_PROVIDER_UNAVAILABLE"
    assert row.next_attempt_at > datetime.now(timezone.utc)
    assert work(db) == 0 and stored(db, ev["id"]).attempts == 1          # todavía no le toca
    # Al agotar los intentos: DEAD y alerta a finanzas.
    db.execute(text("UPDATE payment_webhook_events SET attempts = 7, next_attempt_at = now() - interval '1 minute'"))
    db.commit()
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", retryable=True)
    work(db)
    assert stored(db, ev["id"]).status == W.DEAD and outbox(db, "payment.webhook_dead") == 1


def test_espera_creciente():
    assert [webhooks.backoff(n) for n in (1, 2, 3)] == [timedelta(minutes=1), timedelta(minutes=2),
                                                         timedelta(minutes=4)]
    assert webhooks.backoff(20) == timedelta(hours=6)


# ------------------------------------------------------------------ worker: cuentas y depósitos
def _account(db, tid) -> TechnicianPaymentAccount:
    db.expire_all()
    return db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == tid))


def test_cuenta_actualizada_sin_que_el_tecnico_consulte(client, db, category, reviewer, supervisor, fake):
    tid, th = approved_tech(client, db, category, reviewer, supervisor, payment_account=False)
    client.post(f"{API}/technicians/me/payment-account", headers=th, json={})
    acct = _account(db, tid).provider_account_id
    fake.complete_onboarding(acct)
    post(client, CONNECT, event("account.updated", acct, object_type="account", account=acct))
    work(db)
    assert _account(db, tid).status.value == "ENABLED"


def test_desautorizacion_bloquea_y_suelta_ordenes(client, db, category, people):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    acct = _account(db, tid).provider_account_id
    post(client, CONNECT, event("account.application.deauthorized", "ca_1", object_type="application",
                                account=acct))
    work(db)
    assert _account(db, tid).blocked_reason == "PROVIDER_DEAUTHORIZED"
    assert order_status(db, oid) == "REQUESTED"


def test_depositos_al_tecnico(client, db, category, people, fake):
    tid, *_ = people
    acct = _account(db, tid).provider_account_id
    po = fake.add_payout(acct, amount_cents=88_100, status="in_transit")
    post(client, CONNECT, event("payout.created", po, object_type="payout", account=acct))
    work(db)
    assert db.scalar(select(Payout.status).where(Payout.provider_payout_id == po)) == PayoutStatus.IN_TRANSIT
    fake.payouts[(acct, po)] = fake.payouts[(acct, po)].__class__(
        provider_payout_id=po, amount_cents=88_100, currency="MXN", status="failed", failure_code="invalid_account_number")
    post(client, CONNECT, event("payout.failed", po, object_type="payout", account=acct))
    work(db)
    db.expire_all()
    row = db.scalar(select(Payout).where(Payout.provider_payout_id == po))
    assert row.status == PayoutStatus.FAILED and row.failure_code == "invalid_account_number"
    assert db.scalar(select(func.count()).select_from(OutboxEvent).where(
        OutboxEvent.event_type == "payout.failed", OutboxEvent.recipient_user_id == tid)) == 1


def test_deposito_de_cuenta_desconocida(client, db):
    ev = event("payout.paid", "po_1", object_type="payout", account="acct_ajena")
    post(client, CONNECT, ev)
    work(db)
    assert stored(db, ev["id"]).last_error == "UNKNOWN_ACCOUNT"


# ------------------------------------------------------------------ anulaciones pendientes
def test_anulacion_pendiente_se_reintenta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    pid = payment_of(db, oid).provider_payment_id
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", retryable=True)
    client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Ya no lo necesito"})
    assert fake.intents[pid]["status"] == P.AUTHORIZED                 # la reserva sigue en el proveedor
    assert webhooks.retry_voids(db) == 1
    db.commit()
    assert fake.intents[pid]["status"] == P.CANCELLED
    assert webhooks.retry_voids(db) == 0


# ------------------------------------------------------------------ conciliación
def reconcile(db, **kw) -> int:
    n = reconciliation.reconcile(db, force=True, **kw)
    db.commit()
    db.expire_all()
    return n


def test_conciliacion_corrige_un_webhook_perdido(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    fake.set_intent(payment_of(db, oid).provider_payment_id, status=P.PAID)
    assert reconcile(db) == 1
    assert payment_of(db, oid).status == P.PAID and order_status(db, oid) == "READY_FOR_REVIEW"


def test_conciliacion_alerta_lo_que_no_es_seguro_corregir(client, db, category, people, fake):
    _, th, _, ch = people
    paid = run_order(client, db, ch, th, category)                                   # PAID aquí
    fake.set_intent(payment_of(db, paid).provider_payment_id, status=P.CANCELLED)      # anulado allá
    other = run_order(client, db, ch, th, category, until="AUTHORIZED")
    fake.set_intent(payment_of(db, other).provider_payment_id, amount=1)               # monto distinto
    fake.add_foreign_intent()                                                         # solo en el proveedor
    reconcile(db)
    kinds = sorted(e.payload["kind"] for e in db.scalars(select(OutboxEvent).where(
        OutboxEvent.event_type == "payment.reconciliation_mismatch")))
    assert kinds == ["AMOUNT_MISMATCH", "PROVIDER_ONLY", "STATUS_MISMATCH"]
    assert payment_of(db, paid).status == P.PAID                                     # no se toca solo
    reconcile(db)                                                                     # sin alertas repetidas
    assert outbox(db, "payment.reconciliation_mismatch") == 3


def test_conciliacion_consistente_con_reembolsos(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    from tests.marketplace import webhook
    webhook(db, oid, "refunded", amount=1_000)                                         # PARTIALLY_REFUNDED aquí
    reconcile(db)
    assert outbox(db, "payment.reconciliation_mismatch") == 0


def test_conciliacion_corre_una_vez_al_dia_y_queda_auditada(db):
    assert reconciliation.reconcile(db) == 0
    db.commit()
    runs = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "payment.reconciliation.run"))
    assert runs == 1
    reconciliation.reconcile(db)
    db.commit()
    assert db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "payment.reconciliation.run")) == 1


def test_conciliacion_sincroniza_cuentas_viejas(client, db, category, people, fake):
    tid, *_ = people
    db.execute(text("UPDATE technician_payment_accounts SET last_synced_at = now() - interval '2 days'"))
    db.commit()
    acct = _account(db, tid).provider_account_id
    fake.set_account(acct, requirements_due=("external_account",))
    reconcile(db)
    assert _account(db, tid).status.value == "RESTRICTED"
