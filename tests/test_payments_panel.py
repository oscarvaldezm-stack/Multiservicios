"""Pagos, Fase 6: panel de finanzas (reportes desde el libro, CSV, pagos, reglas, cuentas, webhooks, alertas, límites)."""
import csv
import io
import uuid
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.models import AdminRole, AuditLog, LedgerAccount, LedgerEntry, PaymentWebhookEvent, WebhookEventStatus
from app.payments import ledger
from tests.conftest import API, auth, login, make_admin
from tests.marketplace import ORDERS, approved_tech, choose_card, new_client, payment_of, run_order

A = LedgerAccount


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


def admin(client, db, email: str, *roles) -> dict:
    make_admin(db, email, *roles)
    return auth(login(client, email).json()["access_token"])


def idem() -> dict:
    return {"Idempotency-Key": uuid.uuid4().hex}


def today() -> str:
    return datetime.now(ZoneInfo(get_settings().REPORT_TIMEZONE)).date().isoformat()


@pytest.fixture
def activity(client, db, category, people):
    """Dos servicios cobrados y un reembolso parcial repartido (técnico + plataforma)."""
    tid, th, _, ch = people
    a = run_order(client, db, ch, th, category, price="1000.00")
    b = run_order(client, db, ch, th, category, price="850.00")
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/payments/{payment_of(db, a).id}/refunds", headers=op | idem(),
                    json={"reason_code": "SERVICE_DEFICIENT", "amount": "348.00", "note": "Quedó goteando"})
    assert r.json()["status"] == "SUCCEEDED"
    return tid, a, b, op


# ------------------------------------------------------------------ reportes
def test_resumen_cuadra_con_el_libro(client, db, activity):
    *_, op = activity
    s = client.get(f"{API}/admin/finance/summary", headers=op, params={"from": today(), "to": today()}).json()
    t = s["totals"]
    assert t["charged"] == 116_000 + 98_600 and t["refunded"] == 34_800 and t["captured_payments"] == 2
    for metric, account in (("commission", A.PLATFORM_REVENUE), ("commission_vat", A.VAT_PAYABLE),
                            ("withheld", A.TAX_WITHHELD), ("technicians", A.TECHNICIAN_PAYABLE)):
        assert t[metric] == ledger.balance(db, account)
    # Partida doble: lo que entra menos lo devuelto = lo repartido − lo absorbido por la plataforma.
    assert t["charged"] - t["refunded"] - t["charged_back"] == \
        t["technicians"] + t["commission"] + t["commission_vat"] + t["withheld"] - t["platform_absorbed"]
    assert t["commission"] == 15_000 + 12_750 - 4_500 and t["platform_net"] == t["commission"]
    assert s["timezone"] == "America/Mexico_City" and s["from"] == today()


@pytest.mark.parametrize("group_by", ["day", "week", "month", "technician", "category"])
def test_agrupaciones_suman_el_total(client, db, activity, group_by):
    tid, *_, op = activity
    s = client.get(f"{API}/admin/finance/summary", headers=op,
                   params={"from": today(), "to": today(), "group_by": group_by}).json()
    assert len(s["groups"]) == 1 and s["groups"][0]["charged"] == s["totals"]["charged"]
    if group_by == "technician":
        assert s["groups"][0]["key"] == str(tid) and s["groups"][0]["label"] == "Usuario Prueba"
    if group_by == "category":
        assert s["groups"][0]["label"] == "Plomería"


def test_periodo_sin_movimientos(client, db, activity):
    *_, op = activity
    old = (date.today() - timedelta(days=40)).isoformat()
    s = client.get(f"{API}/admin/finance/summary", headers=op, params={"from": old, "to": old}).json()
    assert s["totals"]["charged"] == 0


@pytest.mark.parametrize("params,code", [({"from": "2026-09-10", "to": "2026-09-01"}, "REPORT_INVALID_RANGE"),
                                         ({"from": "2024-01-01", "to": "2026-01-01"}, "REPORT_RANGE_TOO_LONG")])
def test_rango_invalido(client, db, params, code):
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.get(f"{API}/admin/finance/summary", headers=op, params=params)
    assert r.status_code == 422 and r.json()["detail"]["code"] == code


def test_solo_finanzas_ve_reportes(client, db, activity):
    support = admin(client, db, "soporte@example.com", AdminRole.SUPPORT)
    viewer = admin(client, db, "lectura@example.com", AdminRole.FINANCE_VIEWER)
    params = {"from": today(), "to": today()}
    assert client.get(f"{API}/admin/finance/summary", headers=support, params=params).status_code == 403
    assert client.get(f"{API}/admin/finance/summary", headers=viewer, params=params).status_code == 200


def test_exportacion_csv_del_libro(client, db, activity):
    *_, op = activity
    r = client.get(f"{API}/admin/finance/ledger.csv", headers=op, params={"from": today(), "to": today()})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:4] == ["fecha_local", "grupo", "tipo", "cuenta"]
    assert len(rows) - 1 == db.scalar(select(func.count()).select_from(LedgerEntry))
    assert "@" not in r.text                                          # sin correos ni datos personales
    assert sum(int(round(float(x[4]) * 100)) for x in rows[1:]) == 0  # partida doble
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "finance.ledger.exported")) == 1


# ------------------------------------------------------------------ pagos
def test_listado_y_detalle_de_pagos(client, db, activity):
    tid, a, b, op = activity
    listed = client.get(f"{API}/admin/payments", headers=op, params={"technician_id": str(tid)}).json()
    assert {p["order_id"] for p in listed} == {a, b}
    partial = client.get(f"{API}/admin/payments", headers=op, params={"status": "PARTIALLY_REFUNDED"}).json()
    assert [p["order_id"] for p in partial] == [a]
    d = client.get(f"{API}/admin/payments/{partial[0]['id']}", headers=op).json()
    assert d["provider_payment_id"].startswith("pi_") and d["breakdowns"][0]["stage"] == "QUOTE"
    assert {t["type"] for t in d["transactions"]} == {"AUTHORIZATION", "CAPTURE"}
    assert d["refunds"][0]["technician_recovered_cents"] == 26_430
    assert sum(e["amount_cents"] for e in d["ledger"]) == 0 and len(d["ledger"]) > 5
    assert client.get(f"{API}/admin/payments/{uuid.uuid4()}", headers=op).status_code == 404


def test_pagos_de_una_orden_para_sus_participantes(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    lines = client.get(f"{ORDERS}/{oid}/payments", headers=ch).json()
    assert [(x["kind"], x["status"]) for x in lines] == [("SERVICE", "PAID")]
    assert client.get(f"{ORDERS}/{oid}/payments", headers=th).status_code == 200
    _, other = new_client(client, db, "otro@example.com")
    assert client.get(f"{ORDERS}/{oid}/payments", headers=other).status_code == 404


# ------------------------------------------------------------------ reglas de comisión por la API
def test_reglas_de_comision_por_la_api(client, db, category):
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    body = {"scope": "CATEGORY", "scope_ref": str(category.id), "type": "PERCENT", "rate_bp": 1200,
            "min_cents": 1000, "note": "Plomería más competitiva"}
    assert client.post(f"{API}/admin/commission-rules", headers=op, json=body).status_code == 403
    r = client.post(f"{API}/admin/commission-rules", headers=boss, json=body | {"rate_bp": 200, "min_cents": None})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "COMMISSION_BELOW_PROVIDER_COST"
    assert "price" in r.json()["detail"]
    r = client.post(f"{API}/admin/commission-rules", headers=boss, json=body)
    assert r.status_code == 201
    rid = r.json()["id"]
    assert client.post(f"{API}/admin/commission-rules", headers=boss, json=body | {"amount": 1}).status_code == 422
    active = client.get(f"{API}/admin/commission-rules", headers=op, params={"active_only": True}).json()
    assert {x["scope"] for x in active} == {"GLOBAL", "CATEGORY"}
    prev = client.get(f"{API}/admin/commission-rules/preview", headers=op,
                      params={"price": "1000.00", "category_id": category.id}).json()
    # 12 %: 1,160 − 120 − 19.20 (IVA comisión) − 25 (ISR) − 80 (IVA retenido) = 915.80
    assert (prev["rule_scope"], prev["total_charged"], prev["commission"], prev["technician_net"]) == \
        ("CATEGORY", "1160.00", "120.00", "915.80")
    assert prev["provider_cost_estimate"] == "51.92"
    closed = client.post(f"{API}/admin/commission-rules/{rid}/close", headers=boss, json={})
    assert closed.status_code == 200 and closed.json()["valid_to"] is not None
    prev = client.get(f"{API}/admin/commission-rules/preview", headers=op,
                      params={"price": "1000.00", "category_id": category.id}).json()
    assert prev["rule_scope"] == "GLOBAL" and prev["technician_net"] == "881.00"


# ------------------------------------------------------------------ cuentas, webhooks y alertas
def test_cuentas_de_tecnicos(client, db, people):
    tid, *_ = people
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    rows = client.get(f"{API}/admin/payment-accounts", headers=op).json()
    assert rows[0]["technician_id"] == str(tid) and rows[0]["can_receive_payments"]
    db.execute(text("UPDATE technician_payment_accounts SET blocked_reason = 'NAME_MISMATCH'"))
    db.commit()
    assert len(client.get(f"{API}/admin/payment-accounts", headers=op, params={"blocked": True}).json()) == 1
    assert client.get(f"{API}/admin/payment-accounts", headers=op, params={"blocked": False}).json() == []


def test_reencolar_webhook_muerto(client, db):
    db.add(PaymentWebhookEvent(provider="stripe", provider_event_id="evt_dead", type="payment_intent.succeeded",
                               payload={"object_id": "pi_x", "livemode": False}, signature_valid=True,
                               status=WebhookEventStatus.DEAD, attempts=8, last_error="PAYMENT_PROVIDER_UNAVAILABLE"))
    db.commit()
    eid = db.scalar(select(PaymentWebhookEvent.id))
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    assert client.get(f"{API}/admin/payment-webhooks", headers=op, params={"status": "DEAD"}).json()[0]["id"] == eid
    note = {"note": "Stripe ya responde"}
    assert client.post(f"{API}/admin/payment-webhooks/{eid}/requeue", headers=op, json=note).status_code == 403
    r = client.post(f"{API}/admin/payment-webhooks/{eid}/requeue", headers=boss, json=note)
    assert r.status_code == 200 and r.json()["status"] == "PENDING" and r.json()["attempts"] == 0
    r = client.post(f"{API}/admin/payment-webhooks/{eid}/requeue", headers=boss, json=note)
    assert r.status_code == 409


def test_alertas_de_finanzas(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    client.post(f"{ORDERS}/{oid}/refund-requests", headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"})
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    viewer = admin(client, db, "lectura@example.com", AdminRole.FINANCE_VIEWER)
    alerts = client.get(f"{API}/admin/finance/alerts", headers=viewer).json()
    assert [a["type"] for a in alerts] == ["refund.requested"]
    aid = alerts[0]["id"]
    note = {"note": "Revisado con el cliente"}
    assert client.post(f"{API}/admin/finance/alerts/{aid}/ack", headers=viewer, json=note).status_code == 403
    assert client.post(f"{API}/admin/finance/alerts/{aid}/ack", headers=op, json=note).status_code == 200
    assert client.get(f"{API}/admin/finance/alerts", headers=op).json() == []
    assert len(client.get(f"{API}/admin/finance/alerts", headers=op,
                          params={"include_acknowledged": True}).json()) == 1
    assert client.post(f"{API}/admin/finance/alerts/{aid}/ack", headers=op, json=note).status_code == 409
    assert db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "finance.alert.acknowledged")) == 1


# ------------------------------------------------------------------ límites por usuario
def test_limite_al_elegir_tarjeta(client, db, category, people, monkeypatch):
    _, th, _, ch = people
    monkeypatch.setattr(get_settings(), "RATE_PAYMENT_METHOD_PER_MINUTE", 2)
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    pm = choose_card(client, db, ch, oid)
    client.post(f"{ORDERS}/{oid}/payment-method", headers=ch | idem(), json={"payment_method_id": pm})
    r = client.post(f"{ORDERS}/{oid}/payment-method", headers=ch | idem(), json={"payment_method_id": pm})
    assert r.status_code == 429 and r.json()["detail"]["code"] == "RATE_LIMITED"


def test_limite_de_solicitudes_de_reembolso(client, db, category, people, monkeypatch):
    _, th, _, ch = people
    monkeypatch.setattr(get_settings(), "RATE_REFUND_REQUESTS_PER_HOUR", 1)
    a = run_order(client, db, ch, th, category)
    b = run_order(client, db, ch, th, category)
    assert client.post(f"{ORDERS}/{a}/refund-requests", headers=ch | idem(),
                       json={"reason_code": "SERVICE_DEFICIENT"}).status_code == 201
    r = client.post(f"{ORDERS}/{b}/refund-requests", headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"})
    assert r.status_code == 429
