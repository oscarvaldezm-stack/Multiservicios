"""Pagos, Fase 5: reembolsos (política, doble firma D8, asientos), cancelaciones, captura parcial, contracargos (D9)."""
import re
import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.models import (
    AdminRole,
    CommissionTransaction,
    LedgerAccount,
    OutboxEvent,
    Payment,
    PaymentDispute,
    PaymentKind,
    PaymentRefund,
    PaymentStatus,
    RefundStatus,
    TechnicianPaymentAccount,
)
from app.payments import ledger, refunds
from app.payments.providers import get_provider
from app.payments.providers.base import BalanceInfo, ProviderError
from app.payments.refunds import ALLOWED_REFUND_TRANSITIONS
from tests.conftest import API, auth, login, make_admin
from tests.marketplace import (
    ORDERS,
    approved_tech,
    choose_card,
    new_client,
    order_status,
    payment_of,
    run_order,
)
from tests.test_payments_webhooks import CONNECT, PLATFORM, event, post, work

P, R, A = PaymentStatus, RefundStatus, LedgerAccount


@pytest.fixture
def fake():
    return get_provider()


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


def err(r) -> str:
    return r.json()["detail"]["code"]


def admin(client, db, email: str, *roles) -> dict:
    make_admin(db, email, *roles)
    return auth(login(client, email).json()["access_token"])


def idem() -> dict:
    return {"Idempotency-Key": uuid.uuid4().hex}


def events(db, event_type: str) -> int:
    return db.scalar(select(func.count()).select_from(OutboxEvent).where(OutboxEvent.event_type == event_type))


def refund_row(db, rid) -> PaymentRefund:
    db.expire_all()
    return db.get(PaymentRefund, uuid.UUID(str(rid)))


# ------------------------------------------------------------------ app = trigger
def test_transiciones_de_reembolso_coinciden_con_el_trigger(db):
    src = db.scalar(text("SELECT pg_get_functiondef('payment_refund_guard'::regproc)"))
    assert set(re.findall(r"'([A-Z_]+>[A-Z_]+)'", src)) == {f"{a.value}>{b.value}"
                                                           for a, b in ALLOWED_REFUND_TRANSITIONS}


# ------------------------------------------------------------------ reparto
def test_reparto_segun_la_politica(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    p = payment_of(db, oid)                                   # cobro 116,000: técnico 88,100, comisión 15,000
    shared = refunds.allocate(db, p, 34_800, refunds.REASONS["SERVICE_DEFICIENT"])
    assert (shared.technician, shared.commission, shared.vat, shared.withholding, shared.platform) == \
        (26_430, 4_500, 720, 3_150, 0)
    platform = refunds.allocate(db, p, 34_800, refunds.REASONS["COURTESY"])
    assert (platform.technician, platform.commission, platform.platform) == (0, 0, 34_800)
    full = refunds.allocate(db, p, 116_000, refunds.REASONS["SERVICE_NOT_PROVIDED"])
    assert (full.technician, full.commission, full.vat, full.withholding, full.platform) == \
        (88_100, 15_000, 2_400, 10_500, 0)


# ------------------------------------------------------------------ solicitud del cliente
def test_cliente_pide_y_finanzas_aprueba(client, db, category, people, fake):
    _, th, cid, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    url = f"{ORDERS}/{oid}/refund-requests"
    assert err(client.post(url, headers=ch, json={"reason_code": "SERVICE_DEFICIENT"})) == "IDEMPOTENCY_KEY_REQUIRED"
    r = client.post(url, headers=ch | idem(), json={"reason_code": "COURTESY"})
    assert r.status_code == 422 and err(r) == "REFUND_INVALID_REASON"            # motivo que no pide el cliente
    r = client.post(url, headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT", "amount": "5000.00"})
    assert r.status_code == 422 and err(r) == "REFUND_EXCEEDS_CAPTURED"
    r = client.post(url, headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT", "amount": "348.00",
                                                    "note": "Quedó goteando"})
    assert r.status_code == 201 and r.json()["status"] == "REQUESTED"
    assert set(r.json()) == {"id", "status", "amount", "reason_code", "created_at", "succeeded_at"}
    rid = r.json()["id"]
    again = client.post(url, headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"})
    assert again.status_code == 409 and err(again) == "REFUND_ALREADY_OPEN"
    assert events(db, "refund.requested") == 1

    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    out = client.post(f"{API}/admin/refunds/{rid}/approve", headers=op)
    assert out.status_code == 200 and out.json()["status"] == "SUCCEEDED"
    assert out.json()["technician_recovered"] == "264.30" and out.json()["platform_absorbed"] == "0.00"
    req = fake.refunds[refund_row(db, rid).provider_refund_id]
    assert req["reverse"] and req["fee"] and req["amount"] == 34_800
    p = payment_of(db, oid)
    assert p.status == P.PARTIALLY_REFUNDED and p.refunded_cents == 34_800
    assert ledger.balance(db, A.TECHNICIAN_PAYABLE, payment_id=p.id) == 88_100 - 26_430
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == -116_000 + 34_800
    assert client.get(f"{API}/refunds/{rid}", headers=ch).json()["status"] == "SUCCEEDED"
    _, other = new_client(client, db, "otro@example.com")
    assert client.get(f"{API}/refunds/{rid}", headers=other).status_code == 404


def test_rechazo_y_nueva_solicitud(client, db, category, people):
    _, th, cid, ch = people
    oid = run_order(client, db, ch, th, category)
    url = f"{ORDERS}/{oid}/refund-requests"
    rid = client.post(url, headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"}).json()["id"]
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/refunds/{rid}/reject", headers=op, json={"note": "El trabajo está bien hecho"})
    assert r.json()["status"] == "REJECTED"
    assert db.scalar(select(func.count()).select_from(OutboxEvent).where(
        OutboxEvent.event_type == "refund.rejected", OutboxEvent.recipient_user_id == cid)) == 1
    assert client.post(url, headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"}).status_code == 201


def test_plazo_y_estado_de_la_orden(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    r = client.post(f"{ORDERS}/{oid}/refund-requests", headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"})
    assert r.status_code == 409 and err(r) == "REFUND_ORDER_NOT_ELIGIBLE"
    done = run_order(client, db, ch, th, category)
    db.execute(text("UPDATE service_orders SET paid_at = now() - interval '30 days' WHERE id = :o"), {"o": done})
    db.commit()
    r = client.post(f"{ORDERS}/{done}/refund-requests", headers=ch | idem(), json={"reason_code": "SERVICE_DEFICIENT"})
    assert r.status_code == 409 and err(r) == "REFUND_WINDOW_CLOSED"


# ------------------------------------------------------------------ finanzas y doble firma (D8)
def test_doble_firma_arriba_del_umbral(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="3000.00")              # cobro $3,480
    pid = payment_of(db, oid).id
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    op2 = admin(client, db, "operador2@example.com", AdminRole.FINANCE_OPERATOR)
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    r = client.post(f"{API}/admin/payments/{pid}/refunds", headers=op | idem(),
                    json={"reason_code": "PLATFORM_ERROR", "amount": "2500.00", "note": "Se cobró de más"})
    assert r.status_code == 201 and r.json()["status"] == "REQUESTED" and r.json()["needs_second_approval"]
    rid = r.json()["id"]
    assert events(db, "refund.second_approval_required") == 1
    assert err(client.post(f"{API}/admin/refunds/{rid}/approve", headers=op)) == "REFUND_FOUR_EYES"
    assert client.post(f"{API}/admin/refunds/{rid}/approve", headers=op2).status_code == 403   # sin permiso alto
    r = client.post(f"{API}/admin/refunds/{rid}/approve", headers=boss)
    assert r.status_code == 200 and r.json()["status"] == "SUCCEEDED" and r.json()["platform_absorbed"] == "2500.00"


def test_abajo_del_umbral_basta_una_firma_y_la_misma_llave_no_repite(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    pid = payment_of(db, oid).id
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    key = idem()
    body = {"reason_code": "COURTESY", "amount": "100.00", "note": "Cortesía por retraso"}
    first = client.post(f"{API}/admin/payments/{pid}/refunds", headers=op | key, json=body)
    again = client.post(f"{API}/admin/payments/{pid}/refunds", headers=op | key, json=body)
    assert first.json()["status"] == "SUCCEEDED" and again.json() == first.json()
    assert fake.calls.count("refunds.create") == 1


def test_permisos_de_finanzas(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    pid = payment_of(db, oid).id
    viewer = admin(client, db, "lectura@example.com", AdminRole.FINANCE_VIEWER)
    support = admin(client, db, "soporte@example.com", AdminRole.SUPPORT)
    assert client.get(f"{API}/admin/refunds", headers=viewer).status_code == 200
    assert client.get(f"{API}/admin/refunds", headers=support).status_code == 403
    body = {"reason_code": "COURTESY", "note": "Cortesía por retraso"}
    assert client.post(f"{API}/admin/payments/{pid}/refunds", headers=viewer | idem(), json=body).status_code == 403


# ------------------------------------------------------------------ fallas y confirmación
def test_tecnico_sin_saldo_la_plataforma_decide(client, db, category, people, fake):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    acct = db.scalar(select(TechnicianPaymentAccount.provider_account_id)
                     .where(TechnicianPaymentAccount.technician_id == tid))
    fake.balances[acct] = BalanceInfo(available_cents=0, pending_cents=0, currency="MXN")
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    pid = payment_of(db, oid).id
    r = client.post(f"{API}/admin/payments/{pid}/refunds", headers=op | idem(),
                    json={"reason_code": "SERVICE_DEFICIENT", "amount": "100.00", "note": "Faltó sellar"})
    assert r.json()["status"] == "FAILED" and r.json()["failure_code"] == "balance_insufficient"
    assert events(db, "refund.failed") == 1
    r = client.post(f"{API}/admin/payments/{pid}/refunds", headers=op | idem(),
                    json={"reason_code": "PLATFORM_ERROR", "amount": "100.00", "note": "La plataforma lo cubre"})
    assert r.json()["status"] == "SUCCEEDED"


def test_proveedor_caido_se_reintenta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", retryable=True)
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/payments/{payment_of(db, oid).id}/refunds", headers=op | idem(),
                    json={"reason_code": "COURTESY", "amount": "50.00", "note": "Cortesía por retraso"})
    assert r.json()["status"] == "APPROVED"
    assert refunds.retry_approved(db) == 1
    db.commit()
    assert refund_row(db, r.json()["id"]).status == R.SUCCEEDED


def test_reembolso_pendiente_se_confirma_por_webhook(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    fake.refund_status_next = "pending"
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    rid = client.post(f"{API}/admin/payments/{payment_of(db, oid).id}/refunds", headers=op | idem(),
                      json={"reason_code": "COURTESY", "amount": "50.00", "note": "Cortesía por retraso"}).json()["id"]
    row = refund_row(db, rid)
    assert row.status == R.PENDING and payment_of(db, oid).refunded_cents == 0
    fake.set_refund(row.provider_refund_id, "succeeded")
    post(client, PLATFORM, event("refund.updated", row.provider_refund_id, object_type="refund"))
    work(db)
    assert refund_row(db, rid).status == R.SUCCEEDED and payment_of(db, oid).refunded_cents == 5_000


def test_reembolso_hecho_fuera_de_la_app(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    re_id = fake.refund_outside_app(payment_of(db, oid).provider_payment_id, 10_000)
    post(client, PLATFORM, event("refund.created", re_id, object_type="refund"))
    work(db)
    row = db.scalar(select(PaymentRefund).where(PaymentRefund.provider_refund_id == re_id))
    assert row.request_source == "OUTSIDE_APP" and row.status == R.SUCCEEDED and row.platform_absorbed_cents == 10_000
    assert events(db, "payment.refunded_outside_app") == 1


def test_trigger_protege_los_reembolsos(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    rid = client.post(f"{ORDERS}/{oid}/refund-requests", headers=ch | idem(),
                      json={"reason_code": "SERVICE_DEFICIENT"}).json()["id"]
    for sql, code in (("UPDATE payment_refunds SET amount_cents = 1 WHERE id = :r", "REFUND_IMMUTABLE"),
                      ("UPDATE payment_refunds SET reverse_transfer = false WHERE id = :r", "REFUND_IMMUTABLE"),
                      ("UPDATE payment_refunds SET status = 'SUCCEEDED' WHERE id = :r", "REFUND_INVALID_TRANSITION"),
                      ("DELETE FROM payment_refunds WHERE id = :r", "REFUND_IMMUTABLE")):
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(sql), {"r": rid})
            db.flush()
        db.rollback()
        assert code in str(exc.value.orig)


# ------------------------------------------------------------------ disputas de la orden: reembolso o captura parcial
def test_disputa_antes_de_cobrar_se_captura_solo_una_parte(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL", price="850.00")   # autorizado $986
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Solo arregló una de las dos llaves"})
    fin = admin(client, db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=fin,
                    json={"outcome": "PARTIAL_REFUND", "refund_amount": "500.00", "note": "Servicio a medias"})
    assert r.status_code == 200 and r.json()["status"] == "READY_FOR_REVIEW"
    p = payment_of(db, oid)
    cap = db.scalar(select(CommissionTransaction).where(CommissionTransaction.payment_id == p.id,
                                                        CommissionTransaction.stage == "CAPTURE"))
    assert p.status == P.PAID and p.captured_cents == 48_599 and cap.price_cents == 41_896
    assert fake.intents[p.provider_payment_id]["received"] == 48_599
    assert fake.intents[p.provider_payment_id]["captured_fee"] == cap.commission_cents + cap.commission_tax_cents \
        + cap.withholding_isr_cents + cap.withholding_iva_cents
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == -48_599


def test_disputa_despues_de_cobrar_reembolsa_con_la_politica_del_tecnico(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Quedó una fuga pequeña"})
    fin = admin(client, db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=fin,
                json={"outcome": "PARTIAL_REFUND", "refund_amount": "200.00", "note": "Descuento por la fuga"})
    row = db.scalar(select(PaymentRefund).where(PaymentRefund.payment_id == payment_of(db, oid).id))
    assert row.request_source == "DISPUTE" and row.reason_code == "SERVICE_DEFICIENT" and row.status == R.SUCCEEDED
    assert row.reverse_transfer and row.refund_application_fee and row.technician_recovered_cents > 0


# ------------------------------------------------------------------ cancelaciones con política
def set_policy(client, db, **body):
    boss = admin(client, db, f"jefa{uuid.uuid4().hex[:6]}@example.com", AdminRole.FINANCE_ADMIN)
    r = client.post(f"{API}/admin/cancellation-policies", headers=boss, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_cancelacion_en_sitio_cobra_el_cargo_por_visita(client, db, category, people, fake):
    _, th, _, ch = people
    set_policy(client, db, scenario="CLIENT_CANCEL_ON_SITE", fee_type="FIXED", fee_value=30_000,
               technician_share_bp=7_000)
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED", price="1000.00")
    assert client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Ya no lo necesito"}).status_code == 200
    assert order_status(db, oid) == "CANCELLED"
    p = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid)))
    assert p.status == P.PAID and p.captured_cents == 34_800                  # $300 + IVA
    assert ledger.balance(db, A.TECHNICIAN_PAYABLE, payment_id=p.id) == 34_800 - 9_000 - 1_440 - 750 - 2_400
    from app.models import OrderStatusHistory
    assert db.scalar(select(OrderStatusHistory.reason_code).where(
        OrderStatusHistory.order_id == uuid.UUID(oid), OrderStatusHistory.to_status == "CANCELLED")) \
        == "CLIENT_CANCELLED_ON_SITE"


def test_cancelacion_tardia_con_cargo_y_sin_tarjeta(client, db, category, people, fake):
    _, th, _, ch = people
    set_policy(client, db, scenario="CLIENT_LATE_CANCEL", fee_type="FIXED", fee_value=10_000,
               technician_share_bp=5_000)
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    choose_card(client, db, ch, oid)
    client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Cambio de planes"})
    fee = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid),
                                          Payment.kind == PaymentKind.CANCELLATION_FEE))
    assert fee.status == P.PAID and fee.amount_cents == 11_600
    service = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid),
                                              Payment.kind == PaymentKind.SERVICE))
    assert service.status == P.CANCELLED
    # Sin tarjeta elegida no se puede cobrar: se avisa a finanzas.
    other = run_order(client, db, ch, th, category, until="SCHEDULED")
    client.post(f"{ORDERS}/{other}/cancel", headers=ch, json={"reason": "Cambio de planes"})
    assert events(db, "cancellation_fee.not_collected") == 1


def test_sin_politica_cancelar_no_cuesta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    pid = payment_of(db, oid).provider_payment_id
    client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Ya no lo necesito"})
    assert fake.intents[pid]["status"] == P.CANCELLED


def test_politicas_solo_finanzas_admin_y_validas(client, db):
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    body = {"scenario": "CLIENT_LATE_CANCEL", "fee_type": "FIXED", "fee_value": 5_000, "technician_share_bp": 5_000}
    assert client.post(f"{API}/admin/cancellation-policies", headers=op, json=body).status_code == 403
    boss = admin(client, db, "jefa@example.com", AdminRole.FINANCE_ADMIN)
    bad = client.post(f"{API}/admin/cancellation-policies", headers=boss, json=body | {"technician_share_bp": 0})
    assert bad.status_code == 422 and err(bad) == "CANCELLATION_POLICY_INVALID"
    first = client.post(f"{API}/admin/cancellation-policies", headers=boss, json=body).json()
    client.post(f"{API}/admin/cancellation-policies", headers=boss, json=body | {"fee_value": 8_000})
    listed = client.get(f"{API}/admin/cancellation-policies", headers=boss).json()
    closed = next(p for p in listed if p["id"] == first["id"])
    assert closed["valid_to"] is not None and sum(p["valid_to"] is None for p in listed) == 1


# ------------------------------------------------------------------ contracargos (D9)
def _dispute(client, db, fake, oid, amount=None) -> str:
    p = payment_of(db, oid)
    did = fake.open_dispute(p.provider_payment_id, amount or p.captured_cents)
    post(client, PLATFORM, event("charge.dispute.created", did, object_type="dispute"))
    work(db)
    return did


def test_contracargo_abierto_no_descuenta_al_tecnico(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    _dispute(client, db, fake, oid)
    assert payment_of(db, oid).status == P.DISPUTED
    assert fake.reversals == {} and events(db, "payment.dispute_opened") == 1


def test_evidencia_y_contracargo_perdido(client, db, category, people, fake):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    did = _dispute(client, db, fake, oid)
    row = db.scalar(select(PaymentDispute).where(PaymentDispute.provider_dispute_id == did))
    fin = admin(client, db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    assert client.get(f"{API}/admin/disputes", headers=fin).json()[0]["id"] == str(row.id)
    r = client.post(f"{API}/admin/disputes/{row.id}/evidence", headers=fin, json={"note": "Hay fotos del trabajo"})
    assert r.status_code == 200 and r.json()["status"] == "UNDER_REVIEW" and r.json()["evidence_submitted_at"]
    sent = fake.evidence[did]
    assert "aprobó el trabajo" in sent["uncategorized_text"] and "Hay fotos" in sent["uncategorized_text"]
    assert "@" not in sent["uncategorized_text"]                          # sin datos personales
    assert client.post(f"{API}/admin/disputes/{row.id}/evidence", headers=fin, json={}).status_code == 409
    fake.close_dispute(did, won=False)
    post(client, PLATFORM, event("charge.dispute.closed", did, object_type="dispute"))
    work(db)
    p = payment_of(db, oid)
    assert p.status == P.CHARGED_BACK
    db.expire_all()
    row = db.get(PaymentDispute, row.id)
    assert row.technician_recovered_cents == 88_100 and row.transfer_reversal_id
    assert ledger.balance(db, A.TECHNICIAN_PAYABLE, payment_id=p.id) == 0
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == 0
    assert events(db, "risk.chargeback_lost") == 1


def test_contracargo_ganado(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    did = _dispute(client, db, fake, oid)
    fake.close_dispute(did, won=True)
    post(client, PLATFORM, event("charge.dispute.closed", did, object_type="dispute"))
    work(db)
    assert payment_of(db, oid).status == P.PAID and fake.reversals == {}


def test_contracargo_perdido_sin_saldo_lo_absorbe_la_plataforma(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    did = _dispute(client, db, fake, oid)
    fake.close_dispute(did, won=False)
    post(client, PLATFORM, event("charge.dispute.closed", did, object_type="dispute"))
    fake.fail_next = None
    original = fake.reverse_transfer
    fake.reverse_transfer = lambda *a, **k: (_ for _ in ()).throw(
        ProviderError("sin saldo", code="PAYMENT_PROVIDER_REJECTED", provider_code="balance_insufficient"))
    try:
        work(db)
    finally:
        fake.reverse_transfer = original
    p = payment_of(db, oid)
    assert p.status == P.CHARGED_BACK and events(db, "dispute.reversal_failed") == 1
    assert ledger.balance(db, A.REFUNDS, payment_id=p.id) == -p.captured_cents


def test_evidencia_fuera_de_plazo(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    _dispute(client, db, fake, oid)
    db.execute(text("UPDATE payment_disputes SET evidence_due_by = now() - interval '1 hour'"))
    db.commit()
    row = db.scalar(select(PaymentDispute))
    fin = admin(client, db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    r = client.post(f"{API}/admin/disputes/{row.id}/evidence", headers=fin, json={})
    assert r.status_code == 409 and err(r) == "DISPUTE_EVIDENCE_OVERDUE"


# ------------------------------------------------------------------ estado de cuenta del técnico
def test_ganancias_depositos_y_saldo(client, db, category, people, fake):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    earnings = client.get(f"{API}/technicians/me/earnings", headers=th).json()
    assert earnings["items"][0]["net"] == "881.00" and earnings["total_adjustments"] == "0.00"
    op = admin(client, db, "operador@example.com", AdminRole.FINANCE_OPERATOR)
    client.post(f"{API}/admin/payments/{payment_of(db, oid).id}/refunds", headers=op | idem(),
                json={"reason_code": "SERVICE_DEFICIENT", "amount": "116.00", "note": "Faltó limpiar"})
    earnings = client.get(f"{API}/technicians/me/earnings", headers=th).json()
    assert earnings["total_adjustments"] == "88.10" and earnings["total_net_after_adjustments"] == "792.90"

    acct = db.scalar(select(TechnicianPaymentAccount.provider_account_id)
                     .where(TechnicianPaymentAccount.technician_id == tid))
    po = fake.add_payout(acct, amount_cents=79_290, status="paid")
    post(client, CONNECT, event("payout.paid", po, object_type="payout", account=acct))
    work(db)
    payouts = client.get(f"{API}/technicians/me/payouts", headers=th).json()
    assert payouts[0]["amount"] == "792.90" and payouts[0]["status"] == "PAID"
    fake.balances[acct] = BalanceInfo(available_cents=12_345, pending_cents=500, currency="MXN")
    assert client.get(f"{API}/technicians/me/balance", headers=th).json() == \
        {"available": "123.45", "pending": "5.00", "currency": "MXN"}
    _, ch2 = new_client(client, db, "c2@example.com")
    assert client.get(f"{API}/technicians/me/earnings", headers=ch2).status_code == 403
