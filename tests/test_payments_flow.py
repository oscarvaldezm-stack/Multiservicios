"""Pagos, Fase 3: regla crítica, tarjeta de la orden, autorización al salir, captura, vencimiento y anulación."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.models import (
    LedgerAccount,
    OutboxEvent,
    Payment,
    PaymentStatus,
    ServiceOrder,
    TechnicianPaymentAccount,
)
from app.payments import ledger
from app.payments import service as payments
from app.payments.providers import get_provider
from app.payments.providers.base import ProviderError, ProviderPayment
from tests.conftest import API
from tests.marketplace import (
    ORDERS,
    approved_tech,
    capture_due,
    choose_card,
    create_order,
    new_client,
    order_status,
    payment_of,
    run_order,
)

P = PaymentStatus


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


def events(db, event_type) -> int:
    return db.scalar(select(func.count()).select_from(OutboxEvent).where(OutboxEvent.event_type == event_type))


def idem() -> dict:
    return {"Idempotency-Key": uuid.uuid4().hex}


def intent(fake, db, oid) -> dict:
    return fake.intents[payment_of(db, oid).provider_payment_id]


# ------------------------------------------------------------------ regla crítica ampliada
def test_tecnico_aprobado_sin_cuenta_de_pagos_no_acepta_ni_recibe_reservas(client, db, category, reviewer,
                                                                            supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor, payment_account=False)
    _, ch = new_client(client, db)
    oid = create_order(client, ch, category)["id"]
    r = client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "800.00"})
    assert r.status_code == 403 and err(r) == "PAYMENT_ACCOUNT_NOT_ENABLED"
    body = {"category_id": category.id, "title": "Fuga", "description": "Gotea la llave",
            "address_line": "Av. Independencia 100", "city": "Veracruz", "requested_technician_id": str(tid)}
    r = client.post(ORDERS, headers=ch, json=body)
    assert r.status_code == 409 and err(r) == "ORDER_TECHNICIAN_UNAVAILABLE"


def test_trigger_repite_la_regla_por_sql_directo(client, db, category, reviewer, supervisor):
    tid, _ = approved_tech(client, db, category, reviewer, supervisor, payment_account=False)
    _, ch = new_client(client, db)
    oid = create_order(client, ch, category)["id"]
    with pytest.raises(DBAPIError) as exc:
        db.execute(text("UPDATE service_orders SET status = 'ACCEPTED', technician_id = :t, agreed_price = 800 "
                        "WHERE id = :o"), {"t": tid, "o": oid})
    db.rollback()
    assert "PAYMENT_ACCOUNT_NOT_ENABLED" in str(exc.value.orig)


def test_cuenta_bloqueada_no_agenda(client, db, category, people):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="ACCEPTED")
    db.execute(text("UPDATE technician_payment_accounts SET blocked_reason = 'NAME_MISMATCH' WHERE technician_id = :t"),
               {"t": tid})
    db.commit()
    r = client.post(f"{ORDERS}/{oid}/schedule", headers=th,
                    json={"scheduled_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()})
    assert r.status_code == 403 and err(r) == "PAYMENT_ACCOUNT_NOT_ENABLED"


def test_cuenta_restringida_suelta_ordenes_y_anula_reservas(client, db, category, people, fake):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    acct = db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == tid))
    fake.set_account(acct.provider_account_id, requirements_due=("individual.verification.document",))
    db.execute(text("UPDATE technician_payment_accounts SET last_synced_at = NULL"))
    db.commit()
    assert client.post(f"{API}/technicians/me/payment-account/refresh", headers=th, json={}).json()["status"] \
        == "RESTRICTED"
    assert order_status(db, oid) == "REQUESTED"                           # vuelve a la bolsa
    cancelled = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid)))
    assert cancelled.status == P.CANCELLED
    assert fake.intents[cancelled.provider_payment_id]["status"] == P.CANCELLED     # reserva liberada


# ------------------------------------------------------------------ tarjeta de la orden
def test_elegir_tarjeta_exige_idempotency_key_y_tarjeta_propia(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    client.post(f"{API}/clients/me/payment-methods/setup-intent", headers=ch, json={})
    url = f"{ORDERS}/{oid}/payment-method"
    r = client.post(url, headers=ch, json={"payment_method_id": "pm_fake123"})
    assert r.status_code == 422 and err(r) == "IDEMPOTENCY_KEY_REQUIRED"
    # Tarjeta de otro cliente
    oc, oh = new_client(client, db, "otro@example.com")
    client.post(f"{API}/clients/me/payment-methods/setup-intent", headers=oh, json={})
    from app.models import PaymentCustomer
    other_pm = fake.add_card(db.scalar(select(PaymentCustomer.provider_customer_id)
                                       .where(PaymentCustomer.user_id == oc)))
    r = client.post(url, headers=ch | idem(), json={"payment_method_id": other_pm})
    assert r.status_code == 422 and err(r) == "PAYMENT_METHOD_NOT_FOUND"
    # Otro cliente sobre esta orden: 404
    assert client.post(url, headers=oh | idem(), json={"payment_method_id": other_pm}).status_code == 404
    # Campos colados
    assert client.post(url, headers=ch | idem(), json={"payment_method_id": other_pm, "amount": 1}).status_code == 422


def test_misma_llave_repite_la_respuesta_y_otra_carga_se_rechaza(client, db, category, people, fake):
    _, th, cid, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    client.post(f"{API}/clients/me/payment-methods/setup-intent", headers=ch, json={})
    from app.models import PaymentCustomer
    customer = db.scalar(select(PaymentCustomer.provider_customer_id).where(PaymentCustomer.user_id == cid))
    pm1, pm2 = fake.add_card(customer), fake.add_card(customer, last4="1881")
    key = idem()
    url = f"{ORDERS}/{oid}/payment-method"
    first = client.post(url, headers=ch | key, json={"payment_method_id": pm1})
    again = client.post(url, headers=ch | key, json={"payment_method_id": pm1})
    assert first.status_code == again.status_code == 200 and first.json() == again.json()
    assert again.headers.get("idempotent-replayed") == "true"
    r = client.post(url, headers=ch | key, json={"payment_method_id": pm2})
    assert r.status_code == 422 and err(r) == "IDEMPOTENCY_KEY_REUSED"
    assert payment_of(db, oid).provider_payment_method_id == pm1


def test_vista_del_pago_segun_quien_pregunta(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    mine = client.get(f"{ORDERS}/{oid}/payment", headers=ch).json()
    assert (mine["total"], mine["service_price"], mine["service_tax"]) == ("1160.00", "1000.00", "160.00")
    assert "commission" not in mine and "net" not in mine and mine["client_secret"] is None
    tech = client.get(f"{ORDERS}/{oid}/payment", headers=th).json()
    assert (tech["net"], tech["commission"], tech["withholding_iva"]) == ("881.00", "150.00", "80.00")
    assert "client_secret" not in tech and "total" not in tech
    _, oh = new_client(client, db, "ajeno@example.com")
    assert client.get(f"{ORDERS}/{oid}/payment", headers=oh).status_code == 404


# ------------------------------------------------------------------ en camino: autorización (D7)
def test_salir_sin_tarjeta_avisa_al_cliente(client, db, category, people):
    _, th, cid, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 409 and err(r) == "ORDER_PAYMENT_METHOD_MISSING"
    assert events(db, "payment.method_required") == 1


def test_autorizacion_con_division_hacia_el_tecnico(client, db, category, people, fake):
    tid, th, cid, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    choose_card(client, db, ch, oid)
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 200 and r.json()["can_start"] and r.json()["payment_status"] == "AUTHORIZED"
    p = payment_of(db, oid)
    req = fake.intents[p.provider_payment_id]["request"]
    acct = db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == tid))
    assert (req.amount_cents, req.application_fee_cents, req.destination_account_id) == \
        (116_000, 27_900, acct.provider_account_id)
    assert req.payment_method_id == p.provider_payment_method_id and p.technician_account_id == acct.id
    assert p.capture_deadline > datetime.now(timezone.utc) + timedelta(hours=100)
    db.expire_all()
    assert db.get(ServiceOrder, uuid.UUID(oid)).departed_at is not None
    assert events(db, "order.technician_on_the_way") == 1
    # Repetir "en camino" no vuelve a cobrar
    assert client.post(f"{ORDERS}/{oid}/depart", headers=th).status_code == 200
    assert fake.calls.count("payment_intents.create") == 1
    # Ya autorizado, la tarjeta no se cambia
    r = client.post(f"{ORDERS}/{oid}/payment-method", headers=ch | idem(),
                    json={"payment_method_id": p.provider_payment_method_id})
    assert r.status_code == 409 and err(r) == "PAYMENT_METHOD_LOCKED"


def test_rechazo_al_salir_el_cliente_elige_otra_tarjeta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    choose_card(client, db, ch, oid)
    fake.decline_next = "insufficient_funds"
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 200 and not r.json()["can_start"]
    assert (r.json()["payment_status"], r.json()["failure_code"]) == ("FAILED", "insufficient_funds")
    assert order_status(db, oid) == "SCHEDULED"
    assert events(db, "payment.authorization_failed") == 1 and events(db, "order.payment_not_authorized") == 1
    assert client.post(f"{ORDERS}/{oid}/start", headers=th).status_code == 409      # no se inicia sin cobro
    fresh = payment_of(db, oid)
    assert fresh.status == P.PENDING and fresh.provider_payment_method_id is None
    choose_card(client, db, ch, oid, last4="5556")
    assert client.post(f"{ORDERS}/{oid}/depart", headers=th).json()["can_start"]
    assert client.post(f"{ORDERS}/{oid}/start", headers=th).status_code == 200


def test_banco_pide_autenticacion_y_el_cliente_la_completa(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    choose_card(client, db, ch, oid)
    fake.decline_next = "authentication_required"
    assert client.post(f"{ORDERS}/{oid}/depart", headers=th).json()["payment_status"] == "REQUIRES_ACTION"
    assert events(db, "payment.action_required") == 1
    view = client.get(f"{ORDERS}/{oid}/payment", headers=ch).json()
    assert view["status"] == "REQUIRES_ACTION" and "_secret_" in view["client_secret"]
    assert "client_secret" not in client.get(f"{ORDERS}/{oid}/payment", headers=th).json()
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 409 and err(r) == "PAYMENT_REQUIRES_ACTION"
    fake.complete_authentication(payment_of(db, oid).provider_payment_id)
    out = client.post(f"{ORDERS}/{oid}/payment/refresh", headers=ch).json()
    assert out["status"] == "AUTHORIZED" and out["client_secret"] is None
    assert client.post(f"{ORDERS}/{oid}/start", headers=th).status_code == 200


def test_otro_tecnico_no_sale_por_esta_orden(client, db, category, reviewer, supervisor, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    _, other = approved_tech(client, db, category, reviewer, supervisor, email="otro.tec@example.com", n=5)
    assert client.post(f"{ORDERS}/{oid}/depart", headers=other).status_code == 404


# ------------------------------------------------------------------ captura
def test_aprobar_no_cobra_en_la_peticion_y_el_worker_captura_una_vez(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED", price="1000.00")
    assert payment_of(db, oid).status == P.AUTHORIZED                    # aprobar no depende de Stripe
    assert capture_due(db) == 1
    p = payment_of(db, oid)
    assert p.status == P.PAID and p.captured_cents == 116_000 and order_status(db, oid) == "READY_FOR_REVIEW"
    assert ledger.balance(db, LedgerAccount.TECHNICIAN_PAYABLE, payment_id=p.id) == 88_100
    assert capture_due(db) == 0 and intent(fake, db, oid)["captures"] == 1


def test_proveedor_caido_al_capturar_se_reintenta(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", http_status=503,
                                   retryable=True)
    assert capture_due(db) == 0 and payment_of(db, oid).status == P.AUTHORIZED
    assert capture_due(db) == 1 and payment_of(db, oid).status == P.PAID


def test_autorizacion_vencida_al_capturar_alerta_a_finanzas(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    fake.set_intent(payment_of(db, oid).provider_payment_id, status=P.CANCELLED)
    capture_due(db)
    assert payment_of(db, oid) is None                                   # el pago quedó CANCELLED
    assert events(db, "payment.authorization_expired") == 1 and order_status(db, oid) == "COMPLETED"


def test_aprobacion_automatica_y_captura(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    db.execute(text("UPDATE service_orders SET work_finished_at = now() - interval '73 hours' WHERE id = :o"),
               {"o": oid})
    db.commit()
    from app.orders import service as orders
    assert orders.auto_approve(db) == 1
    db.commit()
    capture_due(db)
    assert order_status(db, oid) == "READY_FOR_REVIEW"


def test_salvaguarda_24_h_antes_de_que_venza_la_autorizacion(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    db.execute(text("UPDATE payments SET capture_deadline = now() + interval '10 hours' WHERE service_order_id = :o"),
               {"o": oid})
    db.commit()
    assert payments.enforce_capture_deadline(db) == 1
    db.commit()
    from app.models import OrderStatusHistory
    reason = db.scalar(select(OrderStatusHistory.reason_code).where(
        OrderStatusHistory.order_id == uuid.UUID(oid), OrderStatusHistory.to_status == "COMPLETED"))
    assert reason == "AUTO_APPROVED_AUTH_EXPIRING"
    capture_due(db)
    assert order_status(db, oid) == "READY_FOR_REVIEW"


def test_salvaguarda_con_disputa_cobra_segun_d4(client, db, category, people):
    """D4: con un reclamo abierto, se captura 24 h antes de vencer y la disputa se resuelve después."""
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "El trabajo quedó incompleto"})
    db.execute(text("UPDATE payments SET capture_deadline = now() + interval '10 hours' WHERE service_order_id = :o"),
               {"o": oid})
    db.commit()
    for _ in range(2):
        payments.enforce_capture_deadline(db)
        db.commit()
    capture_due(db)
    assert payment_of(db, oid).status == P.PAID and order_status(db, oid) == "DISPUTED"
    assert events(db, "payment.captured_under_dispute") == 1 and events(db, "payment.authorization_expiring") == 0


def test_salvaguarda_con_trabajo_en_curso_solo_alerta(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="IN_PROGRESS")
    db.execute(text("UPDATE payments SET capture_deadline = now() + interval '10 hours' WHERE service_order_id = :o"),
               {"o": oid})
    db.commit()
    for _ in range(2):
        payments.enforce_capture_deadline(db)
        db.commit()
    assert payment_of(db, oid).status == P.AUTHORIZED and events(db, "payment.authorization_expiring") == 1


# ------------------------------------------------------------------ anulación
def test_cancelar_despues_de_autorizar_libera_la_reserva(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    pid = payment_of(db, oid).provider_payment_id
    assert client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Ya no lo necesito"}).status_code == 200
    assert fake.intents[pid]["status"] == P.CANCELLED
    assert events(db, "payment.void_requested") == 0


def test_tecnico_se_retira_y_la_reserva_se_anula_aunque_stripe_falle(client, db, category, people, fake):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    fake.fail_next = ProviderError("no responde", code="PAYMENT_PROVIDER_UNAVAILABLE", http_status=503,
                                   retryable=True)
    assert client.post(f"{ORDERS}/{oid}/withdraw", headers=th, json={}).status_code == 200
    assert order_status(db, oid) == "REQUESTED"
    p = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid)))
    assert p.status == P.CANCELLED and events(db, "payment.void_requested") == 1   # queda para reintento


# ------------------------------------------------------------------ reconciliación
def test_evento_adelantado_recorre_los_estados_y_uno_viejo_se_ignora(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    p = payment_of(db, oid)
    payments.apply_provider_state(db, p, ProviderPayment(provider_payment_id="pi_x", status=P.PAID))
    db.commit()
    p = payment_of(db, oid)
    assert p.status == P.PAID and p.authorized_at is not None and p.captured_cents == p.amount_cents
    assert payments.apply_provider_state(db, p, ProviderPayment(provider_payment_id="pi_x", status=P.AUTHORIZED)) \
        is False
    assert p.status == P.PAID
