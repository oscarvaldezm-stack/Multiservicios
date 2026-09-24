"""Órdenes de servicio: flujo, IDOR, técnico aprobado, pagos (webhook simulado), disputas y trabajos automáticos."""
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import select, text

from app.models import AdminRole, OrderStatusHistory, PaymentStatus
from app.orders import service as orders
from app.orders.state_machine import ALLOWED_TRANSITIONS
from app.payments.state_machine import ALLOWED_PAYMENT_TRANSITIONS
from tests.conftest import API, auth, login, make_admin, register
from tests.marketplace import (
    ORDERS,
    approved_tech,
    create_order,
    new_client,
    order_status,
    payment_of,
    run_order,
    webhook,
)


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


def err(r) -> str:
    return r.json()["detail"]["code"]


# ------------------------------------------------------------------ sincronía app = base de datos
def test_transiciones_de_la_app_y_del_trigger_coinciden():
    import importlib
    mig = importlib.import_module("migrations.versions.0005_ordenes_resenas_y_decisiones_kyc")
    app_pairs = {f"{a.value}>{b.value}" for a, b in ALLOWED_TRANSITIONS}
    assert app_pairs == set(mig.ORDER_TRANSITIONS)
    pagos = importlib.import_module("migrations.versions.0006_pagos_fase1_modelo_comisiones_y_ledger")
    assert {f"{a.value}>{b.value}" for a, b in ALLOWED_PAYMENT_TRANSITIONS} == set(pagos.PAYMENT_TRANSITIONS)


# ------------------------------------------------------------------ flujo feliz
def test_flujo_completo_hasta_calificable(client, db, category, people):
    tid, th, cid, ch = people
    oid = run_order(client, db, ch, th, category)
    assert order_status(db, oid) == "READY_FOR_REVIEW"
    p = payment_of(db, oid)
    assert p.status == PaymentStatus.PAID and p.captured_cents == p.amount_cents
    b = p.breakdown
    assert b.technician_cents + b.application_fee_cents == p.amount_cents
    history = [h.to_status.value for h in db.scalars(select(OrderStatusHistory).where(
        OrderStatusHistory.order_id == uuid.UUID(oid)).order_by(OrderStatusHistory.id))]
    assert history == ["ACCEPTED", "SCHEDULED", "IN_PROGRESS", "AWAITING_APPROVAL", "COMPLETED", "PAID",
                       "READY_FOR_REVIEW"]


def test_campos_que_decide_el_servidor_no_se_aceptan(client, db, category, people):
    _, _, _, ch = people
    body = {"category_id": category.id, "title": "Fuga", "description": "Gotea la llave del lavabo",
            "address_line": "Av. Independencia 100", "city": "Veracruz", "status": "PAID"}
    assert client.post(ORDERS, headers=ch, json=body).status_code == 422


# ------------------------------------------------------------------ acceso (IDOR / BOLA)
def test_orden_ajena_da_404_a_otro_cliente_y_otro_tecnico(client, db, category, reviewer, supervisor, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="ACCEPTED")
    _, ch2 = new_client(client, db, "otro@example.com")
    _, th2 = approved_tech(client, db, category, reviewer, supervisor, "tec2@example.com", n=5)
    for h in (ch2, th2):
        assert client.get(f"{ORDERS}/{oid}", headers=h).status_code == 404
    assert err(client.post(f"{ORDERS}/{oid}/cancel", headers=ch2, json={})) == "ORDER_NOT_FOUND"
    assert client.post(f"{ORDERS}/{oid}/start", headers=th2).status_code == 404
    assert client.get(f"{ORDERS}/{uuid.uuid4()}", headers=ch).status_code == 404
    assert client.get(f"{ORDERS}/{oid}").status_code == 401


def test_tecnico_no_crea_ordenes_ni_cliente_acepta(client, db, category, people):
    _, th, _, ch = people
    oid = create_order(client, ch, category)["id"]
    assert client.post(ORDERS, headers=th, json={}).status_code in (403, 422)
    assert client.post(f"{ORDERS}/{oid}/accept", headers=ch, json={"agreed_price": "500"}).status_code == 403


def test_bolsa_de_trabajo_no_muestra_direccion_ni_cliente(client, db, category, people):
    _, th, _, ch = people
    create_order(client, ch, category)
    items = client.get(f"{API}/technicians/me/jobs-feed", headers=th).json()
    assert len(items) == 1 and "address_line" not in items[0] and "client_id" not in items[0]


# ------------------------------------------------------------------ técnico aprobado
def test_tecnico_no_aprobado_no_acepta_ni_por_api_directa(client, db, category, people):
    _, _, _, ch = people
    oid = create_order(client, ch, category)["id"]
    register(client, "technician", "nuevo@example.com", category_ids=[category.id])
    h = auth(login(client, "nuevo@example.com").json()["access_token"])
    r = client.post(f"{ORDERS}/{oid}/accept", headers=h, json={"agreed_price": "500"})
    assert r.status_code == 403 and err(r) == "KYC_NOT_APPROVED"
    assert order_status(db, oid) == "REQUESTED"


def test_tecnico_no_acepta_categoria_que_no_ofrece(client, db, people):
    from app.models import ServiceCategory
    _, th, _, ch = people
    other = ServiceCategory(name="Electricidad", slug="electricidad")
    db.add(other)
    db.commit()
    oid = create_order(client, ch, other)["id"]
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "500"}).status_code == 404


def test_dos_tecnicos_no_ganan_la_misma_orden(client, db, category, reviewer, supervisor, people):
    _, th, _, ch = people
    _, th2 = approved_tech(client, db, category, reviewer, supervisor, "tec2@example.com", n=5)
    oid = create_order(client, ch, category)["id"]
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "500"}).status_code == 200
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th2, json={"agreed_price": "400"}).status_code == 404


def test_reserva_directa_solo_la_acepta_ese_tecnico(client, db, category, reviewer, supervisor, people):
    tid, th, _, ch = people
    _, th2 = approved_tech(client, db, category, reviewer, supervisor, "tec2@example.com", n=5)
    oid = create_order(client, ch, category, requested_technician_id=str(tid))["id"]
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=th2).json() == []
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th2, json={"agreed_price": "500"}).status_code == 404
    assert client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "500"}).status_code == 200


def test_iniciar_exige_pago_autorizado(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    r = client.post(f"{ORDERS}/{oid}/start", headers=th)
    assert r.status_code == 409 and err(r) == "ORDER_PAYMENT_NOT_AUTHORIZED"


def test_no_hay_endpoint_para_marcar_pagado(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    for path in ("pay", "paid", "mark-paid", "payment"):
        assert client.post(f"{ORDERS}/{oid}/{path}", headers=ch, json={}).status_code in (404, 405)
    assert order_status(db, oid) == "COMPLETED"


def test_saltos_de_estado_no_permitidos(client, db, category, people):
    _, th, _, ch = people
    oid = create_order(client, ch, category)["id"]
    r = client.post(f"{ORDERS}/{oid}/approve", headers=ch, json={})
    assert r.status_code == 409 and err(r) == "ORDER_INVALID_TRANSITION"


def test_trigger_bloquea_saltos_por_sql_directo(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="IN_PROGRESS")
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError) as exc:
        db.execute(text("UPDATE service_orders SET status = 'READY_FOR_REVIEW' WHERE id = :id"), {"id": oid})
    db.rollback()
    assert "ORDER_INVALID_TRANSITION" in str(exc.value.orig)


def test_cliente_cancela_antes_de_iniciar_y_se_anula_el_pago(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    assert client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={"reason": "Ya no lo necesito"}).status_code == 200
    assert order_status(db, oid) == "CANCELLED"
    from app.models import Payment
    db.expire_all()
    p = db.scalar(select(Payment).where(Payment.service_order_id == uuid.UUID(oid)))
    assert p.status == PaymentStatus.CANCELLED and p.cancelled_at is not None


def test_tecnico_se_retira_y_cuenta_en_su_confiabilidad(client, db, category, people):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    assert client.post(f"{ORDERS}/{oid}/withdraw", headers=th, json={}).status_code == 200
    assert order_status(db, oid) == "REQUESTED"
    from app.models import TechnicianReputation
    db.expire_all()
    assert db.get(TechnicianReputation, tid).technician_cancellations == 1


def test_limite_de_solicitudes_abiertas(client, db, category, people, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ORDER_MAX_OPEN_PER_CLIENT", 2)
    _, _, _, ch = people
    create_order(client, ch, category)
    create_order(client, ch, category)
    body = {"category_id": category.id, "title": "Otra fuga", "description": "Otra llave que gotea",
            "address_line": "Av. Independencia 100", "city": "Veracruz"}
    assert err(client.post(ORDERS, headers=ch, json=body)) == "ORDER_TOO_MANY_OPEN"


# ------------------------------------------------------------------ pagos
def test_rechazo_antes_de_salir_no_tumba_la_orden(client, db, category, people):
    """Fase 3: si el cobro se rechaza antes de iniciar, la orden sigue y el cliente elige otra tarjeta."""
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    first = payment_of(db, oid)
    webhook(db, oid, "failed")
    assert order_status(db, oid) == "SCHEDULED"
    new = payment_of(db, oid)
    assert new.id != first.id and new.status == PaymentStatus.PENDING and new.amount_cents == first.amount_cents


def test_pago_fallido_al_capturar_deja_la_orden_fallida(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    webhook(db, oid, "failed")
    assert order_status(db, oid) == "FAILED"


def test_eventos_repetidos_son_idempotentes(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    webhook(db, oid, "captured")                      # el proveedor reenvía el evento
    assert order_status(db, oid) == "READY_FOR_REVIEW"


def test_cobro_y_reparto_con_la_regla_global(client, db, category, people):
    """Ejemplo del doc de pagos: $1,000 + IVA, comisión 15 %, técnico con RFC."""
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    p = payment_of(db, oid)
    assert p.amount_cents == 116_000
    b = p.breakdown
    assert (b.price_cents, b.service_tax_cents, b.commission_cents, b.commission_tax_cents,
            b.withholding_isr_cents, b.withholding_iva_cents) == (100_000, 16_000, 15_000, 2_400, 2_500, 8_000)
    assert b.application_fee_cents == 27_900 and b.technician_cents == 88_100
    assert b.rule_scope == "GLOBAL" and b.technician_has_rfc


def test_precio_fuera_de_rango_se_rechaza(client, db, category, people):
    _, th, _, ch = people
    oid = create_order(client, ch, category)["id"]
    r = client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": "10.00"})
    assert r.status_code == 422 and err(r) == "ORDER_PRICE_OUT_OF_RANGE"


def test_monto_del_pago_no_se_altera_por_sql(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError) as exc:
        db.execute(text("UPDATE payments SET amount_cents = 1 WHERE service_order_id = :id"), {"id": oid})
    db.rollback()
    assert "PAYMENT_IMMUTABLE" in str(exc.value.orig)


# ------------------------------------------------------------------ disputas
def test_disputa_congela_y_finanzas_resuelve(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    r = client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "El trabajo quedó incompleto"})
    assert r.status_code == 200 and r.json()["status"] == "DISPUTED"

    make_admin(db, "soporte@example.com", AdminRole.SUPPORT)
    make_admin(db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    url = f"{API}/admin/orders/{oid}/dispute-resolution"
    body = {"outcome": "RELEASE", "note": "Evidencia fotográfica del trabajo completo"}
    sup = auth(login(client, "soporte@example.com").json()["access_token"])
    assert client.post(url, headers=sup, json=body).status_code == 403
    fin = auth(login(client, "finanzas@example.com").json()["access_token"])
    r = client.post(url, headers=fin, json=body)
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED"
    webhook(db, oid, "captured")
    assert order_status(db, oid) == "READY_FOR_REVIEW"


def test_disputa_con_reembolso_total_no_es_calificable(client, db, category, people):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "No vino nadie a hacer el trabajo"})
    make_admin(db, "finanzas@example.com", AdminRole.FINANCE_ADMIN)
    fin = auth(login(client, "finanzas@example.com").json()["access_token"])
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=fin,
                    json={"outcome": "FULL_REFUND", "note": "El técnico no se presentó"})
    # Fase 5: el reembolso se ejecuta en el proveedor y, al confirmarse, la orden queda REFUNDED.
    assert r.status_code == 200 and r.json()["status"] == "REFUNDED"
    p = payment_of(db, oid)
    assert p is None or p.status.value == "REFUNDED"
    from app.models import TechnicianReputation
    db.expire_all()
    assert db.get(TechnicianReputation, tid).disputes_lost == 1


def test_plazo_de_disputa(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    db.execute(text("UPDATE service_orders SET paid_at = now() - interval '30 days' WHERE id = :id"), {"id": oid})
    db.commit()
    r = client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Me arrepentí mucho después"})
    assert err(r) == "ORDER_DISPUTE_WINDOW_CLOSED"


# ------------------------------------------------------------------ trabajos automáticos
def test_aprobacion_automatica_a_las_72_horas(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    assert orders.auto_approve(db) == 0
    db.execute(text("UPDATE service_orders SET work_finished_at = now() - interval '73 hours' WHERE id = :id"),
               {"id": oid})
    db.commit()
    assert orders.auto_approve(db) == 1
    db.commit()
    assert order_status(db, oid) == "COMPLETED"


def test_solicitudes_viejas_caducan(client, db, category, people):
    _, _, _, ch = people
    oid = create_order(client, ch, category)["id"]
    db.execute(text("UPDATE service_orders SET created_at = now() - interval '4 days' WHERE id = :id"), {"id": oid})
    db.commit()
    assert orders.expire_requests(db) == 1
    db.commit()
    assert order_status(db, oid) == "CANCELLED"


def test_desactivar_tecnico_suelta_sus_ordenes(client, db, category, admin_tokens, people):
    tid, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="ACCEPTED")
    r = client.post(f"{API}/admin/users/{tid}/deactivate", headers=auth(admin_tokens["access_token"]))
    assert r.status_code == 204
    assert order_status(db, oid) == "REQUESTED"


def test_orden_del_admin_requiere_permiso(client, db, category, people):
    _, th, _, ch = people
    oid = create_order(client, ch, category)["id"]
    make_admin(db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    make_admin(db, "fin@example.com", AdminRole.FINANCE_VIEWER)
    mod = auth(login(client, "mod@example.com").json()["access_token"])
    fin = auth(login(client, "fin@example.com").json()["access_token"])
    assert client.get(f"{API}/admin/orders/{oid}", headers=mod).status_code == 403
    assert client.get(f"{API}/admin/orders/{oid}", headers=fin).status_code == 200




# ------------------------------------------------------------------ regresiones de la revisión independiente
def test_captura_anticipada_no_deja_la_orden_atorada(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    webhook(db, oid, "captured")                      # el proveedor capturó antes de la aprobación
    assert order_status(db, oid) == "AWAITING_APPROVAL"
    assert client.post(f"{ORDERS}/{oid}/approve", headers=ch, json={}).status_code == 200
    assert order_status(db, oid) == "READY_FOR_REVIEW"


def test_disputa_resuelta_tras_captura_fija_la_fecha_de_pago(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AWAITING_APPROVAL")
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Quedó una fuga pequeña"})
    webhook(db, oid, "captured")
    make_admin(db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    fin = auth(login(client, "finanzas@example.com").json()["access_token"])
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=fin,
                    json={"outcome": "RELEASE", "note": "Se reparó en la segunda visita"})
    assert r.json()["status"] == "READY_FOR_REVIEW" and r.json()["paid_at"] is not None
    elig = client.get(f"{ORDERS}/{oid}/review-eligibility", headers=ch).json()
    assert elig["can_review"] and elig["review_deadline"]


def test_reembolsos_parciales_no_superan_lo_pendiente(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    webhook(db, oid, "refunded", amount=Decimal("900.00"))
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Quiero otro reembolso parcial"})
    make_admin(db, "finanzas@example.com", AdminRole.FINANCE_OPERATOR)
    fin = auth(login(client, "finanzas@example.com").json()["access_token"])
    r = client.post(f"{API}/admin/orders/{oid}/dispute-resolution", headers=fin,
                    json={"outcome": "PARTIAL_REFUND", "refund_amount": "500.00", "note": "Segundo reembolso"})
    assert r.status_code == 422 and err(r) == "ORDER_INVALID_REFUND"


def test_reserva_directa_a_tecnico_suspendido_se_abre_a_otros(client, db, category, supervisor, people):
    from app.kyc import decisions
    from app.core.actor import Actor
    from app.models import KycProfile
    tid, th, _, ch = people
    oid = create_order(client, ch, category, requested_technician_id=str(tid))["id"]
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tid))
    decisions.suspend(db, Actor.from_user(supervisor), profile.id, "INVESTIGACION_EN_CURSO", "Queja")
    db.commit()
    db.expire_all()
    from app.models import ServiceOrder
    assert db.get(ServiceOrder, uuid.UUID(oid)).requested_technician_id is None
