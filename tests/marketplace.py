"""Ayudantes para pruebas de órdenes y calificaciones: técnicos aprobados, clientes y el flujo completo."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from app.models import KycStatus, Payment, ServiceOrder, User
from app.payments import service as payments
from app.payments.providers import get_provider
from app.payments.commission import to_cents
from tests.conftest import API, auth, drive_to, login, register, verify_email

ORDERS = f"{API}/orders"
REVIEWS = f"{API}/reviews"


def approved_tech(client, db, category, reviewer, supervisor, email: str = "tec@example.com", n: int = 4,
                  device: str | None = None, payment_account: bool = True):
    """Técnico con KYC APROBADO y (por defecto) cuenta de pagos habilitada: la regla crítica completa."""
    assert register(client, "technician", email, category_ids=[category.id]).status_code == 201
    uid = db.scalar(select(User.id).where(User.email == email))
    drive_to(db, uid, KycStatus.APPROVED, reviewer, supervisor, n=n)
    db.execute(text("UPDATE technician_profiles SET is_available = true WHERE user_id = :t"), {"t": uid})
    db.commit()
    headers = _headers(client, email, device)
    if payment_account:
        enable_payment_account(client, db, uid, headers)
    return uid, headers


def enable_payment_account(client, db, uid, headers) -> None:
    """Alta en el proveedor falso + formulario completado + consulta: la cuenta queda ENABLED."""
    from app.models import TechnicianPaymentAccount
    assert client.post(f"{API}/technicians/me/payment-account", headers=headers, json={}).status_code == 201
    acct = db.scalar(select(TechnicianPaymentAccount.provider_account_id)
                     .where(TechnicianPaymentAccount.technician_id == uid))
    get_provider().complete_onboarding(acct)
    r = client.post(f"{API}/technicians/me/payment-account/refresh", headers=headers, json={})
    assert r.json()["status"] == "ENABLED", r.text


def choose_card(client, db, ch, order_id, *, fingerprint: str | None = None, last4: str = "4242") -> str:
    """El cliente guarda una tarjeta (simulada en el proveedor) y la elige para la orden."""
    from app.models import PaymentCustomer
    order = db.get(ServiceOrder, uuid.UUID(str(order_id)))
    db.expire_all()
    assert client.post(f"{API}/clients/me/payment-methods/setup-intent", headers=ch, json={}).status_code == 201
    customer = db.scalar(select(PaymentCustomer.provider_customer_id)
                         .where(PaymentCustomer.user_id == order.client_id))
    fake = get_provider()
    pm = fake.add_card(customer, last4=last4)
    if fingerprint:
        fake._fingerprints[pm] = fingerprint
    r = client.post(f"{ORDERS}/{order_id}/payment-method", headers=ch | {"Idempotency-Key": uuid.uuid4().hex},
                    json={"payment_method_id": pm})
    assert r.status_code == 200, r.text
    return pm


def capture_due(db) -> int:
    """Lo que hace el worker cada minuto: capturar lo aprobado."""
    done = payments.capture_due(db)
    db.commit()
    db.expire_all()
    return done


def new_client(client, db, email: str = "cliente@example.com", *, verified: bool = True, device: str | None = None,
               age_days: int = 30):
    assert register(client, "client", email).status_code == 201
    uid = db.scalar(select(User.id).where(User.email == email))
    if verified:
        verify_email(db, uid)
    if age_days:
        # Cuenta "vieja" para no disparar la señal NEW_CLIENT_ACCOUNT salvo cuando se prueba.
        db.execute(text("UPDATE users SET created_at = now() - make_interval(days => :d) WHERE id = :id"),
                   {"d": age_days, "id": uid})
        db.commit()
    return uid, _headers(client, email, device)


def _headers(client, email: str, device: str | None) -> dict:
    extra = {"X-Device-Id": device} if device else {}
    tokens = login_with(client, email, extra)
    return auth(tokens["access_token"]) | extra


def login_with(client, email: str, headers: dict) -> dict:
    if not headers:
        return login(client, email).json()
    from tests.conftest import STRONG_PW
    return client.post(f"{API}/auth/token", data={"username": email, "password": STRONG_PW}, headers=headers).json()


def create_order(client, ch, category, **kw) -> dict:
    body = {"category_id": category.id, "title": "Fuga en el baño", "description": "Gotea la llave del lavabo",
            "address_line": "Av. Independencia 100", "city": "Veracruz"} | kw
    r = client.post(ORDERS, headers=ch, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def payment_of(db, order_id) -> Payment:
    db.expire_all()
    return payments.active_payment(db, uuid.UUID(str(order_id)))


def webhook(db, order_id, event: str, **kw) -> None:
    """Simula el manejador de webhooks del proveedor (firma ya verificada)."""
    p = payment_of(db, order_id)
    if event == "authorized":
        payments.mark_authorized(db, p, provider_payment_id=kw.get("pid", f"pi_{uuid.uuid4().hex[:12]}"),
                                 payment_method_fingerprint=kw.get("fingerprint"))
    elif event == "captured":
        payments.mark_captured(db, p)
    elif event == "failed":
        payments.mark_failed(db, p, "card_declined")
    elif event == "refunded":
        amount = kw["amount"]          # centavos (int) o pesos (Decimal / str)
        payments.mark_refunded(db, p, amount if isinstance(amount, int) else to_cents(amount))
    db.commit()
    db.expire_all()


def run_order(client, db, ch, th, category, *, until: str = "READY_FOR_REVIEW", price: str = "850.00",
              fingerprint: str | None = None, **order_kw) -> str:
    """Lleva una orden por la API hasta el estado pedido. Devuelve su id."""
    oid = create_order(client, ch, category, **order_kw)["id"]
    steps = [
        ("ACCEPTED", lambda: client.post(f"{ORDERS}/{oid}/accept", headers=th, json={"agreed_price": price})),
        ("SCHEDULED", lambda: client.post(f"{ORDERS}/{oid}/schedule", headers=th, json={
            "scheduled_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()})),
        ("AUTHORIZED", lambda: _depart(client, db, ch, th, oid, fingerprint)),
        ("IN_PROGRESS", lambda: client.post(f"{ORDERS}/{oid}/start", headers=th)),
        ("AWAITING_APPROVAL", lambda: client.post(f"{ORDERS}/{oid}/finish", headers=th)),
        ("COMPLETED", lambda: client.post(f"{ORDERS}/{oid}/approve", headers=ch, json={})),
        ("READY_FOR_REVIEW", lambda: capture_due(db) and None),
    ]
    for name, step in steps:
        r = step()
        if r is not None:
            assert r.status_code == 200, (name, r.text)
        if name == until:
            break
    return oid


def _depart(client, db, ch, th, oid, fingerprint):
    choose_card(client, db, ch, oid, fingerprint=fingerprint)
    r = client.post(f"{ORDERS}/{oid}/depart", headers=th)
    assert r.status_code == 200 and r.json()["can_start"], r.text


def order_status(db, oid) -> str:
    db.expire_all()
    return db.get(ServiceOrder, uuid.UUID(str(oid))).status.value
