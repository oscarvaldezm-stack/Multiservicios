"""Pagos, Fase 2: configuración segura de Stripe, adaptador StripePaymentProvider (cliente simulado) y logs."""
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
import stripe

from app.core.config import Settings
from app.payments.providers.base import AccountPrefill, ProviderError
from app.payments.providers.stripe_provider import StripePaymentProvider
from app.security.log_sanitizer import sanitize

# Claves falsas armadas en tiempo de ejecución (que ningún escáner de secretos las confunda con reales).
TEST, LIVE = "_test_", "_live_"
SK_TEST, PK_TEST = "sk" + TEST + "a" * 24, "pk" + TEST + "a" * 24
RK_LIVE, PK_LIVE = "rk" + LIVE + "b" * 24, "pk" + LIVE + "b" * 24
WH1, WH2 = "whsec_" + "1" * 24, "whsec_" + "2" * 24


def settings(**over) -> Settings:
    return Settings(**({"PAYMENT_PROVIDER_BACKEND": "stripe", "STRIPE_SECRET_KEY": SK_TEST,
                        "STRIPE_PUBLISHABLE_KEY": PK_TEST} | over))


# ------------------------------------------------------------------ configuración
def test_modo_prueba_valido():
    s = settings(STRIPE_WEBHOOK_SECRET=WH1, STRIPE_CONNECT_WEBHOOK_SECRET=WH2)
    assert s.STRIPE_API_VERSION and SK_TEST not in repr(s) and WH1 not in repr(s)   # los secretos no salen en repr


@pytest.mark.parametrize("over,msg", [
    ({"STRIPE_SECRET_KEY": "pk" + TEST + "x" * 24}, "clave secreta"),
    ({"STRIPE_SECRET_KEY": "x" * 30}, "clave secreta"),
    ({"STRIPE_PUBLISHABLE_KEY": SK_TEST}, "publicable"),
    ({"STRIPE_SECRET_KEY": None}, "se requieren"),
    ({"STRIPE_PUBLISHABLE_KEY": PK_LIVE}, "mismo modo"),
    ({"STRIPE_SECRET_KEY": RK_LIVE, "STRIPE_PUBLISHABLE_KEY": PK_LIVE}, "Fuera de producción"),
    ({"STRIPE_WEBHOOK_SECRET": WH1, "STRIPE_CONNECT_WEBHOOK_SECRET": WH1}, "distintos"),
    ({"STRIPE_WEBHOOK_SECRET": "abc"}, "whsec_"),
])
def test_configuracion_insegura_se_rechaza(over, msg):
    with pytest.raises(ValueError, match=msg):
        settings(**over)


def _prod(**over) -> Settings:
    base = dict(ENVIRONMENT="production", BCRYPT_ROUNDS=12, ALLOWED_HOSTS=["api.example.mx"],
                CORS_ORIGINS=["https://app.example.mx"], STORAGE_BACKEND="s3", S3_KMS_KEY_ID="arn:aws:kms:x",
                KYC_SCANNER="clamd", PAYMENT_PROVIDER_BACKEND="stripe", STRIPE_SECRET_KEY=RK_LIVE,
                STRIPE_PUBLISHABLE_KEY=PK_LIVE, STRIPE_WEBHOOK_SECRET=WH1, STRIPE_CONNECT_WEBHOOK_SECRET=WH2,
                STRIPE_CONNECT_RETURN_URL="https://app.example.mx/listo",
                STRIPE_CONNECT_REFRESH_URL="https://app.example.mx/reintentar")
    return Settings(**(base | over))


@pytest.mark.parametrize("over,msg", [
    ({"PAYMENT_PROVIDER_BACKEND": "fake"}, "debe ser stripe"),
    ({"STRIPE_SECRET_KEY": SK_TEST, "STRIPE_PUBLISHABLE_KEY": PK_TEST}, "modo live"),
    ({"STRIPE_CONNECT_WEBHOOK_SECRET": None}, "STRIPE_CONNECT_WEBHOOK_SECRET"),
    ({"STRIPE_CONNECT_RETURN_URL": "http://app.example.mx/listo"}, "HTTPS"),
])
def test_produccion_exige_stripe_live_y_webhooks(over, msg):
    with pytest.raises(ValueError, match=msg):
        _prod(**over)


def test_produccion_con_stripe_live_arranca():
    assert _prod().is_production


def test_sin_clave_no_se_construye_el_adaptador():
    with pytest.raises(ProviderError):
        StripePaymentProvider(Settings())


def test_cliente_real_con_version_fijada():
    p = StripePaymentProvider(settings(STRIPE_API_VERSION="2026-08-26.dahlia"))
    assert isinstance(p._c, stripe.StripeClient)          # se construye sin tocar la red


# ------------------------------------------------------------------ logs
def test_logs_enmascaran_secretos_de_stripe():
    secret = "seti_1Abc" + "_secret_" + "Zz9" * 6
    link = "https://connect.stripe.com/setup/e/acct_123/AbCdEf"
    out = sanitize(f"si={secret} url={link} key={RK_LIVE} hook {WH1}")
    assert secret not in out and "AbCdEf" not in out and RK_LIVE not in out and WH1 not in out


# ------------------------------------------------------------------ adaptador con cliente simulado
class _Res:
    def __init__(self, calls, name, result):
        self.calls, self.name, self.result = calls, name, result

    def __call__(self, *args, **kwargs):
        self.calls.append((self.name, args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


PI_AUTHORIZED = {"id": "pi_1", "status": "requires_capture", "amount": 116000, "amount_capturable": 116000,
                 "client_secret": "pi_1_secret_zz",
                 "latest_charge": {"id": "ch_1", "payment_method_details": {"card": {"fingerprint": "fpX"}}}}
PI_PAID = {"id": "pi_1", "status": "succeeded", "amount": 116000, "amount_received": 116000, "latest_charge": "ch_1"}


def stub(**results):
    calls: list = []

    def res(name, default=None):
        return _Res(calls, name, results.get(name, default))

    v1 = SimpleNamespace(
        accounts=SimpleNamespace(create=res("accounts.create", {"id": "acct_1"}),
                                 retrieve=res("accounts.retrieve")),
        account_links=SimpleNamespace(create=res("account_links.create",
                                                 {"url": "https://connect.stripe.com/setup/e/x", "expires_at": 1_800_000_000})),
        customers=SimpleNamespace(create=res("customers.create", {"id": "cus_1"}),
                                  payment_methods=SimpleNamespace(list=res("pm.list", {"data": []}))),
        setup_intents=SimpleNamespace(create=res("setup_intents.create",
                                                 {"id": "seti_1", "client_secret": "seti_1_secret_abc"})),
        payment_intents=SimpleNamespace(create=res("pi.create", PI_AUTHORIZED), capture=res("pi.capture", PI_PAID),
                                        cancel=res("pi.cancel", {"id": "pi_1", "status": "canceled", "amount": 116000}),
                                        retrieve=res("pi.retrieve", PI_AUTHORIZED)),
    )
    return SimpleNamespace(v1=v1), calls


PREFILL = AccountPrefill(technician_id=uuid.UUID(int=7), email="tec@example.com", first_names="Gloria",
                         last_names="Hernández García", birth_date=date(1990, 4, 27), phone="+522291234567",
                         address_line1="Av. Independencia 100", address_line2="Centro", city="Veracruz",
                         state="Veracruz", postal_code="91700")


def test_alta_de_cuenta_conectada():
    client, calls = stub()
    acct = StripePaymentProvider(settings(), client).create_connected_account(PREFILL)
    assert acct == "acct_1"
    _, _, kw = calls[0]
    p = kw["params"]
    assert (p["type"], p["country"], p["business_type"]) == ("express", "MX", "individual")
    assert p["capabilities"] == {"transfers": {"requested": True}}
    assert p["individual"]["dob"] == {"day": 27, "month": 4, "year": 1990}
    assert p["individual"]["address"]["country"] == "MX" and p["individual"]["phone"] == "+522291234567"
    assert "id_number" not in p["individual"]                      # ni CURP ni RFC salen de nuestra base
    assert kw["options"] == {"idempotency_key": f"account-create:{PREFILL.technician_id}"}


def test_telefono_sin_formato_internacional_no_se_envia():
    client, calls = stub()
    from dataclasses import replace
    StripePaymentProvider(settings(), client).create_connected_account(replace(PREFILL, phone="2291234567"))
    assert "phone" not in calls[0][2]["params"]["individual"]


def test_enlace_de_alta():
    client, calls = stub()
    link = StripePaymentProvider(settings(), client).create_onboarding_link("acct_1")
    p = calls[0][2]["params"]
    assert p["type"] == "account_onboarding" and p["account"] == "acct_1"
    assert p["return_url"].startswith("http") and p["refresh_url"].startswith("http")
    assert link.expires_at == datetime.fromtimestamp(1_800_000_000, timezone.utc)


def test_estado_de_la_cuenta():
    client, _ = stub(**{"accounts.retrieve": {
        "id": "acct_1", "capabilities": {"transfers": "active"}, "payouts_enabled": True, "details_submitted": True,
        "requirements": {"currently_due": ["individual.id_number"], "past_due": ["external_account"],
                         "disabled_reason": None},
        "individual": {"first_name": "Gloria", "last_name": "Hernández"}}})
    info = StripePaymentProvider(settings(), client).get_account_status("acct_1")
    assert info.transfers_active and info.payouts_enabled and info.details_submitted
    assert info.requirements_due == ("external_account", "individual.id_number")
    assert (info.legal_first_name, info.legal_last_name) == ("Gloria", "Hernández")


def test_estado_sin_datos_de_persona():
    client, _ = stub(**{"accounts.retrieve": {"id": "acct_1", "capabilities": {"transfers": "inactive"}}})
    info = StripePaymentProvider(settings(), client).get_account_status("acct_1")
    assert not info.transfers_active and not info.payouts_enabled and info.legal_first_name is None


def test_cliente_y_setup_intent():
    client, calls = stub()
    p = StripePaymentProvider(settings(), client)
    uid = uuid.uuid4()
    assert p.create_customer(uid, "c@example.com", "Cliente") == "cus_1"
    assert calls[0][2]["options"] == {"idempotency_key": f"customer-create:{uid}"}
    si = p.create_setup_intent("cus_1", uid)
    params = calls[1][2]["params"]
    assert params["usage"] == "off_session" and params["payment_method_types"] == ["card"]
    assert si.client_secret == "seti_1_secret_abc" and "secret" not in repr(si)


def test_tarjetas_guardadas():
    client, _ = stub(**{"pm.list": {"data": [{"id": "pm_1", "card": {"brand": "visa", "last4": "4242",
                                                                     "exp_month": 12, "exp_year": 2030}}]}})
    cards = StripePaymentProvider(settings(), client).list_saved_cards("cus_1")
    assert [(c.brand, c.last4, c.exp_year) for c in cards] == [("visa", "4242", 2030)]


@pytest.mark.parametrize("exc,code,status,retryable", [
    (stripe.RateLimitError("demasiadas"), "PAYMENT_PROVIDER_UNAVAILABLE", 503, True),
    (stripe.APIConnectionError("red"), "PAYMENT_PROVIDER_UNAVAILABLE", 503, True),
    (stripe.AuthenticationError("Invalid API Key provided: " + SK_TEST), "PAYMENT_PROVIDER_MISCONFIGURED", 503,
     False),
    (stripe.InvalidRequestError("No such account: acct_x (Gloria Hernández)", "account"),
     "PAYMENT_PROVIDER_REJECTED", 502, False),
    (stripe.CardError("Your card was declined", None, "card_declined"), "PAYMENT_CARD_DECLINED", 402, False),
    (stripe.IdempotencyError("otro cuerpo"), "PAYMENT_PROVIDER_IDEMPOTENCY", 409, False),
])
def test_errores_de_stripe_se_traducen_sin_filtrar_datos(exc, code, status, retryable):
    client, _ = stub(**{"accounts.create": exc})
    with pytest.raises(ProviderError) as err:
        StripePaymentProvider(settings(), client).create_connected_account(PREFILL)
    assert (err.value.code, err.value.http_status, err.value.retryable) == (code, status, retryable)
    assert SK_TEST not in str(err.value) and "Gloria" not in str(err.value)


# ------------------------------------------------------------------ cobros (Fase 3)
def _auth_request():
    from app.payments.providers.base import AuthorizationRequest
    return AuthorizationRequest(payment_id=uuid.UUID(int=9), order_id=uuid.UUID(int=10), amount_cents=116_000,
                                currency="MXN", customer_id="cus_1", payment_method_id="pm_1",
                                destination_account_id="acct_tec", application_fee_cents=27_900)


def test_autorizacion_con_cargo_de_destino_y_captura_manual():
    from app.models import PaymentStatus
    client, calls = stub()
    pp = StripePaymentProvider(settings(), client).authorize(_auth_request())
    name, _, kw = calls[0]
    p = kw["params"]
    assert name == "pi.create"
    assert (p["amount"], p["currency"], p["capture_method"], p["confirm"], p["off_session"]) == \
        (116_000, "mxn", "manual", True, True)
    assert p["transfer_data"] == {"destination": "acct_tec"} and p["application_fee_amount"] == 27_900
    assert p["customer"] == "cus_1" and p["payment_method"] == "pm_1" and p["payment_method_types"] == ["card"]
    assert kw["options"] == {"idempotency_key": f"authorize:{uuid.UUID(int=9)}"}
    assert pp.status == PaymentStatus.AUTHORIZED and pp.payment_method_fingerprint == "fpX"
    assert pp.amount_capturable_cents == 116_000


def _card_error(code: str, pi: dict | None):
    body = {"error": {"type": "card_error", "code": code, "decline_code": code}}
    if pi:
        body["error"]["payment_intent"] = pi
    return stripe.CardError("Your card was declined.", None, code, json_body=body)


def test_rechazo_de_tarjeta_no_es_excepcion():
    from app.models import PaymentStatus
    pi = {"id": "pi_2", "object": "payment_intent", "status": "requires_payment_method", "amount": 116000}
    client, _ = stub(**{"pi.create": _card_error("insufficient_funds", pi)})
    pp = StripePaymentProvider(settings(), client).authorize(_auth_request())
    assert pp.status == PaymentStatus.FAILED and pp.failure_code == "insufficient_funds"
    assert pp.provider_payment_id == "pi_2"


def test_banco_pide_autenticacion():
    from app.models import PaymentStatus
    pi = {"id": "pi_3", "object": "payment_intent", "status": "requires_payment_method", "amount": 116000,
          "client_secret": "pi_3_secret_q"}
    client, _ = stub(**{"pi.create": _card_error("authentication_required", pi)})
    pp = StripePaymentProvider(settings(), client).authorize(_auth_request())
    assert pp.status == PaymentStatus.REQUIRES_ACTION and pp.client_secret == "pi_3_secret_q"
    assert "pi_3_secret_q" not in repr(pp)


def test_captura_anulacion_y_consulta():
    from app.models import PaymentStatus
    client, calls = stub()
    p = StripePaymentProvider(settings(), client)
    pay_id = uuid.UUID(int=9)
    assert p.capture("pi_1", pay_id, 116_000).status == PaymentStatus.PAID
    assert calls[-1][2]["params"]["amount_to_capture"] == 116_000
    assert calls[-1][2]["options"] == {"idempotency_key": f"capture:{pay_id}"}
    assert p.cancel_authorization("pi_1", pay_id).status == PaymentStatus.CANCELLED
    assert calls[-1][2]["options"] == {"idempotency_key": f"cancel:{pay_id}"}
    assert p.get_payment("pi_1").status == PaymentStatus.AUTHORIZED


@pytest.mark.parametrize("stripe_status,expected", [
    ("requires_payment_method", "PENDING"), ("requires_confirmation", "PENDING"),
    ("requires_action", "REQUIRES_ACTION"), ("processing", "PROCESSING"), ("requires_capture", "AUTHORIZED"),
    ("succeeded", "PAID"), ("canceled", "CANCELLED"),
])
def test_estados_de_stripe_se_traducen(stripe_status, expected):
    client, _ = stub(**{"pi.retrieve": {"id": "pi_1", "status": stripe_status, "amount": 1}})
    assert StripePaymentProvider(settings(), client).get_payment("pi_1").status.value == expected


def test_intento_rechazado_sin_otro_metodo_es_fallido():
    client, _ = stub(**{"pi.retrieve": {"id": "pi_1", "status": "requires_payment_method", "amount": 1,
                                        "last_payment_error": {"code": "card_declined", "decline_code": "lost_card"}}})
    pp = StripePaymentProvider(settings(), client).get_payment("pi_1")
    assert pp.status.value == "FAILED" and pp.failure_code == "lost_card"


def test_error_de_red_al_capturar_es_reintentable():
    client, _ = stub(**{"pi.capture": stripe.APIConnectionError("red")})
    with pytest.raises(ProviderError) as err:
        StripePaymentProvider(settings(), client).capture("pi_1", uuid.UUID(int=9), 1)
    assert err.value.retryable
