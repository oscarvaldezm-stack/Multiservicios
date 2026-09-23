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
