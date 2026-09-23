"""
Adaptador de Stripe (Connect con cargos de destino). Traduce objetos de Stripe a los tipos
de app.payments.providers.base; ningún objeto de Stripe sale de este archivo.

Seguridad:
- La clave secreta solo existe aquí (StripeClient) y nunca se registra.
- Versión de la API fijada (STRIPE_API_VERSION): un cambio de Stripe no altera el comportamiento.
- Idempotency-Key determinista en toda creación que no debe duplicarse
  (account-create:{técnico}, customer-create:{usuario}): un reintento de red no crea dos cuentas.
- Los errores se traducen a códigos propios; el mensaje de Stripe no se devuelve al cliente
  ni se registra completo (puede contener datos personales).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import stripe

from app.core.config import Settings, get_settings
from app.payments.providers.base import (
    AccountPrefill,
    AccountStatusInfo,
    Capabilities,
    OnboardingLink,
    PaymentProvider,
    ProviderError,
    SavedCard,
    SetupIntentInfo,
)

log = logging.getLogger("payments")


def _get(obj: Any, *path: str) -> Any:
    """Lectura tolerante de objetos de Stripe (dict-like) o dicts anidados."""
    for key in path:
        if obj is None:
            return None
        obj = obj.get(key) if hasattr(obj, "get") else getattr(obj, key, None)
    return obj


class StripePaymentProvider(PaymentProvider):
    name = "stripe"
    capabilities = Capabilities(manual_capture=True, partial_fee_refund=True, connected_accounts=True,
                                saved_cards=True)

    def __init__(self, settings: Settings | None = None, client: Any | None = None):
        self._s = settings or get_settings()
        if client is None:
            if self._s.STRIPE_SECRET_KEY is None:
                raise ProviderError("Stripe no está configurado", code="PAYMENT_PROVIDER_MISCONFIGURED")
            client = stripe.StripeClient(self._s.STRIPE_SECRET_KEY.get_secret_value(),
                                         stripe_version=self._s.STRIPE_API_VERSION,
                                         max_network_retries=self._s.STRIPE_MAX_NETWORK_RETRIES)
        self._c = client

    # ------------------------------------------------------------------ errores
    def _call(self, op: str, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (stripe.RateLimitError, stripe.APIConnectionError) as exc:
            log.warning("Stripe no disponible en %s: %s", op, type(exc).__name__)
            raise ProviderError("El proveedor de pagos no responde; intenta de nuevo",
                                code="PAYMENT_PROVIDER_UNAVAILABLE", http_status=503, retryable=True) from None
        except (stripe.AuthenticationError, stripe.PermissionError) as exc:
            logging.getLogger("security").error("Credencial de Stripe rechazada en %s: %s", op, type(exc).__name__)
            raise ProviderError("El proveedor de pagos no está disponible",
                                code="PAYMENT_PROVIDER_MISCONFIGURED", http_status=503) from None
        except stripe.IdempotencyError:
            raise ProviderError("Solicitud duplicada con otros datos", code="PAYMENT_PROVIDER_IDEMPOTENCY",
                                http_status=409) from None
        except stripe.CardError as exc:
            raise ProviderError("La tarjeta fue rechazada", code="PAYMENT_CARD_DECLINED", http_status=402,
                                provider_code=getattr(exc, "code", None)) from None
        except stripe.InvalidRequestError as exc:
            log.error("Stripe rechazó %s: code=%s param=%s", op, getattr(exc, "code", None),
                      getattr(exc, "param", None))
            raise ProviderError("El proveedor de pagos rechazó la solicitud", code="PAYMENT_PROVIDER_REJECTED",
                                provider_code=getattr(exc, "code", None)) from None
        except stripe.StripeError as exc:
            log.error("Error de Stripe en %s: %s", op, type(exc).__name__)
            raise ProviderError("Error del proveedor de pagos", retryable=True) from None

    # ------------------------------------------------------------------ cuenta del técnico
    def create_connected_account(self, prefill: AccountPrefill) -> str:
        individual: dict[str, Any] = {"first_name": prefill.first_names, "last_name": prefill.last_names,
                                      "email": prefill.email}
        if prefill.phone and prefill.phone.startswith("+"):
            individual["phone"] = prefill.phone
        if prefill.birth_date:
            individual["dob"] = {"day": prefill.birth_date.day, "month": prefill.birth_date.month,
                                 "year": prefill.birth_date.year}
        address = {k: v for k, v in {"line1": prefill.address_line1, "line2": prefill.address_line2,
                                     "city": prefill.city, "state": prefill.state,
                                     "postal_code": prefill.postal_code}.items() if v}
        if address:
            individual["address"] = address | {"country": self._s.PAYMENT_ACCOUNT_COUNTRY}
        params = {
            "type": "express",
            "country": self._s.PAYMENT_ACCOUNT_COUNTRY,
            "business_type": "individual",
            "email": prefill.email,
            "capabilities": {"transfers": {"requested": True}},
            "individual": individual,
            "metadata": {"technician_id": str(prefill.technician_id)},
        }
        acct = self._call("accounts.create", self._c.v1.accounts.create, params=params,
                          options={"idempotency_key": f"account-create:{prefill.technician_id}"})
        return acct["id"]

    def create_onboarding_link(self, provider_account_id: str) -> OnboardingLink:
        link = self._call("account_links.create", self._c.v1.account_links.create, params={
            "account": provider_account_id,
            "refresh_url": self._s.STRIPE_CONNECT_REFRESH_URL,
            "return_url": self._s.STRIPE_CONNECT_RETURN_URL,
            "type": "account_onboarding",
            "collection_options": {"fields": "eventually_due"},
        })
        return OnboardingLink(url=link["url"], expires_at=datetime.fromtimestamp(link["expires_at"], timezone.utc))

    def get_account_status(self, provider_account_id: str) -> AccountStatusInfo:
        acct = self._call("accounts.retrieve", self._c.v1.accounts.retrieve, provider_account_id)
        due = set(_get(acct, "requirements", "currently_due") or []) | set(_get(acct, "requirements", "past_due") or [])
        return AccountStatusInfo(
            provider_account_id=acct["id"],
            transfers_active=_get(acct, "capabilities", "transfers") == "active",
            payouts_enabled=bool(_get(acct, "payouts_enabled")),
            details_submitted=bool(_get(acct, "details_submitted")),
            requirements_due=tuple(sorted(due)),
            disabled_reason=_get(acct, "requirements", "disabled_reason"),
            legal_first_name=_get(acct, "individual", "first_name"),
            legal_last_name=_get(acct, "individual", "last_name"),
        )

    # ------------------------------------------------------------------ cliente y tarjetas
    def create_customer(self, user_id: uuid.UUID, email: str, name: str) -> str:
        cus = self._call("customers.create", self._c.v1.customers.create,
                         params={"email": email, "name": name, "metadata": {"user_id": str(user_id)}},
                         options={"idempotency_key": f"customer-create:{user_id}"})
        return cus["id"]

    def create_setup_intent(self, provider_customer_id: str, user_id: uuid.UUID) -> SetupIntentInfo:
        si = self._call("setup_intents.create", self._c.v1.setup_intents.create, params={
            "customer": provider_customer_id,
            "usage": "off_session",                   # se cobrará cuando el técnico salga, sin el cliente presente
            "payment_method_types": ["card"],          # D3: solo tarjetas (admiten captura manual)
            "metadata": {"user_id": str(user_id)},
        })
        return SetupIntentInfo(provider_id=si["id"], client_secret=si["client_secret"])

    def list_saved_cards(self, provider_customer_id: str) -> list[SavedCard]:
        page = self._call("customers.payment_methods.list", self._c.v1.customers.payment_methods.list,
                          provider_customer_id, params={"type": "card", "limit": 20})
        cards = []
        for pm in _get(page, "data") or []:
            card = _get(pm, "card") or {}
            cards.append(SavedCard(provider_id=pm["id"], brand=str(_get(card, "brand") or "unknown"),
                                   last4=str(_get(card, "last4") or ""), exp_month=int(_get(card, "exp_month") or 0),
                                   exp_year=int(_get(card, "exp_year") or 0)))
        return cards
