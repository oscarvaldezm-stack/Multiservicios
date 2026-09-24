"""
Adaptador de Stripe (Connect con cargos de destino). Traduce objetos de Stripe a los tipos
de app.payments.providers.base; ningún objeto de Stripe sale de este archivo.

Seguridad:
- La clave secreta solo existe aquí (StripeClient) y nunca se registra.
- Versión de la API fijada (STRIPE_API_VERSION): un cambio de Stripe no altera el comportamiento.
- Idempotency-Key determinista en toda creación que no debe duplicarse
  (account-create:{técnico}, customer-create:{usuario}, authorize/capture/cancel:{pago}):
  un reintento de red no crea dos cuentas, dos cobros ni dos capturas.
- Cargos de destino: la plataforma crea el cobro con transfer_data[destination] y
  application_fee_amount; con la captura, Stripe transfiere al técnico una sola vez.
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
from app.models.enums import PaymentStatus
from app.payments.providers.base import (
    AccountPrefill,
    AccountStatusInfo,
    AuthorizationRequest,
    BalanceInfo,
    DisputeInfo,
    Capabilities,
    OnboardingLink,
    PaymentProvider,
    ProviderError,
    PayoutInfo,
    ProviderPayment,
    RefundInfo,
    RefundRequest,
    SavedCard,
    SetupIntentInfo,
    WebhookEvent,
)

WEBHOOK_TOLERANCE_SECONDS = 300          # firma con más de 5 minutos: se rechaza (evita replays)

log = logging.getLogger("payments")


def verify_stripe_signature(payload: bytes, signature: str | None, secret: str | None) -> WebhookEvent:
    """Verificación local (sin red) del encabezado Stripe-Signature sobre el cuerpo crudo."""
    if not secret:
        raise ProviderError("Webhook no configurado", code="PAYMENT_PROVIDER_MISCONFIGURED", http_status=503)
    if not signature:
        raise ProviderError("Falta la firma", code="WEBHOOK_SIGNATURE_INVALID", http_status=400)
    try:
        event = stripe.Webhook.construct_event(payload, signature, secret, tolerance=WEBHOOK_TOLERANCE_SECONDS)
    except (stripe.SignatureVerificationError, ValueError):
        raise ProviderError("Firma inválida", code="WEBHOOK_SIGNATURE_INVALID", http_status=400) from None
    obj = _get(event, "data", "object")
    return WebhookEvent(provider_event_id=str(event["id"]), type=str(_get(event, "type")),
                        object_id=_get(obj, "id"), object_type=_get(obj, "object"),
                        account_id=_get(event, "account"), livemode=bool(_get(event, "livemode")),
                        created=int(_get(event, "created") or 0))


def webhook_secret(settings: Settings, endpoint: str) -> str | None:
    """Un secreto distinto por endpoint: el de la plataforma no valida eventos de Connect ni al revés."""
    secret = {"platform": settings.STRIPE_WEBHOOK_SECRET, "connect": settings.STRIPE_CONNECT_WEBHOOK_SECRET}[endpoint]
    return secret.get_secret_value() if secret else None


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
        except stripe.StripeError as exc:
            self._translate(op, exc)

    @staticmethod
    def _translate(op: str, exc: Exception) -> None:
        """Lanza el ProviderError equivalente, sin el mensaje de Stripe."""
        try:
            raise exc
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

    # ------------------------------------------------------------------ cobros (Fase 3)
    _STATUS = {
        "requires_payment_method": PaymentStatus.PENDING,
        "requires_confirmation": PaymentStatus.PENDING,
        "requires_action": PaymentStatus.REQUIRES_ACTION,
        "processing": PaymentStatus.PROCESSING,
        "requires_capture": PaymentStatus.AUTHORIZED,
        "succeeded": PaymentStatus.PAID,
        "canceled": PaymentStatus.CANCELLED,
    }

    @classmethod
    def _to_payment(cls, pi: Any, *, force_status: PaymentStatus | None = None) -> ProviderPayment:
        error = _get(pi, "last_payment_error")
        status = force_status or cls._STATUS.get(_get(pi, "status"), PaymentStatus.PENDING)
        if status == PaymentStatus.PENDING and error is not None:
            status = PaymentStatus.FAILED            # el intento se rechazó y no hay otro método
        charge = _get(pi, "latest_charge")
        fingerprint = _get(charge, "payment_method_details", "card", "fingerprint") if not isinstance(charge, str) \
            else None
        return ProviderPayment(
            provider_payment_id=_get(pi, "id"), status=status, amount_cents=int(_get(pi, "amount") or 0),
            amount_capturable_cents=int(_get(pi, "amount_capturable") or 0),
            amount_received_cents=int(_get(pi, "amount_received") or 0),
            failure_code=(_get(error, "decline_code") or _get(error, "code")) if error is not None else None,
            payment_method_fingerprint=fingerprint, client_secret=_get(pi, "client_secret"),
            metadata_payment_id=_get(pi, "metadata", "payment_id"))

    def authorize(self, req: AuthorizationRequest) -> ProviderPayment:
        params = {
            "amount": req.amount_cents,
            "currency": req.currency.lower(),
            "customer": req.customer_id,
            "payment_method": req.payment_method_id,
            "payment_method_types": ["card"],
            "capture_method": "manual",              # D7: se reserva al salir el técnico, se cobra al aprobar
            "confirm": True,
            "off_session": True,                     # tarjeta guardada, sin el cliente presente
            "transfer_data": {"destination": req.destination_account_id},
            "application_fee_amount": req.application_fee_cents,
            "metadata": {"payment_id": str(req.payment_id), "order_id": str(req.order_id)},
            "expand": ["latest_charge"],
        }
        try:
            pi = self._c.v1.payment_intents.create(params=params,
                                                   options={"idempotency_key": f"authorize:{req.payment_id}"})
        except stripe.CardError as exc:
            # Un rechazo no es un error del sistema: el cliente cambia de tarjeta o se autentica.
            err = getattr(exc, "error", None)
            pi = getattr(err, "payment_intent", None)
            code = getattr(err, "decline_code", None) or getattr(exc, "code", None) or "card_declined"
            if code == "authentication_required" and pi is not None:
                return self._to_payment(pi, force_status=PaymentStatus.REQUIRES_ACTION)
            return ProviderPayment(provider_payment_id=_get(pi, "id"), status=PaymentStatus.FAILED,
                                   amount_cents=req.amount_cents, failure_code=str(code)[:60])
        except stripe.StripeError as exc:
            self._translate("payment_intents.create", exc)
        return self._to_payment(pi)

    def capture(self, provider_payment_id: str, payment_id: uuid.UUID, amount_cents: int,
                application_fee_cents: int | None = None) -> ProviderPayment:
        params: dict[str, Any] = {"amount_to_capture": amount_cents, "expand": ["latest_charge"]}
        if application_fee_cents is not None:
            params["application_fee_amount"] = application_fee_cents     # comisión recalculada (captura parcial)
        pi = self._call("payment_intents.capture", self._c.v1.payment_intents.capture, provider_payment_id,
                        params=params, options={"idempotency_key": f"capture:{payment_id}"})
        return self._to_payment(pi)

    def cancel_authorization(self, provider_payment_id: str, payment_id: uuid.UUID) -> ProviderPayment:
        pi = self._call("payment_intents.cancel", self._c.v1.payment_intents.cancel, provider_payment_id,
                        params={"cancellation_reason": "requested_by_customer"},
                        options={"idempotency_key": f"cancel:{payment_id}"})
        return self._to_payment(pi)

    def get_payment(self, provider_payment_id: str) -> ProviderPayment:
        pi = self._call("payment_intents.retrieve", self._c.v1.payment_intents.retrieve, provider_payment_id,
                        params={"expand": ["latest_charge"]})
        return self._to_payment(pi)

    # ------------------------------------------------------------------ webhooks y conciliación (Fase 4)
    def verify_webhook(self, payload: bytes, signature: str | None, endpoint: str) -> WebhookEvent:
        return verify_stripe_signature(payload, signature, webhook_secret(self._s, endpoint))

    def get_payout(self, provider_account_id: str, provider_payout_id: str) -> PayoutInfo:
        po = self._call("payouts.retrieve", self._c.v1.payouts.retrieve, provider_payout_id,
                        options={"stripe_account": provider_account_id})
        arrival = _get(po, "arrival_date")
        return PayoutInfo(provider_payout_id=po["id"], amount_cents=int(_get(po, "amount") or 0),
                          currency=str(_get(po, "currency") or "mxn").upper(), status=str(_get(po, "status")),
                          arrival_date=datetime.fromtimestamp(arrival, timezone.utc).date() if arrival else None,
                          failure_code=_get(po, "failure_code"))

    def list_payments(self, created_from: datetime, created_to: datetime) -> list[ProviderPayment]:
        page = self._call("payment_intents.list", self._c.v1.payment_intents.list, params={
            "created": {"gte": int(created_from.timestamp()), "lt": int(created_to.timestamp())}, "limit": 100})
        items = page.auto_paging_iter() if hasattr(page, "auto_paging_iter") else (_get(page, "data") or [])
        return [self._to_payment(pi) for pi in items]

    # ------------------------------------------------------------------ reembolsos, disputas y saldo (Fase 5)
    @staticmethod
    def _to_refund(r: Any) -> RefundInfo:
        return RefundInfo(provider_refund_id=r["id"], provider_payment_id=_get(r, "payment_intent"),
                          amount_cents=int(_get(r, "amount") or 0), status=str(_get(r, "status")),
                          failure_reason=_get(r, "failure_reason"),
                          transfer_reversed=_get(r, "transfer_reversal") is not None,
                          metadata_refund_id=_get(r, "metadata", "refund_id"))

    def refund(self, req: RefundRequest) -> RefundInfo:
        r = self._call("refunds.create", self._c.v1.refunds.create, params={
            "payment_intent": req.provider_payment_id,
            "amount": req.amount_cents,
            "reverse_transfer": req.reverse_transfer,
            "refund_application_fee": req.refund_application_fee,
            "reason": "duplicate" if req.duplicate else "requested_by_customer",
            "metadata": {"refund_id": str(req.refund_id)},
        }, options={"idempotency_key": f"refund:{req.refund_id}"})
        return self._to_refund(r)

    def get_refund(self, provider_refund_id: str) -> RefundInfo:
        return self._to_refund(self._call("refunds.retrieve", self._c.v1.refunds.retrieve, provider_refund_id))

    @staticmethod
    def _to_dispute(d: Any) -> DisputeInfo:
        due = _get(d, "evidence_details", "due_by")
        return DisputeInfo(provider_dispute_id=d["id"], provider_payment_id=_get(d, "payment_intent"),
                           amount_cents=int(_get(d, "amount") or 0), reason=_get(d, "reason"),
                           status=str(_get(d, "status")),
                           evidence_due_by=datetime.fromtimestamp(due, timezone.utc) if due else None)

    def get_dispute(self, provider_dispute_id: str) -> DisputeInfo:
        return self._to_dispute(self._call("disputes.retrieve", self._c.v1.disputes.retrieve, provider_dispute_id))

    def submit_dispute_evidence(self, provider_dispute_id: str, evidence: dict[str, str]) -> DisputeInfo:
        d = self._call("disputes.update", self._c.v1.disputes.update, provider_dispute_id,
                       params={"evidence": evidence, "submit": True})
        return self._to_dispute(d)

    def reverse_transfer(self, provider_payment_id: str, amount_cents: int, key: str) -> str:
        pi = self._call("payment_intents.retrieve", self._c.v1.payment_intents.retrieve, provider_payment_id,
                        params={"expand": ["latest_charge"]})
        transfer = _get(pi, "latest_charge", "transfer")
        if not transfer:
            raise ProviderError("El cobro no tiene transferencia al técnico", code="PAYMENT_PROVIDER_REJECTED")
        rev = self._call("transfers.reversals.create", self._c.v1.transfers.reversals.create,
                         transfer if isinstance(transfer, str) else transfer["id"],
                         params={"amount": amount_cents}, options={"idempotency_key": key})
        return rev["id"]

    def get_balance(self, provider_account_id: str) -> BalanceInfo:
        b = self._call("balance.retrieve", self._c.v1.balance.retrieve,
                       options={"stripe_account": provider_account_id})
        cur = self._s.PAYMENT_CURRENCY.lower()

        def total(kind: str) -> int:
            return sum(int(_get(x, "amount") or 0) for x in (_get(b, kind) or []) if _get(x, "currency") == cur)

        return BalanceInfo(available_cents=total("available"), pending_cents=total("pending"),
                           currency=self._s.PAYMENT_CURRENCY)
