"""
Proveedor en memoria para desarrollo y pruebas (PAYMENT_PROVIDER_BACKEND=fake; prohibido en producción).

Imita lo que importa de Stripe: ids con prefijo, idempotencia por técnico y por usuario,
enlaces que vencen, y un estado de cuenta que las pruebas pueden mover (`set_account`) como
lo haría el formulario de Stripe.
"""
from __future__ import annotations

import secrets
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

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


class FakePaymentProvider(PaymentProvider):
    name = "stripe"            # se comporta como Stripe: las filas quedan con provider = "stripe"
    capabilities = Capabilities(manual_capture=True, partial_fee_refund=True, connected_accounts=True,
                                saved_cards=True)

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.accounts: dict[str, AccountStatusInfo] = {}
        self.prefills: dict[str, AccountPrefill] = {}
        self._account_by_tech: dict[uuid.UUID, str] = {}
        self.customers: dict[str, uuid.UUID] = {}
        self._customer_by_user: dict[uuid.UUID, str] = {}
        self.cards: dict[str, list[SavedCard]] = {}
        self.setup_intents: list[str] = []
        self.calls: list[str] = []
        self.fail_next: ProviderError | None = None
        self.intents: dict[str, dict] = {}
        self._intent_by_payment: dict[uuid.UUID, str] = {}
        self._card_owner: dict[str, str] = {}
        self._fingerprints: dict[str, str] = {}
        self.decline_next: str | None = None        # "card_declined", "insufficient_funds", "authentication_required"
        self.payouts: dict[tuple[str, str], PayoutInfo] = {}
        self.refunds: dict[str, dict] = {}
        self._refund_by_id: dict[uuid.UUID, str] = {}
        self.refund_status_next: str = "succeeded"   # "pending" / "failed" para simular a Stripe
        self.disputes: dict[str, DisputeInfo] = {}
        self.evidence: dict[str, dict] = {}
        self.reversals: dict[str, tuple[str, int]] = {}
        self.balances: dict[str, BalanceInfo] = {}

    def _enter(self, op: str) -> None:
        self.calls.append(op)
        if self.fail_next is not None:
            err, self.fail_next = self.fail_next, None
            raise err

    # ------------------------------------------------------------------ cuenta del técnico
    def create_connected_account(self, prefill: AccountPrefill) -> str:
        self._enter("accounts.create")
        if prefill.technician_id in self._account_by_tech:          # idempotencia por técnico
            return self._account_by_tech[prefill.technician_id]
        acct = f"acct_fake{secrets.token_hex(8)}"
        self._account_by_tech[prefill.technician_id] = acct
        self.prefills[acct] = prefill
        self.accounts[acct] = AccountStatusInfo(
            provider_account_id=acct, transfers_active=False, payouts_enabled=False, details_submitted=False,
            requirements_due=("external_account", "individual.verification.document"),
            legal_first_name=prefill.first_names, legal_last_name=prefill.last_names)
        return acct

    def create_onboarding_link(self, provider_account_id: str) -> OnboardingLink:
        self._enter("account_links.create")
        self._require(provider_account_id)
        return OnboardingLink(url=f"https://connect.stripe.com/setup/e/{provider_account_id}/{secrets.token_hex(8)}",
                              expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))

    def get_account_status(self, provider_account_id: str) -> AccountStatusInfo:
        self._enter("accounts.retrieve")
        return self._require(provider_account_id)

    def set_account(self, provider_account_id: str, **changes) -> None:
        """Simula lo que el técnico o Stripe hacen fuera de nuestra app (formulario, verificación, bloqueo)."""
        self.accounts[provider_account_id] = replace(self._require(provider_account_id), **changes)

    def complete_onboarding(self, provider_account_id: str) -> None:
        self.set_account(provider_account_id, transfers_active=True, payouts_enabled=True, details_submitted=True,
                         requirements_due=(), disabled_reason=None)

    def _require(self, provider_account_id: str) -> AccountStatusInfo:
        if provider_account_id not in self.accounts:
            raise ProviderError("Cuenta inexistente en el proveedor", code="PAYMENT_PROVIDER_REJECTED")
        return self.accounts[provider_account_id]

    # ------------------------------------------------------------------ cliente y tarjetas
    def create_customer(self, user_id: uuid.UUID, email: str, name: str) -> str:
        self._enter("customers.create")
        if user_id not in self._customer_by_user:
            cus = f"cus_fake{secrets.token_hex(8)}"
            self._customer_by_user[user_id] = cus
            self.customers[cus] = user_id
            self.cards[cus] = []
        return self._customer_by_user[user_id]

    def create_setup_intent(self, provider_customer_id: str, user_id: uuid.UUID) -> SetupIntentInfo:
        self._enter("setup_intents.create")
        if self.customers.get(provider_customer_id) != user_id:
            raise ProviderError("Cliente inexistente en el proveedor", code="PAYMENT_PROVIDER_REJECTED")
        sid = f"seti_fake{secrets.token_hex(8)}"
        self.setup_intents.append(sid)
        return SetupIntentInfo(provider_id=sid, client_secret=f"{sid}_secret_{secrets.token_hex(12)}")

    def add_card(self, provider_customer_id: str, brand: str = "visa", last4: str = "4242") -> str:
        """Simula que la app confirmó el SetupIntent con el componente de Stripe. Devuelve el id del método."""
        pm = f"pm_fake{secrets.token_hex(6)}"
        self.cards[provider_customer_id].append(SavedCard(provider_id=pm, brand=brand, last4=last4, exp_month=12,
                                                          exp_year=2030))
        self._card_owner[pm] = provider_customer_id
        self._fingerprints[pm] = f"fp_{secrets.token_hex(6)}"  # cada tarjeta, su huella (las pruebas la fijan)
        return pm

    def list_saved_cards(self, provider_customer_id: str) -> list[SavedCard]:
        self._enter("customers.payment_methods.list")
        return list(self.cards.get(provider_customer_id, []))

    # ------------------------------------------------------------------ cobros (Fase 3)
    def _view(self, pid: str) -> ProviderPayment:
        i = self.intents[pid]
        return ProviderPayment(provider_payment_id=pid, status=i["status"], amount_cents=i["amount"],
                               amount_capturable_cents=i["amount"] if i["status"] == PaymentStatus.AUTHORIZED else 0,
                               amount_received_cents=i["received"], failure_code=i["failure_code"],
                               payment_method_fingerprint=i["fingerprint"], client_secret=i["client_secret"],
                               metadata_payment_id=str(i["request"].payment_id) if i.get("request") else None)

    def authorize(self, req: AuthorizationRequest) -> ProviderPayment:
        self._enter("payment_intents.create")
        if req.payment_id in self._intent_by_payment:                  # idempotencia authorize:{pago}
            return self._view(self._intent_by_payment[req.payment_id])
        if self._card_owner.get(req.payment_method_id) != req.customer_id:
            raise ProviderError("Método de pago inexistente", code="PAYMENT_PROVIDER_REJECTED")
        dest = self.accounts.get(req.destination_account_id)
        if dest is None or not dest.transfers_active:
            raise ProviderError("La cuenta destino no puede recibir transferencias", code="PAYMENT_PROVIDER_REJECTED")
        if not 0 <= req.application_fee_cents <= req.amount_cents:
            raise ProviderError("Comisión inválida", code="PAYMENT_PROVIDER_REJECTED")
        pid = f"pi_fake{secrets.token_hex(8)}"
        decline, self.decline_next = self.decline_next, None
        status = PaymentStatus.AUTHORIZED
        if decline == "authentication_required":
            status = PaymentStatus.REQUIRES_ACTION
        elif decline:
            status = PaymentStatus.FAILED
        self.intents[pid] = {"status": status, "amount": req.amount_cents, "received": 0, "request": req,
                             "failure_code": decline, "fingerprint": self._fingerprints[req.payment_method_id],
                             "client_secret": f"{pid}_secret_{secrets.token_hex(8)}", "captures": 0,
                             "created": datetime.now(timezone.utc)}
        self._intent_by_payment[req.payment_id] = pid
        return self._view(pid)

    def complete_authentication(self, provider_payment_id: str) -> None:
        """Simula que el cliente completó 3D Secure en la app."""
        self.intents[provider_payment_id].update(status=PaymentStatus.AUTHORIZED, failure_code=None)

    def capture(self, provider_payment_id: str, payment_id: uuid.UUID, amount_cents: int,
                application_fee_cents: int | None = None) -> ProviderPayment:
        self._enter("payment_intents.capture")
        i = self.intents[provider_payment_id]
        if i["status"] == PaymentStatus.PAID:                           # idempotencia capture:{pago}
            return self._view(provider_payment_id)
        if i["status"] != PaymentStatus.AUTHORIZED or not 0 < amount_cents <= i["amount"]:
            raise ProviderError("No se puede capturar", code="PAYMENT_PROVIDER_REJECTED")
        if application_fee_cents is not None and not 0 <= application_fee_cents <= amount_cents:
            raise ProviderError("Comisión inválida", code="PAYMENT_PROVIDER_REJECTED")
        i.update(status=PaymentStatus.PAID, received=amount_cents, captures=i["captures"] + 1,
                 captured_fee=application_fee_cents)
        return self._view(provider_payment_id)

    def cancel_authorization(self, provider_payment_id: str, payment_id: uuid.UUID) -> ProviderPayment:
        self._enter("payment_intents.cancel")
        i = self.intents[provider_payment_id]
        if i["status"] == PaymentStatus.PAID:
            raise ProviderError("Un cobro capturado se reembolsa, no se anula", code="PAYMENT_PROVIDER_REJECTED")
        i["status"] = PaymentStatus.CANCELLED
        return self._view(provider_payment_id)

    def get_payment(self, provider_payment_id: str) -> ProviderPayment:
        self._enter("payment_intents.retrieve")
        return self._view(provider_payment_id)

    def set_intent(self, provider_payment_id: str, **changes) -> None:
        """Simula cambios en el proveedor que la app no provocó (p. ej. la autorización venció)."""
        self.intents[provider_payment_id].update(changes)

    # ------------------------------------------------------------------ webhooks y conciliación (Fase 4)
    def verify_webhook(self, payload: bytes, signature: str | None, endpoint: str) -> WebhookEvent:
        # Misma verificación que Stripe (local, sin red) con los secretos configurados.
        from app.core.config import get_settings
        from app.payments.providers.stripe_provider import verify_stripe_signature, webhook_secret

        self._enter("webhooks.verify")
        return verify_stripe_signature(payload, signature, webhook_secret(get_settings(), endpoint))

    def add_payout(self, provider_account_id: str, amount_cents: int = 88_100, status: str = "paid",
                   failure_code: str | None = None) -> str:
        po = f"po_fake{secrets.token_hex(6)}"
        self.payouts[(provider_account_id, po)] = PayoutInfo(
            provider_payout_id=po, amount_cents=amount_cents, currency="MXN", status=status,
            arrival_date=datetime.now(timezone.utc).date(), failure_code=failure_code)
        return po

    def get_payout(self, provider_account_id: str, provider_payout_id: str) -> PayoutInfo:
        self._enter("payouts.retrieve")
        try:
            return self.payouts[(provider_account_id, provider_payout_id)]
        except KeyError:
            raise ProviderError("Depósito inexistente", code="PAYMENT_PROVIDER_REJECTED") from None

    def list_payments(self, created_from: datetime, created_to: datetime) -> list[ProviderPayment]:
        self._enter("payment_intents.list")
        return [self._view(pid) for pid, i in self.intents.items() if created_from <= i["created"] < created_to]

    def add_foreign_intent(self, amount_cents: int = 50_000, status: PaymentStatus = PaymentStatus.PAID) -> str:
        """Cobro creado fuera de nuestra app (p. ej. desde el panel de Stripe): la conciliación debe detectarlo."""
        pid = f"pi_fake{secrets.token_hex(8)}"
        self.intents[pid] = {"status": status, "amount": amount_cents, "received": amount_cents, "request": None,
                             "failure_code": None, "fingerprint": None, "client_secret": f"{pid}_secret_x",
                             "captures": 1, "created": datetime.now(timezone.utc)}
        return pid

    # ------------------------------------------------------------------ reembolsos, disputas y saldo (Fase 5)
    def refund(self, req: RefundRequest) -> RefundInfo:
        self._enter("refunds.create")
        if req.refund_id in self._refund_by_id:                          # idempotencia refund:{id}
            return self.get_refund(self._refund_by_id[req.refund_id])
        i = self.intents.get(req.provider_payment_id)
        already = sum(r["amount"] for r in self.refunds.values()
                      if r["pi"] == req.provider_payment_id and r["status"] in ("pending", "succeeded"))
        if i is None or i["status"] != PaymentStatus.PAID or already + req.amount_cents > i["received"]:
            raise ProviderError("Reembolso inválido", code="PAYMENT_PROVIDER_REJECTED")
        if req.refund_application_fee and not req.reverse_transfer:
            raise ProviderError("La comisión solo se devuelve revirtiendo la transferencia",
                                code="PAYMENT_PROVIDER_REJECTED")
        if req.reverse_transfer:
            acct = i["request"].destination_account_id if i.get("request") else None
            bal = self.balances.get(acct)
            if bal is not None and bal.available_cents <= 0:              # el técnico ya retiró su saldo
                raise ProviderError("Saldo insuficiente del técnico", code="PAYMENT_PROVIDER_REJECTED",
                                    provider_code="balance_insufficient")
        rid = f"re_fake{secrets.token_hex(8)}"
        self.refunds[rid] = {"pi": req.provider_payment_id, "amount": req.amount_cents,
                             "status": self.refund_status_next, "reverse": req.reverse_transfer,
                             "fee": req.refund_application_fee, "refund_id": str(req.refund_id)}
        self._refund_by_id[req.refund_id] = rid
        return self.get_refund(rid)

    def refund_outside_app(self, provider_payment_id: str, amount_cents: int) -> str:
        """Reembolso hecho desde el panel de Stripe (sin pasar por nuestra app)."""
        rid = f"re_fake{secrets.token_hex(8)}"
        self.refunds[rid] = {"pi": provider_payment_id, "amount": amount_cents, "status": "succeeded",
                             "reverse": False, "fee": False, "refund_id": None}
        return rid

    def get_refund(self, provider_refund_id: str) -> RefundInfo:
        r = self.refunds[provider_refund_id]
        return RefundInfo(provider_refund_id=provider_refund_id, provider_payment_id=r["pi"],
                          amount_cents=r["amount"], status=r["status"],
                          failure_reason="declined" if r["status"] == "failed" else None,
                          transfer_reversed=r["reverse"], metadata_refund_id=r["refund_id"])

    def set_refund(self, provider_refund_id: str, status: str) -> None:
        self.refunds[provider_refund_id]["status"] = status

    def open_dispute(self, provider_payment_id: str, amount_cents: int, reason: str = "fraudulent") -> str:
        did = f"dp_fake{secrets.token_hex(6)}"
        self.disputes[did] = DisputeInfo(provider_dispute_id=did, provider_payment_id=provider_payment_id,
                                         amount_cents=amount_cents, reason=reason, status="needs_response",
                                         evidence_due_by=datetime.now(timezone.utc) + timedelta(days=7))
        return did

    def close_dispute(self, provider_dispute_id: str, *, won: bool) -> None:
        self.disputes[provider_dispute_id] = replace(self.disputes[provider_dispute_id],
                                                     status="won" if won else "lost")

    def get_dispute(self, provider_dispute_id: str) -> DisputeInfo:
        self._enter("disputes.retrieve")
        return self.disputes[provider_dispute_id]

    def submit_dispute_evidence(self, provider_dispute_id: str, evidence: dict[str, str]) -> DisputeInfo:
        self._enter("disputes.update")
        self.evidence[provider_dispute_id] = dict(evidence)
        self.disputes[provider_dispute_id] = replace(self.disputes[provider_dispute_id], status="under_review")
        return self.disputes[provider_dispute_id]

    def reverse_transfer(self, provider_payment_id: str, amount_cents: int, key: str) -> str:
        self._enter("transfers.reversals.create")
        if key in self.reversals:                                       # idempotencia por llave
            return self.reversals[key][0]
        trr = f"trr_fake{secrets.token_hex(6)}"
        self.reversals[key] = (trr, amount_cents)
        return trr

    def get_balance(self, provider_account_id: str) -> BalanceInfo:
        self._enter("balance.retrieve")
        return self.balances.get(provider_account_id, BalanceInfo(available_cents=0, pending_cents=0, currency="MXN"))
