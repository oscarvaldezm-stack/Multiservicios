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

    def add_card(self, provider_customer_id: str, brand: str = "visa", last4: str = "4242") -> None:
        """Simula que la app confirmó el SetupIntent con el componente de Stripe."""
        self.cards[provider_customer_id].append(SavedCard(provider_id=f"pm_fake{secrets.token_hex(6)}",
                                                          brand=brand, last4=last4, exp_month=12, exp_year=2030))

    def list_saved_cards(self, provider_customer_id: str) -> list[SavedCard]:
        self._enter("customers.payment_methods.list")
        return list(self.cards.get(provider_customer_id, []))
