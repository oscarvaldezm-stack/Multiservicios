"""
Pagos, Fase 2: cuenta de pagos del técnico y tarjetas del cliente.

- Técnico: crear su cuenta (solo con KYC aprobado), obtener el enlace de un solo uso al
  formulario del proveedor y consultar su estado. Rutas /me: la cuenta sale del usuario
  autenticado, nunca de un parámetro.
- Cliente: preparar el guardado de una tarjeta (client_secret de un SetupIntent) y listar
  sus tarjetas (marca, últimos 4, vencimiento).
- Supervisión: revisar una cuenta cuyo nombre en el proveedor no coincide con el KYC.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, status

from app.api.deps import CurrentClient, CurrentTechnician, DbSession, ReqCtx, require_permission, require_roles
from app.core.actor import Actor
from app.core.config import get_settings
from app.kyc.permissions import Permission
from app.models import TechnicianPaymentAccount, UserRole
from app.payments import accounts, customers, panel
from app.payments.providers import PaymentProvider, get_provider
from app.schemas.payments import (
    CardSetupOut,
    EmptyIn,
    NameReviewIn,
    OnboardingLinkOut,
    PaymentAccountOut,
    SavedCardOut,
)

Provider = Annotated[PaymentProvider, Depends(get_provider)]

tech_router = APIRouter(prefix="/technicians/me/payment-account", tags=["pagos: cuenta del técnico"],
                        dependencies=[Depends(require_roles(UserRole.TECHNICIAN))])
client_router = APIRouter(prefix="/clients/me/payment-methods", tags=["pagos: tarjetas del cliente"],
                          dependencies=[Depends(require_roles(UserRole.CLIENT))])
admin_router = APIRouter(prefix="/admin/payment-accounts", tags=["pagos (administración)"],
                         dependencies=[Depends(require_roles(UserRole.ADMIN))])


def _out(account: TechnicianPaymentAccount | None) -> PaymentAccountOut:
    if account is None:
        return PaymentAccountOut(status="NOT_CREATED", can_receive_payments=False)
    return PaymentAccountOut(status=account.status, can_receive_payments=account.can_receive_payments,
                             transfers_active=account.transfers_active, payouts_enabled=account.payouts_enabled,
                             requirements_due=account.requirements_due or [],
                             in_review=account.blocked_reason is not None, updated_at=account.updated_at)


# ------------------------------------------------------------------ técnico
@tech_router.post("", response_model=PaymentAccountOut, status_code=status.HTTP_201_CREATED,
                  summary="Crear mi cuenta de pagos (requiere KYC aprobado)")
def create_payment_account(_: EmptyIn, tech: CurrentTechnician, db: DbSession, provider: Provider, ctx: ReqCtx):
    panel.check_provider_rate(db, tech.id)
    account = accounts.create_account(db, tech, provider, ctx)
    db.commit()
    return _out(account)


@tech_router.get("", response_model=PaymentAccountOut, summary="Estado de mi cuenta de pagos")
def get_payment_account(tech: CurrentTechnician, db: DbSession, provider: Provider):
    return _out(accounts.get_account(db, tech.id, provider.name))


@tech_router.post("/onboarding-link", response_model=OnboardingLinkOut,
                  summary="Enlace de un solo uso al formulario del proveedor (CLABE y datos)")
def create_onboarding_link(_: EmptyIn, tech: CurrentTechnician, db: DbSession, provider: Provider):
    panel.check_provider_rate(db, tech.id)
    link = accounts.onboarding_link(db, tech, provider)
    return OnboardingLinkOut(url=link.url, expires_at=link.expires_at)


@tech_router.post("/refresh", response_model=PaymentAccountOut,
                  summary="Volver a consultar mi cuenta en el proveedor (no recibe ningún estado)")
def refresh_payment_account(_: EmptyIn, tech: CurrentTechnician, db: DbSession, provider: Provider, ctx: ReqCtx):
    panel.check_provider_rate(db, tech.id)
    account = accounts.get_account(db, tech.id, provider.name, lock=True)
    if account is not None:
        accounts.sync_account(db, account, provider, ctx=ctx)
        db.commit()
    return _out(account)


# ------------------------------------------------------------------ cliente
@client_router.post("/setup-intent", response_model=CardSetupOut, status_code=status.HTTP_201_CREATED,
                    summary="Preparar el guardado de una tarjeta (la tarjeta va directo al proveedor)")
def start_card_setup(_: EmptyIn, client: CurrentClient, db: DbSession, provider: Provider):
    panel.check_provider_rate(db, client.id)
    info = customers.start_card_setup(db, client, provider)
    db.commit()
    return CardSetupOut(client_secret=info.client_secret, publishable_key=get_settings().STRIPE_PUBLISHABLE_KEY)


@client_router.get("", response_model=list[SavedCardOut], summary="Mis tarjetas guardadas")
def list_cards(client: CurrentClient, db: DbSession, provider: Provider):
    panel.check_provider_rate(db, client.id)
    return [SavedCardOut(id=c.provider_id, brand=c.brand, last4=c.last4, exp_month=c.exp_month,
                         exp_year=c.exp_year) for c in customers.saved_cards(db, client, provider)]


# ------------------------------------------------------------------ supervisión
@admin_router.post("/{account_id}/name-review", response_model=PaymentAccountOut,
                   summary="Resolver una cuenta con nombre distinto al del KYC")
def name_review(data: NameReviewIn, db: DbSession, ctx: ReqCtx,
                actor: Actor = Depends(require_permission(Permission.PAYMENT_ACCOUNTS_REVIEW)),
                account_id: uuid.UUID = Path(description="ID de la cuenta de pagos")):
    account = accounts.resolve_name_review(db, actor, account_id, approve=data.approve, note=data.note, ctx=ctx)
    db.commit()
    return _out(account)
