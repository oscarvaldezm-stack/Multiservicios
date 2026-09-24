"""
Políticas de cancelación (sección 9 del doc de pagos). El código aplica mecanismos; los montos
y porcentajes son políticas que edita finanzas (tabla cancellation_policies, con vigencia y
sin traslapes). Sin política vigente, cancelar no cuesta nada.

| Escenario               | Cuándo                                             | Qué pasa con el dinero                     |
|-------------------------|----------------------------------------------------|--------------------------------------------|
| CLIENT_LATE_CANCEL      | el cliente cancela ya aceptada/agendada, antes de  | se anula la reserva; si hay cargo, se      |
|                         | que el técnico salga                               | cobra aparte con la tarjeta elegida        |
| CLIENT_CANCEL_ON_SITE   | el técnico ya salió ("en camino") y el cliente     | captura PARCIAL de la reserva por el cargo |
|                         | cancela                                            | por visita; el resto se libera solo        |

El cargo se reparte según technician_share_bp / platform_share_bp de la política (con el IVA y
las retenciones de siempre). El técnico que cancela no paga cargo: vuelve la orden a la bolsa y
cuenta en su confiabilidad (Fase 4).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.errors import DomainError
from app.models import (
    CancellationPolicy,
    CommissionScope,
    CommissionTransaction,
    CommissionType,
    OutboxEvent,
    Payment,
    PaymentCustomer,
    PaymentKind,
    PaymentStatus,
    ServiceOrder,
)
from app.payments import service as payments
from app.payments.commission import BP, CommissionError, RuleTerms, TaxRates, apply_bp, compute
from app.payments.providers.base import AuthorizationRequest, PaymentProvider, ProviderError

log = logging.getLogger("payments")
LATE = "CLIENT_LATE_CANCEL"
ON_SITE = "CLIENT_CANCEL_ON_SITE"
SCENARIOS = (LATE, ON_SITE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def current_policy(db: Session, scenario: str, at: datetime | None = None) -> CancellationPolicy | None:
    at = at or _now()
    return db.scalar(select(CancellationPolicy).where(
        CancellationPolicy.scenario == scenario, CancellationPolicy.valid_from <= at,
        or_(CancellationPolicy.valid_to.is_(None), CancellationPolicy.valid_to > at)))


def fee_price_cents(policy: CancellationPolicy | None, order_price_cents: int) -> int:
    """Cargo SIN IVA según la política (nunca mayor que el precio acordado)."""
    if policy is None or policy.fee_type == "NONE":
        return 0
    fee = policy.fee_value if policy.fee_type == "FIXED" else apply_bp(order_price_cents, policy.fee_value)
    return max(0, min(fee, order_price_cents))


def shares_terms(policy: CancellationPolicy) -> RuleTerms:
    """El reparto de la política como una regla: la plataforma se queda platform_share_bp del cargo."""
    return RuleTerms(scope=CommissionScope.GLOBAL, type=CommissionType.PERCENT, rate_bp=policy.platform_share_bp)


# =============================================================================
# Administración
# =============================================================================
def set_policy(db: Session, actor: Actor, *, scenario: str, fee_type: str, fee_value: int, technician_share_bp: int,
               ctx: RequestContext | None = None) -> CancellationPolicy:
    """Nueva política vigente desde ahora; la anterior del mismo escenario se cierra."""
    from app.kyc.permissions import Permission, permissions_for

    if Permission.CANCELLATION_POLICIES_MANAGE not in permissions_for(actor.admin_roles):
        raise DomainError("No puedes administrar políticas de cancelación", code="FORBIDDEN", http_status=403)
    if scenario not in SCENARIOS or fee_type not in ("NONE", "FIXED", "PERCENT"):
        raise DomainError("Escenario o tipo de cargo inválido", code="CANCELLATION_POLICY_INVALID", http_status=422)
    if fee_value < 0 or (fee_type == "NONE" and fee_value) or (fee_type == "PERCENT" and fee_value > BP) \
            or not 0 <= technician_share_bp <= BP:
        raise DomainError("Valores de la política fuera de rango", code="CANCELLATION_POLICY_INVALID", http_status=422)
    policy = CancellationPolicy(scenario=scenario, fee_type=fee_type, fee_value=fee_value,
                                technician_share_bp=technician_share_bp, platform_share_bp=BP - technician_share_bp,
                                valid_from=_now(), created_by=actor.user_id)
    if fee_type != "NONE":                       # el reparto debe poder calcularse (sin partes negativas)
        try:
            compute(100_000, shares_terms(policy), TaxRates.current(True))
        except CommissionError as exc:
            raise DomainError("Ese reparto deja al técnico en negativo tras impuestos",
                              code="CANCELLATION_POLICY_INVALID", http_status=422) from exc
    current = db.scalar(select(CancellationPolicy).where(
        CancellationPolicy.scenario == scenario, CancellationPolicy.valid_to.is_(None)).with_for_update())
    if current is not None:
        current.valid_to = policy.valid_from
        db.flush()
    db.add(policy)
    db.flush()
    write_audit(db, action="finance.cancellation_policy.set", actor=actor, target_type="cancellation_policy",
                target_id=str(policy.id), changes={"scenario": scenario, "fee_type": fee_type, "fee_value": fee_value,
                                                   "technician_share_bp": technician_share_bp}, ctx=ctx)
    return policy


# =============================================================================
# Aplicación cuando el cliente cancela
# =============================================================================
def scenario_for(order: ServiceOrder, payment: Payment | None) -> str | None:
    if order.departed_at is not None and payment is not None and payment.status == PaymentStatus.AUTHORIZED:
        return ON_SITE
    if order.technician_id is not None:
        return LATE
    return None


def apply_client_cancellation(db: Session, order: ServiceOrder, scenario: str | None,
                              provider: PaymentProvider | None = None) -> str:
    """
    Aplica el dinero de una cancelación del cliente (orden YA en CANCELLED). Devuelve qué pasó:
    NO_FEE, VISIT_FEE_CAPTURED, LATE_FEE_CHARGED o FEE_NOT_COLLECTED.
    """
    payment = payments.active_payment(db, order.id, lock=True)
    policy = current_policy(db, scenario) if scenario else None
    price = payments.to_cents(order.agreed_price) if order.agreed_price is not None else 0
    fee = fee_price_cents(policy, price)
    if scenario == ON_SITE and fee > 0 and payment is not None and payment.status == PaymentStatus.AUTHORIZED:
        try:
            payments.capture_partial(db, payment, fee, terms=shares_terms(policy), provider=provider)
            return "VISIT_FEE_CAPTURED"
        except (ProviderError, CommissionError):
            log.warning("No se pudo cobrar el cargo por visita de la orden %s", order.id)
            payments.cancel_for_order(db, order, provider)
            return _not_collected(db, order, fee)
    card = payment.provider_payment_method_id if payment is not None else None
    payments.cancel_for_order(db, order, provider)
    if scenario == LATE and fee > 0:
        return _charge_late_fee(db, order, fee, policy, card, provider)
    return "NO_FEE"


def _not_collected(db: Session, order: ServiceOrder, fee: int) -> str:
    db.add(OutboxEvent(event_type="cancellation_fee.not_collected", aggregate_type="service_order",
                       aggregate_id=order.id, payload={"fee_price_cents": fee}))
    db.flush()
    return "FEE_NOT_COLLECTED"


def _charge_late_fee(db: Session, order: ServiceOrder, fee: int, policy: CancellationPolicy, card: str | None,
                     provider: PaymentProvider | None) -> str:
    """Cargo aparte (pago CANCELLATION_FEE) con la tarjeta que el cliente ya había elegido."""
    from app.payments import accounts

    provider = payments._provider(provider)
    customer = db.get(PaymentCustomer, (order.client_id, provider.name))
    account = accounts.get_account(db, order.technician_id, provider.name) if order.technician_id else None
    if not card or customer is None or account is None or not account.can_receive_payments:
        return _not_collected(db, order, fee)
    b = compute(fee, shares_terms(policy), TaxRates.current(payments._technician_has_rfc(db, order.technician_id)))
    charge = Payment(service_order_id=order.id, payer_id=order.client_id, kind=PaymentKind.CANCELLATION_FEE,
                     provider=provider.name, currency=payments.get_settings().PAYMENT_CURRENCY,
                     amount_cents=b.charge_cents, provider_payment_method_id=card, technician_account_id=account.id)
    db.add(charge)
    db.flush()
    t, x = b.terms, b.taxes
    db.add(CommissionTransaction(
        payment_id=charge.id, rule_scope="CANCELLATION", rule_type=t.type.value, rate_bp=t.rate_bp,
        fixed_cents=0, service_tax_bp=x.service_tax_bp, commission_tax_bp=x.commission_tax_bp,
        isr_withholding_bp=x.isr_withholding_bp, iva_withholding_bp=x.iva_withholding_bp,
        technician_has_rfc=x.technician_has_rfc, price_cents=b.price_cents, service_tax_cents=b.service_tax_cents,
        gross_cents=b.gross_cents, discount_cents=0, commission_cents=b.commission_cents,
        commission_tax_cents=b.commission_tax_cents, withholding_isr_cents=b.withholding_isr_cents,
        withholding_iva_cents=b.withholding_iva_cents, technician_cents=b.technician_cents))
    db.flush()
    try:
        result = provider.authorize(AuthorizationRequest(
            payment_id=charge.id, order_id=order.id, amount_cents=charge.amount_cents, currency=charge.currency,
            customer_id=customer.provider_customer_id, payment_method_id=card,
            destination_account_id=account.provider_account_id, application_fee_cents=b.application_fee_cents))
        payments.apply_provider_state(db, charge, result)
        if charge.status == PaymentStatus.AUTHORIZED:
            payments.capture(db, charge, provider)
    except ProviderError:
        log.warning("No se pudo cobrar el cargo por cancelación de la orden %s", order.id)
    if charge.status != PaymentStatus.PAID:
        return _not_collected(db, order, fee)
    return "LATE_FEE_CHARGED"


def policy_view(p: CancellationPolicy) -> dict:
    return {"id": p.id, "scenario": p.scenario, "fee_type": p.fee_type, "fee_value": p.fee_value,
            "technician_share_bp": p.technician_share_bp, "platform_share_bp": p.platform_share_bp,
            "valid_from": p.valid_from, "valid_to": p.valid_to}


__all__ = ["LATE", "ON_SITE", "SCENARIOS", "apply_client_cancellation", "current_policy", "fee_price_cents",
           "policy_view", "scenario_for", "set_policy"]
