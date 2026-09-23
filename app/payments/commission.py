"""
CommissionEngine: calcula en el backend, en centavos enteros, cuánto se cobra al cliente
y cómo se divide (sección 7 del doc de pagos). El frontend solo manda el id de la orden:
ningún importe viene del cliente.

Orden del cálculo (sin centavos perdidos):
  1. IVA del servicio sobre el precio acordado (sin IVA)        → bruto = precio + IVA
  2. Comisión según la regla (half-up al centavo), con mínimo/máximo y nunca mayor al precio
  3. IVA de la comisión, retención de ISR y retención de IVA (half-up cada una)
  4. El técnico recibe el remanente exacto
  Invariante: técnico + comisión + IVA comisión + retenciones = bruto − descuento.

Qué regla se aplica: PROMOTION → TECHNICIAN → CATEGORY → GLOBAL; gana la primera vigente
en la fecha de la cotización. Cada pago guarda una copia de la regla y de las tasas.

Descuentos (Fase 1): solo los que paga la plataforma. Reducen comisión + su IVA en el
monto exacto del descuento, así el técnico recibe lo mismo que sin descuento; no pueden
superar la comisión con su IVA (con cargos de destino, application_fee no puede ser negativa).
Los descuentos que absorbe el técnico requieren que él acepte la promoción: fase posterior.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from sqlalchemy import or_, select, tuple_
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.config import get_settings
from app.core.errors import DomainError
from app.models import (
    ActorType,
    CommissionRule,
    CommissionScope,
    CommissionType,
    ServiceCategory,
    User,
    UserRole,
)

BP = 10_000
PRECEDENCE = (CommissionScope.PROMOTION, CommissionScope.TECHNICIAN, CommissionScope.CATEGORY,
              CommissionScope.GLOBAL)
_PROMO_CODE = re.compile(r"^[A-Z0-9_-]{3,64}$")


class CommissionError(DomainError):
    http_status = 422
    code = "COMMISSION_ERROR"


# =============================================================================
# Aritmética en centavos
# =============================================================================
def to_cents(amount: Decimal | str | int) -> int:
    """Pesos → centavos, exacto. Rechaza fracciones de centavo en lugar de redondearlas en silencio."""
    try:
        d = Decimal(str(amount))
    except InvalidOperation as exc:
        raise CommissionError("Importe inválido", code="PAYMENT_INVALID_AMOUNT") from exc
    cents = d * 100
    if cents != cents.to_integral_value():
        raise CommissionError("El importe tiene fracciones de centavo", code="PAYMENT_INVALID_AMOUNT")
    return int(cents)


def from_cents(cents: int) -> Decimal:
    return (Decimal(cents) / 100).quantize(Decimal("0.01"))


def apply_bp(amount_cents: int, rate_bp: int) -> int:
    """amount × rate / 10 000, redondeo half-up al centavo (solo importes no negativos)."""
    if amount_cents < 0 or rate_bp < 0:
        raise ValueError("apply_bp solo admite valores no negativos")
    return (amount_cents * rate_bp * 2 + BP) // (2 * BP)


def _div_half_up(numerator: int, denominator: int) -> int:
    return (numerator * 2 + denominator) // (2 * denominator)


# =============================================================================
# Tipos del cálculo
# =============================================================================
@dataclass(frozen=True)
class RuleTerms:
    scope: CommissionScope
    type: CommissionType
    rate_bp: int
    fixed_cents: int = 0
    min_cents: int | None = None
    max_cents: int | None = None
    rule_id: int | None = None

    @classmethod
    def of(cls, rule: CommissionRule) -> RuleTerms:
        return cls(scope=rule.scope, type=rule.type, rate_bp=rule.rate_bp, fixed_cents=rule.fixed_cents,
                   min_cents=rule.min_cents, max_cents=rule.max_cents, rule_id=rule.id)

    def raw_commission(self, price_cents: int) -> int:
        """Comisión con mínimo y máximo, sin el tope del precio."""
        value = 0
        if self.type in (CommissionType.PERCENT, CommissionType.PERCENT_PLUS_FIXED):
            value += apply_bp(price_cents, self.rate_bp)
        if self.type in (CommissionType.FIXED, CommissionType.PERCENT_PLUS_FIXED):
            value += self.fixed_cents
        if self.min_cents is not None:
            value = max(value, self.min_cents)
        if self.max_cents is not None:
            value = min(value, self.max_cents)
        return value

    def commission(self, price_cents: int) -> int:
        return min(self.raw_commission(price_cents), price_cents)


@dataclass(frozen=True)
class TaxRates:
    service_tax_bp: int
    commission_tax_bp: int
    isr_withholding_bp: int
    iva_withholding_bp: int
    technician_has_rfc: bool

    @classmethod
    def current(cls, technician_has_rfc: bool) -> TaxRates:
        s = get_settings()
        return cls(
            service_tax_bp=s.TAX_IVA_BP,
            commission_tax_bp=s.TAX_IVA_BP,
            isr_withholding_bp=s.WITHHOLDING_ISR_BP if technician_has_rfc else s.WITHHOLDING_ISR_NO_RFC_BP,
            iva_withholding_bp=s.WITHHOLDING_IVA_BP if technician_has_rfc else s.WITHHOLDING_IVA_NO_RFC_BP,
            technician_has_rfc=technician_has_rfc,
        )


@dataclass(frozen=True)
class Breakdown:
    price_cents: int
    service_tax_cents: int
    gross_cents: int
    discount_cents: int
    commission_cents: int
    commission_tax_cents: int
    withholding_isr_cents: int
    withholding_iva_cents: int
    technician_cents: int
    terms: RuleTerms
    taxes: TaxRates

    @property
    def charge_cents(self) -> int:
        """Lo que se cobra al cliente (amount del PaymentIntent)."""
        return self.gross_cents - self.discount_cents

    @property
    def application_fee_cents(self) -> int:
        """Lo que se queda la plataforma con cargos de destino (application_fee_amount)."""
        return self.commission_cents + self.commission_tax_cents + self.withholding_isr_cents \
            + self.withholding_iva_cents

    def check(self) -> None:
        parts = (self.technician_cents + self.commission_cents + self.commission_tax_cents
                 + self.withholding_isr_cents + self.withholding_iva_cents)
        assert parts == self.charge_cents, "el desglose no cuadra"          # noqa: S101 (invariante)
        assert self.gross_cents == self.price_cents + self.service_tax_cents  # noqa: S101


# =============================================================================
# Cálculo
# =============================================================================
def compute(price_cents: int, terms: RuleTerms, taxes: TaxRates, *, platform_discount_cents: int = 0) -> Breakdown:
    if price_cents <= 0:
        raise CommissionError("El precio debe ser mayor a cero", code="PAYMENT_INVALID_AMOUNT")
    if platform_discount_cents < 0:
        raise CommissionError("El descuento no puede ser negativo", code="PAYMENT_INVALID_DISCOUNT")

    service_tax = apply_bp(price_cents, taxes.service_tax_bp)
    gross = price_cents + service_tax
    commission = terms.commission(price_cents)
    commission_tax = apply_bp(commission, taxes.commission_tax_bp)
    isr = apply_bp(price_cents, taxes.isr_withholding_bp)
    iva_w = apply_bp(price_cents, taxes.iva_withholding_bp)

    if platform_discount_cents:
        fee = commission + commission_tax
        if platform_discount_cents > fee:
            raise CommissionError("El descuento de la plataforma no puede superar su comisión con IVA",
                                  code="PAYMENT_DISCOUNT_EXCEEDS_COMMISSION")
        # Comisión + IVA bajan exactamente lo que vale el descuento; el técnico no se entera.
        target = fee - platform_discount_cents
        commission = _div_half_up(target * BP, BP + taxes.commission_tax_bp)
        commission_tax = target - commission

    technician = gross - platform_discount_cents - commission - commission_tax - isr - iva_w
    if technician < 0:
        raise CommissionError("Comisión y retenciones superan el cobro", code="PAYMENT_SPLIT_NEGATIVE")
    b = Breakdown(price_cents=price_cents, service_tax_cents=service_tax, gross_cents=gross,
                  discount_cents=platform_discount_cents, commission_cents=commission,
                  commission_tax_cents=commission_tax, withholding_isr_cents=isr, withholding_iva_cents=iva_w,
                  technician_cents=technician, terms=terms, taxes=taxes)
    b.check()
    return b


def provider_cost_cents(price_cents: int, taxes: TaxRates) -> int:
    """Costo estimado del proveedor sobre lo que se cobra (precio + IVA), más el IVA de esa comisión."""
    s = get_settings()
    charge = price_cents + apply_bp(price_cents, taxes.service_tax_bp)
    fee = apply_bp(charge, s.PROVIDER_FEE_RATE_BP) + s.PROVIDER_FEE_FIXED_CENTS
    return fee + apply_bp(fee, taxes.commission_tax_bp)


def uncovered_price(terms: RuleTerms, lo: int | None = None, hi: int | None = None) -> int | None:
    """
    Primer precio del rango admitido en el que la comisión no cubre el costo del proveedor,
    o None si la cubre en todo el rango. Comisión y costo son lineales por tramos: basta revisar
    los extremos y los quiebres (donde entran el mínimo, el máximo o el tope del precio).
    """
    s = get_settings()
    lo = s.PAYMENT_MIN_SERVICE_CENTS if lo is None else lo
    hi = s.PAYMENT_MAX_SERVICE_CENTS if hi is None else hi
    taxes = TaxRates.current(technician_has_rfc=True)
    points = {lo, hi}
    rate = terms.rate_bp if terms.type != CommissionType.FIXED else 0
    fixed = terms.fixed_cents if terms.type != CommissionType.PERCENT else 0
    if rate:
        for bound in (terms.min_cents, terms.max_cents):
            if bound is not None and bound > fixed:
                points.add((bound - fixed) * BP // rate)
    if rate < BP:
        points.add(fixed * BP // (BP - rate))          # donde la comisión deja de toparse con el precio
    candidates = sorted({p + d for p in points for d in (-1, 0, 1) if lo <= p + d <= hi})
    for price in candidates:
        if terms.commission(price) < provider_cost_cents(price, taxes):
            return price
    return None


# =============================================================================
# Reglas: resolución, alta y cierre
# =============================================================================
def resolve_rule(db: Session, *, category_id: int, technician_id: uuid.UUID | None,
                 promotion_code: str | None = None, at: datetime | None = None) -> CommissionRule:
    at = at or datetime.now(timezone.utc)
    keys: list[tuple[CommissionScope, str | None]] = []
    if promotion_code:
        keys.append((CommissionScope.PROMOTION, promotion_code))
    if technician_id is not None:
        keys.append((CommissionScope.TECHNICIAN, str(technician_id)))
    keys.append((CommissionScope.CATEGORY, str(category_id)))
    rules = db.scalars(select(CommissionRule).where(
        CommissionRule.valid_from <= at,
        or_(CommissionRule.valid_to.is_(None), CommissionRule.valid_to > at),
        or_(CommissionRule.scope == CommissionScope.GLOBAL,
            tuple_(CommissionRule.scope, CommissionRule.scope_ref).in_(keys)),
    )).all()
    by_scope = {r.scope: r for r in rules}      # sin traslapes (EXCLUDE): a lo más una por alcance y referencia
    for scope in PRECEDENCE:
        if scope in by_scope:
            return by_scope[scope]
    raise CommissionError("No hay una regla de comisión vigente", code="COMMISSION_RULE_MISSING", http_status=409)


def _require_manager(actor: Actor) -> None:
    from app.kyc.permissions import Permission, permissions_for

    if actor.actor_type != ActorType.ADMIN or Permission.COMMISSION_RULES_MANAGE not in permissions_for(
            actor.admin_roles):
        raise CommissionError("No puedes administrar reglas de comisión", code="FORBIDDEN", http_status=403)


def _validate_scope_ref(db: Session, scope: CommissionScope, scope_ref: str | None) -> str | None:
    if scope == CommissionScope.GLOBAL:
        if scope_ref is not None:
            raise CommissionError("La regla global no lleva referencia", code="COMMISSION_RULE_INVALID")
        return None
    if not scope_ref:
        raise CommissionError("Falta la referencia de la regla", code="COMMISSION_RULE_INVALID")
    if scope == CommissionScope.CATEGORY:
        if not scope_ref.isdigit() or db.get(ServiceCategory, int(scope_ref)) is None:
            raise CommissionError("Categoría inexistente", code="COMMISSION_RULE_INVALID")
        return str(int(scope_ref))
    if scope == CommissionScope.TECHNICIAN:
        try:
            tech = db.get(User, uuid.UUID(scope_ref))
        except ValueError:
            tech = None
        if tech is None or tech.role != UserRole.TECHNICIAN:
            raise CommissionError("Técnico inexistente", code="COMMISSION_RULE_INVALID")
        return str(tech.id)
    code = scope_ref.upper()
    if not _PROMO_CODE.fullmatch(code):
        raise CommissionError("Código de promoción inválido", code="COMMISSION_RULE_INVALID")
    return code


def create_rule(db: Session, actor: Actor, *, scope: CommissionScope, scope_ref: str | None,
                type: CommissionType, rate_bp: int = 0, fixed_cents: int = 0,  # noqa: A002
                min_cents: int | None = None, max_cents: int | None = None,
                valid_from: datetime | None = None, valid_to: datetime | None = None, note: str | None = None,
                ctx: RequestContext | None = None) -> CommissionRule:
    """
    Crea una regla. Si ya hay una abierta del mismo alcance, se cierra en valid_from de la nueva
    (los pagos anteriores conservan su copia). Se rechaza una regla que dé pérdida frente al
    costo del proveedor en cualquier precio del rango admitido.
    """
    _require_manager(actor)
    now = datetime.now(timezone.utc)
    valid_from = valid_from or now
    if valid_from < now - timedelta(minutes=1):
        raise CommissionError("Una regla no puede empezar en el pasado", code="COMMISSION_RULE_BACKDATED")
    if valid_to is not None and valid_to <= valid_from:
        raise CommissionError("La vigencia termina antes de empezar", code="COMMISSION_RULE_INVALID")
    if not 0 <= rate_bp <= BP or fixed_cents < 0 or (min_cents or 0) < 0 \
            or (max_cents is not None and max_cents < (min_cents or 0)):
        raise CommissionError("Valores de la regla fuera de rango", code="COMMISSION_RULE_INVALID")
    if (type == CommissionType.PERCENT and fixed_cents) or (type == CommissionType.FIXED and rate_bp):
        raise CommissionError("Los valores no corresponden al tipo de regla", code="COMMISSION_RULE_INVALID")
    ref = _validate_scope_ref(db, scope, scope_ref)
    terms = RuleTerms(scope=scope, type=type, rate_bp=rate_bp, fixed_cents=fixed_cents, min_cents=min_cents,
                      max_cents=max_cents)
    bad = uncovered_price(terms)
    if bad is not None:
        raise CommissionError("La comisión no cubre el costo del proveedor de pagos",
                              code="COMMISSION_BELOW_PROVIDER_COST",
                              extra={"price": str(from_cents(bad)),
                                     "commission": str(from_cents(terms.commission(bad))),
                                     "provider_cost": str(from_cents(
                                         provider_cost_cents(bad, TaxRates.current(True))))})

    same_scope = select(CommissionRule).where(
        CommissionRule.scope == scope,
        CommissionRule.scope_ref.is_(None) if ref is None else CommissionRule.scope_ref == ref,
        or_(CommissionRule.valid_to.is_(None), CommissionRule.valid_to > valid_from),
    ).with_for_update()
    closed: list[int] = []
    for current in db.scalars(same_scope).all():
        if current.valid_from >= valid_from:
            raise CommissionError("Ya hay una regla programada para esa fecha", code="COMMISSION_RULE_OVERLAP",
                                  http_status=409)
        current.valid_to = valid_from
        closed.append(current.id)
    db.flush()

    rule = CommissionRule(scope=scope, scope_ref=ref, type=type, rate_bp=rate_bp, fixed_cents=fixed_cents,
                          min_cents=min_cents, max_cents=max_cents, valid_from=valid_from, valid_to=valid_to,
                          note=note, created_by=actor.user_id)
    db.add(rule)
    db.flush()
    write_audit(db, action="finance.commission_rule.created", actor=actor, target_type="commission_rule",
                target_id=str(rule.id),
                changes={"scope": scope.value, "scope_ref": ref, "type": type.value, "rate_bp": rate_bp,
                         "fixed_cents": fixed_cents, "min_cents": min_cents, "max_cents": max_cents,
                         "valid_from": valid_from.isoformat(), "closed_rules": closed},
                ctx=ctx)
    return rule


def close_rule(db: Session, actor: Actor, rule_id: int, *, valid_to: datetime | None = None,
               ctx: RequestContext | None = None) -> CommissionRule:
    """Termina una regla (p. ej. una excepción por categoría). La regla GLOBAL no se cierra sin reemplazo."""
    _require_manager(actor)
    rule = db.scalar(select(CommissionRule).where(CommissionRule.id == rule_id).with_for_update())
    if rule is None:
        raise CommissionError("Regla no encontrada", code="COMMISSION_RULE_NOT_FOUND", http_status=404)
    if rule.scope == CommissionScope.GLOBAL:
        raise CommissionError("La regla global se reemplaza creando otra, no se cierra",
                              code="COMMISSION_RULE_GLOBAL_REQUIRED", http_status=409)
    valid_to = valid_to or datetime.now(timezone.utc)
    if valid_to <= rule.valid_from or (rule.valid_to is not None and valid_to > rule.valid_to):
        raise CommissionError("Fecha de cierre inválida", code="COMMISSION_RULE_INVALID")
    rule.valid_to = valid_to
    db.flush()
    write_audit(db, action="finance.commission_rule.closed", actor=actor, target_type="commission_rule",
                target_id=str(rule.id), changes={"valid_to": valid_to.isoformat()}, ctx=ctx)
    return rule
