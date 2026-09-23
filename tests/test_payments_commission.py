"""Pagos, Fase 1: CommissionEngine (cálculo en centavos, redondeo, impuestos, descuentos y costo del proveedor)."""
import random

import pytest

from app.models import CommissionScope, CommissionType
from app.payments.commission import (
    CommissionError,
    RuleTerms,
    TaxRates,
    apply_bp,
    compute,
    from_cents,
    provider_cost_cents,
    to_cents,
    uncovered_price,
)

G = CommissionScope.GLOBAL
PCT, FIX, BOTH = CommissionType.PERCENT, CommissionType.FIXED, CommissionType.PERCENT_PLUS_FIXED
RFC = TaxRates(service_tax_bp=1600, commission_tax_bp=1600, isr_withholding_bp=250, iva_withholding_bp=800,
               technician_has_rfc=True)
NO_RFC = TaxRates(service_tax_bp=1600, commission_tax_bp=1600, isr_withholding_bp=2000, iva_withholding_bp=1600,
                  technician_has_rfc=False)
FIFTEEN = RuleTerms(scope=G, type=PCT, rate_bp=1500)


def split_sum(b) -> int:
    return (b.technician_cents + b.commission_cents + b.commission_tax_cents + b.withholding_isr_cents
            + b.withholding_iva_cents)


# ------------------------------------------------------------------ aritmética
@pytest.mark.parametrize("amount,rate,expected", [
    (5, 1000, 1),          # 0.5 → 1 (half-up)
    (4, 1250, 1),          # 0.5 → 1
    (3, 1500, 0),          # 0.45 → 0
    (100_000, 1600, 16_000),
    (99_999, 1600, 16_000),  # 15 999.84 → 16 000
    (0, 1600, 0),
])
def test_apply_bp_redondea_half_up(amount, rate, expected):
    assert apply_bp(amount, rate) == expected


def test_pesos_a_centavos_es_exacto():
    assert to_cents("1000.00") == 100_000
    assert to_cents("0.1") == 10
    assert str(from_cents(116_000)) == "1160.00"
    with pytest.raises(CommissionError):
        to_cents("10.005")               # fracción de centavo: se rechaza, no se redondea en silencio
    with pytest.raises(CommissionError):
        to_cents("abc")


# ------------------------------------------------------------------ ejemplo del documento
def test_ejemplo_del_doc_1000_mas_iva_tecnico_con_rfc():
    b = compute(100_000, FIFTEEN, RFC)
    assert b.service_tax_cents == 16_000 and b.gross_cents == b.charge_cents == 116_000
    assert (b.commission_cents, b.commission_tax_cents) == (15_000, 2_400)
    assert (b.withholding_isr_cents, b.withholding_iva_cents) == (2_500, 8_000)
    assert b.application_fee_cents == 27_900
    assert b.technician_cents == 88_100


def test_tecnico_sin_rfc_tiene_retenciones_mayores():
    b = compute(100_000, FIFTEEN, NO_RFC)
    assert (b.withholding_isr_cents, b.withholding_iva_cents) == (20_000, 16_000)
    assert b.technician_cents == 116_000 - 15_000 - 2_400 - 20_000 - 16_000


# ------------------------------------------------------------------ tipos de regla, mínimo y máximo
def test_minimo_maximo_y_tope_del_precio():
    with_min = RuleTerms(scope=G, type=PCT, rate_bp=1500, min_cents=5_000)
    assert compute(10_000, with_min, RFC).commission_cents == 5_000
    with_max = RuleTerms(scope=G, type=PCT, rate_bp=1500, max_cents=20_000)
    assert compute(1_000_000, with_max, RFC).commission_cents == 20_000
    big_fixed = RuleTerms(scope=G, type=FIX, rate_bp=0, fixed_cents=9_000)
    assert big_fixed.commission(5_000) == 5_000                          # nunca mayor al precio
    with pytest.raises(CommissionError) as exc:                          # y aun así no puede dejar al técnico en negativo
        compute(5_000, big_fixed, RFC)
    assert exc.value.code == "PAYMENT_SPLIT_NEGATIVE"


def test_porcentaje_mas_fijo():
    rule = RuleTerms(scope=G, type=BOTH, rate_bp=1000, fixed_cents=500)
    assert compute(100_000, rule, RFC).commission_cents == 10_500


# ------------------------------------------------------------------ invariante: ningún centavo se pierde
def test_el_reparto_siempre_cuadra_al_centavo():
    rng = random.Random(20260923)
    rules = [FIFTEEN, RuleTerms(scope=G, type=PCT, rate_bp=1234, min_cents=1_000, max_cents=90_000),
             RuleTerms(scope=G, type=FIX, rate_bp=0, fixed_cents=4_321),
             RuleTerms(scope=G, type=BOTH, rate_bp=777, fixed_cents=333)]
    for _ in range(3_000):
        price = rng.randint(5_000, 5_000_000)
        rule = rng.choice(rules)
        taxes = rng.choice([RFC, NO_RFC])
        b = compute(price, rule, taxes)
        assert split_sum(b) == b.charge_cents == b.gross_cents
        assert b.gross_cents == price + b.service_tax_cents
        assert 0 <= b.commission_cents <= price
        assert b.technician_cents >= 0


# ------------------------------------------------------------------ descuentos de la plataforma
def test_descuento_de_la_plataforma_no_toca_al_tecnico():
    sin = compute(100_000, FIFTEEN, RFC)
    con = compute(100_000, FIFTEEN, RFC, platform_discount_cents=5_000)
    assert con.charge_cents == 111_000
    assert con.technician_cents == sin.technician_cents == 88_100
    assert con.commission_cents + con.commission_tax_cents == 17_400 - 5_000
    assert con.commission_cents == 10_690                  # 12 400 / 1.16 = 10 689.66 → 10 690
    assert split_sum(con) == con.charge_cents


def test_descuento_igual_a_la_comision_deja_comision_cero():
    b = compute(100_000, FIFTEEN, RFC, platform_discount_cents=17_400)
    assert (b.commission_cents, b.commission_tax_cents) == (0, 0)
    assert b.technician_cents == 88_100


def test_descuento_mayor_a_la_comision_se_rechaza():
    with pytest.raises(CommissionError) as exc:
        compute(100_000, FIFTEEN, RFC, platform_discount_cents=17_401)
    assert exc.value.code == "PAYMENT_DISCOUNT_EXCEEDS_COMMISSION"


@pytest.mark.parametrize("price,discount", [(0, 0), (-100, 0), (10_000, -1)])
def test_valores_invalidos(price, discount):
    with pytest.raises(CommissionError):
        compute(price, FIFTEEN, RFC, platform_discount_cents=discount)


# ------------------------------------------------------------------ costo del proveedor
def test_costo_del_proveedor():
    # $1,160 cobrados: 3.6 % = 41.76 + $3 = 44.76, más IVA 7.16 = 51.92
    assert provider_cost_cents(100_000, RFC) == 5_192


def test_regla_global_cubre_el_costo_en_todo_el_rango():
    assert uncovered_price(FIFTEEN) is None
    assert uncovered_price(RuleTerms(scope=G, type=PCT, rate_bp=1500, min_cents=1_000)) is None


@pytest.mark.parametrize("rule", [
    RuleTerms(scope=G, type=PCT, rate_bp=300),                          # 3 %: siempre pierde
    RuleTerms(scope=G, type=FIX, rate_bp=0, fixed_cents=500),           # fija: pierde en servicios grandes
    RuleTerms(scope=G, type=PCT, rate_bp=1500, max_cents=2_000),        # tope bajo: pierde arriba
    RuleTerms(scope=G, type=PCT, rate_bp=500, min_cents=2_000),         # pierde en el tramo intermedio
])
def test_reglas_que_dan_perdida_se_detectan(rule):
    bad = uncovered_price(rule)
    assert bad is not None
    assert rule.commission(bad) < provider_cost_cents(bad, RFC)
