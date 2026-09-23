"""Pagos, Fase 1: reglas de comisión, desglose congelado, libro contable y defensas en la base de datos."""
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.core.actor import Actor
from app.models import (
    AdminRole,
    CommissionRule,
    CommissionScope,
    CommissionType,
    LedgerAccount,
    LedgerEntry,
    Payment,
    PaymentKind,
    PaymentStatus,
    ServiceCategory,
)
from app.payments import ledger
from app.payments import service as payments
from app.payments.commission import CommissionError, create_rule, close_rule, resolve_rule
from app.payments.state_machine import ALLOWED_PAYMENT_TRANSITIONS, PaymentError, move
from tests.conftest import make_admin
from tests.marketplace import approved_tech, new_client, order_status, payment_of, run_order, webhook

P = PaymentStatus
A = LedgerAccount
PCT = CommissionType.PERCENT


@pytest.fixture
def finance(db) -> Actor:
    return Actor.from_user(make_admin(db, "finanzas@example.com", AdminRole.FINANCE_ADMIN))


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


def _raises_db(db, sql: str, params: dict, fragment: str, *, commit: bool = False):
    with pytest.raises(DBAPIError) as exc:
        db.execute(text(sql), params)
        db.commit() if commit else db.flush()
    db.rollback()
    assert fragment in str(exc.value.orig)


# ------------------------------------------------------------------ app = trigger
def test_transiciones_de_pago_en_la_app_y_en_el_trigger_coinciden(db):
    src = db.scalar(text("SELECT pg_get_functiondef('payment_enforce_transition'::regproc)"))
    in_db = set(re.findall(r"'([A-Z_]+>[A-Z_]+)'", src))
    assert in_db == {f"{a.value}>{b.value}" for a, b in ALLOWED_PAYMENT_TRANSITIONS}


@pytest.mark.parametrize("src", list(P))
def test_maquina_de_estados_del_pago(src):
    for dst in P:
        p = Payment(status=src, version=1)
        if src == dst:
            assert move(p, dst) is False and p.version == 1
        elif (src, dst) in ALLOWED_PAYMENT_TRANSITIONS:
            assert move(p, dst) is True and p.status == dst and p.version == 2
        else:
            with pytest.raises(PaymentError):
                move(p, dst)


# ------------------------------------------------------------------ reglas de comisión
def test_precedencia_tecnico_categoria_global(db, client, category, reviewer, supervisor, finance):
    tid, _ = approved_tech(client, db, category, reviewer, supervisor)
    other = ServiceCategory(name="Electricidad", slug="electricidad")
    db.add(other)
    db.commit()
    create_rule(db, finance, scope=CommissionScope.CATEGORY, scope_ref=str(category.id), type=PCT, rate_bp=1200,
                min_cents=1_000)
    create_rule(db, finance, scope=CommissionScope.TECHNICIAN, scope_ref=str(tid), type=PCT, rate_bp=1000,
                min_cents=1_000)
    db.commit()
    assert resolve_rule(db, category_id=category.id, technician_id=tid).rate_bp == 1000
    assert resolve_rule(db, category_id=category.id, technician_id=uuid.uuid4()).rate_bp == 1200
    assert resolve_rule(db, category_id=other.id, technician_id=tid).rate_bp == 1000
    assert resolve_rule(db, category_id=other.id, technician_id=None).scope == CommissionScope.GLOBAL


def test_promocion_gana_a_todo(db, category, finance):
    create_rule(db, finance, scope=CommissionScope.PROMOTION, scope_ref="buen-fin", type=PCT, rate_bp=1100,
                min_cents=1_000)
    db.commit()
    rule = resolve_rule(db, category_id=category.id, technician_id=None, promotion_code="BUEN-FIN")
    assert rule.scope == CommissionScope.PROMOTION and rule.rate_bp == 1100
    assert resolve_rule(db, category_id=category.id, technician_id=None).scope == CommissionScope.GLOBAL


def test_nueva_regla_cierra_la_anterior_del_mismo_alcance(db, category, finance):
    old = resolve_rule(db, category_id=category.id, technician_id=None)
    new = create_rule(db, finance, scope=CommissionScope.GLOBAL, scope_ref=None, type=PCT, rate_bp=1400)
    db.commit()
    db.refresh(old)
    assert old.valid_to == new.valid_from
    assert resolve_rule(db, category_id=category.id, technician_id=None).id == new.id
    assert resolve_rule(db, category_id=category.id, technician_id=None,
                        at=new.valid_from - timedelta(seconds=1)).id == old.id


def test_regla_programada_a_futuro(db, category, finance):
    later = datetime.now(timezone.utc) + timedelta(days=10)
    create_rule(db, finance, scope=CommissionScope.CATEGORY, scope_ref=str(category.id), type=PCT, rate_bp=1300,
                valid_from=later)
    db.commit()
    assert resolve_rule(db, category_id=category.id, technician_id=None).scope == CommissionScope.GLOBAL
    assert resolve_rule(db, category_id=category.id, technician_id=None,
                        at=later + timedelta(hours=1)).rate_bp == 1300
    with pytest.raises(CommissionError) as exc:          # una regla abierta antes de la programada se traslaparía
        create_rule(db, finance, scope=CommissionScope.CATEGORY, scope_ref=str(category.id), type=PCT,
                    rate_bp=1250)
    assert exc.value.code == "COMMISSION_RULE_OVERLAP"


@pytest.mark.parametrize("kwargs,code", [
    ({"rate_bp": 300}, "COMMISSION_BELOW_PROVIDER_COST"),
    ({"rate_bp": 1500, "max_cents": 2_000}, "COMMISSION_BELOW_PROVIDER_COST"),
    ({"rate_bp": 1500, "fixed_cents": 100}, "COMMISSION_RULE_INVALID"),       # PERCENT con fijo
    ({"rate_bp": 20_000}, "COMMISSION_RULE_INVALID"),
    ({"rate_bp": 1500, "valid_from": datetime(2026, 1, 1, tzinfo=timezone.utc)}, "COMMISSION_RULE_BACKDATED"),
])
def test_reglas_invalidas_se_rechazan(db, finance, kwargs, code):
    with pytest.raises(CommissionError) as exc:
        create_rule(db, finance, scope=CommissionScope.GLOBAL, scope_ref=None, type=PCT, **kwargs)
    assert exc.value.code == code


@pytest.mark.parametrize("scope,ref", [
    (CommissionScope.CATEGORY, "999999"), (CommissionScope.CATEGORY, "plomeria"),
    (CommissionScope.TECHNICIAN, str(uuid.uuid4())), (CommissionScope.TECHNICIAN, "no-es-uuid"),
    (CommissionScope.PROMOTION, "a b"), (CommissionScope.GLOBAL, "algo"), (CommissionScope.CATEGORY, None),
])
def test_referencia_de_la_regla_se_valida(db, finance, scope, ref):
    with pytest.raises(CommissionError) as exc:
        create_rule(db, finance, scope=scope, scope_ref=ref, type=PCT, rate_bp=1500)
    assert exc.value.code == "COMMISSION_RULE_INVALID"


@pytest.mark.parametrize("role", [AdminRole.FINANCE_OPERATOR, AdminRole.FINANCE_VIEWER, AdminRole.SUPERADMIN,
                                  AdminRole.SUPPORT])
def test_solo_finanzas_admin_administra_reglas(db, role):
    actor = Actor.from_user(make_admin(db, f"{role.value.lower()}@example.com", role))
    with pytest.raises(CommissionError) as exc:
        create_rule(db, actor, scope=CommissionScope.GLOBAL, scope_ref=None, type=PCT, rate_bp=1500)
    assert exc.value.http_status == 403


def test_alta_y_cierre_de_reglas_quedan_auditados(db, category, finance):
    rule = create_rule(db, finance, scope=CommissionScope.CATEGORY, scope_ref=str(category.id), type=PCT,
                       rate_bp=1200)
    close_rule(db, finance, rule.id)
    db.commit()
    actions = db.scalars(text("SELECT action FROM audit_logs ORDER BY id")).all()
    assert actions[-2:] == ["finance.commission_rule.created", "finance.commission_rule.closed"]
    assert resolve_rule(db, category_id=category.id, technician_id=None).scope == CommissionScope.GLOBAL
    glob = resolve_rule(db, category_id=category.id, technician_id=None)
    with pytest.raises(CommissionError):
        close_rule(db, finance, glob.id)


def test_reglas_en_la_base_no_se_editan_ni_borran_ni_se_traslapan(db):
    rid = db.scalar(select(CommissionRule.id).where(CommissionRule.scope == CommissionScope.GLOBAL))
    _raises_db(db, "UPDATE commission_rules SET rate_bp = 100 WHERE id = :id", {"id": rid},
               "COMMISSION_RULE_IMMUTABLE")
    _raises_db(db, "DELETE FROM commission_rules WHERE id = :id", {"id": rid}, "COMMISSION_RULE_IMMUTABLE")
    _raises_db(db, "INSERT INTO commission_rules (scope, type, rate_bp, valid_from) "
                   "VALUES ('GLOBAL', 'PERCENT', 1000, '2027-01-01')", {}, "ex_commission_rules_no_overlap")
    db.execute(text("UPDATE commission_rules SET valid_to = '2030-01-01' WHERE id = :id"), {"id": rid})
    db.flush()
    _raises_db(db, "UPDATE commission_rules SET valid_to = NULL WHERE id = :id", {"id": rid},
               "COMMISSION_RULE_IMMUTABLE")


# ------------------------------------------------------------------ desglose congelado
def test_el_pago_conserva_su_regla_aunque_cambie_la_comision(client, db, category, people, finance):
    _, th, _, ch = people
    first = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    create_rule(db, finance, scope=CommissionScope.GLOBAL, scope_ref=None, type=PCT, rate_bp=1000, min_cents=1_000)
    db.commit()
    second = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    assert payment_of(db, first).breakdown.commission_cents == 15_000
    assert payment_of(db, second).breakdown.commission_cents == 10_000
    assert payment_of(db, second).breakdown.technician_cents == 116_000 - 10_000 - 1_600 - 2_500 - 8_000


def test_desglose_no_se_modifica_y_debe_cuadrar_con_el_cobro(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED", price="1000.00")
    p = payment_of(db, oid)
    _raises_db(db, "UPDATE commission_transactions SET commission_cents = 0 WHERE payment_id = :p", {"p": p.id},
               "APPEND_ONLY")
    _raises_db(db, "UPDATE commission_transactions SET technician_cents = technician_cents + 1 "
                   "WHERE payment_id = :p", {"p": p.id}, "APPEND_ONLY")
    # Un desglose que no corresponde a lo cobrado: el trigger lo rechaza.
    other = Payment(service_order_id=p.service_order_id, payer_id=p.payer_id, provider="stripe",
                    kind=PaymentKind.ADJUSTMENT, amount_cents=5_000)
    db.add(other)
    db.flush()
    _raises_db(db, """
        INSERT INTO commission_transactions (payment_id, rule_scope, rate_bp, fixed_cents, service_tax_bp,
            commission_tax_bp, isr_withholding_bp, iva_withholding_bp, technician_has_rfc, price_cents,
            service_tax_cents, gross_cents, commission_cents, commission_tax_cents, withholding_isr_cents,
            withholding_iva_cents, technician_cents)
        VALUES (:p, 'GLOBAL', 0, 0, 0, 0, 0, 0, true, 9000, 0, 9000, 0, 0, 0, 0, 9000)""",
               {"p": other.id}, "COMMISSION_MISMATCH")


def test_un_solo_pago_de_servicio_activo_por_orden(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="SCHEDULED")
    p = payment_of(db, oid)
    db.add(Payment(service_order_id=p.service_order_id, payer_id=p.payer_id, provider="stripe", amount_cents=100))
    with pytest.raises(DBAPIError) as exc:
        db.flush()
    db.rollback()
    assert "uq_payments_active_service" in str(exc.value.orig)


def test_pago_en_la_base_no_retrocede_ni_salta_estados(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    pid = payment_of(db, oid).id
    _raises_db(db, "UPDATE payments SET captured_cents = 0 WHERE id = :id", {"id": pid}, "PAYMENT_IMMUTABLE")
    _raises_db(db, "UPDATE payments SET payer_id = gen_random_uuid() WHERE id = :id", {"id": pid},
               "PAYMENT_IMMUTABLE")
    _raises_db(db, "UPDATE payments SET status = 'AUTHORIZED' WHERE id = :id", {"id": pid},
               "PAYMENT_INVALID_TRANSITION")


# ------------------------------------------------------------------ libro contable
def test_cobro_se_asienta_en_partida_doble(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    p = payment_of(db, oid)
    assert p.capture_deadline is not None and p.capture_deadline > p.authorized_at
    expected = {A.CUSTOMER: -116_000, A.TECHNICIAN_PAYABLE: 88_100, A.PLATFORM_REVENUE: 15_000,
                A.VAT_PAYABLE: 2_400, A.TAX_WITHHELD: 10_500}
    for acct, cents in expected.items():
        assert ledger.balance(db, acct, payment_id=p.id) == cents
    groups = db.execute(select(LedgerEntry.transaction_group_id, func.sum(LedgerEntry.amount_cents))
                        .where(LedgerEntry.payment_id == p.id).group_by(LedgerEntry.transaction_group_id)).all()
    assert len(groups) == 1 and groups[0][1] == 0
    webhook(db, oid, "captured")                         # evento repetido: no se asienta dos veces
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == -116_000


def test_libro_rechaza_asientos_descuadrados_y_ediciones(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    p = payment_of(db, oid)
    with pytest.raises(ledger.LedgerError):
        ledger.post(db, p, "AJUSTE", {A.CUSTOMER: 100, A.PLATFORM_REVENUE: -99})
    # Por SQL directo el trigger diferido lo detecta al confirmar.
    _raises_db(db, "INSERT INTO ledger_entries (transaction_group_id, payment_id, entry_type, account, amount_cents) "
                   "VALUES (gen_random_uuid(), :p, 'AJUSTE', 'PLATFORM_REVENUE', 500)", {"p": p.id},
               "LEDGER_UNBALANCED", commit=True)
    _raises_db(db, "UPDATE ledger_entries SET amount_cents = 1 WHERE payment_id = :p", {"p": p.id}, "APPEND_ONLY")
    _raises_db(db, "DELETE FROM ledger_entries WHERE payment_id = :p", {"p": p.id}, "APPEND_ONLY")


def test_reembolsos_parciales_y_total_en_el_libro(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, price="1000.00")
    webhook(db, oid, "refunded", amount=16_000)
    p = payment_of(db, oid)
    assert p.status == P.PARTIALLY_REFUNDED and p.refunded_cents == 16_000
    assert order_status(db, oid) == "READY_FOR_REVIEW"
    webhook(db, oid, "refunded", amount=500_000)         # excede lo cobrado: se limita a lo pendiente
    p = payment_of(db, oid)
    assert p.status == P.REFUNDED and p.refunded_cents == 116_000
    assert order_status(db, oid) == "REFUNDED"
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == 0
    assert ledger.balance(db, A.REFUNDS, payment_id=p.id) == -116_000
    webhook(db, oid, "refunded", amount=100)             # ya reembolsado: sin efecto
    assert ledger.balance(db, A.REFUNDS, payment_id=p.id) == -116_000


def test_reembolso_de_un_pago_no_cobrado_se_rechaza(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    with pytest.raises(PaymentError):
        payments.mark_refunded(db, payment_of(db, oid), 1_000)
    with pytest.raises(PaymentError):
        payments.mark_refunded(db, payment_of(db, oid), 0)


# ------------------------------------------------------------------ contracargos
def test_contracargo_ganado_y_perdido(client, db, category, people):
    _, th, _, ch = people
    won = run_order(client, db, ch, th, category, price="1000.00")
    p = payment_of(db, won)
    payments.mark_disputed(db, p)
    db.commit()
    assert not payments.get_order_payment_summary(db, p.service_order_id).confirmed
    payments.mark_dispute_closed(db, p, won=True)
    db.commit()
    assert payment_of(db, won).status == P.PAID

    lost = run_order(client, db, ch, th, category, price="1000.00")
    webhook(db, lost, "refunded", amount=6_000)
    p = payment_of(db, lost)
    payments.mark_disputed(db, p)
    payments.mark_dispute_closed(db, p, won=False)
    db.commit()
    db.expire_all()
    p = db.get(Payment, p.id)
    assert p.status == P.CHARGED_BACK
    assert ledger.balance(db, A.CUSTOMER, payment_id=p.id) == 0
    kinds = db.scalars(select(LedgerEntry.entry_type).where(LedgerEntry.payment_id == p.id).distinct()).all()
    assert set(kinds) == {"CAPTURE", "REFUND", "CHARGEBACK"}


def test_disputa_ganada_sobre_pago_con_reembolso_parcial(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category)
    webhook(db, oid, "refunded", amount=1_000)
    p = payment_of(db, oid)
    payments.mark_disputed(db, p)
    payments.mark_dispute_closed(db, p, won=True)
    db.commit()
    assert payment_of(db, oid).status == P.PARTIALLY_REFUNDED
