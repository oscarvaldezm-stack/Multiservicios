"""Pagos, Fase 1: pagos en centavos, reglas de comisión, desglose congelado y libro contable.

- payments: importes en centavos (BIGINT), tipo de pago (SERVICE / ADJUSTMENT /
  CANCELLATION_FEE), pagador, cuenta del técnico, fecha límite de captura, versión.
  Estados del doc de pagos (PAID, REQUIRES_ACTION, PROCESSING, DISPUTED, CHARGED_BACK;
  CAPTURED y RELEASED pasan a PAID, CANCELED a CANCELLED). Un solo pago SERVICE activo
  por orden. El reparto (comisión / técnico) sale de payments y va a commission_transactions.
- Tablas nuevas: commission_rules (sin traslapes por alcance, EXCLUDE con btree_gist),
  commission_transactions, ledger_entries (partida doble), payment_transactions,
  payment_refunds, payment_disputes, payouts, technician_payment_accounts,
  payment_customers, payment_webhook_events, idempotency_keys, cancellation_policies.
- service_categories.commission_rate se convierte en reglas CATEGORY y desaparece.
- Triggers: transiciones e inmutables del pago, reglas de comisión que solo se cierran,
  desglose que cuadra con el pago y no cambia, libro solo inserción y cuadrado por grupo,
  reseñas solo con pago PAID o PARTIALLY_REFUNDED.

Los pagos existentes se convierten (con un desglose LEGACY que conserva su reparto).

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-23 22:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PAYMENT_STATES = ('PENDING', 'REQUIRES_ACTION', 'PROCESSING', 'AUTHORIZED', 'PAID', 'FAILED', 'CANCELLED',
                  'PARTIALLY_REFUNDED', 'REFUNDED', 'DISPUTED', 'CHARGED_BACK')
OLD_PAYMENT_STATES = ('PENDING', 'AUTHORIZED', 'CAPTURED', 'RELEASED', 'PARTIALLY_REFUNDED', 'REFUNDED', 'FAILED',
                      'CANCELED')

# Deben coincidir EXACTAMENTE con app.payments.state_machine.ALLOWED_PAYMENT_TRANSITIONS (lo verifica una prueba).
PAYMENT_TRANSITIONS = [
    "PENDING>REQUIRES_ACTION", "PENDING>PROCESSING", "PENDING>AUTHORIZED", "PENDING>FAILED", "PENDING>CANCELLED",
    "REQUIRES_ACTION>PENDING", "REQUIRES_ACTION>PROCESSING", "REQUIRES_ACTION>AUTHORIZED", "REQUIRES_ACTION>FAILED",
    "REQUIRES_ACTION>CANCELLED", "PROCESSING>AUTHORIZED", "PROCESSING>FAILED", "AUTHORIZED>PAID",
    "AUTHORIZED>CANCELLED", "AUTHORIZED>FAILED", "PAID>PARTIALLY_REFUNDED", "PAID>REFUNDED", "PAID>DISPUTED",
    "PARTIALLY_REFUNDED>REFUNDED", "PARTIALLY_REFUNDED>DISPUTED", "DISPUTED>PAID", "DISPUTED>PARTIALLY_REFUNDED",
    "DISPUTED>CHARGED_BACK",
]

payment_status = postgresql.ENUM(*PAYMENT_STATES, name='payment_status', create_type=False)
payment_kind = postgresql.ENUM('SERVICE', 'ADJUSTMENT', 'CANCELLATION_FEE', name='payment_kind', create_type=False)
commission_scope = postgresql.ENUM('PROMOTION', 'TECHNICIAN', 'CATEGORY', 'GLOBAL', name='commission_scope',
                                   create_type=False)
commission_type = postgresql.ENUM('PERCENT', 'FIXED', 'PERCENT_PLUS_FIXED', name='commission_type',
                                  create_type=False)
ledger_account = postgresql.ENUM('CUSTOMER', 'TECHNICIAN_PAYABLE', 'PLATFORM_REVENUE', 'VAT_PAYABLE',
                                 'TAX_WITHHELD', 'PROVIDER_FEES', 'REFUNDS', name='ledger_account', create_type=False)
payment_transaction_type = postgresql.ENUM('AUTHORIZATION', 'CAPTURE', 'CANCEL', 'REFUND', 'TRANSFER_REVERSAL',
                                           name='payment_transaction_type', create_type=False)
payment_account_status = postgresql.ENUM('NOT_CREATED', 'ONBOARDING', 'PENDING_VERIFICATION', 'ENABLED',
                                         'RESTRICTED', 'DISABLED', name='payment_account_status', create_type=False)
refund_status = postgresql.ENUM('REQUESTED', 'APPROVED', 'PENDING', 'SUCCEEDED', 'FAILED', 'REJECTED',
                                name='refund_status', create_type=False)
dispute_status = postgresql.ENUM('NEEDS_RESPONSE', 'UNDER_REVIEW', 'WON', 'LOST', name='dispute_status',
                                 create_type=False)
payout_status = postgresql.ENUM('PENDING', 'IN_TRANSIT', 'PAID', 'FAILED', 'CANCELED', name='payout_status',
                                create_type=False)
webhook_event_status = postgresql.ENUM('PENDING', 'PROCESSED', 'IGNORED', 'FAILED', 'DEAD',
                                       name='webhook_event_status', create_type=False)
NEW_ENUMS = (payment_kind, commission_scope, commission_type, ledger_account, payment_transaction_type,
             payment_account_status, refund_status, dispute_status, payout_status, webhook_event_status)

# Regla global inicial (decisión D6: tasas configurables; se cambia creando otra regla desde el panel).
GLOBAL_RATE_BP = 1500
GLOBAL_MIN_CENTS = 1000


def _sql_list(items: list[str]) -> str:
    return ", ".join(f"'{t}'" for t in items)


TRIGGERS_UP = [
    # 1. Transiciones del pago e inmutables
    f"""
    CREATE FUNCTION payment_enforce_transition() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'PENDING' THEN
                RAISE EXCEPTION 'PAYMENT_INVALID_INITIAL_STATUS: %', NEW.status USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status
           AND NOT ((OLD.status::text || '>' || NEW.status::text) = ANY (ARRAY[{_sql_list(PAYMENT_TRANSITIONS)}])) THEN
            RAISE EXCEPTION 'PAYMENT_INVALID_TRANSITION: % -> %', OLD.status, NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.service_order_id IS DISTINCT FROM OLD.service_order_id
           OR NEW.payer_id IS DISTINCT FROM OLD.payer_id
           OR NEW.kind IS DISTINCT FROM OLD.kind
           OR NEW.amount_cents IS DISTINCT FROM OLD.amount_cents
           OR NEW.currency IS DISTINCT FROM OLD.currency
           OR NEW.provider IS DISTINCT FROM OLD.provider THEN
            RAISE EXCEPTION 'PAYMENT_IMMUTABLE: orden, pagador, tipo, monto, moneda y proveedor no cambian'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.captured_cents < OLD.captured_cents OR NEW.refunded_cents < OLD.refunded_cents THEN
            RAISE EXCEPTION 'PAYMENT_IMMUTABLE: lo capturado y lo reembolsado solo crecen'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_payments_transition BEFORE INSERT OR UPDATE ON payments
        FOR EACH ROW EXECUTE FUNCTION payment_enforce_transition();
    """,
    # 2. Reseñas: solo con el pago SERVICE confirmado (PAID o PARTIALLY_REFUNDED).
    """
    CREATE OR REPLACE FUNCTION review_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        o record;
    BEGIN
        SELECT client_id, technician_id, status INTO o FROM service_orders
         WHERE id = NEW.service_order_id FOR UPDATE;
        IF NOT FOUND OR o.client_id <> NEW.client_id OR o.technician_id IS DISTINCT FROM NEW.technician_id THEN
            RAISE EXCEPTION 'REVIEW_ORDER_MISMATCH: la reseña no corresponde a la orden' USING ERRCODE = 'check_violation';
        END IF;
        IF o.status <> 'READY_FOR_REVIEW' THEN
            RAISE EXCEPTION 'REVIEW_NOT_ELIGIBLE: la orden está en %', o.status USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1 FROM payments p WHERE p.service_order_id = NEW.service_order_id AND p.kind = 'SERVICE'
           AND p.status IN ('PAID', 'PARTIALLY_REFUNDED');
        IF NOT FOUND THEN
            RAISE EXCEPTION 'REVIEW_PAYMENT_NOT_CONFIRMED: el pago no está confirmado' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    # 3. Reglas de comisión: no se borran; lo único que cambia es valid_to (cerrarla).
    """
    CREATE FUNCTION commission_rule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'COMMISSION_RULE_IMMUTABLE: las reglas no se borran, se cierran'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF (NEW.scope, NEW.scope_ref, NEW.type, NEW.rate_bp, NEW.fixed_cents, NEW.min_cents, NEW.max_cents,
            NEW.valid_from, NEW.note, NEW.created_by, NEW.created_at)
           IS DISTINCT FROM
           (OLD.scope, OLD.scope_ref, OLD.type, OLD.rate_bp, OLD.fixed_cents, OLD.min_cents, OLD.max_cents,
            OLD.valid_from, OLD.note, OLD.created_by, OLD.created_at) THEN
            RAISE EXCEPTION 'COMMISSION_RULE_IMMUTABLE: solo se puede cerrar una regla (valid_to)'
                USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.valid_to IS NOT NULL AND (NEW.valid_to IS NULL OR NEW.valid_to > OLD.valid_to) THEN
            RAISE EXCEPTION 'COMMISSION_RULE_IMMUTABLE: una regla cerrada no se reabre ni se alarga'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_commission_rules_guard BEFORE UPDATE OR DELETE ON commission_rules
        FOR EACH ROW EXECUTE FUNCTION commission_rule_guard();
    """,
    # 4. El desglose debe corresponder a lo que se cobra y no cambia.
    """
    CREATE FUNCTION commission_transaction_matches_payment() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        charged bigint;
    BEGIN
        SELECT amount_cents INTO charged FROM payments WHERE id = NEW.payment_id;
        IF charged IS DISTINCT FROM NEW.gross_cents - NEW.discount_cents THEN
            RAISE EXCEPTION 'COMMISSION_MISMATCH: el desglose (%) no coincide con el cobro (%)',
                NEW.gross_cents - NEW.discount_cents, charged USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_commission_transactions_matches BEFORE INSERT ON commission_transactions
        FOR EACH ROW EXECUTE FUNCTION commission_transaction_matches_payment();
    """,
    """
    CREATE TRIGGER trg_commission_transactions_append_only BEFORE UPDATE OR DELETE ON commission_transactions
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
    # 5. Libro contable: solo inserción y cada grupo cuadra en cero al confirmar la transacción.
    """
    CREATE TRIGGER trg_ledger_entries_append_only BEFORE UPDATE OR DELETE ON ledger_entries
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
    """
    CREATE FUNCTION ledger_group_balanced() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        total bigint;
    BEGIN
        SELECT sum(amount_cents) INTO total FROM ledger_entries
         WHERE transaction_group_id = NEW.transaction_group_id;
        IF total <> 0 THEN
            RAISE EXCEPTION 'LEDGER_UNBALANCED: el grupo % suma % centavos', NEW.transaction_group_id, total
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
    END $$;
    """,
    """
    CREATE CONSTRAINT TRIGGER trg_ledger_entries_balanced AFTER INSERT ON ledger_entries
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_group_balanced();
    """,
    """
    CREATE TRIGGER trg_payment_transactions_append_only BEFORE UPDATE OR DELETE ON payment_transactions
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
]

TRIGGERS_DOWN = [
    "DROP TRIGGER IF EXISTS trg_payment_transactions_append_only ON payment_transactions",
    "DROP TRIGGER IF EXISTS trg_ledger_entries_balanced ON ledger_entries",
    "DROP FUNCTION IF EXISTS ledger_group_balanced()",
    "DROP TRIGGER IF EXISTS trg_ledger_entries_append_only ON ledger_entries",
    "DROP TRIGGER IF EXISTS trg_commission_transactions_append_only ON commission_transactions",
    "DROP TRIGGER IF EXISTS trg_commission_transactions_matches ON commission_transactions",
    "DROP FUNCTION IF EXISTS commission_transaction_matches_payment()",
    "DROP TRIGGER IF EXISTS trg_commission_rules_guard ON commission_rules",
    "DROP FUNCTION IF EXISTS commission_rule_guard()",
    "DROP TRIGGER IF EXISTS trg_payments_transition ON payments",
    "DROP FUNCTION IF EXISTS payment_enforce_transition()",
]


def upgrade() -> None:
    bind = op.get_bind()
    # btree_gist es una extensión "trusted": la puede instalar el dueño de la base sin superusuario.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
    op.execute("DROP TRIGGER IF EXISTS trg_payments_transition ON payments")
    op.execute("DROP FUNCTION IF EXISTS payment_enforce_transition()")
    for e in NEW_ENUMS:
        e.create(bind)

    # ------------------------------------------------------------------ cuentas del técnico (FK de payments)
    op.create_table('technician_payment_accounts',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=30), nullable=False),
    sa.Column('provider_account_id', sa.String(length=120), nullable=True),
    sa.Column('status', payment_account_status, server_default='NOT_CREATED', nullable=False),
    sa.Column('transfers_active', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('payouts_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('requirements_due', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('name_matches_kyc', sa.Boolean(), nullable=True),
    sa.Column('blocked_reason', sa.String(length=60), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status = 'NOT_CREATED' OR provider_account_id IS NOT NULL", name=op.f('ck_technician_payment_accounts_account_id_when_created')),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_technician_payment_accounts_technician_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_technician_payment_accounts')),
    sa.UniqueConstraint('provider_account_id', name=op.f('uq_technician_payment_accounts_provider_account_id')),
    sa.UniqueConstraint('technician_id', 'provider', name='uq_technician_payment_accounts_technician_provider')
    )
    op.create_index(op.f('ix_technician_payment_accounts_technician_id'), 'technician_payment_accounts', ['technician_id'], unique=False)

    # ------------------------------------------------------------------ payments: estados
    op.drop_index('uq_payments_active_order', table_name='payments')
    op.execute("ALTER TABLE payments ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TYPE payment_status RENAME TO payment_status_v2")
    postgresql.ENUM(*PAYMENT_STATES, name='payment_status').create(bind)
    op.execute("""
        ALTER TABLE payments ALTER COLUMN status TYPE payment_status USING (CASE status::text
            WHEN 'CAPTURED' THEN 'PAID' WHEN 'RELEASED' THEN 'PAID' WHEN 'CANCELED' THEN 'CANCELLED'
            ELSE status::text END)::payment_status
    """)
    op.execute("ALTER TABLE payments ALTER COLUMN status SET DEFAULT 'PENDING'")
    op.execute("DROP TYPE payment_status_v2")

    # ------------------------------------------------------------------ payments: centavos y columnas nuevas
    op.add_column('payments', sa.Column('payer_id', sa.Uuid(), nullable=True))
    op.add_column('payments', sa.Column('technician_account_id', sa.Uuid(), nullable=True))
    op.add_column('payments', sa.Column('kind', payment_kind, server_default='SERVICE', nullable=False))
    op.add_column('payments', sa.Column('amount_cents', sa.BigInteger(), nullable=True))
    op.add_column('payments', sa.Column('captured_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False))
    op.add_column('payments', sa.Column('refunded_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False))
    op.add_column('payments', sa.Column('capture_deadline', sa.DateTime(timezone=True), nullable=True))
    op.add_column('payments', sa.Column('cancelled_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('payments', sa.Column('version', sa.Integer(), server_default=sa.text('1'), nullable=False))
    op.execute("""
        UPDATE payments p SET payer_id = o.client_id,
               amount_cents = round(p.amount * 100)::bigint,
               captured_cents = CASE WHEN p.status IN ('PAID', 'PARTIALLY_REFUNDED', 'REFUNDED')
                                     THEN round(p.amount * 100)::bigint ELSE 0 END,
               refunded_cents = round(p.amount_refunded * 100)::bigint
          FROM service_orders o WHERE o.id = p.service_order_id
    """)
    op.alter_column('payments', 'payer_id', nullable=False)
    op.alter_column('payments', 'amount_cents', nullable=False)

    # ------------------------------------------------------------------ reglas y desglose
    op.create_table('commission_rules',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('scope', commission_scope, nullable=False),
    sa.Column('scope_ref', sa.String(length=64), nullable=True),
    sa.Column('type', commission_type, nullable=False),
    sa.Column('rate_bp', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('fixed_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('min_cents', sa.BigInteger(), nullable=True),
    sa.Column('max_cents', sa.BigInteger(), nullable=True),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_to', sa.DateTime(timezone=True), nullable=True),
    sa.Column('note', sa.String(length=200), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(scope = 'GLOBAL') = (scope_ref IS NULL)", name=op.f('ck_commission_rules_scope_ref_matches_scope')),
    sa.CheckConstraint("(type = 'PERCENT' AND fixed_cents = 0) OR (type = 'FIXED' AND rate_bp = 0) OR type = 'PERCENT_PLUS_FIXED'", name=op.f('ck_commission_rules_type_matches_values')),
    sa.CheckConstraint('fixed_cents >= 0', name=op.f('ck_commission_rules_fixed_non_negative')),
    sa.CheckConstraint('max_cents IS NULL OR max_cents >= coalesce(min_cents, 0)', name=op.f('ck_commission_rules_max_at_least_min')),
    sa.CheckConstraint('min_cents IS NULL OR min_cents >= 0', name=op.f('ck_commission_rules_min_non_negative')),
    sa.CheckConstraint('rate_bp >= 0 AND rate_bp <= 10000', name=op.f('ck_commission_rules_rate_bp_range')),
    sa.CheckConstraint('valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_commission_rules_valid_range')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_commission_rules_created_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_commission_rules'))
    )
    op.execute("""
        ALTER TABLE commission_rules ADD CONSTRAINT ex_commission_rules_no_overlap
            EXCLUDE USING gist (scope WITH =, (coalesce(scope_ref, '')) WITH =,
                                tstzrange(valid_from, valid_to) WITH &&)
    """)
    op.execute(f"""
        INSERT INTO commission_rules (scope, type, rate_bp, min_cents, valid_from, note)
        VALUES ('GLOBAL', 'PERCENT', {GLOBAL_RATE_BP}, {GLOBAL_MIN_CENTS}, '2026-01-01T00:00:00Z',
                'Regla global inicial (migración 0006)')
    """)
    op.execute(f"""
        INSERT INTO commission_rules (scope, scope_ref, type, rate_bp, valid_from, note)
        SELECT 'CATEGORY', id::text, 'PERCENT', round(commission_rate * 10000)::int, '2026-01-01T00:00:00Z',
               'Migrada de service_categories.commission_rate'
          FROM service_categories WHERE round(commission_rate * 10000)::int <> {GLOBAL_RATE_BP}
    """)
    op.drop_constraint(op.f('ck_service_categories_commission_rate_range'), 'service_categories', type_='check')
    op.drop_column('service_categories', 'commission_rate')

    op.create_table('commission_transactions',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('rule_id', sa.BigInteger(), nullable=True),
    sa.Column('rule_scope', sa.String(length=20), nullable=False),
    sa.Column('rule_type', sa.String(length=20), nullable=True),
    sa.Column('rate_bp', sa.Integer(), nullable=False),
    sa.Column('fixed_cents', sa.BigInteger(), nullable=False),
    sa.Column('min_cents', sa.BigInteger(), nullable=True),
    sa.Column('max_cents', sa.BigInteger(), nullable=True),
    sa.Column('service_tax_bp', sa.Integer(), nullable=False),
    sa.Column('commission_tax_bp', sa.Integer(), nullable=False),
    sa.Column('isr_withholding_bp', sa.Integer(), nullable=False),
    sa.Column('iva_withholding_bp', sa.Integer(), nullable=False),
    sa.Column('technician_has_rfc', sa.Boolean(), nullable=False),
    sa.Column('price_cents', sa.BigInteger(), nullable=False),
    sa.Column('service_tax_cents', sa.BigInteger(), nullable=False),
    sa.Column('gross_cents', sa.BigInteger(), nullable=False),
    sa.Column('discount_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('commission_cents', sa.BigInteger(), nullable=False),
    sa.Column('commission_tax_cents', sa.BigInteger(), nullable=False),
    sa.Column('withholding_isr_cents', sa.BigInteger(), nullable=False),
    sa.Column('withholding_iva_cents', sa.BigInteger(), nullable=False),
    sa.Column('technician_cents', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('discount_cents < gross_cents', name=op.f('ck_commission_transactions_discount_below_gross')),
    sa.CheckConstraint('gross_cents = price_cents + service_tax_cents', name=op.f('ck_commission_transactions_gross_is_price_plus_tax')),
    sa.CheckConstraint('price_cents > 0 AND service_tax_cents >= 0 AND discount_cents >= 0 AND commission_cents >= 0 AND commission_tax_cents >= 0 AND withholding_isr_cents >= 0 AND withholding_iva_cents >= 0 AND technician_cents >= 0', name=op.f('ck_commission_transactions_amounts_non_negative')),
    sa.CheckConstraint('technician_cents + commission_cents + commission_tax_cents + withholding_isr_cents + withholding_iva_cents = gross_cents - discount_cents', name=op.f('ck_commission_transactions_split_adds_up')),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_commission_transactions_payment_id_payments'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['rule_id'], ['commission_rules.id'], name=op.f('fk_commission_transactions_rule_id_commission_rules'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_commission_transactions')),
    sa.UniqueConstraint('payment_id', name=op.f('uq_commission_transactions_payment_id'))
    )
    # Pagos anteriores: conservan su reparto como desglose LEGACY (sin IVA ni retenciones).
    op.execute("""
        INSERT INTO commission_transactions (payment_id, rule_scope, rate_bp, fixed_cents, service_tax_bp,
            commission_tax_bp, isr_withholding_bp, iva_withholding_bp, technician_has_rfc, price_cents,
            service_tax_cents, gross_cents, discount_cents, commission_cents, commission_tax_cents,
            withholding_isr_cents, withholding_iva_cents, technician_cents, created_at)
        SELECT id, 'LEGACY', 0, 0, 0, 0, 0, 0, true, amount_cents, 0, amount_cents, 0,
               amount_cents - round(technician_payout * 100)::bigint, 0, 0, 0,
               round(technician_payout * 100)::bigint, created_at
          FROM payments
    """)

    # ------------------------------------------------------------------ payments: fuera lo viejo
    for ck in ('ck_payments_amount_positive', 'ck_payments_split_matches_amount', 'ck_payments_split_non_negative',
               'ck_payments_refund_within_amount'):
        op.drop_constraint(op.f(ck), 'payments', type_='check')
    for c in ('amount', 'platform_fee', 'technician_payout', 'amount_refunded', 'released_at'):
        op.drop_column('payments', c)
    op.create_check_constraint(op.f('ck_payments_amount_positive'), 'payments', 'amount_cents > 0')
    op.create_check_constraint(op.f('ck_payments_captured_within_amount'), 'payments',
                               'captured_cents >= 0 AND captured_cents <= amount_cents')
    op.create_check_constraint(op.f('ck_payments_refunded_within_captured'), 'payments',
                               'refunded_cents >= 0 AND refunded_cents <= captured_cents')
    op.create_check_constraint(op.f('ck_payments_version_positive'), 'payments', 'version >= 1')
    op.create_foreign_key(op.f('fk_payments_payer_id_users'), 'payments', 'users', ['payer_id'], ['id'],
                          ondelete='RESTRICT')
    op.create_foreign_key(op.f('fk_payments_technician_account_id_technician_payment_accounts'), 'payments',
                          'technician_payment_accounts', ['technician_account_id'], ['id'], ondelete='RESTRICT')
    op.create_index(op.f('ix_payments_payer_id'), 'payments', ['payer_id'], unique=False)
    op.create_index(op.f('ix_payments_technician_account_id'), 'payments', ['technician_account_id'], unique=False)
    op.create_index('uq_payments_active_service', 'payments', ['service_order_id'], unique=True,
                    postgresql_where=sa.text("kind = 'SERVICE' AND status NOT IN ('CANCELLED', 'FAILED')"))

    # ------------------------------------------------------------------ libro contable e historial
    op.create_table('ledger_entries',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('transaction_group_id', sa.Uuid(), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('entry_type', sa.String(length=40), nullable=False),
    sa.Column('account', ledger_account, nullable=False),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), server_default=sa.text("'MXN'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name=op.f('ck_ledger_entries_currency_iso4217')),
    sa.CheckConstraint('amount_cents <> 0', name=op.f('ck_ledger_entries_amount_not_zero')),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_ledger_entries_payment_id_payments'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ledger_entries'))
    )
    op.create_index('ix_ledger_entries_account_created', 'ledger_entries', ['account', 'created_at'], unique=False)
    op.create_index(op.f('ix_ledger_entries_payment_id'), 'ledger_entries', ['payment_id'], unique=False)
    op.create_index(op.f('ix_ledger_entries_transaction_group_id'), 'ledger_entries', ['transaction_group_id'], unique=False)

    op.create_table('payment_transactions',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('type', payment_transaction_type, nullable=False),
    sa.Column('provider_object_id', sa.String(length=120), nullable=True),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('failure_code', sa.String(length=60), nullable=True),
    sa.Column('raw_status', sa.String(length=60), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('amount_cents >= 0', name=op.f('ck_payment_transactions_amount_non_negative')),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_payment_transactions_payment_id_payments'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payment_transactions')),
    sa.UniqueConstraint('type', 'provider_object_id', name='uq_payment_transactions_type_object')
    )
    op.create_index(op.f('ix_payment_transactions_payment_id'), 'payment_transactions', ['payment_id'], unique=False)

    # ------------------------------------------------------------------ reembolsos, disputas, depósitos
    op.create_table('payment_refunds',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('provider_refund_id', sa.String(length=120), nullable=True),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('reason_code', sa.String(length=40), nullable=False),
    sa.Column('reverse_transfer', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('refund_application_fee', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('technician_recovered_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('commission_returned_cents', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('status', refund_status, server_default='REQUESTED', nullable=False),
    sa.Column('failure_code', sa.String(length=60), nullable=True),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('approved_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('NOT refund_application_fee OR reverse_transfer', name=op.f('ck_payment_refunds_fee_refund_needs_reversal')),
    sa.CheckConstraint('amount_cents > 0', name=op.f('ck_payment_refunds_amount_positive')),
    sa.CheckConstraint('approved_by IS NULL OR approved_by <> requested_by', name=op.f('ck_payment_refunds_four_eyes')),
    sa.CheckConstraint('technician_recovered_cents >= 0 AND commission_returned_cents >= 0', name=op.f('ck_payment_refunds_split_non_negative')),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name=op.f('fk_payment_refunds_approved_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_payment_refunds_payment_id_payments'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_payment_refunds_requested_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payment_refunds')),
    sa.UniqueConstraint('provider_refund_id', name=op.f('uq_payment_refunds_provider_refund_id'))
    )
    op.create_index(op.f('ix_payment_refunds_payment_id'), 'payment_refunds', ['payment_id'], unique=False)

    op.create_table('payment_disputes',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('provider_dispute_id', sa.String(length=120), nullable=False),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('reason', sa.String(length=60), nullable=True),
    sa.Column('status', dispute_status, server_default='NEEDS_RESPONSE', nullable=False),
    sa.Column('evidence_due_by', sa.DateTime(timezone=True), nullable=True),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('transfer_reversal_id', sa.String(length=120), nullable=True),
    sa.Column('opened_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('amount_cents > 0', name=op.f('ck_payment_disputes_amount_positive')),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_payment_disputes_payment_id_payments'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payment_disputes')),
    sa.UniqueConstraint('provider_dispute_id', name=op.f('uq_payment_disputes_provider_dispute_id'))
    )
    op.create_index('ix_payment_disputes_inbox', 'payment_disputes', ['status', 'evidence_due_by'], unique=False)
    op.create_index(op.f('ix_payment_disputes_payment_id'), 'payment_disputes', ['payment_id'], unique=False)

    op.create_table('payouts',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('technician_account_id', sa.Uuid(), nullable=False),
    sa.Column('provider_payout_id', sa.String(length=120), nullable=False),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), server_default=sa.text("'MXN'"), nullable=False),
    sa.Column('status', payout_status, server_default='PENDING', nullable=False),
    sa.Column('arrival_date', sa.Date(), nullable=True),
    sa.Column('failure_code', sa.String(length=60), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name=op.f('ck_payouts_currency_iso4217')),
    sa.CheckConstraint('amount_cents > 0', name=op.f('ck_payouts_amount_positive')),
    sa.ForeignKeyConstraint(['technician_account_id'], ['technician_payment_accounts.id'], name=op.f('fk_payouts_technician_account_id_technician_payment_accounts'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payouts')),
    sa.UniqueConstraint('provider_payout_id', name=op.f('uq_payouts_provider_payout_id'))
    )
    op.create_index(op.f('ix_payouts_technician_account_id'), 'payouts', ['technician_account_id'], unique=False)

    # ------------------------------------------------------------------ clientes, webhooks, idempotencia, políticas
    op.create_table('payment_customers',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=30), nullable=False),
    sa.Column('provider_customer_id', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_payment_customers_user_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('user_id', 'provider', name=op.f('pk_payment_customers')),
    sa.UniqueConstraint('provider_customer_id', name=op.f('uq_payment_customers_provider_customer_id'))
    )

    op.create_table('payment_webhook_events',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('provider', sa.String(length=30), nullable=False),
    sa.Column('provider_event_id', sa.String(length=120), nullable=False),
    sa.Column('type', sa.String(length=80), nullable=False),
    sa.Column('account_id', sa.String(length=120), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('signature_valid', sa.Boolean(), nullable=False),
    sa.Column('status', webhook_event_status, server_default='PENDING', nullable=False),
    sa.Column('attempts', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('last_error', sa.String(length=500), nullable=True),
    sa.Column('received_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payment_webhook_events')),
    sa.UniqueConstraint('provider', 'provider_event_id', name='uq_payment_webhook_events_provider_event')
    )
    op.create_index('ix_payment_webhook_events_pending', 'payment_webhook_events', ['next_attempt_at'], unique=False,
                    postgresql_where=sa.text("status IN ('PENDING', 'FAILED')"))

    op.create_table('idempotency_keys',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('key', sa.String(length=100), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('endpoint', sa.String(length=120), nullable=False),
    sa.Column('request_hash', sa.String(length=64), nullable=False),
    sa.Column('response_code', sa.Integer(), nullable=True),
    sa.Column('response_body', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_idempotency_keys_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_idempotency_keys')),
    sa.UniqueConstraint('user_id', 'endpoint', 'key', name='uq_idempotency_keys_user_endpoint_key')
    )
    op.create_index('ix_idempotency_keys_expires_at', 'idempotency_keys', ['expires_at'], unique=False)

    op.create_table('cancellation_policies',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('scenario', sa.String(length=40), nullable=False),
    sa.Column('fee_type', sa.String(length=10), nullable=False),
    sa.Column('fee_value', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('technician_share_bp', sa.Integer(), nullable=False),
    sa.Column('platform_share_bp', sa.Integer(), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_to', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("fee_type <> 'PERCENT' OR fee_value <= 10000", name=op.f('ck_cancellation_policies_percent_fee_range')),
    sa.CheckConstraint("fee_type IN ('NONE', 'FIXED', 'PERCENT')", name=op.f('ck_cancellation_policies_fee_type_valid')),
    sa.CheckConstraint('fee_value >= 0', name=op.f('ck_cancellation_policies_fee_value_non_negative')),
    sa.CheckConstraint('technician_share_bp >= 0 AND platform_share_bp >= 0 AND technician_share_bp + platform_share_bp = 10000', name=op.f('ck_cancellation_policies_shares_add_up')),
    sa.CheckConstraint('valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_cancellation_policies_valid_range')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_cancellation_policies_created_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cancellation_policies'))
    )
    op.execute("""
        ALTER TABLE cancellation_policies ADD CONSTRAINT ex_cancellation_policies_no_overlap
            EXCLUDE USING gist (scenario WITH =, tstzrange(valid_from, valid_to) WITH &&)
    """)

    for stmt in TRIGGERS_UP:
        op.execute(stmt)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM payments")).scalar():
        raise RuntimeError("payments tiene datos: el downgrade perdería el desglose. Respáldalos y vacía la tabla.")
    for stmt in TRIGGERS_DOWN:
        op.execute(stmt)
    for t in ("cancellation_policies", "idempotency_keys", "payment_webhook_events", "payment_customers", "payouts",
              "payment_disputes", "payment_refunds", "payment_transactions", "ledger_entries",
              "commission_transactions"):
        op.drop_table(t)

    # service_categories.commission_rate vuelve con lo que diga la regla CATEGORY vigente (o 15 %).
    op.add_column('service_categories', sa.Column('commission_rate', sa.Numeric(precision=5, scale=4),
                                                  server_default=sa.text('0.15'), nullable=False))
    op.execute("""
        UPDATE service_categories c SET commission_rate = r.rate_bp / 10000.0
          FROM commission_rules r
         WHERE r.scope = 'CATEGORY' AND r.scope_ref = c.id::text AND r.type = 'PERCENT'
           AND r.valid_from <= now() AND (r.valid_to IS NULL OR r.valid_to > now())
    """)
    op.create_check_constraint(op.f('ck_service_categories_commission_rate_range'), 'service_categories',
                               'commission_rate >= 0 AND commission_rate < 1')
    op.drop_table('commission_rules')

    # payments vuelve a la forma de 0005 (vacía)
    op.drop_index('uq_payments_active_service', table_name='payments')
    op.drop_index(op.f('ix_payments_technician_account_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_payer_id'), table_name='payments')
    op.drop_constraint(op.f('fk_payments_technician_account_id_technician_payment_accounts'), 'payments',
                       type_='foreignkey')
    op.drop_constraint(op.f('fk_payments_payer_id_users'), 'payments', type_='foreignkey')
    for ck in ('ck_payments_amount_positive', 'ck_payments_captured_within_amount',
               'ck_payments_refunded_within_captured', 'ck_payments_version_positive'):
        op.drop_constraint(op.f(ck), 'payments', type_='check')
    for c in ('payer_id', 'technician_account_id', 'kind', 'amount_cents', 'captured_cents', 'refunded_cents',
              'capture_deadline', 'cancelled_at', 'version'):
        op.drop_column('payments', c)
    op.add_column('payments', sa.Column('amount', sa.Numeric(precision=10, scale=2), nullable=False))
    op.add_column('payments', sa.Column('platform_fee', sa.Numeric(precision=10, scale=2), nullable=False))
    op.add_column('payments', sa.Column('technician_payout', sa.Numeric(precision=10, scale=2), nullable=False))
    op.add_column('payments', sa.Column('amount_refunded', sa.Numeric(precision=10, scale=2),
                                        server_default=sa.text('0'), nullable=False))
    op.add_column('payments', sa.Column('released_at', sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(op.f('ck_payments_amount_positive'), 'payments', 'amount > 0')
    op.create_check_constraint(op.f('ck_payments_split_matches_amount'), 'payments',
                               'platform_fee + technician_payout = amount')
    op.create_check_constraint(op.f('ck_payments_split_non_negative'), 'payments',
                               'platform_fee >= 0 AND technician_payout >= 0')
    op.create_check_constraint('refund_within_amount', 'payments', 'amount_refunded >= 0 AND amount_refunded <= amount')
    op.execute("ALTER TABLE payments ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TYPE payment_status RENAME TO payment_status_v3")
    postgresql.ENUM(*OLD_PAYMENT_STATES, name='payment_status').create(bind)
    op.execute("ALTER TABLE payments ALTER COLUMN status TYPE payment_status USING 'PENDING'::payment_status")
    op.execute("ALTER TABLE payments ALTER COLUMN status SET DEFAULT 'PENDING'")
    op.execute("DROP TYPE payment_status_v3")
    op.create_index('uq_payments_active_order', 'payments', ['service_order_id'], unique=True,
                    postgresql_where=sa.text("status NOT IN ('CANCELED', 'FAILED')"))
    op.drop_table('technician_payment_accounts')
    for e in NEW_ENUMS:
        e.drop(bind)

    # Triggers de 0005 sobre pagos y la versión anterior de review_insert_guard.
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "m0005", Path(__file__).with_name("0005_ordenes_resenas_y_decisiones_kyc.py"))
    m0005 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m0005)
    for stmt in m0005.TRIGGERS_UP:
        if "payment_enforce_transition" in stmt:
            op.execute(stmt)
        elif "CREATE FUNCTION review_insert_guard" in stmt:
            op.execute(stmt.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
