"""Pagos, Fase 5: reembolsos, captura parcial y contracargos.

- commission_transactions.stage (QUOTE / CAPTURE): la captura parcial guarda su propio desglose,
  recalculado sobre lo cobrado; uno por etapa y pago.
- payment_refunds: reparto de quién absorbe (técnico, comisión, IVA, retenciones, plataforma),
  origen (cliente, finanzas, disputa, fuera de la app), nota, fechas; una sola solicitud abierta
  por pago; trigger de estados e inmutables; sin DELETE.
- payment_disputes: lo recuperado del técnico (D9) y la fecha de envío de la evidencia.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-24 22:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Deben coincidir EXACTAMENTE con app.payments.refunds.ALLOWED_REFUND_TRANSITIONS (lo verifica una prueba).
REFUND_TRANSITIONS = [
    "REQUESTED>APPROVED", "REQUESTED>REJECTED",
    "APPROVED>PENDING", "APPROVED>SUCCEEDED", "APPROVED>FAILED",
    "PENDING>SUCCEEDED", "PENDING>FAILED",
]


def _sql_list(items: list[str]) -> str:
    return ", ".join(f"'{t}'" for t in items)


TRIGGERS_UP = [
    """
    CREATE OR REPLACE FUNCTION commission_transaction_matches_payment() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        charged bigint;
    BEGIN
        SELECT amount_cents INTO charged FROM payments WHERE id = NEW.payment_id;
        IF NEW.stage = 'QUOTE' AND charged IS DISTINCT FROM NEW.gross_cents - NEW.discount_cents THEN
            RAISE EXCEPTION 'COMMISSION_MISMATCH: el desglose (%) no coincide con el cobro (%)',
                NEW.gross_cents - NEW.discount_cents, charged USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.stage = 'CAPTURE' AND NEW.gross_cents - NEW.discount_cents > charged THEN
            RAISE EXCEPTION 'COMMISSION_MISMATCH: la captura (%) excede lo autorizado (%)',
                NEW.gross_cents - NEW.discount_cents, charged USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    f"""
    CREATE FUNCTION payment_refund_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'REFUND_IMMUTABLE: los reembolsos no se borran' USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'REQUESTED' THEN
                RAISE EXCEPTION 'REFUND_INVALID_TRANSITION: estado inicial %', NEW.status
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status
           AND NOT ((OLD.status::text || '>' || NEW.status::text) = ANY (ARRAY[{_sql_list(REFUND_TRANSITIONS)}])) THEN
            RAISE EXCEPTION 'REFUND_INVALID_TRANSITION: % -> %', OLD.status, NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF (NEW.payment_id, NEW.amount_cents, NEW.reason_code, NEW.reverse_transfer, NEW.refund_application_fee,
            NEW.requested_by, NEW.request_source)
           IS DISTINCT FROM
           (OLD.payment_id, OLD.amount_cents, OLD.reason_code, OLD.reverse_transfer, OLD.refund_application_fee,
            OLD.requested_by, OLD.request_source)
           OR (OLD.approved_by IS NOT NULL AND NEW.approved_by IS DISTINCT FROM OLD.approved_by)
           OR (OLD.provider_refund_id IS NOT NULL AND NEW.provider_refund_id IS DISTINCT FROM OLD.provider_refund_id)
        THEN
            RAISE EXCEPTION 'REFUND_IMMUTABLE: monto, motivo, política, solicitante y aprobador no cambian'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_payment_refunds_guard BEFORE INSERT OR UPDATE OR DELETE ON payment_refunds
        FOR EACH ROW EXECUTE FUNCTION payment_refund_guard();
    """,
]


def upgrade() -> None:
    op.add_column('commission_transactions', sa.Column('stage', sa.String(length=10),
                                                       server_default=sa.text("'QUOTE'"), nullable=False))
    op.drop_constraint(op.f('uq_commission_transactions_payment_id'), 'commission_transactions', type_='unique')
    op.create_unique_constraint('uq_commission_transactions_payment_stage', 'commission_transactions',
                                ['payment_id', 'stage'])
    op.create_check_constraint(op.f('ck_commission_transactions_stage_valid'), 'commission_transactions',
                               "stage IN ('QUOTE', 'CAPTURE')")

    for name in ('vat_returned_cents', 'withholding_returned_cents', 'platform_absorbed_cents'):
        op.add_column('payment_refunds', sa.Column(name, sa.BigInteger(), server_default=sa.text('0'), nullable=False))
    op.add_column('payment_refunds', sa.Column('request_source', sa.String(length=20),
                                               server_default=sa.text("'FINANCE'"), nullable=False))
    op.add_column('payment_refunds', sa.Column('note', sa.String(length=500), nullable=True))
    op.add_column('payment_refunds', sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('payment_refunds', sa.Column('succeeded_at', sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(op.f('ck_payment_refunds_allocation_non_negative'), 'payment_refunds',
                               'vat_returned_cents >= 0 AND withholding_returned_cents >= 0 AND platform_absorbed_cents >= 0')
    op.create_check_constraint(op.f('ck_payment_refunds_source_valid'), 'payment_refunds',
                               "request_source IN ('CLIENT', 'FINANCE', 'DISPUTE', 'OUTSIDE_APP')")
    op.create_index('uq_payment_refunds_open', 'payment_refunds', ['payment_id'], unique=True,
                    postgresql_where=sa.text("status IN ('REQUESTED', 'APPROVED', 'PENDING')"))

    op.add_column('payment_disputes', sa.Column('technician_recovered_cents', sa.BigInteger(),
                                                server_default=sa.text('0'), nullable=False))
    op.add_column('payment_disputes', sa.Column('evidence_submitted_at', sa.DateTime(timezone=True), nullable=True))
    for stmt in TRIGGERS_UP:
        op.execute(stmt)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM commission_transactions WHERE stage <> 'QUOTE'")).scalar():
        raise RuntimeError("Hay desgloses de captura parcial: el downgrade los perdería.")
    op.execute("DROP TRIGGER IF EXISTS trg_payment_refunds_guard ON payment_refunds")
    op.execute("DROP FUNCTION IF EXISTS payment_refund_guard()")
    op.execute("""
        CREATE OR REPLACE FUNCTION commission_transaction_matches_payment() RETURNS trigger LANGUAGE plpgsql AS $$
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
    """)
    op.drop_column('payment_disputes', 'evidence_submitted_at')
    op.drop_column('payment_disputes', 'technician_recovered_cents')
    op.drop_index('uq_payment_refunds_open', table_name='payment_refunds')
    op.drop_constraint(op.f('ck_payment_refunds_source_valid'), 'payment_refunds', type_='check')
    op.drop_constraint(op.f('ck_payment_refunds_allocation_non_negative'), 'payment_refunds', type_='check')
    for name in ('succeeded_at', 'executed_at', 'note', 'request_source', 'platform_absorbed_cents',
                 'withholding_returned_cents', 'vat_returned_cents'):
        op.drop_column('payment_refunds', name)
    op.drop_constraint(op.f('ck_commission_transactions_stage_valid'), 'commission_transactions', type_='check')
    op.drop_constraint('uq_commission_transactions_payment_stage', 'commission_transactions', type_='unique')
    op.create_unique_constraint(op.f('uq_commission_transactions_payment_id'), 'commission_transactions',
                                ['payment_id'])
    op.drop_column('commission_transactions', 'stage')
