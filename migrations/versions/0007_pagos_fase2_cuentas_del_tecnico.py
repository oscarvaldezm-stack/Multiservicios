"""Pagos, Fase 2: cuenta de pagos del técnico (estado del proveedor, bloqueo de la plataforma).

- technician_payment_accounts: details_submitted, provider_disabled_reason, enabled_at,
  last_synced_at, version.
- Trigger: solo nace en NOT_CREATED, transiciones permitidas, técnico y proveedor inmutables,
  el id de la cuenta en el proveedor no cambia una vez asignado, y la fila no se borra.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-24 10:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Deben coincidir EXACTAMENTE con app.payments.accounts.ALLOWED_ACCOUNT_TRANSITIONS (lo verifica una prueba).
ACCOUNT_TRANSITIONS = [
    "NOT_CREATED>ONBOARDING",
    "ONBOARDING>PENDING_VERIFICATION", "ONBOARDING>ENABLED", "ONBOARDING>DISABLED",
    "PENDING_VERIFICATION>ENABLED", "PENDING_VERIFICATION>ONBOARDING", "PENDING_VERIFICATION>DISABLED",
    "ENABLED>RESTRICTED", "ENABLED>DISABLED",
    "RESTRICTED>ENABLED", "RESTRICTED>DISABLED",
]


def _sql_list(items: list[str]) -> str:
    return ", ".join(f"'{t}'" for t in items)


TRIGGERS_UP = [
    f"""
    CREATE FUNCTION payment_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'PAYMENT_ACCOUNT_IMMUTABLE: la cuenta de pagos no se borra, se bloquea'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'NOT_CREATED' THEN
                RAISE EXCEPTION 'PAYMENT_ACCOUNT_INVALID_TRANSITION: estado inicial %', NEW.status
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status
           AND NOT ((OLD.status::text || '>' || NEW.status::text) = ANY (ARRAY[{_sql_list(ACCOUNT_TRANSITIONS)}])) THEN
            RAISE EXCEPTION 'PAYMENT_ACCOUNT_INVALID_TRANSITION: % -> %', OLD.status, NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.technician_id IS DISTINCT FROM OLD.technician_id OR NEW.provider IS DISTINCT FROM OLD.provider
           OR (OLD.provider_account_id IS NOT NULL
               AND NEW.provider_account_id IS DISTINCT FROM OLD.provider_account_id) THEN
            RAISE EXCEPTION 'PAYMENT_ACCOUNT_IMMUTABLE: técnico, proveedor y cuenta no cambian'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_technician_payment_accounts_guard BEFORE INSERT OR UPDATE OR DELETE
        ON technician_payment_accounts FOR EACH ROW EXECUTE FUNCTION payment_account_guard();
    """,
]


def upgrade() -> None:
    op.add_column('technician_payment_accounts', sa.Column('details_submitted', sa.Boolean(),
                                                           server_default=sa.text('false'), nullable=False))
    op.add_column('technician_payment_accounts', sa.Column('provider_disabled_reason', sa.String(length=80),
                                                           nullable=True))
    op.add_column('technician_payment_accounts', sa.Column('enabled_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('technician_payment_accounts', sa.Column('last_synced_at', sa.DateTime(timezone=True),
                                                           nullable=True))
    op.add_column('technician_payment_accounts', sa.Column('version', sa.Integer(), server_default=sa.text('1'),
                                                           nullable=False))
    for stmt in TRIGGERS_UP:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_technician_payment_accounts_guard ON technician_payment_accounts")
    op.execute("DROP FUNCTION IF EXISTS payment_account_guard()")
    for c in ('version', 'last_synced_at', 'enabled_at', 'provider_disabled_reason', 'details_submitted'):
        op.drop_column('technician_payment_accounts', c)
