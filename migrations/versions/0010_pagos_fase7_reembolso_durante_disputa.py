"""Pagos, Fase 7 (revisión de seguridad): transición DISPUTED → REFUNDED y límites por usuario.

Un reembolso que ya estaba en curso cuando el cliente abrió un contracargo puede confirmarse
DURANTE la disputa. Antes eso sacaba al pago de DISPUTED y el contracargo perdido ya no se
procesaba (sin reversión al técnico, sin asiento). Ahora el pago se queda en DISPUTED mientras
dure la disputa y, si se gana con todo reembolsado, pasa directo a REFUNDED.

rate_limit_hits: intentos por usuario en las rutas que llaman al proveedor, guardados en una
transacción propia para que cuenten aunque la petición falle.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-25 10:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Deben coincidir EXACTAMENTE con app.payments.state_machine.ALLOWED_PAYMENT_TRANSITIONS (lo verifica una prueba).
PAYMENT_TRANSITIONS = [
    "PENDING>REQUIRES_ACTION", "PENDING>PROCESSING", "PENDING>AUTHORIZED", "PENDING>FAILED",
    "PENDING>CANCELLED", "REQUIRES_ACTION>PENDING", "REQUIRES_ACTION>PROCESSING", "REQUIRES_ACTION>AUTHORIZED",
    "REQUIRES_ACTION>FAILED", "REQUIRES_ACTION>CANCELLED", "PROCESSING>AUTHORIZED", "PROCESSING>FAILED",
    "AUTHORIZED>PAID", "AUTHORIZED>CANCELLED", "AUTHORIZED>FAILED", "PAID>PARTIALLY_REFUNDED", "PAID>REFUNDED",
    "PAID>DISPUTED", "PARTIALLY_REFUNDED>REFUNDED", "PARTIALLY_REFUNDED>DISPUTED", "DISPUTED>PAID",
    "DISPUTED>PARTIALLY_REFUNDED", "DISPUTED>CHARGED_BACK", "DISPUTED>REFUNDED",
]
PREVIOUS_TRANSITIONS = [t for t in PAYMENT_TRANSITIONS if t != "DISPUTED>REFUNDED"]


def _sql_list(items: list[str]) -> str:
    return ", ".join(f"'{t}'" for t in items)


def _function(transitions: list[str]) -> str:
    return f"""
    CREATE OR REPLACE FUNCTION payment_enforce_transition() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'PENDING' THEN
                RAISE EXCEPTION 'PAYMENT_INVALID_INITIAL_STATUS: %', NEW.status USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status
           AND NOT ((OLD.status::text || '>' || NEW.status::text) = ANY (ARRAY[{_sql_list(transitions)}])) THEN
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
    """


def upgrade() -> None:
    op.execute(_function(PAYMENT_TRANSITIONS))
    op.create_table(
        'rate_limit_hits',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('action', sa.String(length=40), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_rate_limit_hits_user_id_users'),
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_rate_limit_hits')),
    )
    op.create_index('ix_rate_limit_hits_user_action_created', 'rate_limit_hits', ['user_id', 'action', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_rate_limit_hits_user_action_created', table_name='rate_limit_hits')
    op.drop_table('rate_limit_hits')
    # Un pago que ya pasó DISPUTED → REFUNDED quedaría fuera de la regla anterior; solo afecta a
    # cambios futuros de esa fila (que ya es terminal), así que no hay datos que migrar.
    op.execute(_function(PREVIOUS_TRANSITIONS))
