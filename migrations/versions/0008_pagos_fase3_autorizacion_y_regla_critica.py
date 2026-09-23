"""Pagos, Fase 3: autorización al salir el técnico y regla crítica ampliada.

- payments.provider_payment_method_id: la tarjeta guardada que el cliente eligió (solo el id pm_...).
- service_orders.departed_at: el técnico marcó "en camino" y se autorizó el cobro (decisión D7).
- order_technician_guard: además del KYC APROBADO, aceptar, agendar o recibir una reserva
  directa exige una cuenta de pagos ENABLED y sin bloqueo de la plataforma.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-24 16:00:00
"""
import importlib.util
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUARD = """
CREATE OR REPLACE FUNCTION order_technician_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tech uuid;
BEGIN
    IF NEW.requested_technician_id IS NOT NULL
       AND (TG_OP = 'INSERT' OR NEW.requested_technician_id IS DISTINCT FROM OLD.requested_technician_id) THEN
        tech := NEW.requested_technician_id;
        PERFORM 1 FROM kyc_profiles k JOIN users u ON u.id = k.technician_id
         WHERE k.technician_id = tech AND k.status = 'APPROVED' AND u.is_active FOR SHARE OF k;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'KYC_NOT_APPROVED: el técnico no puede recibir órdenes' USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1 FROM technician_payment_accounts a
         WHERE a.technician_id = tech AND a.status = 'ENABLED' AND a.blocked_reason IS NULL FOR SHARE OF a;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'PAYMENT_ACCOUNT_NOT_ENABLED: el técnico no puede recibir pagos'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF NEW.technician_id IS NOT NULL AND (
           TG_OP = 'INSERT'
        OR NEW.technician_id IS DISTINCT FROM OLD.technician_id
        OR (NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('ACCEPTED', 'SCHEDULED', 'IN_PROGRESS'))
    ) THEN
        PERFORM 1 FROM kyc_profiles k JOIN users u ON u.id = k.technician_id
         WHERE k.technician_id = NEW.technician_id AND k.status = 'APPROVED' AND u.is_active
           AND u.role = 'technician'
         FOR SHARE OF k;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'KYC_NOT_APPROVED: el técnico no puede recibir órdenes' USING ERRCODE = 'check_violation';
        END IF;
        -- Regla crítica ampliada: aceptar o agendar exige además poder recibir el pago. Iniciar no
        -- (el cobro ya quedó autorizado con su cuenta destino al salir el técnico).
        IF NEW.status IN ('ACCEPTED', 'SCHEDULED') THEN
            PERFORM 1 FROM technician_payment_accounts a
             WHERE a.technician_id = NEW.technician_id AND a.status = 'ENABLED' AND a.blocked_reason IS NULL
             FOR SHARE OF a;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'PAYMENT_ACCOUNT_NOT_ENABLED: el técnico no puede recibir pagos'
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;
"""


def upgrade() -> None:
    op.add_column('payments', sa.Column('provider_payment_method_id', sa.String(length=120), nullable=True))
    op.add_column('service_orders', sa.Column('departed_at', sa.DateTime(timezone=True), nullable=True))
    op.execute(GUARD)


def downgrade() -> None:
    spec = importlib.util.spec_from_file_location(
        "m0005", Path(__file__).with_name("0005_ordenes_resenas_y_decisiones_kyc.py"))
    m0005 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m0005)
    for stmt in m0005.TRIGGERS_UP:
        if "CREATE FUNCTION order_technician_guard" in stmt:
            op.execute(stmt.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    op.drop_column('service_orders', 'departed_at')
    op.drop_column('payments', 'provider_payment_method_id')
