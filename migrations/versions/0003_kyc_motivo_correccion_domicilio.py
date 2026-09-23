"""Motivo de corrección CORRECCION_DOMICILIO (desbloquea domicilio + documentos).

Revision ID: 0003
Revises: 0002
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "INSERT INTO rejection_reasons (id, code, label, scope, requires_note) "
        "VALUES (22, 'CORRECCION_DOMICILIO', 'Corregir domicilio y comprobante', 'CORRECTION', false)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM rejection_reasons WHERE code = 'CORRECCION_DOMICILIO'"))
