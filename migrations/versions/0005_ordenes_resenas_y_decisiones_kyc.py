"""Fase 4: órdenes de servicio, pagos, calificaciones verificadas y reputación.

- service_requests -> service_orders (estados nuevos en mayúsculas, fechas por etapa,
  reserva directa, versión) + order_status_history (solo inserción).
- payments: estados de autorización/captura/reembolso, huella del método de pago,
  un solo pago vivo por orden.
- reviews rehecha (verificada, moderable, firmada), review_ratings, review_reports,
  review_audit_logs (solo inserción), technician_reputation, user_signals.
- Triggers: transiciones de orden y de pago, técnico con KYC aprobado para aceptar /
  agendar / iniciar, reseña solo con orden READY_FOR_REVIEW y pago confirmado, columnas
  inmutables en reseñas, sin DELETE.
- actor_type += CLIENT; admin_role += CONTENT_MODERATOR; motivo REACTIVACION.

Las tablas service_requests y reviews no tenían API; si tuvieran filas, la migración
las convierte (órdenes) o se detiene (reseñas) para no perder datos en silencio.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-23 10:30:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ORDER_STATES = ('REQUESTED', 'ACCEPTED', 'SCHEDULED', 'IN_PROGRESS', 'AWAITING_APPROVAL', 'COMPLETED', 'PAID',
                'READY_FOR_REVIEW', 'REVIEWED', 'CANCELLED', 'FAILED', 'DISPUTED', 'REFUNDED')
PAYMENT_STATES = ('PENDING', 'AUTHORIZED', 'CAPTURED', 'RELEASED', 'PARTIALLY_REFUNDED', 'REFUNDED', 'FAILED',
                  'CANCELED')

order_status = postgresql.ENUM(*ORDER_STATES, name='order_status', create_type=False)
actor_type = postgresql.ENUM('CLIENT', 'TECHNICIAN', 'ADMIN', 'SYSTEM', name='actor_type', create_type=False)

# Deben coincidir EXACTAMENTE con app.orders.state_machine.ALLOWED_TRANSITIONS (lo verifica una prueba).
ORDER_TRANSITIONS = [
    "REQUESTED>ACCEPTED", "REQUESTED>CANCELLED", "ACCEPTED>SCHEDULED", "ACCEPTED>REQUESTED",
    "SCHEDULED>REQUESTED", "ACCEPTED>CANCELLED", "SCHEDULED>CANCELLED", "SCHEDULED>IN_PROGRESS",
    "SCHEDULED>FAILED", "IN_PROGRESS>AWAITING_APPROVAL", "IN_PROGRESS>DISPUTED", "AWAITING_APPROVAL>COMPLETED",
    "AWAITING_APPROVAL>DISPUTED", "COMPLETED>PAID", "COMPLETED>FAILED", "COMPLETED>DISPUTED",
    "PAID>READY_FOR_REVIEW", "PAID>DISPUTED", "READY_FOR_REVIEW>DISPUTED", "REVIEWED>DISPUTED",
    "READY_FOR_REVIEW>REVIEWED", "READY_FOR_REVIEW>REFUNDED", "REVIEWED>REFUNDED", "DISPUTED>COMPLETED",
    "DISPUTED>READY_FOR_REVIEW", "DISPUTED>REVIEWED", "DISPUTED>REFUNDED", "DISPUTED>CANCELLED",
]
# Deben coincidir con app.payments.service.ALLOWED_PAYMENT_TRANSITIONS.
PAYMENT_TRANSITIONS = [
    "PENDING>AUTHORIZED", "PENDING>FAILED", "PENDING>CANCELED", "AUTHORIZED>CAPTURED", "AUTHORIZED>CANCELED",
    "AUTHORIZED>FAILED", "CAPTURED>RELEASED", "CAPTURED>PARTIALLY_REFUNDED", "CAPTURED>REFUNDED",
    "RELEASED>PARTIALLY_REFUNDED", "RELEASED>REFUNDED", "PARTIALLY_REFUNDED>REFUNDED",
    "PARTIALLY_REFUNDED>RELEASED",
]


def _sql_list(items: list[str]) -> str:
    return ", ".join(f"'{t}'" for t in items)


TRIGGERS_UP = [
    # 1. Transiciones de la orden
    f"""
    CREATE FUNCTION order_enforce_transition() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'REQUESTED' THEN
                RAISE EXCEPTION 'ORDER_INVALID_INITIAL_STATUS: %', NEW.status USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status
           AND NOT ((OLD.status::text || '>' || NEW.status::text) = ANY (ARRAY[{_sql_list(ORDER_TRANSITIONS)}])) THEN
            RAISE EXCEPTION 'ORDER_INVALID_TRANSITION: % -> %', OLD.status, NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.client_id IS DISTINCT FROM OLD.client_id THEN
            RAISE EXCEPTION 'ORDER_IMMUTABLE: el cliente de una orden no cambia' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_service_orders_transition BEFORE INSERT OR UPDATE ON service_orders
        FOR EACH ROW EXECUTE FUNCTION order_enforce_transition();
    """,
    # 2. Regla crítica: un técnico sin KYC APROBADO (o desactivado) no recibe, agenda ni inicia órdenes,
    #    ni se le puede hacer una reserva directa.
    """
    CREATE FUNCTION order_technician_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_service_orders_technician BEFORE INSERT OR UPDATE OF technician_id, status,
        requested_technician_id ON service_orders
        FOR EACH ROW EXECUTE FUNCTION order_technician_guard();
    """,
    # 3. Transiciones del pago
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
        IF NEW.service_order_id IS DISTINCT FROM OLD.service_order_id OR NEW.amount IS DISTINCT FROM OLD.amount THEN
            RAISE EXCEPTION 'PAYMENT_IMMUTABLE: orden y monto no cambian' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_payments_transition BEFORE INSERT OR UPDATE ON payments
        FOR EACH ROW EXECUTE FUNCTION payment_enforce_transition();
    """,
    # 4. Regla absoluta de calificaciones: solo con orden real, del mismo cliente y técnico,
    #    en READY_FOR_REVIEW y con pago confirmado.
    """
    CREATE FUNCTION review_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
        PERFORM 1 FROM payments p WHERE p.service_order_id = NEW.service_order_id
           AND p.status IN ('CAPTURED', 'RELEASED', 'PARTIALLY_REFUNDED');
        IF NOT FOUND THEN
            RAISE EXCEPTION 'REVIEW_PAYMENT_NOT_CONFIRMED: el pago no está confirmado' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_reviews_insert BEFORE INSERT ON reviews
        FOR EACH ROW EXECUTE FUNCTION review_insert_guard();
    """,
    """
    CREATE FUNCTION review_immutable_columns() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.service_order_id IS DISTINCT FROM OLD.service_order_id
           OR NEW.client_id IS DISTINCT FROM OLD.client_id
           OR NEW.technician_id IS DISTINCT FROM OLD.technician_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.verification IS DISTINCT FROM OLD.verification
           OR NEW.editable_until IS DISTINCT FROM OLD.editable_until
           OR NEW.edit_count < OLD.edit_count THEN
            RAISE EXCEPTION 'REVIEW_IMMUTABLE: orden, cliente, técnico, fechas y conteo de ediciones no cambian'
                USING ERRCODE = 'check_violation';
        END IF;
        -- Estrellas y comentario: solo dentro del periodo de edición y contando la edición.
        IF (NEW.rating IS DISTINCT FROM OLD.rating OR NEW.comment IS DISTINCT FROM OLD.comment) AND (
               now() > OLD.editable_until OR NEW.edit_count <> OLD.edit_count + 1) THEN
            RAISE EXCEPTION 'REVIEW_IMMUTABLE: la calificación ya no se puede modificar' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_reviews_immutable BEFORE UPDATE ON reviews
        FOR EACH ROW EXECUTE FUNCTION review_immutable_columns();
    """,
    """
    CREATE FUNCTION review_rating_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        until timestamptz;
    BEGIN
        SELECT editable_until INTO until FROM reviews WHERE id = NEW.review_id;
        IF TG_OP = 'UPDATE' AND NEW.review_id IS DISTINCT FROM OLD.review_id THEN
            RAISE EXCEPTION 'REVIEW_IMMUTABLE: la calificación por categoría no cambia de reseña'
                USING ERRCODE = 'check_violation';
        END IF;
        IF now() > until THEN
            RAISE EXCEPTION 'REVIEW_IMMUTABLE: la calificación ya no se puede modificar' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    """,
    """
    CREATE TRIGGER trg_review_ratings_guard BEFORE INSERT OR UPDATE ON review_ratings
        FOR EACH ROW EXECUTE FUNCTION review_rating_guard();
    """,
    # 5. Nada de DELETE en reseñas ni calificaciones; historiales solo inserción.
    """
    CREATE TRIGGER trg_reviews_no_delete BEFORE DELETE ON reviews
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
    """
    CREATE TRIGGER trg_review_ratings_no_delete BEFORE DELETE ON review_ratings
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
    """
    CREATE TRIGGER trg_review_audit_logs_append_only BEFORE UPDATE OR DELETE ON review_audit_logs
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
    """
    CREATE TRIGGER trg_order_status_history_append_only BEFORE UPDATE OR DELETE ON order_status_history
        FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
    """,
]

TRIGGERS_DOWN = [
    "DROP TRIGGER IF EXISTS trg_order_status_history_append_only ON order_status_history",
    "DROP TRIGGER IF EXISTS trg_review_audit_logs_append_only ON review_audit_logs",
    "DROP TRIGGER IF EXISTS trg_review_ratings_no_delete ON review_ratings",
    "DROP TRIGGER IF EXISTS trg_reviews_no_delete ON reviews",
    "DROP TRIGGER IF EXISTS trg_review_ratings_guard ON review_ratings",
    "DROP FUNCTION IF EXISTS review_rating_guard()",
    "DROP TRIGGER IF EXISTS trg_reviews_immutable ON reviews",
    "DROP FUNCTION IF EXISTS review_immutable_columns()",
    "DROP TRIGGER IF EXISTS trg_reviews_insert ON reviews",
    "DROP FUNCTION IF EXISTS review_insert_guard()",
    "DROP TRIGGER IF EXISTS trg_payments_transition ON payments",
    "DROP FUNCTION IF EXISTS payment_enforce_transition()",
    "DROP TRIGGER IF EXISTS trg_service_orders_technician ON service_orders",
    "DROP FUNCTION IF EXISTS order_technician_guard()",
    "DROP TRIGGER IF EXISTS trg_service_orders_transition ON service_orders",
    "DROP FUNCTION IF EXISTS order_enforce_transition()",
]


def upgrade() -> None:
    bind = op.get_bind()
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actor_type ADD VALUE IF NOT EXISTS 'CLIENT' BEFORE 'TECHNICIAN'")
        op.execute("ALTER TYPE admin_role ADD VALUE IF NOT EXISTS 'CONTENT_MODERATOR'")

    if bind.execute(sa.text("SELECT count(*) FROM reviews")).scalar():
        raise RuntimeError("La tabla reviews tiene filas: migrarlas a mano antes de aplicar 0005")

    # ------------------------------------------------------------------ órdenes
    order_status.create(bind)
    op.create_table('service_orders',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.Uuid(), nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=True),
    sa.Column('requested_technician_id', sa.Uuid(), nullable=True),
    sa.Column('category_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('address_line', sa.String(length=200), nullable=False),
    sa.Column('city', sa.String(length=80), nullable=False),
    sa.Column('latitude', sa.Numeric(precision=9, scale=6), nullable=True),
    sa.Column('longitude', sa.Numeric(precision=9, scale=6), nullable=True),
    sa.Column('status', order_status, server_default='REQUESTED', nullable=False),
    sa.Column('agreed_price', sa.Numeric(precision=10, scale=2), nullable=True),
    sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('work_finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('cancelled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('disputed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status_before_dispute', order_status, nullable=True),
    sa.Column('version', sa.Integer(), server_default=sa.text('1'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'REQUESTED' AND technician_id IS NULL) OR status = 'CANCELLED' OR technician_id IS NOT NULL", name=op.f('ck_service_orders_technician_matches_status')),
    sa.CheckConstraint("status = 'REQUESTED' OR status = 'CANCELLED' OR agreed_price IS NOT NULL", name=op.f('ck_service_orders_price_after_acceptance')),
    sa.CheckConstraint('agreed_price IS NULL OR agreed_price > 0', name=op.f('ck_service_orders_agreed_price_positive')),
    sa.CheckConstraint('requested_technician_id IS NULL OR requested_technician_id <> client_id', name=op.f('ck_service_orders_client_is_not_requested_technician')),
    sa.CheckConstraint('technician_id IS NULL OR technician_id <> client_id', name=op.f('ck_service_orders_client_is_not_technician')),
    sa.ForeignKeyConstraint(['category_id'], ['service_categories.id'], name=op.f('fk_service_orders_category_id_service_categories'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['client_id'], ['users.id'], name=op.f('fk_service_orders_client_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['requested_technician_id'], ['users.id'], name=op.f('fk_service_orders_requested_technician_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_service_orders_technician_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_service_orders'))
    )
    op.create_index(op.f('ix_service_orders_client_id'), 'service_orders', ['client_id'], unique=False)
    op.create_index('ix_service_orders_open', 'service_orders', ['category_id', 'created_at'], unique=False, postgresql_where=sa.text("status = 'REQUESTED'"))
    op.create_index(op.f('ix_service_orders_status'), 'service_orders', ['status'], unique=False)
    op.create_index(op.f('ix_service_orders_technician_id'), 'service_orders', ['technician_id'], unique=False)

    # Copia de órdenes existentes (si las hubiera) con el mapeo de estados.
    op.execute("""
        INSERT INTO service_orders (id, client_id, technician_id, category_id, title, description, address_line, city,
            latitude, longitude, status, agreed_price, scheduled_at, work_finished_at, completed_at,
            created_at, updated_at)
        SELECT id, client_id, CASE WHEN status::text = 'open' THEN NULL ELSE technician_id END, category_id, title,
               description, address_line, city, latitude, longitude,
               (CASE status::text WHEN 'open' THEN 'REQUESTED' WHEN 'assigned' THEN 'ACCEPTED'
                    WHEN 'in_progress' THEN 'IN_PROGRESS' WHEN 'pending_approval' THEN 'AWAITING_APPROVAL'
                    WHEN 'completed' THEN 'COMPLETED' WHEN 'disputed' THEN 'DISPUTED' ELSE 'CANCELLED' END)::order_status,
               agreed_price, scheduled_at, completed_at, client_approved_at, created_at, updated_at
          FROM service_requests
    """)

    op.create_table('order_status_history',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('order_id', sa.Uuid(), nullable=False),
    sa.Column('from_status', order_status, nullable=True),
    sa.Column('to_status', order_status, nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('actor_type', actor_type, nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=True),
    sa.Column('reason_code', sa.String(length=40), nullable=True),
    sa.Column('note', sa.String(length=500), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['order_id'], ['service_orders.id'], name=op.f('fk_order_status_history_order_id_service_orders'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_order_status_history'))
    )
    op.create_index(op.f('ix_order_status_history_order_id'), 'order_status_history', ['order_id'], unique=False)
    op.create_index(op.f('ix_order_status_history_technician_id'), 'order_status_history', ['technician_id'], unique=False)

    # ------------------------------------------------------------------ pagos (en su lugar)
    op.execute("ALTER TYPE payment_status RENAME TO payment_status_v1")
    postgresql.ENUM(*PAYMENT_STATES, name='payment_status').create(bind)
    op.execute("ALTER TABLE payments ALTER COLUMN status DROP DEFAULT")
    op.execute("""
        ALTER TABLE payments ALTER COLUMN status TYPE payment_status USING (CASE status::text
            WHEN 'pending' THEN 'PENDING' WHEN 'held' THEN 'CAPTURED' WHEN 'released' THEN 'RELEASED'
            WHEN 'refunded' THEN 'REFUNDED' ELSE 'FAILED' END)::payment_status
    """)
    op.execute("ALTER TABLE payments ALTER COLUMN status SET DEFAULT 'PENDING'")
    op.execute("DROP TYPE payment_status_v1")

    op.add_column('payments', sa.Column('service_order_id', sa.Uuid(), nullable=True))
    op.execute("UPDATE payments SET service_order_id = service_request_id")
    op.alter_column('payments', 'service_order_id', nullable=False)
    op.add_column('payments', sa.Column('amount_refunded', sa.Numeric(precision=10, scale=2), server_default=sa.text('0'), nullable=False))
    op.add_column('payments', sa.Column('payment_method_fingerprint', sa.String(length=64), nullable=True))
    op.add_column('payments', sa.Column('failure_code', sa.String(length=60), nullable=True))
    op.add_column('payments', sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('payments', sa.Column('captured_at', sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE payments SET captured_at = held_at")
    op.drop_constraint(op.f('uq_payments_service_request_id'), 'payments', type_='unique')
    op.drop_constraint(op.f('fk_payments_service_request_id_service_requests'), 'payments', type_='foreignkey')
    op.drop_column('payments', 'service_request_id')
    op.drop_column('payments', 'held_at')
    op.create_foreign_key(op.f('fk_payments_service_order_id_service_orders'), 'payments', 'service_orders', ['service_order_id'], ['id'], ondelete='RESTRICT')
    op.create_index(op.f('ix_payments_service_order_id'), 'payments', ['service_order_id'], unique=False)
    op.create_index('uq_payments_active_order', 'payments', ['service_order_id'], unique=True, postgresql_where=sa.text("status NOT IN ('CANCELED', 'FAILED')"))
    op.create_index(op.f('ix_payments_payment_method_fingerprint'), 'payments', ['payment_method_fingerprint'], unique=False)
    op.create_check_constraint('refund_within_amount', 'payments', 'amount_refunded >= 0 AND amount_refunded <= amount')

    # ------------------------------------------------------------------ fuera la tabla vieja
    op.execute("DROP TRIGGER IF EXISTS trg_service_requests_assignment ON service_requests")
    op.execute("DROP FUNCTION IF EXISTS service_request_assignment_guard()")
    op.drop_table('reviews')
    op.drop_table('service_requests')
    op.execute("DROP TYPE service_request_status")

    # ------------------------------------------------------------------ reseñas
    op.create_table('reviews',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('service_order_id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.Uuid(), nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=False),
    sa.Column('rating', sa.SmallInteger(), nullable=False),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('PUBLISHED', 'PENDING_MODERATION', 'HIDDEN', 'REMOVED', name='review_status'), server_default='PUBLISHED', nullable=False),
    sa.Column('verification', sa.String(length=20), server_default=sa.text("'VERIFIED_SERVICE'"), nullable=False),
    sa.Column('risk_flags', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('weight', sa.Numeric(precision=3, scale=2), server_default=sa.text('1'), nullable=False),
    sa.Column('edit_count', sa.SmallInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('editable_until', sa.DateTime(timezone=True), nullable=False),
    sa.Column('technician_reply', sa.Text(), nullable=True),
    sa.Column('technician_reply_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('moderation_reason', sa.String(length=40), nullable=True),
    sa.Column('moderated_by_id', sa.Uuid(), nullable=True),
    sa.Column('moderated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('integrity_mac', sa.String(length=64), nullable=False),
    sa.Column('version', sa.Integer(), server_default=sa.text('1'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('rating BETWEEN 1 AND 5', name=op.f('ck_reviews_rating_range')),
    sa.CheckConstraint("verification = 'VERIFIED_SERVICE'", name=op.f('ck_reviews_only_verified')),
    sa.CheckConstraint('comment IS NULL OR char_length(comment) BETWEEN 1 AND 1000', name=op.f('ck_reviews_comment_length')),
    sa.CheckConstraint('technician_reply IS NULL OR char_length(technician_reply) BETWEEN 1 AND 500', name=op.f('ck_reviews_reply_length')),
    sa.CheckConstraint('weight >= 0 AND weight <= 1', name=op.f('ck_reviews_weight_range')),
    sa.CheckConstraint('edit_count >= 0', name=op.f('ck_reviews_edit_count_non_negative')),
    sa.CheckConstraint('client_id <> technician_id', name=op.f('ck_reviews_not_self_review')),
    sa.ForeignKeyConstraint(['service_order_id'], ['service_orders.id'], name=op.f('fk_reviews_service_order_id_service_orders'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['client_id'], ['users.id'], name=op.f('fk_reviews_client_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_reviews_technician_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['moderated_by_id'], ['users.id'], name=op.f('fk_reviews_moderated_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reviews')),
    sa.UniqueConstraint('service_order_id', name=op.f('uq_reviews_service_order_id'))
    )
    op.create_index(op.f('ix_reviews_client_id'), 'reviews', ['client_id'], unique=False)
    op.create_index('ix_reviews_technician_public', 'reviews', ['technician_id', 'created_at'], unique=False, postgresql_where=sa.text("status = 'PUBLISHED'"))

    op.create_table('review_ratings',
    sa.Column('review_id', sa.Uuid(), nullable=False),
    sa.Column('category', sa.Enum('QUALITY', 'PUNCTUALITY', 'COMMUNICATION', 'CLEANLINESS', 'PROFESSIONALISM', name='review_category'), nullable=False),
    sa.Column('score', sa.SmallInteger(), nullable=False),
    sa.CheckConstraint('score BETWEEN 1 AND 5', name=op.f('ck_review_ratings_score_range')),
    sa.ForeignKeyConstraint(['review_id'], ['reviews.id'], name=op.f('fk_review_ratings_review_id_reviews'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('review_id', 'category', name=op.f('pk_review_ratings'))
    )
    op.create_table('review_audit_logs',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('review_id', sa.Uuid(), nullable=False),
    sa.Column('action', sa.String(length=40), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('actor_type', actor_type, nullable=False),
    sa.Column('old_values', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('new_values', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('reason', sa.String(length=300), nullable=True),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['review_id'], ['reviews.id'], name=op.f('fk_review_audit_logs_review_id_reviews'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_review_audit_logs'))
    )
    op.create_index(op.f('ix_review_audit_logs_review_id'), 'review_audit_logs', ['review_id'], unique=False)
    op.create_table('review_reports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('review_id', sa.Uuid(), nullable=False),
    sa.Column('reporter_id', sa.Uuid(), nullable=False),
    sa.Column('reason', sa.Enum('OFFENSIVE', 'FALSE', 'SPAM', 'NOT_RELATED', 'OTHER', name='report_reason'), nullable=False),
    sa.Column('note', sa.String(length=500), nullable=True),
    sa.Column('status', sa.Enum('OPEN', 'RESOLVED', name='report_status'), server_default='OPEN', nullable=False),
    sa.Column('resolution', sa.Enum('KEEP', 'HIDE', 'REMOVE', name='report_resolution'), nullable=True),
    sa.Column('resolution_note', sa.String(length=500), nullable=True),
    sa.Column('resolved_by_id', sa.Uuid(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'OPEN') = (resolution IS NULL)", name=op.f('ck_review_reports_resolution_matches_status')),
    sa.ForeignKeyConstraint(['reporter_id'], ['users.id'], name=op.f('fk_review_reports_reporter_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['resolved_by_id'], ['users.id'], name=op.f('fk_review_reports_resolved_by_id_users')),
    sa.ForeignKeyConstraint(['review_id'], ['reviews.id'], name=op.f('fk_review_reports_review_id_reviews'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_review_reports')),
    sa.UniqueConstraint('review_id', 'reporter_id', name=op.f('uq_review_reports_review_id'))
    )
    op.create_index('ix_review_reports_open', 'review_reports', ['created_at'], unique=False, postgresql_where=sa.text("status = 'OPEN'"))
    op.create_index(op.f('ix_review_reports_review_id'), 'review_reports', ['review_id'], unique=False)

    op.create_table('technician_reputation',
    sa.Column('technician_id', sa.Uuid(), nullable=False),
    sa.Column('completed_jobs', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('verified_reviews', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('rating_avg', sa.Numeric(precision=3, scale=2), server_default=sa.text('0'), nullable=False),
    sa.Column('bayes_rating', sa.Numeric(precision=4, scale=3), server_default=sa.text('0'), nullable=False),
    sa.Column('category_avgs', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('technician_cancellations', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('disputes_lost', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('fraud_strikes', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('reliability', sa.Numeric(precision=4, scale=3), server_default=sa.text('1'), nullable=False),
    sa.Column('reputation_score', sa.Numeric(precision=5, scale=2), server_default=sa.text('0'), nullable=False),
    sa.Column('computed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('reputation_score BETWEEN 0 AND 100', name=op.f('ck_technician_reputation_score_range')),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_technician_reputation_technician_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('technician_id', name=op.f('pk_technician_reputation'))
    )
    op.create_table('user_signals',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.Enum('DEVICE', 'IP', name='signal_kind'), nullable=False),
    sa.Column('value_hash', sa.String(length=64), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('hits', sa.Integer(), server_default=sa.text('1'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_signals_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_signals')),
    sa.UniqueConstraint('user_id', 'kind', 'value_hash', name=op.f('uq_user_signals_user_id'))
    )
    op.create_index('ix_user_signals_lookup', 'user_signals', ['kind', 'value_hash'], unique=False)

    # ------------------------------------------------------------------ catálogo y triggers
    op.execute("INSERT INTO rejection_reasons (id, code, label, scope, requires_note) "
               "VALUES (64, 'REACTIVACION', 'Reactivación tras suspensión', 'SUSPENSION', true)")
    for stmt in TRIGGERS_UP:
        op.execute(stmt)


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("service_orders", "reviews"):
        if bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar():
            raise RuntimeError(f"{table} tiene datos: el downgrade los perdería. Respáldalos y vacía la tabla.")
    for stmt in TRIGGERS_DOWN:
        op.execute(stmt)
    op.execute("DELETE FROM rejection_reasons WHERE id = 64")
    for t in ("user_signals", "technician_reputation", "review_reports", "review_audit_logs", "review_ratings",
              "reviews"):
        op.drop_table(t)
    for e in ("signal_kind", "report_resolution", "report_status", "report_reason", "review_category",
              "review_status"):
        op.execute(f"DROP TYPE {e}")

    # payments vuelve a la forma de 0001 (vacía: no hay órdenes)
    op.execute("DELETE FROM payments")
    op.drop_constraint('refund_within_amount', 'payments', type_='check')
    op.drop_index(op.f('ix_payments_payment_method_fingerprint'), table_name='payments')
    op.drop_index('uq_payments_active_order', table_name='payments')
    op.drop_index(op.f('ix_payments_service_order_id'), table_name='payments')
    op.drop_constraint(op.f('fk_payments_service_order_id_service_orders'), 'payments', type_='foreignkey')
    for c in ("captured_at", "authorized_at", "failure_code", "payment_method_fingerprint", "amount_refunded",
              "service_order_id"):
        op.drop_column('payments', c)
    op.execute("ALTER TABLE payments ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TYPE payment_status RENAME TO payment_status_v2")
    postgresql.ENUM('pending', 'held', 'released', 'refunded', 'failed', name='payment_status').create(bind)
    op.execute("ALTER TABLE payments ALTER COLUMN status TYPE payment_status USING 'pending'::payment_status")
    op.execute("ALTER TABLE payments ALTER COLUMN status SET DEFAULT 'pending'")
    op.execute("DROP TYPE payment_status_v2")
    op.add_column('payments', sa.Column('held_at', sa.DateTime(timezone=True), nullable=True))

    service_request_status = postgresql.ENUM('open', 'assigned', 'in_progress', 'pending_approval', 'completed',
                                             'disputed', 'cancelled', name='service_request_status')
    service_request_status.create(bind)
    op.create_table('service_requests',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.Uuid(), nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=True),
    sa.Column('category_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('address_line', sa.String(length=200), nullable=False),
    sa.Column('city', sa.String(length=80), nullable=False),
    sa.Column('latitude', sa.Numeric(precision=9, scale=6), nullable=True),
    sa.Column('longitude', sa.Numeric(precision=9, scale=6), nullable=True),
    sa.Column('status', postgresql.ENUM(name='service_request_status', create_type=False), server_default='open', nullable=False),
    sa.Column('agreed_price', sa.Numeric(precision=10, scale=2), nullable=True),
    sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('client_approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('open','cancelled') OR technician_id IS NOT NULL", name=op.f('ck_service_requests_technician_required_after_open')),
    sa.CheckConstraint('agreed_price IS NULL OR agreed_price > 0', name=op.f('ck_service_requests_agreed_price_positive')),
    sa.CheckConstraint('technician_id IS NULL OR technician_id <> client_id', name=op.f('ck_service_requests_client_is_not_technician')),
    sa.ForeignKeyConstraint(['category_id'], ['service_categories.id'], name=op.f('fk_service_requests_category_id_service_categories'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['client_id'], ['users.id'], name=op.f('fk_service_requests_client_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_service_requests_technician_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_service_requests'))
    )
    op.create_index(op.f('ix_service_requests_client_id'), 'service_requests', ['client_id'], unique=False)
    op.create_index(op.f('ix_service_requests_status'), 'service_requests', ['status'], unique=False)
    op.create_index(op.f('ix_service_requests_technician_id'), 'service_requests', ['technician_id'], unique=False)
    op.add_column('payments', sa.Column('service_request_id', sa.Uuid(), nullable=False))
    op.create_foreign_key(op.f('fk_payments_service_request_id_service_requests'), 'payments', 'service_requests', ['service_request_id'], ['id'], ondelete='RESTRICT')
    op.create_unique_constraint(op.f('uq_payments_service_request_id'), 'payments', ['service_request_id'])
    op.create_table('reviews',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('service_request_id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.Uuid(), nullable=False),
    sa.Column('technician_id', sa.Uuid(), nullable=False),
    sa.Column('rating', sa.SmallInteger(), nullable=False),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('technician_reply', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('rating BETWEEN 1 AND 5', name=op.f('ck_reviews_rating_range')),
    sa.ForeignKeyConstraint(['client_id'], ['users.id'], name=op.f('fk_reviews_client_id_users'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_request_id'], ['service_requests.id'], name=op.f('fk_reviews_service_request_id_service_requests'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['technician_id'], ['users.id'], name=op.f('fk_reviews_technician_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reviews')),
    sa.UniqueConstraint('service_request_id', name=op.f('uq_reviews_service_request_id'))
    )
    op.create_index(op.f('ix_reviews_technician_id'), 'reviews', ['technician_id'], unique=False)

    op.drop_table('order_status_history')
    op.drop_table('service_orders')
    op.execute("DROP TYPE order_status")
    # Se restituye la regla crítica de 0002 sobre la tabla vieja.
    op.execute("""
    CREATE FUNCTION service_request_assignment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.technician_id IS NOT NULL
           AND (TG_OP = 'INSERT' OR NEW.technician_id IS DISTINCT FROM OLD.technician_id) THEN
            PERFORM 1 FROM kyc_profiles k JOIN users u ON u.id = k.technician_id
             WHERE k.technician_id = NEW.technician_id AND k.status = 'APPROVED' AND u.is_active
             FOR SHARE OF k;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'KYC_NOT_APPROVED: el técnico no puede recibir órdenes'
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_service_requests_assignment BEFORE INSERT OR UPDATE OF technician_id ON service_requests
        FOR EACH ROW EXECUTE FUNCTION service_request_assignment_guard();
    """)
    # Nota: PostgreSQL no permite quitar valores de un ENUM; CLIENT y CONTENT_MODERATOR quedan (sin uso).
