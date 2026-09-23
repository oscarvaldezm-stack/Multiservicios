"""
Defensas en la propia base de datos: triggers, CHECK y cadena de auditoría.
Estas pruebas usan SQL directo a propósito: simulan un script, un error de código
o alguien con acceso a la base que intenta saltarse la aplicación.
"""
import re
import uuid

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.audit.writer import verify_chain
from app.db.base import Base
from app.db.session import engine
from app.kyc.state_machine import ALLOWED_TRANSITIONS, transition
from app.models import (
    ActorType,
    AuditLog,
    KycAddress,
    KycStatus,
    ServiceCategory,
    ServiceOrder,
    User,
)
from app.core.actor import Actor
from tests.conftest import drive_to, get_profile, register

S = KycStatus


@pytest.fixture
def tech_id(client, category, db):
    register(client, "technician", "tec@example.com", category_ids=[category.id])
    return db.scalar(select(User.id).where(User.email == "tec@example.com"))


def _raises_db(db, sql: str, params: dict, fragment: str):
    with pytest.raises(DBAPIError) as exc:
        db.execute(text(sql), params)
        db.flush()
    db.rollback()
    assert fragment in str(exc.value.orig)


# ------------------------------------------------------------ modelo = migraciones
def test_modelos_y_migraciones_no_divergen():
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == [], f"Los modelos cambiaron sin migración: {diff}"


def test_trigger_de_transiciones_coincide_con_el_codigo(db):
    src = db.scalar(text("SELECT pg_get_functiondef('kyc_enforce_transition'::regproc)"))
    in_db = set(re.findall(r"'([A-Z_]+>[A-Z_]+)'", src))
    in_code = {f"{a.value}>{b.value}" for a, b in ALLOWED_TRANSITIONS}
    assert in_db == in_code


# ------------------------------------------------------------ transiciones por SQL directo
def test_sql_directo_no_puede_aprobar_saltandose_la_revision(tech_id, db):
    p = get_profile(db, tech_id)
    _raises_db(db, "UPDATE kyc_profiles SET status = 'APPROVED' WHERE id = :id", {"id": p.id},
               "KYC_INVALID_TRANSITION")


def test_no_se_puede_insertar_un_expediente_ya_aprobado(tech_id, client, category, db):
    register(client, "technician", "t2@example.com", category_ids=[category.id])
    uid = db.scalar(select(User.id).where(User.email == "t2@example.com"))
    _raises_db(db, "INSERT INTO kyc_profiles (id, technician_id, status) VALUES (:id, :tid, 'APPROVED')",
               {"id": uuid.uuid4(), "tid": uid}, "KYC_INVALID_INITIAL_STATUS")


def test_enviar_sin_datos_completos_lo_impide_la_base(tech_id, db):
    p = get_profile(db, tech_id)
    tech = Actor(user_id=tech_id, actor_type=ActorType.TECHNICIAN)
    transition(db, p.id, S.PENDING_DOCUMENTS, tech)
    with pytest.raises(IntegrityError) as exc:
        transition(db, p.id, S.SUBMITTED, tech)
    db.rollback()
    assert "complete_data_after_submission" in str(exc.value.orig)


def test_menor_de_edad_no_puede_quedar_enviado(tech_id, reviewer, supervisor, db):
    p = drive_to(db, tech_id, S.SUBMITTED, reviewer, supervisor)
    _raises_db(db, "UPDATE kyc_profiles SET birth_date = '2012-01-01' WHERE id = :id", {"id": p.id},
               "adult_at_submission")


def test_revisor_asignado_solo_en_revision(tech_id, reviewer, db):
    p = get_profile(db, tech_id)
    _raises_db(db, "UPDATE kyc_profiles SET assigned_reviewer_id = :r WHERE id = :id",
               {"r": reviewer.id, "id": p.id}, "reviewer_only_under_review")


# ------------------------------------------------------------ solo inserción
@pytest.mark.parametrize("sql", [
    "UPDATE audit_logs SET reason_note = 'borrado'",
    "DELETE FROM audit_logs",
    "UPDATE kyc_status_history SET note = 'alterado'",
    "DELETE FROM kyc_status_history",
])
def test_historial_y_auditoria_no_se_modifican_ni_borran(sql, tech_id, db):
    _raises_db(db, sql, {}, "APPEND_ONLY")


def test_cadena_de_auditoria_detecta_alteraciones(tech_id, reviewer, supervisor, db):
    drive_to(db, tech_id, S.APPROVED, reviewer, supervisor)
    assert verify_chain(db) == []
    ids = db.scalars(select(AuditLog.id).order_by(AuditLog.id)).all()
    victim, deleted = ids[2], ids[4]
    # Alguien con privilegios de dueño desactiva el trigger y altera / borra registros.
    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_append_only"))
    db.execute(text("UPDATE audit_logs SET reason_note = 'maquillado' WHERE id = :id"), {"id": victim})
    db.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": deleted})
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_append_only"))
    db.commit()
    db.expire_all()
    broken = verify_chain(db)
    assert victim in broken                     # fila alterada
    assert ids[5] in broken                     # la siguiente a la borrada ya no enlaza


def test_auditoria_rechaza_campos_sensibles(db):
    from app.audit.writer import write_audit
    with pytest.raises(ValueError):
        write_audit(db, action="x", actor=Actor.system(), changes={"nested": {"curp": "HEGG560427MVZRRL04"}})


# ------------------------------------------------------------ domicilio congelado
def test_domicilio_enviado_no_se_puede_editar(tech_id, reviewer, supervisor, db):
    p = drive_to(db, tech_id, S.SUBMITTED, reviewer, supervisor)
    addr = db.get(KycAddress, p.current_address_id)
    addr.locked_at = db.scalar(text("SELECT now()"))
    db.commit()
    _raises_db(db, "UPDATE kyc_addresses SET street = 'Otra calle' WHERE id = :id", {"id": addr.id},
               "KYC_ADDRESS_LOCKED")


# ------------------------------------------------------------ regla crítica
def _new_request(db) -> ServiceOrder:
    cliente = User(email=f"c{uuid.uuid4().hex[:6]}@example.com", hashed_password="x",
                   role="client", full_name="Cliente")
    db.add(cliente)
    db.flush()
    cat = db.scalar(select(ServiceCategory))
    order = ServiceOrder(client_id=cliente.id, category_id=cat.id, title="Fuga", description="Fuga en baño",
                         address_line="Calle 1", city="Veracruz")
    db.add(order)
    db.flush()
    return order


_ASSIGN = "UPDATE service_orders SET technician_id = :t, status = 'ACCEPTED', agreed_price = 500 WHERE id = :id"


@pytest.mark.parametrize("state", [s for s in S if s != S.APPROVED], ids=lambda s: s.value)
def test_base_de_datos_rechaza_asignar_orden_a_tecnico_no_aprobado(state, tech_id, reviewer, supervisor, db):
    drive_to(db, tech_id, state, reviewer, supervisor)
    order = _new_request(db)
    db.commit()
    _raises_db(db, _ASSIGN, {"t": tech_id, "id": order.id}, "KYC_NOT_APPROVED")


def test_reserva_directa_a_tecnico_no_aprobado_se_rechaza(tech_id, db):
    cliente = User(email="c-directa@example.com", hashed_password="x", role="client", full_name="Cliente")
    db.add(cliente)
    db.flush()
    cat = db.scalar(select(ServiceCategory))
    db.add(ServiceOrder(client_id=cliente.id, category_id=cat.id, title="Fuga", description="Fuga en baño",
                        address_line="Calle 1", city="Veracruz", requested_technician_id=tech_id))
    with pytest.raises(IntegrityError) as exc:
        db.flush()
    db.rollback()
    assert "KYC_NOT_APPROVED" in str(exc.value.orig)


def _enabled_payment_account(db, tech_id) -> None:
    """Regla crítica ampliada (pagos, Fase 3): recibir órdenes exige también una cuenta de pagos habilitada."""
    db.execute(text("INSERT INTO technician_payment_accounts (id, technician_id, provider) "
                    "VALUES (gen_random_uuid(), :t, 'stripe')"), {"t": tech_id})
    db.execute(text("UPDATE technician_payment_accounts SET status = 'ONBOARDING', provider_account_id = 'acct_t' "
                    "WHERE technician_id = :t"), {"t": tech_id})
    db.execute(text("UPDATE technician_payment_accounts SET status = 'ENABLED' WHERE technician_id = :t"),
               {"t": tech_id})


def test_tecnico_aprobado_si_recibe_y_al_suspenderlo_se_bloquea(tech_id, reviewer, supervisor, db):
    drive_to(db, tech_id, S.APPROVED, reviewer, supervisor)
    _enabled_payment_account(db, tech_id)
    first = _new_request(db)
    db.execute(text(_ASSIGN), {"t": tech_id, "id": first.id})
    db.execute(text("UPDATE technician_profiles SET is_available = true WHERE user_id = :t"), {"t": tech_id})
    db.commit()

    p = get_profile(db, tech_id)
    transition(db, p.id, S.SUSPENDED, Actor.from_user(supervisor), reason_code="INVESTIGACION_EN_CURSO")
    db.commit()
    # Al salir de APPROVED queda no disponible automáticamente...
    assert db.scalar(text("SELECT is_available FROM technician_profiles WHERE user_id = :t"), {"t": tech_id}) is False
    # ...no se le pueden asignar órdenes nuevas...
    order = _new_request(db)
    db.commit()
    _raises_db(db, _ASSIGN, {"t": tech_id, "id": order.id}, "KYC_NOT_APPROVED")
    # ...ni avanzar la que ya tenía (agendar o iniciar).
    _raises_db(db, "UPDATE service_orders SET status = 'SCHEDULED' WHERE id = :id", {"id": first.id},
               "KYC_NOT_APPROVED")


def test_tecnico_desactivado_no_recibe_ordenes_aunque_este_aprobado(tech_id, reviewer, supervisor, db):
    drive_to(db, tech_id, S.APPROVED, reviewer, supervisor)
    db.execute(text("UPDATE users SET is_active = false WHERE id = :t"), {"t": tech_id})
    order = _new_request(db)
    db.commit()
    _raises_db(db, _ASSIGN, {"t": tech_id, "id": order.id}, "KYC_NOT_APPROVED")


def test_disponibilidad_por_sql_directo_exige_kyc(tech_id, db):
    _raises_db(db, "UPDATE technician_profiles SET is_available = true WHERE user_id = :t", {"t": tech_id},
               "KYC_NOT_APPROVED")


# ------------------------------------------------------------ catálogos sembrados
def test_catalogos_sembrados_y_retencion_deshabilitada(db):
    assert db.scalar(text("SELECT count(*) FROM mx_states")) == 32
    assert db.scalar(text("SELECT name FROM mx_states WHERE id = 19")) == "Nuevo León"
    cats = set(db.scalars(text("SELECT category::text FROM document_types WHERE is_active")).all())
    assert cats == {"IDENTITY", "ADDRESS", "SELFIE", "BACKGROUND_CHECK"}
    assert db.scalar(text("SELECT count(*) FROM retention_policies WHERE is_enabled")) == 0
    assert db.scalar(text("SELECT is_active FROM document_types WHERE code = 'CURP_BIOMETRIC'")) is False
