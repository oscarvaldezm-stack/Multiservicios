"""Máquina de estados del KYC contra PostgreSQL real."""
import threading

import pytest
from sqlalchemy import func, select

from app.core.actor import Actor
from app.db.session import SessionLocal
from app.kyc.state_machine import (
    ALLOWED_TRANSITIONS,
    ActorNotAllowed,
    InvalidTransition,
    NotAssignedReviewer,
    ReasonRequired,
    StaleVersion,
    Who,
    transition,
)
from app.models import (
    ActorType,
    AdminRole,
    AuditLog,
    KycProfile,
    KycStatus,
    KycStatusHistory,
    OutboxEvent,
    User,
)
from tests.conftest import drive_to, fill_profile, get_profile, make_admin, register

S = KycStatus
REASONS = {S.CORRECTION_REQUIRED: "CORRECCION_DOCUMENTOS", S.REJECTED: "FRAUDE_IDENTIDAD",
           S.SUSPENDED: "INVESTIGACION_EN_CURSO", S.EXPIRED: "DOCUMENTO_OBLIGATORIO_VENCIDO",
           S.UNDER_REVIEW: "REACTIVACION"}


@pytest.fixture
def tech_id(client, category, db):
    assert register(client, "technician", "tec@example.com", category_ids=[category.id]).status_code == 201
    return db.scalar(select(User.id).where(User.email == "tec@example.com"))


def actor_for(who: Who, profile: KycProfile, reviewer: User, supervisor: User) -> Actor:
    return {
        Who.TECHNICIAN: Actor(user_id=profile.technician_id, actor_type=ActorType.TECHNICIAN),
        Who.REVIEWER: Actor.from_user(reviewer),
        Who.SUPERVISOR: Actor.from_user(supervisor),
        Who.SYSTEM: Actor.system(),
    }[who]


# ------------------------------------------------------------ transiciones válidas
@pytest.mark.parametrize("pair", list(ALLOWED_TRANSITIONS), ids=lambda p: f"{p[0].value}->{p[1].value}")
def test_cada_transicion_valida_persiste_y_deja_rastro(pair, tech_id, reviewer, supervisor, db):
    frm, to = pair
    rule = ALLOWED_TRANSITIONS[pair]
    profile = drive_to(db, tech_id, frm, reviewer, supervisor)
    # En revisión, el caso está asignado al revisor: se usa a él si la regla lo permite.
    who = Who.REVIEWER if Who.REVIEWER in rule.who else sorted(rule.who, key=lambda w: w.value)[0]
    actor = actor_for(who, profile, reviewer, supervisor)
    version_before = profile.version
    reason = REASONS.get(to) if rule.reason_required else None
    if to == S.SUBMITTED and profile.curp_hash is None:
        fill_profile(db, profile)

    transition(db, profile.id, to, actor, reason_code=reason, expected_version=version_before)
    db.commit()

    with SessionLocal() as fresh:  # se relee en otra sesión: el cambio quedó en la base
        p = fresh.get(KycProfile, profile.id)
        assert p.status == to
        assert p.version == version_before + 1
        last = fresh.scalars(select(KycStatusHistory).where(KycStatusHistory.kyc_profile_id == p.id)
                             .order_by(KycStatusHistory.id.desc())).first()
        assert (last.from_status, last.to_status, last.actor_type) == (frm, to, actor.actor_type)
        assert last.reason_code == reason
        audit = fresh.scalars(select(AuditLog).where(AuditLog.kyc_profile_id == p.id)
                              .order_by(AuditLog.id.desc())).first()
        assert audit.action == f"kyc.status.{to.value.lower()}"
        assert audit.changes["status"] == {"from": frm.value, "to": to.value}
        events = fresh.scalar(select(func.count()).select_from(OutboxEvent)
                              .where(OutboxEvent.aggregate_id == p.id, OutboxEvent.event_type == rule.notify))
        assert (events >= 1) if rule.notify else True


# ------------------------------------------------------------ transiciones inválidas
@pytest.mark.parametrize("frm", list(S), ids=lambda s: s.value)
def test_todas_las_transiciones_no_listadas_se_rechazan(frm, tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, frm, reviewer, supervisor)
    sys_actor = Actor.system()
    for to in S:
        if (frm, to) in ALLOWED_TRANSITIONS:
            continue
        with pytest.raises(InvalidTransition):
            transition(db, profile.id, to, sys_actor, reason_code="X")
    db.rollback()
    assert db.get(KycProfile, profile.id).status == frm


# ------------------------------------------------------------ quién puede
def test_tecnico_no_puede_mover_expediente_ajeno(tech_id, client, category, db):
    register(client, "technician", "otro@example.com", category_ids=[category.id])
    otro = db.scalar(select(User.id).where(User.email == "otro@example.com"))
    profile = get_profile(db, tech_id)
    with pytest.raises(ActorNotAllowed):
        transition(db, profile.id, S.PENDING_DOCUMENTS, Actor(user_id=otro, actor_type=ActorType.TECHNICIAN))


def test_cliente_no_es_actor_valido(client_tokens, db):
    cliente = db.scalar(select(User).where(User.email == "cliente@example.com"))
    with pytest.raises(PermissionError):
        Actor.from_user(cliente)


def test_admin_sin_rol_kyc_no_puede_revisar(tech_id, reviewer, supervisor, db):
    soporte = make_admin(db, "soporte@example.com", AdminRole.SUPPORT, AdminRole.SUPERADMIN)
    profile = drive_to(db, tech_id, S.SUBMITTED, reviewer, supervisor)
    with pytest.raises(ActorNotAllowed):
        transition(db, profile.id, S.UNDER_REVIEW, Actor.from_user(soporte))


def test_revisor_no_puede_rechazar_definitivamente(tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.UNDER_REVIEW, reviewer, supervisor)
    with pytest.raises(ActorNotAllowed):
        transition(db, profile.id, S.REJECTED, Actor.from_user(reviewer), reason_code="FRAUDE_IDENTIDAD")


def test_revisor_no_asignado_no_puede_decidir(tech_id, reviewer, supervisor, db):
    otro_revisor = make_admin(db, "revisor2@example.com", AdminRole.KYC_REVIEWER)
    profile = drive_to(db, tech_id, S.UNDER_REVIEW, reviewer, supervisor)
    assert profile.assigned_reviewer_id == reviewer.id
    with pytest.raises(NotAssignedReviewer):
        transition(db, profile.id, S.APPROVED, Actor.from_user(otro_revisor))
    # Un supervisor sí puede decidir aunque el caso esté asignado a otro revisor.
    transition(db, profile.id, S.APPROVED, Actor.from_user(supervisor))


def test_solo_el_sistema_marca_como_vencido(tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.APPROVED, reviewer, supervisor)
    with pytest.raises(ActorNotAllowed):
        transition(db, profile.id, S.EXPIRED, Actor.from_user(supervisor), reason_code="X")


@pytest.mark.parametrize("target", [S.CORRECTION_REQUIRED, S.REJECTED])
def test_decisiones_negativas_exigen_motivo(target, tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.UNDER_REVIEW, reviewer, supervisor)
    with pytest.raises(ReasonRequired):
        transition(db, profile.id, target, Actor.from_user(supervisor))


def test_suspension_exige_motivo(tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.APPROVED, reviewer, supervisor)
    with pytest.raises(ReasonRequired):
        transition(db, profile.id, S.SUSPENDED, Actor.from_user(supervisor))


# ------------------------------------------------------------ efectos
def test_ciclos_asignacion_y_aprobador(tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.CORRECTION_REQUIRED, reviewer, supervisor)
    assert profile.cycle == 1 and profile.assigned_reviewer_id is None
    tech = Actor(user_id=tech_id, actor_type=ActorType.TECHNICIAN)
    transition(db, profile.id, S.SUBMITTED, tech)
    assert profile.cycle == 2                                   # reenvío = ciclo nuevo
    transition(db, profile.id, S.UNDER_REVIEW, Actor.from_user(reviewer))
    assert profile.assigned_reviewer_id == reviewer.id
    transition(db, profile.id, S.SUBMITTED, Actor.from_user(reviewer))   # libera el caso
    assert profile.assigned_reviewer_id is None and profile.cycle == 2  # liberar NO abre ciclo
    transition(db, profile.id, S.UNDER_REVIEW, Actor.from_user(reviewer))
    transition(db, profile.id, S.APPROVED, Actor.from_user(reviewer))
    db.commit()
    assert profile.approved_by_id == reviewer.id and profile.approved_at is not None


def test_version_obsoleta_se_rechaza(tech_id, reviewer, supervisor, db):
    profile = drive_to(db, tech_id, S.UNDER_REVIEW, reviewer, supervisor)
    with pytest.raises(StaleVersion):
        transition(db, profile.id, S.APPROVED, Actor.from_user(reviewer), expected_version=profile.version - 1)


def test_dos_decisiones_simultaneas_no_se_pisan(tech_id, reviewer, supervisor, db):
    """
    Sesión A aprueba y aún no hace commit. Sesión B intenta pedir corrección al mismo
    tiempo: queda bloqueada por FOR UPDATE, y al liberarse ve APPROVED y falla.
    """
    profile = drive_to(db, tech_id, S.UNDER_REVIEW, reviewer, supervisor)
    rev_actor, sup_actor = Actor.from_user(reviewer), Actor.from_user(supervisor)
    a = SessionLocal()
    transition(a, profile.id, S.APPROVED, rev_actor)          # bloquea la fila

    result: dict[str, object] = {}

    def session_b():
        with SessionLocal() as b:
            try:
                transition(b, profile.id, S.CORRECTION_REQUIRED, sup_actor, reason_code="CORRECCION_DOCUMENTOS")
                b.commit()
                result["b"] = "ok"
            except Exception as exc:  # noqa: BLE001
                result["b"] = exc

    t = threading.Thread(target=session_b)
    t.start()
    t.join(timeout=1.0)
    assert t.is_alive(), "B debería estar esperando el bloqueo de A"
    a.commit()
    a.close()
    t.join(timeout=10)
    assert isinstance(result["b"], InvalidTransition)
    db.expire_all()
    assert db.get(KycProfile, profile.id).status == S.APPROVED
