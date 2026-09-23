"""API de administración del KYC: permisos, IDOR/BOLA, cola enmascarada y roles."""
import uuid

import pytest
from sqlalchemy import select

from app.kyc.permissions import ROLE_PERMISSIONS, Permission, check_role_set, permissions_for
from app.models import AdminRegionScope, AdminRole, AuditLog, AuditResult, KycStatus, User
from tests.conftest import API, auth, drive_to, login, make_admin, register, valid_curp, valid_rfc

CASES = f"{API}/admin/kyc/cases"


def token(client, email: str) -> dict:
    return auth(login(client, email).json()["access_token"])


def new_tech(client, db, category, email: str) -> uuid.UUID:
    assert register(client, "technician", email, category_ids=[category.id]).status_code == 201
    return db.scalar(select(User.id).where(User.email == email))


@pytest.fixture
def case_under_review(client, db, category, reviewer, supervisor):
    """Un expediente en revisión asignado a `reviewer`."""
    tid = new_tech(client, db, category, "tec1@example.com")
    return drive_to(db, tid, KycStatus.UNDER_REVIEW, reviewer, supervisor, n=1)


def audits(db, action: str) -> list[AuditLog]:
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == action)).all()


# ------------------------------------------------------------------ mapa de permisos (unitario)
def test_superadmin_nunca_ve_expedientes_ni_decide():
    perms = ROLE_PERMISSIONS[AdminRole.SUPERADMIN]
    assert not perms & {Permission.KYC_CASE_READ_ANY, Permission.KYC_CASE_READ_ASSIGNED,
                        Permission.KYC_APPROVE, Permission.KYC_DOCUMENT_DECIDE}


def test_supervisor_incluye_todo_lo_del_revisor():
    assert ROLE_PERMISSIONS[AdminRole.KYC_REVIEWER] <= ROLE_PERMISSIONS[AdminRole.KYC_SUPERVISOR]


def test_revisor_no_rechaza_definitivo_ni_suspende():
    perms = ROLE_PERMISSIONS[AdminRole.KYC_REVIEWER]
    assert Permission.KYC_REJECT_FINAL not in perms and Permission.KYC_SUSPEND not in perms


@pytest.mark.parametrize("combo", [{AdminRole.SUPERADMIN, AdminRole.KYC_REVIEWER},
                                   {AdminRole.SUPERADMIN, AdminRole.KYC_SUPERVISOR}])
def test_combinaciones_prohibidas(combo):
    with pytest.raises(ValueError, match="Separación de funciones"):
        check_role_set(combo)


def test_permisos_se_suman_por_rol():
    both = permissions_for({AdminRole.SUPPORT, AdminRole.KYC_REVIEWER})
    assert Permission.USERS_READ in both and Permission.KYC_CASE_CLAIM in both


# ------------------------------------------------------------------ cola
def test_cola_requiere_permiso_y_audita_el_intento(client, db):
    make_admin(db, "finanzas@example.com", AdminRole.FINANCE_VIEWER)
    r = client.get(CASES, headers=token(client, "finanzas@example.com"))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "PERMISSION_DENIED"
    denied = audits(db, "admin.permission.denied")
    assert len(denied) == 1 and denied[0].result == AuditResult.DENIED


def test_admin_sin_ningun_rol_no_ve_nada(client, db):
    make_admin(db, "vacio@example.com")
    assert client.get(CASES, headers=token(client, "vacio@example.com")).status_code == 403


def test_tecnico_y_cliente_no_acceden_a_la_administracion(client, tech_tokens, client_tokens):
    for t in (tech_tokens, client_tokens):
        assert client.get(CASES, headers=auth(t["access_token"])).status_code == 403


def test_cola_solo_muestra_datos_enmascarados(client, db, case_under_review):
    r = client.get(CASES, headers=token(client, "revisor@example.com"))
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["technician_display"] == "Gloria H." and item["assigned_to_me"] is True
    for secret in (valid_curp(1), valid_rfc(1), "Hernández", "García", "tec1@example.com", "1956"):
        assert secret not in r.text


def test_cola_filtra_y_pagina(client, db, category, reviewer, supervisor):
    for i in range(3):
        tid = new_tech(client, db, category, f"t{i}@example.com")
        drive_to(db, tid, KycStatus.SUBMITTED, reviewer, supervisor, n=i + 2)
    h = token(client, "revisor@example.com")
    page1 = client.get(CASES, headers=h, params={"limit": 2}).json()
    assert len(page1["items"]) == 2 and page1["next_cursor"]
    page2 = client.get(CASES, headers=h, params={"limit": 2, "cursor": page1["next_cursor"]}).json()
    assert len(page2["items"]) == 1 and page2["next_cursor"] is None
    ids = [i["case_id"] for i in page1["items"] + page2["items"]]
    assert len(set(ids)) == 3                                              # sin repetidos ni saltos
    assert client.get(CASES, headers=h, params={"assigned": "me"}).json()["items"] == []
    assert client.get(CASES, headers=h, params={"cursor": "no-es-un-cursor"}).status_code == 422
    assert client.get(CASES, headers=h, params={"limit": 1000}).status_code == 422


def test_cola_respeta_la_region_del_revisor(client, db, case_under_review):
    db.add(AdminRegionScope(user_id=db.scalar(select(User.id).where(User.email == "revisor@example.com")),
                            state_id=19))  # Nuevo León; el caso es de Veracruz
    db.commit()
    assert client.get(CASES, headers=token(client, "revisor@example.com")).json()["items"] == []


# ------------------------------------------------------------------ expediente (IDOR / BOLA)
def test_revisor_asignado_ve_el_expediente_completo_y_queda_auditado(client, db, case_under_review):
    r = client.get(f"{CASES}/{case_under_review.id}", headers=token(client, "revisor@example.com"))
    assert r.status_code == 200
    body = r.json()
    assert body["curp"] == valid_curp(1) and body["rfc"] == valid_rfc(1)
    assert body["version"] == case_under_review.version and body["address"]["postal_code"] == "91700"
    assert [h["to_status"] for h in body["history"]][-1] == "UNDER_REVIEW"
    assert len(audits(db, "kyc.case.viewed")) == 1


def test_revisor_no_asignado_recibe_404_y_se_audita(client, db, case_under_review):
    make_admin(db, "revisor2@example.com", AdminRole.KYC_REVIEWER)
    r = client.get(f"{CASES}/{case_under_review.id}", headers=token(client, "revisor2@example.com"))
    assert r.status_code == 404 and r.json()["detail"]["code"] == "KYC_CASE_NOT_FOUND"
    denied = audits(db, "kyc.case.access_denied")
    assert len(denied) == 1 and denied[0].kyc_profile_id == case_under_review.id
    assert audits(db, "kyc.case.viewed") == []


def test_mismo_404_para_caso_ajeno_y_caso_inexistente(client, db, case_under_review):
    make_admin(db, "revisor2@example.com", AdminRole.KYC_REVIEWER)
    h = token(client, "revisor2@example.com")
    ajeno = client.get(f"{CASES}/{case_under_review.id}", headers=h)
    inexistente = client.get(f"{CASES}/{uuid.uuid4()}", headers=h)
    assert ajeno.status_code == inexistente.status_code == 404
    assert ajeno.json() == inexistente.json()                             # no revela cuál existe


def test_supervisor_ve_cualquier_expediente(client, db, case_under_review):
    assert client.get(f"{CASES}/{case_under_review.id}", headers=token(client, "supervisor@example.com")).status_code == 200


@pytest.mark.parametrize("role", [AdminRole.SUPPORT, AdminRole.SUPERADMIN])
def test_soporte_y_superadmin_no_ven_expedientes(role, client, db, case_under_review):
    make_admin(db, "otro@example.com", role)
    assert client.get(f"{CASES}/{case_under_review.id}", headers=token(client, "otro@example.com")).status_code == 404


def test_revisor_asignado_fuera_de_su_region_no_ve(client, db, case_under_review):
    rid = db.scalar(select(User.id).where(User.email == "revisor@example.com"))
    db.add(AdminRegionScope(user_id=rid, state_id=19))
    db.commit()
    assert client.get(f"{CASES}/{case_under_review.id}", headers=token(client, "revisor@example.com")).status_code == 404


def test_id_mal_formado_422(client, db, case_under_review):
    h = token(client, "supervisor@example.com")
    assert client.get(f"{CASES}/1 OR 1=1", headers=h).status_code == 422


def test_perder_la_asignacion_quita_el_acceso(client, db, case_under_review, reviewer):
    from app.core.actor import Actor
    from app.kyc.state_machine import transition
    h = token(client, "revisor@example.com")
    assert client.get(f"{CASES}/{case_under_review.id}", headers=h).status_code == 200
    transition(db, case_under_review.id, KycStatus.SUBMITTED, Actor.from_user(reviewer))  # libera el caso
    db.commit()
    assert client.get(f"{CASES}/{case_under_review.id}", headers=h).status_code == 404


# ------------------------------------------------------------------ roles
@pytest.fixture
def superadmin(client, db):
    make_admin(db, "root@example.com", AdminRole.SUPERADMIN)
    return token(client, "root@example.com")


def roles_url(uid) -> str:
    return f"{API}/admin/users/{uid}/roles"


def test_superadmin_asigna_roles_y_queda_auditado(client, db, superadmin):
    target = make_admin(db, "nuevo@example.com")
    r = client.put(roles_url(target.id), headers=superadmin, json={"roles": ["KYC_REVIEWER"]})
    assert r.status_code == 200 and r.json()["roles"] == ["KYC_REVIEWER"]
    assert "kyc:case:read_assigned" in r.json()["permissions"]
    entry = audits(db, "admin.roles.updated")[0]
    assert entry.changes == {"before": [], "after": ["KYC_REVIEWER"]}
    assert client.get(CASES, headers=token(client, "nuevo@example.com")).status_code == 200


def test_nadie_modifica_sus_propios_roles(client, db, superadmin):
    me = db.scalar(select(User.id).where(User.email == "root@example.com"))
    r = client.put(roles_url(me), headers=superadmin, json={"roles": ["SUPERADMIN", "KYC_SUPERVISOR"]})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "SELF_ROLE_CHANGE"
    assert len(audits(db, "admin.roles.self_change_denied")) == 1


def test_separacion_de_funciones_al_asignar(client, db, superadmin):
    target = make_admin(db, "nuevo@example.com")
    r = client.put(roles_url(target.id), headers=superadmin, json={"roles": ["SUPERADMIN", "KYC_SUPERVISOR"]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "ROLE_CONFLICT"


def test_quitarle_superadmin_a_otro_cierra_su_sesion_al_instante(client, db, superadmin):
    make_admin(db, "root2@example.com", AdminRole.SUPERADMIN)
    h2 = token(client, "root2@example.com")
    root = db.scalar(select(User.id).where(User.email == "root@example.com"))
    assert client.put(roles_url(root), headers=h2, json={"roles": []}).status_code == 200
    target = make_admin(db, "x@example.com")
    assert client.put(roles_url(target.id), headers=superadmin, json={"roles": []}).status_code == 401


def test_no_se_puede_quitar_el_ultimo_superadmin(client, db, monkeypatch):
    """
    Hoy solo un SUPERADMIN gestiona roles y no puede editarse a sí mismo, así que siempre
    queda al menos uno. La protección existe por si en el futuro otro rol recibe el permiso:
    se simula ese escenario.
    """
    from app.kyc import permissions as perms
    monkeypatch.setitem(perms.ROLE_PERMISSIONS, AdminRole.SUPPORT,
                        perms.ROLE_PERMISSIONS[AdminRole.SUPPORT] | {Permission.ADMIN_ROLES_MANAGE})
    solo = make_admin(db, "solo@example.com", AdminRole.SUPERADMIN)
    make_admin(db, "soporte@example.com", AdminRole.SUPPORT)
    r = client.put(roles_url(solo.id), headers=token(client, "soporte@example.com"), json={"roles": []})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "LAST_SUPERADMIN"


def test_quitar_privilegios_cierra_sesiones(client, db, superadmin):
    make_admin(db, "rev@example.com", AdminRole.KYC_REVIEWER)
    old = token(client, "rev@example.com")
    rid = db.scalar(select(User.id).where(User.email == "rev@example.com"))
    client.put(roles_url(rid), headers=superadmin, json={"roles": ["SUPPORT"]})
    assert client.get(f"{API}/users/me", headers=old).status_code == 401


def test_solo_superadmin_gestiona_roles(client, db, case_under_review):
    target = make_admin(db, "nuevo@example.com")
    r = client.put(roles_url(target.id), headers=token(client, "supervisor@example.com"),
                   json={"roles": ["KYC_SUPERVISOR"]})
    assert r.status_code == 403


def test_roles_solo_para_usuarios_administradores(client, db, superadmin, tech_tokens):
    tid = db.scalar(select(User.id).where(User.email == "tecnico@example.com"))
    assert client.put(roles_url(tid), headers=superadmin, json={"roles": ["KYC_REVIEWER"]}).status_code == 404
    assert client.put(roles_url(uuid.uuid4()), headers=superadmin, json={"roles": []}).status_code == 404
    assert client.put(roles_url(tid), headers=superadmin, json={"roles": ["GOD_MODE"]}).status_code == 422
