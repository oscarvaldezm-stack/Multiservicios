from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import select

from app.models import KycStatus, RefreshToken, TechnicianProfile, User
from tests.conftest import API, STRONG_PW, auth, drive_to, login, register


# --------------------------------------------------------------------------- registro
def test_registro_cliente_guarda_hash_bcrypt_y_no_lo_expone(client, db):
    r = register(client, "client", "Ana@Example.com")
    assert r.status_code == 201
    body = r.json()
    assert body["role"] == "client"
    assert body["email"] == "ana@example.com"  # normalizado
    assert "password" not in str(body) and "hashed" not in str(body)

    user = db.scalar(select(User).where(User.email == "ana@example.com"))
    assert user.hashed_password.startswith("$2b$")
    assert STRONG_PW not in user.hashed_password


def test_no_se_puede_auto_asignar_rol_admin(client):
    r = register(client, "client", "x@example.com", role="admin")
    assert r.status_code == 422  # extra="forbid" rechaza el campo


def test_tecnico_no_puede_auto_verificarse_al_registrarse(client, category):
    r = register(client, "technician", "t@example.com", kyc_status="APPROVED")
    assert r.status_code == 422


def test_contrasena_debil_rechazada(client):
    r = client.post(f"{API}/auth/register/client",
                    json={"email": "d@example.com", "password": "12345678", "full_name": "Débil"})
    assert r.status_code == 422


def test_contrasena_mayor_a_72_bytes_rechazada(client):
    r = client.post(f"{API}/auth/register/client",
                    json={"email": "l@example.com", "password": "Aa1" + "ñ" * 40, "full_name": "Larga"})
    assert r.status_code == 422


def test_email_duplicado(client):
    assert register(client, "client", "dup@example.com").status_code == 201
    assert register(client, "technician", "DUP@example.com").status_code == 409


# --------------------------------------------------------------------------- login
def test_login_ok_y_me(client, client_tokens):
    assert client_tokens["token_type"] == "bearer"
    r = client.get(f"{API}/users/me", headers=auth(client_tokens["access_token"]))
    assert r.status_code == 200 and r.json()["email"] == "cliente@example.com"


def test_login_mismo_error_si_usuario_no_existe_o_password_mala(client, client_tokens):
    a = login(client, "noexiste@example.com")
    b = login(client, "cliente@example.com", "OtraClave999")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_inyeccion_sql_en_login_no_rompe_nada(client, client_tokens, db):
    for payload in ["' OR '1'='1", "cliente@example.com'--", "'; DROP TABLE users; --"]:
        r = login(client, payload, "' OR '1'='1")
        assert r.status_code == 401
    assert db.scalar(select(User).where(User.email == "cliente@example.com")) is not None


def test_bloqueo_por_intentos_fallidos(client, client_tokens):
    for _ in range(5):
        assert login(client, "cliente@example.com", "Incorrecta123").status_code == 401
    # Aun con la contraseña correcta, la cuenta queda bloqueada
    assert login(client, "cliente@example.com").status_code == 423


# --------------------------------------------------------------------------- JWT
def test_token_manipulado_rechazado(client, client_tokens):
    token = client_tokens["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    payload["role"] = "admin"
    forged = jwt.encode(payload, "clave-del-atacante-que-no-conoce-la-real-xxxxx", algorithm="HS256")
    assert client.get(f"{API}/users/me", headers=auth(forged)).status_code == 401


def test_token_alg_none_rechazado(client, client_tokens):
    payload = jwt.decode(client_tokens["access_token"], options={"verify_signature": False})
    unsigned = jwt.encode(payload, None, algorithm="none")
    assert client.get(f"{API}/users/me", headers=auth(unsigned)).status_code == 401


def test_token_expirado_rechazado(client, client_tokens):
    from app.core.config import get_settings
    s = get_settings()
    payload = jwt.decode(client_tokens["access_token"], options={"verify_signature": False})
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    payload.update(iat=past, nbf=past, exp=past + timedelta(minutes=1))
    expired = jwt.encode(payload, s.JWT_SECRET_KEY.get_secret_value(), algorithm=s.JWT_ALGORITHM)
    assert client.get(f"{API}/users/me", headers=auth(expired)).status_code == 401


def test_refresh_token_no_sirve_como_access_token(client, client_tokens):
    assert client.get(f"{API}/users/me", headers=auth(client_tokens["refresh_token"])).status_code == 401


# --------------------------------------------------------------------------- roles
def test_cliente_no_accede_a_rutas_de_tecnico_ni_admin(client, client_tokens):
    h = auth(client_tokens["access_token"])
    assert client.get(f"{API}/clients/me/profile", headers=h).status_code == 200
    assert client.get(f"{API}/technicians/me/profile", headers=h).status_code == 403
    assert client.get(f"{API}/admin/users", headers=h).status_code == 403


def test_tecnico_no_accede_a_rutas_de_cliente_ni_admin(client, tech_tokens):
    h = auth(tech_tokens["access_token"])
    assert client.get(f"{API}/technicians/me/profile", headers=h).status_code == 200
    assert client.get(f"{API}/clients/me/profile", headers=h).status_code == 403
    assert client.get(f"{API}/admin/users", headers=h).status_code == 403


def test_sin_token_401(client):
    assert client.get(f"{API}/clients/me/profile").status_code == 401


def test_tecnico_no_puede_editar_campos_protegidos(client, tech_tokens):
    h = auth(tech_tokens["access_token"])
    r = client.patch(f"{API}/technicians/me/profile", headers=h, json={"rating_avg": 5})
    assert r.status_code == 422
    r = client.patch(f"{API}/technicians/me/profile", headers=h, json={"bio": "10 años de experiencia"})
    assert r.status_code == 200 and r.json()["bio"] == "10 años de experiencia"


def test_tecnico_sin_kyc_aprobado_no_ve_trabajos_hasta_que_se_aprueba(client, tech_tokens, reviewer, supervisor, db):
    h = auth(tech_tokens["access_token"])
    r = client.get(f"{API}/technicians/me/jobs-feed", headers=h)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "KYC_NOT_APPROVED"

    tech_id = db.scalar(select(User.id).where(User.email == "tecnico@example.com"))
    drive_to(db, tech_id, KycStatus.APPROVED, reviewer, supervisor)
    assert client.get(f"{API}/technicians/me/jobs-feed", headers=h).status_code == 200


def test_perfil_tecnico_muestra_estado_kyc(client, tech_tokens):
    r = client.get(f"{API}/technicians/me/profile", headers=auth(tech_tokens["access_token"]))
    assert r.status_code == 200 and r.json()["kyc_status"] == "NOT_STARTED"


def test_tecnico_no_puede_marcarse_disponible_sin_kyc(client, tech_tokens):
    r = client.patch(f"{API}/technicians/me/profile", headers=auth(tech_tokens["access_token"]),
                     json={"is_available": True})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "KYC_NOT_APPROVED"


def test_endpoint_viejo_de_aprobacion_ya_no_existe(client, admin_tokens, tech_tokens, db):
    tech_id = db.scalar(select(TechnicianProfile.user_id))
    r = client.post(f"{API}/admin/technicians/{tech_id}/verification",
                    headers=auth(admin_tokens["access_token"]), json={"status": "approved"})
    assert r.status_code in (404, 405)


def test_path_param_con_inyeccion_rechazado(client, admin_tokens):
    r = client.post(f"{API}/admin/users/1 OR 1=1/deactivate", headers=auth(admin_tokens["access_token"]))
    assert r.status_code == 422


def test_cambio_de_rol_o_desactivacion_surte_efecto_inmediato(client, client_tokens, admin_tokens, db):
    uid = db.scalar(select(User.id).where(User.email == "cliente@example.com"))
    r = client.post(f"{API}/admin/users/{uid}/deactivate", headers=auth(admin_tokens["access_token"]))
    assert r.status_code == 204
    assert client.get(f"{API}/users/me", headers=auth(client_tokens["access_token"])).status_code == 401


# --------------------------------------------------------------------------- refresh
def test_refresh_rota_el_token(client, client_tokens):
    r = client.post(f"{API}/auth/refresh", json={"refresh_token": client_tokens["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != client_tokens["refresh_token"]
    assert client.get(f"{API}/users/me", headers=auth(new["access_token"])).status_code == 200


def test_reuso_de_refresh_revoca_toda_la_sesion(client, client_tokens, db):
    old = client_tokens["refresh_token"]
    new = client.post(f"{API}/auth/refresh", json={"refresh_token": old}).json()

    # Un atacante reutiliza el token viejo robado
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": old}).status_code == 401
    # ...y como consecuencia el token legítimo nuevo también queda revocado
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401
    assert client.get(f"{API}/users/me", headers=auth(new["access_token"])).status_code == 401


def test_logout_all_invalida_access_token(client, client_tokens):
    h = auth(client_tokens["access_token"])
    assert client.post(f"{API}/auth/logout-all", headers=h).status_code == 204
    assert client.get(f"{API}/users/me", headers=h).status_code == 401
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": client_tokens["refresh_token"]}).status_code == 401


def test_refresh_se_guarda_hasheado(client, client_tokens, db):
    hashes = db.scalars(select(RefreshToken.token_hash)).all()
    assert client_tokens["refresh_token"] not in hashes
    assert all(len(h) == 64 for h in hashes)


def test_headers_de_seguridad(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
