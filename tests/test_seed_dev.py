"""scripts/seed_dev.py: usuarios de prueba para correr la guía 17.3 contra Stripe en modo prueba."""
import pytest
from sqlalchemy import select

from app.models import (
    AdminRoleAssignment,
    KycProfile,
    KycStatus,
    TechnicianPaymentAccount,
    User,
)
from scripts import seed_dev
from tests.conftest import API, auth, login
from tests.marketplace import ORDERS, create_order

PW = "Prueba-Seed-2026x"


def _headers(client, email):
    r = login(client, email, PW)
    assert r.status_code == 200, r.text
    return auth(r.json()["access_token"])


def test_deja_listo_al_tecnico_aprobado_y_a_finanzas(client, db, category, capsys):
    seed_dev.main(["--password", PW])
    assert PW in capsys.readouterr().out
    tech = db.scalar(select(User).where(User.email == seed_dev.TECH_EMAIL))
    assert db.scalar(select(KycProfile.status).where(KycProfile.technician_id == tech.id)) == KycStatus.APPROVED
    assert tech.technician_profile.is_available and tech.is_email_verified
    # Sin cuenta de Stripe: darla de alta es lo que se prueba.
    assert db.scalar(select(TechnicianPaymentAccount).where(TechnicianPaymentAccount.technician_id == tech.id)) \
        is None
    roles = {e: {r.value for r in db.scalars(select(AdminRoleAssignment.role).join(User, User.id == AdminRoleAssignment.user_id)
                                                     .where(User.email == e))}
             for e, _, _ in seed_dev.ADMINS}
    assert roles["finanzas.admin@example.com"] == {"FINANCE_ADMIN"}
    assert roles["kyc.supervisor@example.com"] == {"KYC_SUPERVISOR"}

    # Con esos usuarios, el flujo de la guía arranca: el técnico aprobado da de alta su cuenta de pagos.
    th, ch = _headers(client, seed_dev.TECH_EMAIL), _headers(client, seed_dev.CLIENT_EMAIL)
    assert client.post(f"{API}/technicians/me/payment-account", headers=th, json={}).status_code == 201
    oid = create_order(client, ch, category)["id"]
    assert client.get(f"{ORDERS}/{oid}", headers=ch).status_code == 200
    assert _headers(client, "finanzas.admin@example.com")


def test_se_puede_correr_dos_veces(client, db, category, capsys):
    seed_dev.main(["--password", PW])
    seed_dev.main([])                                    # contraseña nueva, mismos usuarios
    out = capsys.readouterr().out
    assert "ya existía" in out and "ya estaba aprobado" in out
    assert db.scalar(select(User.id).where(User.email == seed_dev.TECH_EMAIL))
    assert login(client, seed_dev.CLIENT_EMAIL, PW).status_code == 401    # la de la primera corrida ya no sirve


def test_contrasena_debil_se_rechaza(client, db, category):
    with pytest.raises(SystemExit, match="mayúsculas"):
        seed_dev.main(["--password", "solominusculas"])


def test_no_corre_en_produccion(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    with pytest.raises(SystemExit, match="producción"):
        seed_dev.main(["--password", PW])
