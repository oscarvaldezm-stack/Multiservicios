"""
Las pruebas corren contra un PostgreSQL REAL (base separada), no SQLite: los ENUM,
CHECK, FOR UPDATE y sobre todo los TRIGGERS del KYC solo existen en PostgreSQL.
El esquema se crea ejecutando las migraciones de Alembic, igual que en producción.

    export TEST_DATABASE_URL=postgresql+psycopg://usuario:pass@localhost:5432/multiservicios_test
    pytest -v
"""
import base64
import os

os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://multiservicios_app:dev_pass_local@localhost:5432/multiservicios_test",
)
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-que-solo-se-usa-en-pruebas-0123456789")
# Llaves fijas SOLO para pruebas (32 bytes en base64url). Nunca reutilizarlas en otro entorno.
os.environ.setdefault("KYC_MASTER_KEY", base64.urlsafe_b64encode(b"m" * 32).decode())
os.environ.setdefault("KYC_BLIND_INDEX_KEY", base64.urlsafe_b64encode(b"b" * 32).decode())
os.environ.setdefault("INTEGRITY_KEY", base64.urlsafe_b64encode(b"i" * 32).decode())
os.environ["BCRYPT_ROUNDS"] = "4"  # rápido en pruebas; en producción >= 12
os.environ["ENVIRONMENT"] = "development"
os.environ["ALLOWED_HOSTS"] = '["testserver"]'
import tempfile as _tempfile  # noqa: E402
os.environ["STORAGE_BACKEND"] = "local"
os.environ["STORAGE_LOCAL_ROOT"] = _tempfile.mkdtemp(prefix="kyc-storage-test-")
os.environ["KYC_SCANNER"] = "dev_eicar"

from datetime import date  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

import app.models  # noqa: E402, F401
from app.core.actor import Actor  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.kyc import identity  # noqa: E402
from app.kyc.state_machine import transition  # noqa: E402
from app.kyc.validators import _curp_check_digit, _rfc_check_digit  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    ActorType,
    AdminRole,
    AdminRoleAssignment,
    KycAddress,
    KycProfile,
    KycStatus,
    MxMunicipality,
    ServiceCategory,
    User,
    UserRole,
)

API = "/api/v1"
STRONG_PW = "ClaveSegura123"
ROOT = Path(__file__).resolve().parents[1]

# Tablas sembradas por la migración: no se vacían entre pruebas.
SEEDED = {"countries", "mx_states", "document_types", "rejection_reasons", "retention_policies", "alembic_version"}


def alembic_config() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return cfg


@pytest.fixture(scope="session", autouse=True)
def _schema():
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    command.upgrade(alembic_config(), "head")
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    yield
    with engine.begin() as conn:
        names = conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars().all()
        tables = ", ".join(f'"{n}"' for n in names if n not in SEEDED)  # nombres del catálogo del sistema
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        _seed_key_metadata(conn)
        _seed_commission_rule(conn)


def _seed_commission_rule(conn) -> None:
    """Deja la regla GLOBAL que siembra la migración 0006 (las pruebas de comisiones crean otras)."""
    import importlib

    mig = importlib.import_module("migrations.versions.0006_pagos_fase1_modelo_comisiones_y_ledger")
    conn.execute(text(
        "INSERT INTO commission_rules (scope, type, rate_bp, min_cents, valid_from, note) "
        "VALUES ('GLOBAL', 'PERCENT', :r, :m, '2026-01-01T00:00:00Z', 'Regla global inicial (migración 0006)')"
    ), {"r": mig.GLOBAL_RATE_BP, "m": mig.GLOBAL_MIN_CENTS})


def _seed_key_metadata(conn) -> None:
    """Deja encryption_keys_metadata como la deja la migración 0004 (las pruebas de rotación la cambian)."""
    from app.core.config import get_settings
    from app.core.crypto import _b64_key, key_fingerprint

    s = get_settings()
    for purpose, key_id, raw in (("KYC_KEK", s.KYC_MASTER_KEY_ID, s.KYC_MASTER_KEY),
                                 ("BLIND_INDEX", 1, s.KYC_BLIND_INDEX_KEY)):
        conn.execute(text(
            "INSERT INTO encryption_keys_metadata (purpose, key_id, status, provider, fingerprint, activated_at) "
            "VALUES (CAST(:p AS key_purpose), :k, 'ACTIVE', 'local', :fp, now())"
        ), {"p": purpose, "k": key_id, "fp": key_fingerprint(_b64_key(raw.get_secret_value(), purpose))})


@pytest.fixture(autouse=True)
def _reset_fake_provider():
    """El proveedor falso vive en memoria durante todo el proceso: se vacía entre pruebas."""
    from app.payments.providers import get_provider

    get_provider().reset()
    yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def category(db) -> ServiceCategory:
    c = ServiceCategory(name="Plomería", slug="plomeria")
    db.add(c)
    db.commit()
    return c


def register(client, kind: str, email: str, **extra):
    body = {"email": email, "password": STRONG_PW, "full_name": "Usuario Prueba", **extra}
    return client.post(f"{API}/auth/register/{kind}", json=body)


def login(client, email: str, password: str = STRONG_PW):
    return client.post(f"{API}/auth/token", data={"username": email, "password": password})


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client_tokens(client):
    assert register(client, "client", "cliente@example.com").status_code == 201
    return login(client, "cliente@example.com").json()


@pytest.fixture
def tech_tokens(client, category):
    r = register(client, "technician", "tecnico@example.com", category_ids=[category.id])
    assert r.status_code == 201, r.text
    return login(client, "tecnico@example.com").json()


def make_admin(db, email: str, *roles: AdminRole) -> User:
    user = User(email=email, hashed_password=hash_password(STRONG_PW), role=UserRole.ADMIN, full_name="Admin")
    db.add(user)
    db.flush()
    for r in roles:
        db.add(AdminRoleAssignment(user_id=user.id, role=r))
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_tokens(client, db):
    make_admin(db, "admin@example.com", AdminRole.SUPERADMIN)
    return login(client, "admin@example.com").json()


@pytest.fixture
def reviewer(db) -> User:
    return make_admin(db, "revisor@example.com", AdminRole.KYC_REVIEWER)


@pytest.fixture
def supervisor(db) -> User:
    return make_admin(db, "supervisor@example.com", AdminRole.KYC_SUPERVISOR)


# ---------------------------------------------------------------------------
# Identidades válidas de prueba (dígito verificador correcto, misma fecha: 1956-04-27)
# ---------------------------------------------------------------------------
BIRTH = date(1956, 4, 27)


def valid_curp(n: int = 4) -> str:
    """n=4 reproduce el ejemplo oficial de RENAPO HEGG560427MVZRRL04."""
    base = f"HEGG560427MVZRRL{n % 10}"
    return base + _curp_check_digit(base)


def valid_rfc(n: int = 0) -> str:
    base = f"HEGG560427A{n % 10}"
    return base + _rfc_check_digit(base)


def municipality(db) -> MxMunicipality:
    m = db.scalar(select(MxMunicipality).where(MxMunicipality.state_id == 30, MxMunicipality.inegi_code == 193))
    if m is None:
        m = MxMunicipality(state_id=30, inegi_code=193, name="Veracruz")
        db.add(m)
        db.flush()
    return m


def get_profile(db, technician_id) -> KycProfile:
    return db.scalar(select(KycProfile).where(KycProfile.technician_id == technician_id))


def fill_profile(db, profile: KycProfile, n: int = 4) -> None:
    """Datos completos: identidad cifrada + domicilio actual."""
    tech_actor = Actor(user_id=profile.technician_id, actor_type=ActorType.TECHNICIAN)
    identity.set_identity(db, profile, tech_actor, first_names="Gloria", paternal_surname="Hernández",
                          maternal_surname="García", birth_date=BIRTH, curp=valid_curp(n), rfc=valid_rfc(n))
    m = municipality(db)
    addr = KycAddress(kyc_profile_id=profile.id, street="Av. Independencia", exterior_number="100",
                      settlement="Centro", postal_code="91700", city="Veracruz",
                      municipality_id=m.id, state_id=30)
    db.add(addr)
    db.flush()
    profile.current_address_id = addr.id
    db.flush()


def drive_to(db, technician_id, target: KycStatus, reviewer: User, supervisor: User, n: int = 4) -> KycProfile:
    """Lleva un expediente recién creado al estado pedido por un camino válido."""
    profile = get_profile(db, technician_id)
    tech = Actor(user_id=technician_id, actor_type=ActorType.TECHNICIAN)
    rev, sup = Actor.from_user(reviewer), Actor.from_user(supervisor)
    path = {
        KycStatus.NOT_STARTED: [],
        KycStatus.PENDING_DOCUMENTS: [(KycStatus.PENDING_DOCUMENTS, tech, None)],
        KycStatus.SUBMITTED: [(KycStatus.PENDING_DOCUMENTS, tech, None), (KycStatus.SUBMITTED, tech, None)],
    }
    base = path[KycStatus.SUBMITTED] + [(KycStatus.UNDER_REVIEW, rev, None)]
    path[KycStatus.UNDER_REVIEW] = base
    path[KycStatus.APPROVED] = base + [(KycStatus.APPROVED, rev, None)]
    path[KycStatus.CORRECTION_REQUIRED] = base + [(KycStatus.CORRECTION_REQUIRED, rev, "CORRECCION_DOCUMENTOS")]
    path[KycStatus.REJECTED] = base[:-1] + [(KycStatus.UNDER_REVIEW, sup, None),
                                            (KycStatus.REJECTED, sup, "FRAUDE_IDENTIDAD")]
    path[KycStatus.SUSPENDED] = path[KycStatus.APPROVED] + [(KycStatus.SUSPENDED, sup, "INVESTIGACION_EN_CURSO")]
    path[KycStatus.EXPIRED] = path[KycStatus.APPROVED] + [
        (KycStatus.EXPIRED, Actor.system(), "DOCUMENTO_OBLIGATORIO_VENCIDO")]

    for to, actor, reason in path[target]:
        if to == KycStatus.SUBMITTED and profile.curp_hash is None:
            fill_profile(db, profile, n)
        transition(db, profile.id, to, actor, reason_code=reason)
    db.commit()
    db.refresh(profile)
    return profile


# ---------------------------------------------------------------------------
# Documentos simulados (la subida real llega en la Fase 3)
# ---------------------------------------------------------------------------
def add_document(db, profile: KycProfile, code: str, *, issued_at=None, expires_at=None, address_id=None,
                 files: int | None = None, scan=None, status=None):
    import hashlib
    import uuid as _uuid

    from app.models import DocumentType, KycDocument, KycDocumentFile, KycDocumentStatus, ScanStatus

    dt = db.scalar(select(DocumentType).where(DocumentType.code == code))
    doc = KycDocument(kyc_profile_id=profile.id, document_type_id=dt.id, issued_at=issued_at,
                      expires_at=expires_at, address_id=address_id,
                      status=status or KycDocumentStatus.PENDING_REVIEW)
    db.add(doc)
    db.flush()
    for i in range(files if files is not None else dt.sides_required):
        key = f"kyc/{profile.id}/{_uuid.uuid4()}"
        db.add(KycDocumentFile(document_id=doc.id, side="FRONT" if i == 0 else "BACK", bucket="kyc-clean",
                               object_key=key, detected_mime="image/jpeg", size_bytes=1000,
                               sha256=hashlib.sha256(key.encode()).hexdigest(),
                               scan_status=scan or ScanStatus.CLEAN,
                               file_key_enc=b"\x01simulado"))  # archivo simulado: nunca se lee
    db.flush()
    return doc


def add_required_documents(db, profile: KycProfile, *, proof_age_days: int = 10):
    from datetime import date as _date, timedelta

    today = _date.today()
    add_document(db, profile, "INE", expires_at=today + timedelta(days=365 * 3))
    add_document(db, profile, "UTILITY_ELECTRICITY", issued_at=today - timedelta(days=proof_age_days),
                 address_id=profile.current_address_id)
    add_document(db, profile, "SELFIE_WITH_ID")
    db.commit()


def verify_email(db, user_id) -> None:
    db.execute(text("UPDATE users SET is_email_verified = true WHERE id = :id"), {"id": user_id})
    db.commit()
