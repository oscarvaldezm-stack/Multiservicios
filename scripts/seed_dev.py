"""
SOLO DESARROLLO: deja lista la base para probar pagos contra Stripe en modo prueba.

    docker compose exec api python -m scripts.seed_dev                # contraseña aleatoria
    docker compose exec api python -m scripts.seed_dev --password 'MiClave-Prueba-2026'

Crea (o actualiza, si ya existen) estos usuarios con el correo verificado:

    finanzas.admin@example.com     FINANCE_ADMIN     segunda firma, reglas, políticas de cancelación
    finanzas.operador@example.com  FINANCE_OPERATOR  reembolsos hasta el umbral, disputas, alertas
    kyc.revisor@example.com        KYC_REVIEWER      (quien "aprobó" al técnico)
    kyc.supervisor@example.com     KYC_SUPERVISOR    revisión de nombre de la cuenta de pagos
    cliente@example.com            cliente
    tecnico@example.com            técnico con KYC APROBADO y disponible en todas las categorías

El técnico queda aprobado SIN documentos reales (datos de identidad de ejemplo, válidos solo en
formato). NO se le crea la cuenta de Stripe: darla de alta es justo lo que vas a probar (guía 17.3).

Todos los usuarios comparten la contraseña que se imprime al final. Cada ejecución la cambia
(salvo que pases --password). Se niega a correr con ENVIRONMENT=production.
"""
from __future__ import annotations

import argparse
import secrets
from datetime import date

from sqlalchemy import select

from app.core.actor import Actor
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.kyc import identity
from app.kyc.identity import create_kyc_profile
from app.kyc.permissions import check_role_set
from app.kyc.state_machine import transition
from app.kyc.validators import _curp_check_digit, _rfc_check_digit
from app.models import (
    ActorType,
    AdminRole,
    AdminRoleAssignment,
    ClientProfile,
    KycAddress,
    KycProfile,
    KycStatus,
    MxMunicipality,
    ServiceCategory,
    TechnicianProfile,
    TechnicianService,
    User,
    UserRole,
)
from app.schemas.auth import _validate_password_strength

S = KycStatus

ADMINS = [
    ("finanzas.admin@example.com", "Finanzas Admin", {AdminRole.FINANCE_ADMIN}),
    ("finanzas.operador@example.com", "Finanzas Operador", {AdminRole.FINANCE_OPERATOR}),
    ("kyc.revisor@example.com", "KYC Revisor", {AdminRole.KYC_REVIEWER}),
    ("kyc.supervisor@example.com", "KYC Supervisor", {AdminRole.KYC_SUPERVISOR}),
]
CLIENT_EMAIL = "cliente@example.com"
TECH_EMAIL = "tecnico@example.com"

# Identidad de ejemplo (formato válido con dígito verificador; no corresponde a una persona real).
_CURP_BASE = "HEGG560427MVZRRL4"
_RFC_BASE = "HEGG560427A0"


def _password(given: str | None) -> str:
    if given:
        return _validate_password_strength(given)
    return f"Prueba-{secrets.token_urlsafe(9)}-7a"


def _user(db, email: str, name: str, role: UserRole, pw_hash: str) -> tuple[User, bool]:
    user = db.scalar(select(User).where(User.email == email))
    created = user is None
    if created:
        user = User(email=email, full_name=name, role=role, hashed_password=pw_hash, is_email_verified=True)
        db.add(user)
        db.flush()
    elif user.role != role:
        raise SystemExit(f"{email} ya existe con rol {user.role.value}; bórralo o usa otra base.")
    else:
        user.hashed_password = pw_hash
        user.is_email_verified = True
    user.is_active = True
    return user, created


def _admin_roles(db, user: User, roles: set[AdminRole]) -> None:
    check_role_set(roles)
    have = set(db.scalars(select(AdminRoleAssignment.role).where(AdminRoleAssignment.user_id == user.id)).all())
    for role in roles - have:
        db.add(AdminRoleAssignment(user_id=user.id, role=role))


def _municipality(db) -> MxMunicipality:
    m = db.scalar(select(MxMunicipality).where(MxMunicipality.state_id == 30, MxMunicipality.inegi_code == 193))
    if m is None:                       # sin catálogo SEPOMEX cargado: Veracruz, Ver.
        m = MxMunicipality(state_id=30, inegi_code=193, name="Veracruz")
        db.add(m)
        db.flush()
    return m


def _approve_technician(db, tech: User, reviewer: User) -> str:
    profile = db.scalar(select(KycProfile).where(KycProfile.technician_id == tech.id))
    if profile is None:
        profile = create_kyc_profile(db, tech.id)
    if profile.status == S.APPROVED:
        return "ya estaba aprobado"
    if profile.status not in (S.NOT_STARTED, S.PENDING_DOCUMENTS):
        raise SystemExit(f"El KYC del técnico está en {profile.status.value}; usa una base limpia "
                         "(docker compose down -v) o apruébalo desde el panel.")
    tech_actor = Actor(user_id=tech.id, actor_type=ActorType.TECHNICIAN)
    rev = Actor.from_user(reviewer)
    if profile.status == S.NOT_STARTED:
        transition(db, profile.id, S.PENDING_DOCUMENTS, tech_actor)
    if profile.curp_hash is None:
        identity.set_identity(db, profile, tech_actor, first_names="Gloria", paternal_surname="Hernández",
                              maternal_surname="García", birth_date=date(1956, 4, 27),
                              curp=_CURP_BASE + _curp_check_digit(_CURP_BASE),
                              rfc=_RFC_BASE + _rfc_check_digit(_RFC_BASE))
        m = _municipality(db)
        addr = KycAddress(kyc_profile_id=profile.id, street="Av. Independencia", exterior_number="100",
                          settlement="Centro", postal_code="91700", city="Veracruz", municipality_id=m.id,
                          state_id=30)
        db.add(addr)
        db.flush()
        profile.current_address_id = addr.id
        db.flush()
    transition(db, profile.id, S.SUBMITTED, tech_actor)
    transition(db, profile.id, S.UNDER_REVIEW, rev)
    transition(db, profile.id, S.APPROVED, rev, note="Aprobado por scripts.seed_dev (solo desarrollo)")
    return "aprobado ahora"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="seed_dev", description="Usuarios de prueba para desarrollo")
    parser.add_argument("--password", help="contraseña para todos (mayúsculas, minúsculas y números; 10+)")
    args = parser.parse_args(argv)
    if get_settings().is_production:
        raise SystemExit("seed_dev no se ejecuta en producción.")
    try:
        password = _password(args.password)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    pw_hash = hash_password(password)

    with SessionLocal() as db:
        categories = db.scalars(select(ServiceCategory).where(ServiceCategory.is_active.is_(True))).all()
        if not categories:
            raise SystemExit("No hay categorías: corre primero las migraciones (python -m scripts.init_db).")

        lines = []
        admins = {}
        for email, name, roles in ADMINS:
            user, created = _user(db, email, name, UserRole.ADMIN, pw_hash)
            _admin_roles(db, user, roles)
            admins[email] = user
            lines.append((email, ", ".join(sorted(r.value for r in roles)), created))

        client, created = _user(db, CLIENT_EMAIL, "Cliente Prueba", UserRole.CLIENT, pw_hash)
        if client.client_profile is None:
            client.client_profile = ClientProfile(city="Veracruz")
        lines.append((CLIENT_EMAIL, "cliente", created))

        tech, created = _user(db, TECH_EMAIL, "Gloria Hernández García", UserRole.TECHNICIAN, pw_hash)
        if tech.technician_profile is None:
            tech.technician_profile = TechnicianProfile(base_city="Veracruz", years_experience=5,
                                                        bio="Técnica de prueba para desarrollo")
            db.flush()
        profile = tech.technician_profile
        have = {s.category_id for s in profile.services}
        profile.services.extend(TechnicianService(category_id=c.id) for c in categories if c.id not in have)
        db.flush()
        kyc = _approve_technician(db, tech, admins["kyc.revisor@example.com"])
        profile.is_available = True             # un trigger lo exige DESPUÉS de aprobar el KYC
        db.flush()
        lines.append((TECH_EMAIL, f"técnico (KYC {kyc})", created))
        db.commit()

    print("\nUsuarios de prueba listos (solo desarrollo):\n")
    for email, what, created in lines:
        print(f"  {email:<32} {what}{'' if created else '  [ya existía: contraseña actualizada]'}")
    print(f"\n  Contraseña de todos: {password}")
    print("\nEntra en http://localhost:8080/docs con el botón Authorize (usuario = correo).")
    print("Siguiente paso de la guía 17.3: el técnico da de alta su cuenta de Stripe.\n")


if __name__ == "__main__":
    main()
