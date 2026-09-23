"""
Los administradores NO se registran por la API pública. Se crean desde el
servidor con este comando (requiere acceso a la máquina y a la BD):

    python -m scripts.create_admin admin@tuempresa.com "Nombre Apellido"

La contraseña se pide de forma interactiva (no queda en el historial de la terminal).
"""
import getpass
import sys

from pydantic import ValidationError
from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import User, UserRole
from app.schemas.auth import ClientRegister


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    email, full_name = sys.argv[1], sys.argv[2]
    password = getpass.getpass("Contraseña: ")
    if password != getpass.getpass("Confirmar: "):
        raise SystemExit("Las contraseñas no coinciden")
    try:  # reutiliza las mismas reglas de validación que el registro público
        data = ClientRegister(email=email, password=password, full_name=full_name)
    except ValidationError as exc:
        raise SystemExit(f"Datos inválidos:\n{exc}") from None

    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.email == data.email)):
            raise SystemExit("Ya existe un usuario con ese correo")
        db.add(User(
            email=data.email,
            hashed_password=hash_password(data.password),
            role=UserRole.ADMIN,
            full_name=data.full_name,
            is_email_verified=True,
        ))
        db.commit()
    print(f"Administrador {data.email} creado.")


if __name__ == "__main__":
    main()
