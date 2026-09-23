"""
SOLO DESARROLLO: aplica las migraciones y carga categorías de servicio de ejemplo.

    python -m scripts.init_db

Importante: el esquema se crea SIEMPRE con Alembic (nunca con Base.metadata.create_all),
porque los triggers de seguridad del KYC (transiciones válidas, auditoría inmutable,
regla crítica de órdenes) solo existen en las migraciones.
"""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import ServiceCategory

ROOT = Path(__file__).resolve().parents[1]

CATEGORIES = [
    ("Plomería", "plomeria"),
    ("Electricidad", "electricidad"),
    ("Carpintería", "carpinteria"),
    ("Aire acondicionado", "aire-acondicionado"),
    ("Pintura", "pintura"),
    ("Cerrajería", "cerrajeria"),
]


def main() -> None:
    if get_settings().is_production:
        raise SystemExit("init_db no debe ejecutarse en producción; usa 'alembic upgrade head'.")
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")
    with SessionLocal() as db:
        existing = set(db.scalars(select(ServiceCategory.slug)).all())
        for name, slug in CATEGORIES:
            if slug not in existing:
                db.add(ServiceCategory(name=name, slug=slug))
        db.commit()
    print("Migraciones aplicadas y categorías cargadas.")


if __name__ == "__main__":
    main()
