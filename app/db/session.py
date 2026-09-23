from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,           # descarta conexiones muertas
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    # Límite por consulta: una consulta costosa (o un ataque) no bloquea el pool.
    connect_args={"options": "-c statement_timeout=15000"},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
