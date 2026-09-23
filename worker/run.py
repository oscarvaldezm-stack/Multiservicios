"""
Worker de documentos KYC. Se ejecuta en un contenedor aparte:
- SIN acceso a internet (solo PostgreSQL, el bucket y clamd);
- con límites de CPU y memoria (los decodificadores de imagen/PDF procesan datos no confiables);
- con credenciales de almacenamiento que solo leen cuarentena y escriben en el bucket limpio.

    python -m worker.run
"""
from __future__ import annotations

import logging
import signal
import time

from app.core.actor import Actor
from app.db.session import SessionLocal
from app.kyc import documents, view_tickets
from app.security import log_sanitizer
from app.security.encryption_service import verify_key_configuration
from app.security.scanner import get_scanner
from app.storage.object_storage import get_storage

log = logging.getLogger("worker")
_running = True


def _stop(*_):
    global _running
    _running = False


def run_once() -> documents.ProcessStats:
    with SessionLocal() as db:
        stats = documents.process_pending(db, get_storage(), get_scanner())
        view_tickets.purge_expired(db)
        db.commit()
        return stats


def main(poll_seconds: float = 5.0) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log_sanitizer.install()
    with SessionLocal() as db:
        verify_key_configuration(db)          # no procesa nada con una llave equivocada o revocada
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("Worker KYC iniciado (%s)", Actor.system().actor_type.value)
    while _running:
        try:
            stats = run_once()
            if stats.clean or stats.rejected or stats.retry:
                log.info("Procesados: limpios=%s rechazados=%s reintentos=%s", stats.clean, stats.rejected, stats.retry)
        except Exception:  # noqa: BLE001
            log.exception("Error en el ciclo del worker")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
