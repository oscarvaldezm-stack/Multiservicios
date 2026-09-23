"""
Trabajos periódicos del negocio (proceso aparte del worker de documentos, que no tiene red):

    python -m worker.jobs            # un ciclo (para cron / Kubernetes CronJob cada 5 min)
    python -m worker.jobs --loop     # ciclo continuo

- KYC: libera casos tomados y abandonados; vence aprobaciones con identificación vencida o
  revalidación cumplida (y el técnico pierde en ese momento sus órdenes no iniciadas).
- Órdenes: aprobación automática a las 72 h (decisión D5); solicitudes sin técnico caducan.
- Pagos: aprobación y captura 24 h antes de que venza la autorización; captura de las órdenes
  aprobadas (idempotente en el proveedor: capture:{pago}); limpieza de Idempotency-Keys vencidas.

Cada trabajo corre en su propia transacción: si uno falla, los demás siguen. Un candado
consultivo de PostgreSQL evita que dos réplicas ejecuten el mismo ciclo a la vez.
"""
from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.kyc import decisions
from app.orders import service as orders
from app.payments import idempotency
from app.payments import service as payments
from app.security import log_sanitizer

log = logging.getLogger("jobs")
_LOCK_ID = 0x4D554C5449          # "MULTI": candado consultivo del programador de trabajos

JOBS: dict[str, Callable[[Session], int]] = {
    "kyc.release_stale_claims": decisions.release_stale_claims,
    "kyc.expire_approvals": decisions.expire_approvals,
    "orders.auto_approve": orders.auto_approve,
    "orders.expire_requests": orders.expire_requests,
    "payments.enforce_capture_deadline": payments.enforce_capture_deadline,
    "payments.capture_due": payments.capture_due,
    "payments.purge_idempotency_keys": idempotency.purge_expired,
}


def run_once() -> dict[str, int | str]:
    results: dict[str, int | str] = {}
    with SessionLocal() as lock_db:
        if not lock_db.scalar(text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_ID}):
            return {"skipped": "otro proceso está ejecutando los trabajos"}
        try:
            for name, job in JOBS.items():
                with SessionLocal() as db:
                    try:
                        results[name] = job(db)
                        db.commit()
                    except Exception:  # noqa: BLE001  (un trabajo roto no detiene a los demás)
                        db.rollback()
                        log.exception("Falló el trabajo %s", name)
                        results[name] = "error"
        finally:
            lock_db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_ID})
    return results


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="jobs")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--every", type=float, default=300.0, help="segundos entre ciclos con --loop")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log_sanitizer.install()
    while True:
        log.info("Trabajos: %s", run_once())
        if not args.loop:
            break
        time.sleep(args.every)


if __name__ == "__main__":
    main()
