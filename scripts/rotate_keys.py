"""
Gestión de llaves de cifrado del KYC.

    python -m scripts.rotate_keys status
    python -m scripts.rotate_keys activate [--ref ARN]     # registra la KEK configurada como activa
    python -m scripts.rotate_keys rewrap                   # re-envuelve DEK viejas con la KEK activa
    python -m scripts.rotate_keys revoke <key_id> --reason "..."
    python -m scripts.rotate_keys rekey-profile <kyc_profile_id>
    python -m scripts.rotate_keys reindex-blind            # usa KYC_BLIND_INDEX_KEY_NEW

Rotación de la llave maestra (sin perder datos ni re-cifrar archivos):
  1. Generar la llave nueva y configurarla como activa:
       KYC_MASTER_KEY_ID=2  KYC_MASTER_KEY=<nueva>  KYC_PREVIOUS_MASTER_KEYS="1:<anterior>"
  2. activate   -> la 2 queda ACTIVE y la 1 DECRYPT_ONLY (lo viejo sigue legible).
  3. rewrap     -> todas las DEK pasan a la llave 2 (por lotes, reanudable).
  4. revoke 1   -> se niega si queda algo envuelto con la 1; si no, la marca REVOCADA.
  5. Quitar la llave 1 de KYC_PREVIOUS_MASTER_KEYS y destruirla.
Si la llave 1 se comprometió, se hacen los pasos 1-5 de inmediato.
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
import uuid

from sqlalchemy import func, select

from app.core.actor import Actor
from app.db.session import SessionLocal
from app.models import EncryptionKeyMetadata, KycProfile
from app.security import encryption_service as es


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rotate_keys")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    a = sub.add_parser("activate")
    a.add_argument("--ref", default=None)
    sub.add_parser("rewrap")
    r = sub.add_parser("revoke")
    r.add_argument("key_id", type=int)
    r.add_argument("--reason", required=True)
    k = sub.add_parser("rekey-profile")
    k.add_argument("profile_id", type=uuid.UUID)
    sub.add_parser("reindex-blind")
    args = parser.parse_args(argv)
    system = Actor.system()

    with SessionLocal() as db:
        if args.cmd == "status":
            for m in db.scalars(select(EncryptionKeyMetadata).order_by(EncryptionKeyMetadata.purpose,
                                                                       EncryptionKeyMetadata.key_id)):
                extra = f"  expedientes={es.count_wrapped_with(db, m.key_id)}" if m.purpose.value == "KYC_KEK" else ""
                print(f"{m.purpose.value:12} id={m.key_id:<3} {m.status.value:13} huella={m.fingerprint}{extra}")
            total = db.scalar(select(func.count()).select_from(KycProfile))
            print(f"Expedientes: {total}")
            try:
                es.verify_key_configuration(db)
                print("Configuración de llaves: OK")
            except es.KeyConfigurationError as exc:
                print(f"Configuración de llaves: ERROR - {exc}")
                return 2
        elif args.cmd == "activate":
            es.register_active_kek(db, system, external_ref=args.ref)
            db.commit()
            print("Llave activa registrada.")
        elif args.cmd == "rewrap":
            print(f"DEK re-envueltas: {es.rotate_keys(db, system)}")
        elif args.cmd == "revoke":
            es.revoke_kek(db, system, args.key_id, args.reason)
            db.commit()
            print(f"Llave {args.key_id} revocada. Quítala de la configuración y destrúyela.")
        elif args.cmd == "rekey-profile":
            profile = db.get(KycProfile, args.profile_id)
            if profile is None:
                print("Expediente no encontrado", file=sys.stderr)
                return 1
            es.rekey_profile(db, system, profile)
            db.commit()
            print("Expediente re-cifrado con una DEK nueva.")
        elif args.cmd == "reindex-blind":
            raw = os.environ.get("KYC_BLIND_INDEX_KEY_NEW")
            if not raw:
                print("Define KYC_BLIND_INDEX_KEY_NEW", file=sys.stderr)
                return 1
            new_key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            n = es.reindex_blind_indexes(db, system, new_key)
            db.commit()
            print(f"Reindexados {n} expedientes. Ahora cambia KYC_BLIND_INDEX_KEY por la llave nueva.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
