"""
SOLO DESARROLLO: crea .env a partir de .env.example con secretos aleatorios.

    python scripts/dev_env.py

- Nunca sobrescribe un .env existente (ahí pueden estar tus claves de Stripe).
- Cada secreto es distinto (la app no arranca si se repiten).
- La misma contraseña de la app queda en POSTGRES_APP_PASSWORD y en DATABASE_URL.
Solo usa la biblioteca estándar: corre sin instalar dependencias.
"""
from __future__ import annotations

import base64
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _key32() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def render(template: str) -> str:
    app_password = secrets.token_urlsafe(24)
    values = {
        "JWT_SECRET_KEY": secrets.token_urlsafe(64),
        "KYC_MASTER_KEY": _key32(),
        "KYC_BLIND_INDEX_KEY": _key32(),
        "INTEGRITY_KEY": _key32(),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        "POSTGRES_APP_PASSWORD": app_password,
    }
    out = []
    for line in template.splitlines():
        name, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            if name in values:
                line = f"{name}={values[name]}"
            elif name == "DATABASE_URL":
                line = f"{name}={value.replace('CAMBIA_ESTA_PASSWORD', app_password)}"
        out.append(line)
    return "\n".join(out) + "\n"


def main() -> None:
    target = ROOT / ".env"
    if target.exists():
        sys.exit(".env ya existe: no se sobrescribe. Bórralo tú si de verdad quieres regenerarlo.")
    target.write_text(render((ROOT / ".env.example").read_text(encoding="utf-8")), encoding="utf-8")
    target.chmod(0o600)
    print(f"Creado {target} (permisos 600). No lo subas a git.")


if __name__ == "__main__":
    main()
