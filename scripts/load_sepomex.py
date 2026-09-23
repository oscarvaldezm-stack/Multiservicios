"""
Carga el catálogo oficial de códigos postales de SEPOMEX (Correos de México).

1. Descarga el archivo en formato TXT desde el sitio de Correos de México
   ("Descarga la base de datos de códigos postales"). Viene en latin-1, separado por "|",
   con una línea de aviso y después el encabezado.
2. Ejecuta:
       python -m scripts.load_sepomex ruta/CPdescarga.txt

Es idempotente: se puede volver a correr con una versión nueva del archivo. Los
municipios se toman del mismo archivo (c_estado + c_mnpio coinciden con las claves INEGI).
"""
from __future__ import annotations

import csv
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

REQUIRED_COLUMNS = {"d_codigo", "d_asenta", "d_tipo_asenta", "D_mnpio", "c_estado", "c_mnpio",
                    "id_asenta_cpcons", "d_ciudad"}


def iter_rows(lines: Iterable[str]) -> Iterator[dict[str, str]]:
    """Salta la línea de aviso inicial y lee a partir del encabezado real."""
    it = iter(lines)
    header_line = 0
    for line in it:
        header_line += 1
        if line.startswith("d_codigo|"):
            header = line.rstrip("\r\n").split("|")
            break
    else:
        raise ValueError("No se encontró el encabezado 'd_codigo|...' en el archivo")
    missing = REQUIRED_COLUMNS - set(header)
    if missing:
        raise ValueError(f"Faltan columnas en el archivo SEPOMEX: {sorted(missing)}")
    reader = csv.DictReader(it, fieldnames=header, delimiter="|", quoting=csv.QUOTE_NONE)
    for line_no, row in enumerate(reader, start=header_line + 1):
        if row.get("d_codigo"):
            row["_line"] = str(line_no)
            yield row


def load(db: Session, rows: Iterable[dict[str, str]], batch: int = 5000) -> tuple[int, int]:
    from app.models import MxMunicipality, MxPostalSettlement

    muni_ids: dict[tuple[int, int], int] = {
        (s, c): i for i, s, c in db.execute(
            select(MxMunicipality.id, MxMunicipality.state_id, MxMunicipality.inegi_code))
    }
    n_muni = n_sett = 0
    pending: list[dict] = []

    def flush() -> None:
        nonlocal pending, n_sett
        if pending:
            stmt = insert(MxPostalSettlement).values(pending)
            stmt = stmt.on_conflict_do_update(
                index_elements=["postal_code", "municipality_id", "sepomex_id"],
                set_={"name": stmt.excluded.name, "settlement_type": stmt.excluded.settlement_type,
                      "city": stmt.excluded.city},
            )
            db.execute(stmt)
            n_sett += len(pending)
            pending = []

    for r in rows:
        try:
            state_id, muni_code, sepomex_id = int(r["c_estado"]), int(r["c_mnpio"]), int(r["id_asenta_cpcons"])
        except (TypeError, ValueError):
            raise ValueError(f"Fila inválida en la línea {r.get('_line', '?')} del archivo SEPOMEX") from None
        if not 1 <= state_id <= 32:
            raise ValueError(f"Clave de estado {state_id} fuera de rango en la línea {r.get('_line', '?')}")
        key = (state_id, muni_code)
        if key not in muni_ids:
            stmt = insert(MxMunicipality).values(state_id=state_id, inegi_code=muni_code, name=r["D_mnpio"].strip())
            stmt = stmt.on_conflict_do_update(index_elements=["state_id", "inegi_code"],
                                              set_={"name": stmt.excluded.name}).returning(MxMunicipality.id)
            muni_ids[key] = db.execute(stmt).scalar_one()
            n_muni += 1
        pending.append({
            "postal_code": r["d_codigo"].strip().zfill(5),
            "name": r["d_asenta"].strip(),
            "settlement_type": r["d_tipo_asenta"].strip(),
            "municipality_id": muni_ids[key],
            "city": (r.get("d_ciudad") or "").strip() or None,
            "sepomex_id": sepomex_id,
        })
        if len(pending) >= batch:
            flush()
    flush()
    return n_muni, n_sett


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    from app.db.session import SessionLocal

    path = Path(sys.argv[1])
    with path.open(encoding="latin-1", newline="") as fh, SessionLocal() as db:
        n_muni, n_sett = load(db, iter_rows(fh))
        db.commit()
    print(f"Municipios nuevos: {n_muni}. Asentamientos cargados o actualizados: {n_sett}.")


if __name__ == "__main__":
    main()
