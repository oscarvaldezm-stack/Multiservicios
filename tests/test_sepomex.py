"""Cargador del catálogo SEPOMEX con un extracto en el formato oficial (latin-1, separado por '|')."""
import io

import pytest
from sqlalchemy import func, select

from app.models import MxMunicipality, MxPostalSettlement
from scripts.load_sepomex import iter_rows, load

HEADER = ("d_codigo|d_asenta|d_tipo_asenta|D_mnpio|d_estado|d_ciudad|d_CP|c_estado|c_oficina|c_CP|"
          "c_tipo_asenta|c_mnpio|id_asenta_cpcons|d_zona|c_cve_ciudad")
SAMPLE = "\n".join([
    "El Catálogo Nacional de Códigos Postales, es elaborado por Correos de México y se proporciona en forma gratuita",
    HEADER,
    "64000|Monterrey Centro|Colonia|Monterrey|Nuevo León|Monterrey|64001|19|64001||09|039|0001|Urbano|07",
    "64010|Obispado|Colonia|Monterrey|Nuevo León|Monterrey|64001|19|64001||09|039|0002|Urbano|07",
    "66220|Del Valle|Colonia|San Pedro Garza García|Nuevo León|San Pedro Garza García|66221|19|66221||09|019|0100|Urbano|18",
    "91700|Veracruz Centro|Colonia|Veracruz|Veracruz de Ignacio de la Llave|Veracruz|91701|30|91701||09|193|0001|Urbano|01",
]) + "\n"


def _rows():
    return iter_rows(io.StringIO(SAMPLE.encode("latin-1").decode("latin-1")))


def test_carga_municipios_y_colonias(db):
    n_muni, n_sett = load(db, _rows())
    db.commit()
    assert (n_muni, n_sett) == (3, 4)
    mty = db.scalar(select(MxMunicipality).where(MxMunicipality.state_id == 19, MxMunicipality.inegi_code == 39))
    assert mty.name == "Monterrey"
    col = db.scalar(select(MxPostalSettlement).where(MxPostalSettlement.postal_code == "66220"))
    assert col.name == "Del Valle" and col.city == "San Pedro Garza García"


def test_recarga_es_idempotente(db):
    load(db, _rows())
    db.commit()
    load(db, _rows())
    db.commit()
    assert db.scalar(select(func.count()).select_from(MxPostalSettlement)) == 4
    assert db.scalar(select(func.count()).select_from(MxMunicipality)) == 3


def test_fila_mal_formada_indica_la_linea(db):
    bad = SAMPLE.replace("|19|64001||09|039|0001|", "||64001||09|039|0001|", 1)
    with pytest.raises(ValueError, match="línea 3"):
        load(db, iter_rows(io.StringIO(bad)))


def test_archivo_sin_encabezado_se_rechaza():
    with pytest.raises(ValueError, match="encabezado"):
        list(iter_rows(io.StringIO("basura|sin|encabezado\n")))
