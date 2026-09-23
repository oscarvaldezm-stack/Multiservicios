"""Pruebas unitarias puras (sin base de datos) de los validadores de identidad."""
from datetime import date

import pytest

from app.kyc.validators import (
    IdentityValidationError,
    age_on,
    parse_curp,
    validate_adult,
    validate_curp_matches,
    validate_postal_code,
    validate_rfc_persona_fisica,
)
from tests.conftest import valid_curp, valid_rfc

OFFICIAL_CURP = "HEGG560427MVZRRL04"   # ejemplo publicado por RENAPO
OFFICIAL_RFC = "GODE561231GR8"         # ejemplo publicado por el SAT


def code_of(fn, *args, **kw) -> str:
    with pytest.raises(IdentityValidationError) as exc:
        fn(*args, **kw)
    return exc.value.code


# ------------------------------------------------------------------ CURP
def test_curp_oficial_valida_y_decodifica():
    info = parse_curp(OFFICIAL_CURP)
    assert info.birth_date == date(1956, 4, 27)
    assert info.sex == "M" and info.state_code == "VZ"


def test_curp_normaliza_espacios_y_minusculas():
    assert parse_curp(" hegg560427mvzrrl04 ").curp == OFFICIAL_CURP


@pytest.mark.parametrize("curp,code", [
    ("HEGG560427MVZRRL05", "CURP_CHECK_DIGIT"),   # dígito verificador alterado
    ("HEGG560427MXXRRL04", "CURP_STATE"),         # entidad inexistente
    ("HEGG560230MVZRRL04", "CURP_DATE"),          # 30 de febrero
    ("HEGG5604", "CURP_FORMAT"),
    ("' OR 1=1 --", "CURP_FORMAT"),
])
def test_curp_invalidas(curp, code):
    assert code_of(parse_curp, curp) == code


def test_curp_posicion_17_letra_indica_siglo_2000():
    from app.kyc.validators import _curp_check_digit
    base = "HEGG050427MVZRRLA"
    assert parse_curp(base + _curp_check_digit(base)).birth_date == date(2005, 4, 27)


def test_curp_debe_coincidir_con_fecha_y_sexo():
    assert validate_curp_matches(OFFICIAL_CURP, date(1956, 4, 27), "M").curp == OFFICIAL_CURP
    assert code_of(validate_curp_matches, OFFICIAL_CURP, date(1956, 4, 28)) == "CURP_BIRTHDATE_MISMATCH"
    assert code_of(validate_curp_matches, OFFICIAL_CURP, date(1956, 4, 27), "H") == "CURP_SEX_MISMATCH"


def test_generador_de_curps_de_prueba_produce_curps_validas():
    for n in range(10):
        assert parse_curp(valid_curp(n)).birth_date == date(1956, 4, 27)


# ------------------------------------------------------------------ RFC
def test_rfc_oficial_valido():
    assert validate_rfc_persona_fisica(OFFICIAL_RFC, date(1956, 12, 31)) == OFFICIAL_RFC


@pytest.mark.parametrize("rfc,code", [
    ("GODE561231GR9", "RFC_CHECK_DIGIT"),
    ("XAXX010101000", "RFC_GENERIC"),
    ("ABC680524P76", "RFC_FORMAT"),        # 12 caracteres = persona moral
    ("GODE561331GR8", "RFC_FORMAT"),       # mes 13
    ("GODE560230GR8", "RFC_DATE"),         # 30 de febrero
])
def test_rfc_invalidos(rfc, code):
    assert code_of(validate_rfc_persona_fisica, rfc) == code


def test_rfc_debe_coincidir_con_fecha_de_nacimiento():
    assert code_of(validate_rfc_persona_fisica, OFFICIAL_RFC, date(1956, 12, 30)) == "RFC_BIRTHDATE_MISMATCH"
    assert validate_rfc_persona_fisica(valid_rfc(3), date(1956, 4, 27))


# ------------------------------------------------------------------ edad y CP
def test_mayoria_de_edad_exacta():
    today = date(2026, 9, 23)
    validate_adult(date(2008, 9, 23), today)                      # cumple 18 hoy
    assert code_of(validate_adult, date(2008, 9, 24), today) == "UNDERAGE"
    assert code_of(validate_adult, date(2027, 1, 1), today) == "BIRTHDATE_FUTURE"
    assert code_of(validate_adult, date(1900, 1, 1), today) == "BIRTHDATE_IMPLAUSIBLE"


def test_edad_en_29_de_febrero():
    assert age_on(date(2008, 2, 29), date(2026, 2, 28)) == 17
    assert age_on(date(2008, 2, 29), date(2026, 3, 1)) == 18


@pytest.mark.parametrize("cp,ok", [("64000", True), ("01000", True), ("6400", False), ("64000a", False)])
def test_codigo_postal(cp, ok):
    if ok:
        assert validate_postal_code(cp) == cp
    else:
        assert code_of(validate_postal_code, cp) == "POSTAL_CODE_FORMAT"
