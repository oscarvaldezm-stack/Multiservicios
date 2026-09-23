"""
Validadores de identidad mexicana. Funciones puras (sin BD) para poder probarlas
de forma aislada y reutilizarlas en schemas Pydantic y en la lógica de envío.

Los algoritmos de dígito verificador se comprobaron contra los ejemplos oficiales:
CURP HEGG560427MVZRRL04 (RENAPO) y RFC GODE561231GR8 (SAT).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

# Claves de entidad federativa válidas en la CURP (+ NE = nacido en el extranjero)
CURP_STATE_CODES = frozenset({
    "AS", "BC", "BS", "CC", "CL", "CM", "CS", "CH", "DF", "DG", "GT", "GR", "HG", "JC",
    "MC", "MN", "MS", "NT", "NL", "OC", "PL", "QT", "QR", "SP", "SL", "SR", "TC", "TS",
    "TL", "VZ", "YN", "ZS", "NE",
})

_CURP_RE = re.compile(
    r"^(?P<letters>[A-Z][AEIOUX][A-Z]{2})"
    r"(?P<yy>\d{2})(?P<mm>0[1-9]|1[0-2])(?P<dd>0[1-9]|[12]\d|3[01])"
    r"(?P<sex>[HMX])(?P<state>[A-Z]{2})"
    r"(?P<cons>[B-DF-HJ-NP-TV-Z]{3})"
    r"(?P<diff>[A-Z\d])(?P<check>\d)$"
)
_CURP_DICT = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"

# RFC de persona física: 4 letras + fecha + homoclave(2) + dígito verificador
_RFC_PF_RE = re.compile(
    r"^(?P<letters>[A-ZÑ&]{4})(?P<yy>\d{2})(?P<mm>0[1-9]|1[0-2])(?P<dd>0[1-9]|[12]\d|3[01])"
    r"(?P<homo>[A-Z\d]{2})(?P<check>[\dA])$"
)
_RFC_DICT = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ Ñ"
# RFC genéricos del SAT: nunca identifican a una persona real
_RFC_GENERIC = frozenset({"XAXX010101000", "XEXX010101000"})

_POSTAL_RE = re.compile(r"^\d{5}$")

MIN_AGE_YEARS = 18


class IdentityValidationError(ValueError):
    """Error de validación con código estable para la API."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CurpInfo:
    curp: str
    birth_date: date
    sex: str        # H, M o X
    state_code: str


def _curp_check_digit(first17: str) -> str:
    total = sum(_CURP_DICT.index(ch) * (18 - i) for i, ch in enumerate(first17))
    return str((10 - total % 10) % 10)


def _century_date(yy: int, mm: int, dd: int, diff: str) -> date:
    # Posición 17 de la CURP: dígito = nacido antes de 2000, letra = 2000 en adelante.
    year = (1900 if diff.isdigit() else 2000) + yy
    return date(year, mm, dd)


def parse_curp(value: str) -> CurpInfo:
    curp = "".join(value.split()).upper()
    m = _CURP_RE.fullmatch(curp)
    if not m:
        raise IdentityValidationError("CURP_FORMAT", "La CURP no tiene un formato válido")
    if m["state"] not in CURP_STATE_CODES:
        raise IdentityValidationError("CURP_STATE", "La clave de entidad de la CURP no existe")
    try:
        born = _century_date(int(m["yy"]), int(m["mm"]), int(m["dd"]), m["diff"])
    except ValueError:
        raise IdentityValidationError("CURP_DATE", "La fecha contenida en la CURP no existe") from None
    if _curp_check_digit(curp[:17]) != m["check"]:
        raise IdentityValidationError("CURP_CHECK_DIGIT", "El dígito verificador de la CURP no coincide")
    return CurpInfo(curp=curp, birth_date=born, sex=m["sex"], state_code=m["state"])


def validate_curp_matches(curp: str, birth_date: date, sex: str | None = None) -> CurpInfo:
    """La CURP debe codificar la misma fecha de nacimiento (y sexo, si se captura) que el expediente."""
    info = parse_curp(curp)
    if info.birth_date != birth_date:
        raise IdentityValidationError("CURP_BIRTHDATE_MISMATCH",
                                      "La fecha de nacimiento no coincide con la CURP")
    if sex is not None and sex.upper() != info.sex:
        raise IdentityValidationError("CURP_SEX_MISMATCH", "El sexo capturado no coincide con la CURP")
    return info


def _rfc_check_digit(first12: str) -> str:
    padded = first12.rjust(12)
    total = sum(_RFC_DICT.index(ch) * (13 - i) for i, ch in enumerate(padded))
    rem = total % 11
    if rem == 0:
        return "0"
    d = 11 - rem
    return "A" if d == 10 else str(d)


def validate_rfc_persona_fisica(value: str, birth_date: date | None = None) -> str:
    rfc = "".join(value.split()).upper()
    if rfc in _RFC_GENERIC:
        raise IdentityValidationError("RFC_GENERIC", "No se aceptan RFC genéricos")
    m = _RFC_PF_RE.fullmatch(rfc)
    if not m:
        raise IdentityValidationError("RFC_FORMAT", "El RFC debe ser de persona física (13 caracteres)")
    try:
        yy, mm, dd = int(m["yy"]), int(m["mm"]), int(m["dd"])
        # El RFC no indica el siglo; 2000+yy tiene el mismo patrón bisiesto que 1900+yy
        # para 1901-1999, así que basta para saber si la fecha existe.
        date(2000 + yy, mm, dd)
    except ValueError:
        raise IdentityValidationError("RFC_DATE", "La fecha contenida en el RFC no existe") from None
    if _rfc_check_digit(rfc[:12]) != m["check"]:
        raise IdentityValidationError("RFC_CHECK_DIGIT", "El dígito verificador del RFC no coincide")
    if birth_date is not None and (yy, mm, dd) != (birth_date.year % 100, birth_date.month, birth_date.day):
        raise IdentityValidationError("RFC_BIRTHDATE_MISMATCH",
                                      "La fecha del RFC no coincide con la fecha de nacimiento")
    return rfc


def age_on(birth_date: date, on: date) -> int:
    return on.year - birth_date.year - ((on.month, on.day) < (birth_date.month, birth_date.day))


def validate_adult(birth_date: date, on: date | None = None) -> None:
    on = on or date.today()
    if birth_date > on:
        raise IdentityValidationError("BIRTHDATE_FUTURE", "La fecha de nacimiento no puede ser futura")
    if age_on(birth_date, on) < MIN_AGE_YEARS:
        raise IdentityValidationError("UNDERAGE", "Debes ser mayor de edad para registrarte como técnico")
    if age_on(birth_date, on) > 100:
        raise IdentityValidationError("BIRTHDATE_IMPLAUSIBLE", "Revisa la fecha de nacimiento")


def validate_postal_code(value: str) -> str:
    v = value.strip()
    if not _POSTAL_RE.fullmatch(v):
        raise IdentityValidationError("POSTAL_CODE_FORMAT", "El código postal debe tener 5 dígitos")
    return v
