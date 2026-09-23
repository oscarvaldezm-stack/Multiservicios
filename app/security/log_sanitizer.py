"""
Sanitización de logs: última línea de defensa si algún dato sensible llega a un log.

La regla primaria sigue siendo NO registrar datos sensibles; este filtro enmascara lo
que se escape (un mensaje de error de una librería, un print olvidado, una URL con
token). Se instala en el logger raíz y en los de uvicorn (incluido el de accesos, porque
las URLs de visualización llevan un ticket).
"""
from __future__ import annotations

import logging
import re

# Orden importa: lo más específico primero.
_RULES: list[tuple[re.Pattern[str], object]] = [
    # JWT (header.payload.firma)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "[JWT-REDACTADO]"),
    # Encabezado Authorization y parámetros típicos de secretos
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTADO]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|refresh_token|access_token|client_secret)"
                r"(\"?\s*[:=]\s*\"?)[^\s\"&,}]+"), r"\1\2[REDACTADO]"),
    # Ticket de visualización de documentos en la URL
    (re.compile(r"(/kyc/file-views/)[A-Za-z0-9._-]+"), r"\1[TICKET-REDACTADO]"),
    # Llaves de Stripe
    (re.compile(r"\b(sk|rk|whsec)_(live|test)?_?[A-Za-z0-9]{8,}\b"), "[LLAVE-PROVEEDOR-REDACTADA]"),
    # client_secret de PaymentIntent / SetupIntent (permite confirmar el pago desde la app)
    (re.compile(r"\b(pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+\b"), "[CLIENT-SECRET-REDACTADO]"),
    # Enlaces de un solo uso del formulario de alta de Stripe (quien los tenga entra a la cuenta del técnico)
    (re.compile(r"https://connect\.stripe\.com/[^\s\"']+"), "https://connect.stripe.com/[ENLACE-REDACTADO]"),
    # CURP y RFC de persona física
    (re.compile(r"\b[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{5}[A-Z\d]\d\b"), lambda m: m.group(0)[:4] + "**************"),
    (re.compile(r"\b[A-ZÑ&]{4}\d{6}[A-Z\d]{3}\b"), lambda m: m.group(0)[:4] + "*********"),
    # CLABE (18 dígitos) y tarjetas (13-19 dígitos, con o sin separadores): solo últimos 4
    (re.compile(r"\b\d{18}\b"), lambda m: "*" * 14 + m.group(0)[-4:]),
    (re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), lambda m: "****" + re.sub(r"\D", "", m.group(0))[-4:]),
]


def sanitize(text: str) -> str:
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001  (mensaje mal formado: no romper el logging)
            return True
        clean = sanitize(message)
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = sanitize(record.exc_text)
        record.msg, record.args = clean, None
        return True


_INSTALLED = False


def install() -> None:
    """Idempotente. Agrega el filtro a los handlers existentes y a los loggers de uvicorn."""
    global _INSTALLED
    if _INSTALLED:
        return
    flt = SensitiveDataFilter()
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy.engine", "security"):
        logger = logging.getLogger(name)
        logger.addFilter(flt)
        for h in logger.handlers:
            h.addFilter(flt)
    _INSTALLED = True
