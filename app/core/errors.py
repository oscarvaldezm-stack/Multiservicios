"""
Errores de dominio con código estable → respuesta JSON uniforme:

    {"detail": {"code": "KYC_NOT_EDITABLE", "message": "..."}}

La app (Flutter / panel) decide qué mostrar por `code`, nunca por el texto.
Los errores internos nunca exponen trazas ni SQL al cliente.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.kyc.identity import IdentityError
from app.kyc.state_machine import KycTransitionError
from app.kyc.validators import IdentityValidationError


class DomainError(Exception):
    http_status = 400
    code = "DOMAIN_ERROR"

    def __init__(self, message: str, code: str | None = None, http_status: int | None = None,
                 extra: dict | None = None):
        super().__init__(message)
        if code:
            self.code = code
        if http_status:
            self.http_status = http_status
        self.extra = extra or {}


# Códigos que lanzan los triggers de PostgreSQL (última barrera). Si una regla llega hasta
# la base es porque la validación de la aplicación no la atrapó: se responde con el código
# estable y nunca con el texto del error SQL.
_DB_RULE_CODES = ("KYC_NOT_APPROVED", "ORDER_INVALID_TRANSITION", "ORDER_IMMUTABLE", "PAYMENT_INVALID_TRANSITION",
                  "PAYMENT_IMMUTABLE", "REVIEW_ORDER_MISMATCH", "REVIEW_NOT_ELIGIBLE", "REVIEW_PAYMENT_NOT_CONFIRMED",
                  "REVIEW_IMMUTABLE", "APPEND_ONLY", "KYC_INVALID_TRANSITION", "KYC_ADDRESS_LOCKED",
                  "PAYMENT_ACCOUNT_INVALID_TRANSITION", "PAYMENT_ACCOUNT_IMMUTABLE", "COMMISSION_RULE_IMMUTABLE",
                  "COMMISSION_MISMATCH", "LEDGER_UNBALANCED")


def error_body(code: str, message: str, **extra) -> dict:
    return {"detail": {"code": code, "message": message, **extra}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain(_: Request, exc: DomainError):
        return JSONResponse(error_body(exc.code, str(exc), **exc.extra), status_code=exc.http_status)

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: IntegrityError):
        text = str(exc.orig)
        code = next((c for c in _DB_RULE_CODES if c in text), "CONFLICT")
        return JSONResponse(error_body(code, "La operación viola una regla de integridad"), status_code=409)

    @app.exception_handler(KycTransitionError)
    async def _transition(_: Request, exc: KycTransitionError):
        return JSONResponse(error_body(exc.code, str(exc)), status_code=exc.http_status)

    @app.exception_handler(IdentityError)
    async def _identity(_: Request, exc: IdentityError):
        return JSONResponse(error_body(exc.code, str(exc)), status_code=exc.http_status)

    @app.exception_handler(IdentityValidationError)
    async def _validation(_: Request, exc: IdentityValidationError):
        return JSONResponse(error_body(exc.code, str(exc)), status_code=422)
