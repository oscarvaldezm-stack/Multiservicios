"""
Webhooks de Stripe: /webhooks/stripe (plataforma) y /webhooks/stripe-connect (cuentas conectadas).

Sin JWT: se autentican con la firma Stripe-Signature, calculada sobre los BYTES EXACTOS del cuerpo
(por eso se lee crudo, antes de cualquier conversión a JSON), con un secreto distinto por
endpoint y una tolerancia de 5 minutos contra replays. Firma inválida → 400, registro en el log
de seguridad y nada más. Firma válida → se guarda (un evento repetido se neutraliza por su id)
y se responde 200 de inmediato: el procesamiento lo hace el worker.
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.api.deps import DbSession
from app.core.config import get_settings
from app.payments import webhooks
from app.payments.providers import PaymentProvider, ProviderError, get_provider

router = APIRouter(prefix="/webhooks", tags=["webhooks del proveedor"])
Provider = Annotated[PaymentProvider, Depends(get_provider)]
security_log = logging.getLogger("security")


async def raw_body(request: Request) -> bytes:
    """Cuerpo crudo con tope de tamaño (una inundación no llena la memoria)."""
    limit = get_settings().WEBHOOK_MAX_BODY_BYTES
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > limit):
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail={"code": "WEBHOOK_TOO_LARGE", "message": "Evento demasiado grande"})
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail={"code": "WEBHOOK_TOO_LARGE", "message": "Evento demasiado grande"})
    return body


def _receive(endpoint: str, request: Request, body: bytes, signature: str | None, db, provider: PaymentProvider):
    try:
        event = provider.verify_webhook(body, signature, endpoint)
    except ProviderError as exc:
        if exc.code == "WEBHOOK_SIGNATURE_INVALID":
            security_log.warning("Webhook %s con firma inválida desde %s", endpoint,
                                 request.client.host if request.client else "?")
        raise
    duplicate = not webhooks.store(db, provider.name, event, endpoint)
    db.commit()
    return {"received": True, "duplicate": duplicate}


@router.post("/stripe", summary="Eventos de la plataforma (firma STRIPE_WEBHOOK_SECRET)")
def stripe_platform(request: Request, db: DbSession, provider: Provider, body: bytes = Depends(raw_body),
                    stripe_signature: str | None = Header(None, alias="Stripe-Signature")):
    return _receive("platform", request, body, stripe_signature, db, provider)


@router.post("/stripe-connect", summary="Eventos de cuentas conectadas (firma STRIPE_CONNECT_WEBHOOK_SECRET)")
def stripe_connect(request: Request, db: DbSession, provider: Provider, body: bytes = Depends(raw_body),
                   stripe_signature: str | None = Header(None, alias="Stripe-Signature")):
    return _receive("connect", request, body, stripe_signature, db, provider)
