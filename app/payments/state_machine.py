"""
Máquina de estados del pago (sección 5 del doc de pagos): ÚNICA vía para cambiar payments.status.

Igual que en el KYC y en las órdenes: la tabla ALLOWED_PAYMENT_TRANSITIONS dice qué pares
existen y un trigger (migración 0006) la repite en la base; una prueba verifica que ambas
coincidan. Repetir el mismo estado no hace nada (eventos duplicados del proveedor).

Además de lo que pide el doc, se admiten:
  REQUIRES_ACTION → PROCESSING / AUTHORIZED / FAILED / CANCELLED  (el cliente completa o abandona 3D Secure)
  AUTHORIZED → FAILED                                        (la captura falla)
  DISPUTED → PARTIALLY_REFUNDED                              (disputa ganada sobre un pago con reembolso parcial)
  DISPUTED → REFUNDED                                        (disputa ganada; un reembolso en curso se confirmó
                                                              durante ella y cubrió todo; migración 0010)
"""
from __future__ import annotations

from app.core.errors import DomainError
from app.models import Payment, PaymentStatus

P = PaymentStatus

ALLOWED_PAYMENT_TRANSITIONS: frozenset[tuple[PaymentStatus, PaymentStatus]] = frozenset({
    (P.PENDING, P.REQUIRES_ACTION), (P.PENDING, P.PROCESSING), (P.PENDING, P.AUTHORIZED), (P.PENDING, P.FAILED),
    (P.PENDING, P.CANCELLED),
    (P.REQUIRES_ACTION, P.PENDING), (P.REQUIRES_ACTION, P.PROCESSING), (P.REQUIRES_ACTION, P.AUTHORIZED),
    (P.REQUIRES_ACTION, P.FAILED), (P.REQUIRES_ACTION, P.CANCELLED),
    (P.PROCESSING, P.AUTHORIZED), (P.PROCESSING, P.FAILED),
    (P.AUTHORIZED, P.PAID), (P.AUTHORIZED, P.CANCELLED), (P.AUTHORIZED, P.FAILED),
    (P.PAID, P.PARTIALLY_REFUNDED), (P.PAID, P.REFUNDED), (P.PAID, P.DISPUTED),
    (P.PARTIALLY_REFUNDED, P.REFUNDED), (P.PARTIALLY_REFUNDED, P.DISPUTED),
    (P.DISPUTED, P.PAID), (P.DISPUTED, P.PARTIALLY_REFUNDED), (P.DISPUTED, P.CHARGED_BACK),
    (P.DISPUTED, P.REFUNDED),
})

# Estados en los que todavía no hay dinero cobrado y la reserva se puede anular.
CANCELLABLE = frozenset({P.PENDING, P.REQUIRES_ACTION, P.PROCESSING, P.AUTHORIZED})
# Estados "vivos": cuentan para el índice de un solo pago SERVICE activo por orden.
LIVE = frozenset(set(P) - {P.CANCELLED, P.FAILED})
# Estados finales: ningún evento los mueve.
TERMINAL = frozenset({P.FAILED, P.CANCELLED, P.REFUNDED, P.CHARGED_BACK})


class PaymentError(DomainError):
    http_status = 409
    code = "PAYMENT_ERROR"


def can_move(from_status: PaymentStatus, to_status: PaymentStatus) -> bool:
    return from_status == to_status or (from_status, to_status) in ALLOWED_PAYMENT_TRANSITIONS


def move(payment: Payment, to_status: PaymentStatus) -> bool:
    """Aplica la transición sobre un pago YA BLOQUEADO. Devuelve False si ya estaba en ese estado."""
    if payment.status == to_status:
        return False
    if (payment.status, to_status) not in ALLOWED_PAYMENT_TRANSITIONS:
        raise PaymentError(f"Pago: {payment.status.value} → {to_status.value} no permitido",
                           code="PAYMENT_INVALID_TRANSITION", extra={"status": payment.status.value})
    payment.status = to_status
    payment.version += 1
    return True
