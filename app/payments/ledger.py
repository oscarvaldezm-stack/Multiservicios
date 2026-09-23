"""
Libro contable de partida doble (sección 6 del doc de pagos).

Cada movimiento de dinero se registra como un grupo de asientos que suma cero; la base lo
exige con un trigger diferido y la tabla es de solo inserción. Los reportes ("cuánto le
debemos al técnico", "cuánto ganó la plataforma en septiembre") salen de aquí, no de sumar
columnas de payments.

Signo: + abono a la cuenta (se le debe / ingresa), − cargo.

  Cobro de $1,160 (servicio $1,000 + IVA, comisión 15 %, técnico con RFC):
    CUSTOMER            −1,160.00
    TECHNICIAN_PAYABLE    +881.00
    PLATFORM_REVENUE      +150.00
    VAT_PAYABLE            +24.00
    TAX_WITHHELD          +105.00   (ISR 25 + IVA 80)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import CommissionTransaction, LedgerAccount, LedgerEntry, Payment

A = LedgerAccount


class LedgerError(DomainError):
    http_status = 500
    code = "LEDGER_UNBALANCED"


def post(db: Session, payment: Payment, entry_type: str, lines: dict[LedgerAccount, int]) -> uuid.UUID:
    """Registra un grupo de asientos. Omite las líneas en cero; el grupo debe sumar cero."""
    lines = {acct: cents for acct, cents in lines.items() if cents}
    if not lines:
        raise LedgerError("Asiento vacío", code="LEDGER_EMPTY")
    if sum(lines.values()) != 0:
        raise LedgerError(f"El asiento {entry_type} no cuadra: {sum(lines.values())} centavos")
    group = uuid.uuid4()
    for acct, cents in lines.items():
        db.add(LedgerEntry(transaction_group_id=group, payment_id=payment.id, entry_type=entry_type,
                           account=acct, amount_cents=cents, currency=payment.currency))
    db.flush()
    return group


def post_capture(db: Session, payment: Payment, breakdown: CommissionTransaction) -> uuid.UUID:
    """Cobro confirmado por el proveedor: el cliente paga y se reparte según el desglose congelado."""
    return post(db, payment, "CAPTURE", {
        A.CUSTOMER: -breakdown.gross_cents + breakdown.discount_cents,
        A.TECHNICIAN_PAYABLE: breakdown.technician_cents,
        A.PLATFORM_REVENUE: breakdown.commission_cents,
        A.VAT_PAYABLE: breakdown.commission_tax_cents,
        A.TAX_WITHHELD: breakdown.withholding_isr_cents + breakdown.withholding_iva_cents,
    })


def post_refund(db: Session, payment: Payment, amount_cents: int, entry_type: str = "REFUND") -> uuid.UUID:
    """
    Dinero devuelto al cliente (reembolso o contracargo perdido). Queda en REFUNDS hasta que la
    Fase 5 lo asigne según la política (reverse_transfer / refund_application_fee): quién lo
    absorbe no se decide aquí.
    """
    return post(db, payment, entry_type, {A.CUSTOMER: amount_cents, A.REFUNDS: -amount_cents})


def balance(db: Session, account: LedgerAccount, *, payment_id: uuid.UUID | None = None,
            since: datetime | None = None, until: datetime | None = None) -> int:
    stmt = select(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)).where(LedgerEntry.account == account)
    if payment_id is not None:
        stmt = stmt.where(LedgerEntry.payment_id == payment_id)
    if since is not None:
        stmt = stmt.where(LedgerEntry.created_at >= since)
    if until is not None:
        stmt = stmt.where(LedgerEntry.created_at < until)
    return int(db.scalar(stmt))
