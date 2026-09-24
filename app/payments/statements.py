"""Estado de cuenta del técnico: ganancias por orden (con ajustes), depósitos y saldo en el proveedor."""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Payment,
    PaymentDispute,
    PaymentRefund,
    PaymentStatus,
    Payout,
    RefundStatus,
    ServiceOrder,
    TechnicianPaymentAccount,
)
from app.payments import service as payments
from app.payments.providers.base import BalanceInfo, PaymentProvider

P = PaymentStatus
EARNED = (P.PAID, P.PARTIALLY_REFUNDED, P.REFUNDED, P.DISPUTED, P.CHARGED_BACK)


def earnings(db: Session, technician_id: uuid.UUID, *, limit: int = 100) -> list[dict]:
    """Una fila por cobro: el desglose de lo capturado y lo que se le recuperó después."""
    rows = db.execute(select(Payment, ServiceOrder.id).join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
                      .where(ServiceOrder.technician_id == technician_id, Payment.status.in_(EARNED))
                      .order_by(Payment.captured_at.desc()).limit(limit)).all()
    out = []
    for payment, order_id in rows:
        b = payments.effective_breakdown(db, payment)
        recovered = (db.scalar(select(func.coalesce(func.sum(PaymentRefund.technician_recovered_cents), 0)).where(
            PaymentRefund.payment_id == payment.id, PaymentRefund.status == RefundStatus.SUCCEEDED)) or 0) + \
            (db.scalar(select(func.coalesce(func.sum(PaymentDispute.technician_recovered_cents), 0)).where(
                PaymentDispute.payment_id == payment.id)) or 0)
        out.append({"order_id": str(order_id), "status": payment.status.value, "captured_at": payment.captured_at,
                    "price_cents": b.price_cents, "commission_cents": b.commission_cents,
                    "commission_tax_cents": b.commission_tax_cents, "withholding_isr_cents": b.withholding_isr_cents,
                    "withholding_iva_cents": b.withholding_iva_cents, "net_cents": b.technician_cents,
                    "adjustments_cents": int(recovered)})
    return out


def payouts(db: Session, technician_id: uuid.UUID, *, limit: int = 100) -> list[Payout]:
    return db.scalars(select(Payout).join(TechnicianPaymentAccount,
                                          TechnicianPaymentAccount.id == Payout.technician_account_id)
                      .where(TechnicianPaymentAccount.technician_id == technician_id)
                      .order_by(Payout.created_at.desc()).limit(limit)).all()


def balance(db: Session, technician_id: uuid.UUID, provider: PaymentProvider) -> BalanceInfo | None:
    account = db.scalar(select(TechnicianPaymentAccount).where(
        TechnicianPaymentAccount.technician_id == technician_id, TechnicianPaymentAccount.provider == provider.name))
    if account is None or account.provider_account_id is None:
        return None
    return provider.get_balance(account.provider_account_id)
