"""
Contracargos (sección 9 del doc de pagos). Los inicia el banco del cliente después del cobro; con
cargos de destino, Stripe debita a la plataforma el monto más la comisión de disputa.

- Se abre (charge.dispute.created): pago en DISPUTED, registro en payment_disputes con monto,
  motivo y fecha límite de evidencia, y alerta a finanzas. D9: al técnico NO se le descuenta al
  abrirse (la plataforma absorbe el riesgo temporal; no se castiga por reclamos que se ganan).
- Evidencia: el sistema arma el expediente con lo que ya tiene (fechas de aceptación, salida,
  inicio, término y aprobación, precio y descripción del servicio) y finanzas lo envía antes del plazo.
- Se gana: el pago vuelve a PAID (o PARTIALLY_REFUNDED).
- Se pierde: CHARGED_BACK; D9 → se revierte la transferencia al técnico por su parte proporcional
  (si ya no tiene saldo, lo absorbe la plataforma y se alerta); asientos y métrica de riesgo.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import write_audit
from app.core.actor import Actor, RequestContext
from app.core.errors import DomainError
from app.models import (
    DisputeStatus,
    LedgerAccount,
    OutboxEvent,
    Payment,
    PaymentDispute,
    PaymentStatus,
    ServiceOrder,
)
from app.payments import ledger
from app.payments import service as payments
from app.payments.commission import from_cents
from app.payments.providers.base import DisputeInfo, PaymentProvider, ProviderError
from app.payments.state_machine import move

log = logging.getLogger("payments")
P, D, A = PaymentStatus, DisputeStatus, LedgerAccount
_STATUS = {"warning_needs_response": D.NEEDS_RESPONSE, "needs_response": D.NEEDS_RESPONSE,
           "warning_under_review": D.UNDER_REVIEW, "under_review": D.UNDER_REVIEW,
           "won": D.WON, "warning_closed": D.WON, "lost": D.LOST}


class DisputeError(DomainError):
    http_status = 409
    code = "DISPUTE_ERROR"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sync_from_provider(db: Session, info: DisputeInfo, provider: PaymentProvider | None = None) -> PaymentDispute | None:
    """Aplica el estado real de un contracargo (lo llama el worker de webhooks charge.dispute.*)."""
    if not info.provider_payment_id:
        return None
    payment = db.scalar(select(Payment).where(Payment.provider_payment_id == info.provider_payment_id)
                        .with_for_update().execution_options(populate_existing=True))
    if payment is None:
        return None
    row = db.scalar(select(PaymentDispute).where(PaymentDispute.provider_dispute_id == info.provider_dispute_id)
                    .with_for_update().execution_options(populate_existing=True))
    status = _STATUS.get(info.status, D.NEEDS_RESPONSE)
    if row is None:
        row = PaymentDispute(payment_id=payment.id, provider_dispute_id=info.provider_dispute_id,
                             amount_cents=max(info.amount_cents, 1), reason=(info.reason or None) and info.reason[:60],
                             status=status, evidence_due_by=info.evidence_due_by, opened_at=_now())
        db.add(row)
        db.flush()
        if payment.status in (P.PAID, P.PARTIALLY_REFUNDED):
            payments.mark_disputed(db, payment)
        db.add(OutboxEvent(event_type="payment.dispute_opened", aggregate_type="payment_dispute", aggregate_id=row.id,
                           payload={"payment_id": str(payment.id), "amount_cents": row.amount_cents,
                                    "evidence_due_by": info.evidence_due_by.isoformat() if info.evidence_due_by
                                    else None}))
    else:
        row.status, row.evidence_due_by = status, info.evidence_due_by or row.evidence_due_by
    if status in (D.WON, D.LOST) and payment.status == P.DISPUTED:
        row.closed_at = _now()
        if status == D.WON:
            payments.mark_dispute_closed(db, payment, won=True)
        else:
            charge_back(db, payment, dispute=row, provider=provider)
    db.flush()
    return row


def charge_back(db: Session, payment: Payment, *, dispute: PaymentDispute | None = None,
                provider: PaymentProvider | None = None) -> None:
    """Contracargo perdido: CHARGED_BACK, reversión al técnico por su parte (D9) y asientos."""
    if payment.status != P.DISPUTED:
        return
    lost = payment.captured_cents - payment.refunded_cents
    if dispute is not None:
        lost = min(lost, dispute.amount_cents)
    move(payment, P.CHARGED_BACK)
    db.flush()
    if lost <= 0:
        return
    b = payments.effective_breakdown(db, payment)
    share = b.technician_cents * lost // (b.gross_cents - b.discount_cents)
    recovered = 0
    if share > 0:
        key = f"dispute-reversal:{dispute.id if dispute else payment.id}"
        try:
            reversal = payments._provider(provider).reverse_transfer(payment.provider_payment_id, share, key)
            recovered = share
            if dispute is not None:
                dispute.transfer_reversal_id = reversal
        except ProviderError as exc:
            # El técnico ya retiró su saldo: la plataforma lo absorbe y finanzas decide cómo recuperarlo.
            db.add(OutboxEvent(event_type="dispute.reversal_failed", aggregate_type="payment", aggregate_id=payment.id,
                               payload={"amount_cents": share, "failure_code": exc.provider_code or exc.code}))
    if dispute is not None:
        dispute.technician_recovered_cents = recovered
    ledger.post(db, payment, "CHARGEBACK", {A.CUSTOMER: lost, A.TECHNICIAN_PAYABLE: -recovered,
                                            A.REFUNDS: -(lost - recovered)})
    order = db.get(ServiceOrder, payment.service_order_id)
    if order is not None:                       # métrica de riesgo del técnico y del cliente
        db.add(OutboxEvent(event_type="risk.chargeback_lost", aggregate_type="service_order", aggregate_id=order.id,
                           payload={"technician_id": str(order.technician_id), "client_id": str(order.client_id),
                                    "amount_cents": lost}))
    db.flush()


# =============================================================================
# Evidencia
# =============================================================================
def build_evidence(db: Session, dispute: PaymentDispute, note: str | None) -> dict[str, str]:
    """Expediente con datos que ya existen. Sin datos de tarjeta ni identificadores del KYC."""
    payment = db.get(Payment, dispute.payment_id)
    order = db.get(ServiceOrder, payment.service_order_id)

    def ts(value: datetime | None) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value else "—"

    lines = [
        f"Servicio a domicilio: {order.title}. Precio acordado {order.agreed_price} MXN + IVA; "
        f"cobrado {from_cents(payment.captured_cents)} {payment.currency}.",
        f"Técnico aceptó: {ts(order.accepted_at)}. Agendado para: {ts(order.scheduled_at)}.",
        f"Técnico en camino (cobro autorizado): {ts(order.departed_at)}. Inicio: {ts(order.started_at)}. "
        f"Terminó: {ts(order.work_finished_at)}.",
        f"El cliente aprobó el trabajo: {ts(order.completed_at)}. Cobro capturado: {ts(payment.captured_at)}.",
    ]
    if note:
        lines.append(f"Nota de finanzas: {note}")
    return {"service_date": (order.started_at or order.scheduled_at or order.created_at).strftime("%Y-%m-%d"),
            "product_description": f"{order.title}: {order.description}"[:1000],
            "uncategorized_text": "\n".join(lines)[:20000]}


def submit_evidence(db: Session, actor: Actor, dispute_id: uuid.UUID, note: str | None = None, *,
                    provider: PaymentProvider | None = None, ctx: RequestContext | None = None) -> PaymentDispute:
    from app.kyc.permissions import Permission, permissions_for

    if Permission.DISPUTES_MANAGE not in permissions_for(actor.admin_roles):
        raise DisputeError("No puedes gestionar contracargos", code="FORBIDDEN", http_status=403)
    dispute = db.scalar(select(PaymentDispute).where(PaymentDispute.id == dispute_id).with_for_update()
                        .execution_options(populate_existing=True))
    if dispute is None:
        raise DisputeError("Disputa no encontrada", code="DISPUTE_NOT_FOUND", http_status=404)
    if dispute.status != D.NEEDS_RESPONSE:
        raise DisputeError("La disputa ya no admite evidencia", code="DISPUTE_CLOSED_FOR_EVIDENCE")
    if dispute.evidence_due_by and _now() > dispute.evidence_due_by:
        raise DisputeError("El plazo para enviar evidencia venció", code="DISPUTE_EVIDENCE_OVERDUE")
    evidence = build_evidence(db, dispute, note)
    info = payments._provider(provider).submit_dispute_evidence(dispute.provider_dispute_id, evidence)
    dispute.evidence = evidence
    dispute.evidence_submitted_at = _now()
    dispute.status = _STATUS.get(info.status, D.UNDER_REVIEW)
    db.flush()
    write_audit(db, action="dispute.evidence_submitted", actor=actor, target_type="payment_dispute",
                target_id=str(dispute.id), reason_note=note, ctx=ctx)
    return dispute
