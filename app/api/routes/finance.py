"""
Pagos, Fase 5: reembolsos, contracargos, políticas de cancelación y estado de cuenta del técnico.

- Cliente: pedir un reembolso de su orden (Idempotency-Key) y ver su estado (sin el reparto interno).
- Finanzas (permisos finos): crear, aprobar (segunda firma arriba del umbral D8) y rechazar
  reembolsos; bandeja de contracargos y envío de evidencia; políticas de cancelación.
- Técnico: ganancias por orden, depósitos y saldo en su cuenta del proveedor. Rutas /me: todo
  sale del usuario autenticado.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api.deps import CurrentClient, CurrentTechnician, CurrentUser, DbSession, ReqCtx, require_permission, \
    require_roles
from app.core.actor import Actor
from app.core.config import get_settings
from app.core.errors import DomainError
from app.kyc.permissions import Permission
from app.models import CancellationPolicy, Payment, PaymentDispute, PaymentRefund, RefundStatus, ServiceOrder, UserRole
from app.payments import cancellations, disputes, idempotency, refunds, statements
from app.payments.commission import from_cents, to_cents
from app.payments.providers import PaymentProvider, get_provider
from app.schemas.payments import (
    BalanceOut,
    CancellationPolicyIn,
    CancellationPolicyOut,
    DisputeOut,
    EarningOut,
    EarningsOut,
    EvidenceIn,
    FinanceRefundIn,
    NoteIn,
    PayoutOut,
    RefundClientOut,
    RefundFinanceOut,
    RefundRequestIn,
)

Provider = Annotated[PaymentProvider, Depends(get_provider)]
client_router = APIRouter(tags=["pagos: reembolsos del cliente"])
tech_router = APIRouter(prefix="/technicians/me", tags=["pagos: estado de cuenta del técnico"],
                        dependencies=[Depends(require_roles(UserRole.TECHNICIAN))])
admin_router = APIRouter(prefix="/admin", tags=["pagos: finanzas"], dependencies=[Depends(require_roles(UserRole.ADMIN))])
_404 = DomainError("Reembolso no encontrado", code="REFUND_NOT_FOUND", http_status=404)


def _client_out(r: PaymentRefund) -> RefundClientOut:
    return RefundClientOut(id=str(r.id), status=r.status.value, amount=from_cents(r.amount_cents),
                           reason_code=r.reason_code, created_at=r.created_at, succeeded_at=r.succeeded_at)


def _finance_out(r: PaymentRefund) -> RefundFinanceOut:
    return RefundFinanceOut(
        **_client_out(r).model_dump(), payment_id=str(r.payment_id), request_source=r.request_source,
        reverse_transfer=r.reverse_transfer, refund_application_fee=r.refund_application_fee,
        technician_recovered=from_cents(r.technician_recovered_cents),
        commission_returned=from_cents(r.commission_returned_cents), vat_returned=from_cents(r.vat_returned_cents),
        withholding_returned=from_cents(r.withholding_returned_cents),
        platform_absorbed=from_cents(r.platform_absorbed_cents),
        needs_second_approval=r.status == RefundStatus.REQUESTED
        and r.amount_cents > get_settings().REFUND_DOUBLE_APPROVAL_CENTS,
        failure_code=r.failure_code)


def _dispute_out(d: PaymentDispute) -> DisputeOut:
    return DisputeOut(id=str(d.id), payment_id=str(d.payment_id), amount=from_cents(d.amount_cents), reason=d.reason,
                      status=d.status.value, evidence_due_by=d.evidence_due_by,
                      evidence_submitted_at=d.evidence_submitted_at,
                      technician_recovered=from_cents(d.technician_recovered_cents), opened_at=d.opened_at,
                      closed_at=d.closed_at)


# ------------------------------------------------------------------ cliente
@client_router.post("/orders/{order_id}/refund-requests", response_model=RefundClientOut, status_code=201,
                    summary="Pedir un reembolso (cliente dueño; requiere Idempotency-Key)")
def request_refund(data: RefundRequestIn, client: CurrentClient, db: DbSession,
                   idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
                   order_id: uuid.UUID = Path(description="ID de la orden")):
    def operation() -> dict:
        refund = refunds.request_by_client(db, client, order_id, reason_code=data.reason_code,
                                           amount_cents=to_cents(data.amount) if data.amount is not None else None,
                                           note=data.note)
        return _client_out(refund).model_dump(mode="json")

    code, body, replayed = idempotency.run(db, user_id=client.id, endpoint=f"orders/{order_id}/refund-requests",
                                           key=idempotency_key, body=data.model_dump(mode="json"),
                                           operation=operation, status_code=201)
    db.commit()
    return JSONResponse(body, status_code=code, headers={"Idempotent-Replayed": "true"} if replayed else None)


@client_router.get("/refunds/{refund_id}", response_model=RefundClientOut,
                   summary="Estado de un reembolso (cliente dueño)")
def get_refund(user: CurrentUser, db: DbSession, refund_id: uuid.UUID = Path(description="ID del reembolso")):
    refund = db.get(PaymentRefund, refund_id)
    if refund is None or user.role != UserRole.CLIENT:
        raise _404
    owner = db.scalar(select(ServiceOrder.client_id).join(Payment, Payment.service_order_id == ServiceOrder.id)
                      .where(Payment.id == refund.payment_id))
    if owner != user.id:
        raise _404
    return _client_out(refund)


# ------------------------------------------------------------------ finanzas: reembolsos
@admin_router.get("/refunds", response_model=list[RefundFinanceOut], summary="Reembolsos (finanzas)")
def list_refunds(db: DbSession, _: Actor = Depends(require_permission(Permission.FINANCE_READ)),
                 status_: RefundStatus | None = Query(None, alias="status"), limit: int = Query(50, ge=1, le=200)):
    stmt = select(PaymentRefund)
    if status_:
        stmt = stmt.where(PaymentRefund.status == status_)
    return [_finance_out(r) for r in db.scalars(stmt.order_by(PaymentRefund.created_at.desc()).limit(limit))]


@admin_router.post("/payments/{payment_id}/refunds", response_model=RefundFinanceOut, status_code=201,
                   summary="Crear reembolso (finanzas; arriba del umbral espera segunda firma)")
def create_refund(data: FinanceRefundIn, db: DbSession, ctx: ReqCtx, provider: Provider,
                  actor: Actor = Depends(require_permission(Permission.REFUNDS_EXECUTE)),
                  idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
                  payment_id: uuid.UUID = Path(description="ID del pago")):
    def operation() -> dict:
        refund = refunds.create_by_finance(db, actor, payment_id, reason_code=data.reason_code, note=data.note,
                                           amount_cents=to_cents(data.amount) if data.amount is not None else None,
                                           provider=provider, ctx=ctx)
        return _finance_out(refund).model_dump(mode="json")

    code, body, replayed = idempotency.run(db, user_id=actor.user_id, endpoint=f"admin/payments/{payment_id}/refunds",
                                           key=idempotency_key, body=data.model_dump(mode="json"),
                                           operation=operation, status_code=201)
    db.commit()
    return JSONResponse(body, status_code=code, headers={"Idempotent-Replayed": "true"} if replayed else None)


@admin_router.post("/refunds/{refund_id}/approve", response_model=RefundFinanceOut,
                   summary="Aprobar y ejecutar (arriba del umbral: FINANCE_ADMIN distinto a quien lo pidió)")
def approve_refund(db: DbSession, ctx: ReqCtx, provider: Provider,
                   actor: Actor = Depends(require_permission(Permission.REFUNDS_EXECUTE)),
                   refund_id: uuid.UUID = Path(description="ID del reembolso")):
    refund = refunds.approve(db, actor, refund_id, provider=provider, ctx=ctx)
    db.commit()
    return _finance_out(refund)


@admin_router.post("/refunds/{refund_id}/reject", response_model=RefundFinanceOut, summary="Rechazar solicitud")
def reject_refund(data: NoteIn, db: DbSession, ctx: ReqCtx,
                  actor: Actor = Depends(require_permission(Permission.REFUNDS_EXECUTE)),
                  refund_id: uuid.UUID = Path(description="ID del reembolso")):
    refund = refunds.reject(db, actor, refund_id, data.note, ctx)
    db.commit()
    return _finance_out(refund)


# ------------------------------------------------------------------ finanzas: contracargos
@admin_router.get("/disputes", response_model=list[DisputeOut], summary="Bandeja de contracargos (por fecha límite)")
def list_disputes(db: DbSession, _: Actor = Depends(require_permission(Permission.FINANCE_READ)),
                  limit: int = Query(50, ge=1, le=200)):
    rows = db.scalars(select(PaymentDispute).order_by(PaymentDispute.closed_at.is_not(None),
                                                      PaymentDispute.evidence_due_by.asc().nulls_last()).limit(limit))
    return [_dispute_out(d) for d in rows]


@admin_router.post("/disputes/{dispute_id}/evidence", response_model=DisputeOut,
                   summary="Enviar evidencia armada con los datos de la orden")
def submit_evidence(data: EvidenceIn, db: DbSession, ctx: ReqCtx, provider: Provider,
                    actor: Actor = Depends(require_permission(Permission.DISPUTES_MANAGE)),
                    dispute_id: uuid.UUID = Path(description="ID de la disputa")):
    dispute = disputes.submit_evidence(db, actor, dispute_id, data.note, provider=provider, ctx=ctx)
    db.commit()
    return _dispute_out(dispute)


# ------------------------------------------------------------------ finanzas: políticas de cancelación
@admin_router.get("/cancellation-policies", response_model=list[CancellationPolicyOut],
                  summary="Políticas de cancelación (vigentes e históricas)")
def list_policies(db: DbSession, _: Actor = Depends(require_permission(Permission.FINANCE_READ))):
    rows = db.scalars(select(CancellationPolicy).order_by(CancellationPolicy.scenario,
                                                          CancellationPolicy.valid_from.desc()))
    return [CancellationPolicyOut(**cancellations.policy_view(p)) for p in rows]


@admin_router.post("/cancellation-policies", response_model=CancellationPolicyOut, status_code=201,
                   summary="Nueva política vigente desde ahora (cierra la anterior)")
def set_policy(data: CancellationPolicyIn, db: DbSession, ctx: ReqCtx,
               actor: Actor = Depends(require_permission(Permission.CANCELLATION_POLICIES_MANAGE))):
    policy = cancellations.set_policy(db, actor, **data.model_dump(), ctx=ctx)
    db.commit()
    return CancellationPolicyOut(**cancellations.policy_view(policy))


# ------------------------------------------------------------------ técnico
@tech_router.get("/earnings", response_model=EarningsOut, summary="Mis ganancias por orden (bruto, comisión, neto)")
def my_earnings(tech: CurrentTechnician, db: DbSession, limit: int = Query(100, ge=1, le=500)):
    items = []
    for e in statements.earnings(db, tech.id, limit=limit):
        items.append(EarningOut(
            order_id=e["order_id"], status=e["status"], captured_at=e["captured_at"],
            service_price=from_cents(e["price_cents"]), commission=from_cents(e["commission_cents"]),
            commission_tax=from_cents(e["commission_tax_cents"]), withholding_isr=from_cents(e["withholding_isr_cents"]),
            withholding_iva=from_cents(e["withholding_iva_cents"]), net=from_cents(e["net_cents"]),
            adjustments=from_cents(e["adjustments_cents"]),
            net_after_adjustments=from_cents(e["net_cents"] - e["adjustments_cents"])))
    total_net = sum((i.net for i in items), start=from_cents(0))
    total_adj = sum((i.adjustments for i in items), start=from_cents(0))
    return EarningsOut(items=items, total_net=total_net, total_adjustments=total_adj,
                       total_net_after_adjustments=total_net - total_adj)


@tech_router.get("/payouts", response_model=list[PayoutOut], summary="Mis depósitos")
def my_payouts(tech: CurrentTechnician, db: DbSession, limit: int = Query(100, ge=1, le=500)):
    return [PayoutOut(id=str(p.id), amount=from_cents(p.amount_cents), currency=p.currency, status=p.status.value,
                      arrival_date=p.arrival_date.isoformat() if p.arrival_date else None, failure_code=p.failure_code,
                      created_at=p.created_at) for p in statements.payouts(db, tech.id, limit=limit)]


@tech_router.get("/balance", response_model=BalanceOut, summary="Mi saldo en el proveedor (disponible y pendiente)")
def my_balance(tech: CurrentTechnician, db: DbSession, provider: Provider):
    info = statements.balance(db, tech.id, provider)
    if info is None:
        raise DomainError("Primero crea tu cuenta de pagos", code="PAYMENT_ACCOUNT_NOT_FOUND", http_status=404)
    return BalanceOut(available=from_cents(info.available_cents), pending=from_cents(info.pending_cents),
                      currency=info.currency)
