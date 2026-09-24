"""
Pagos, Fase 6: panel de finanzas (solo administradores con permisos finos; toda acción queda auditada).

- Reportes desde el libro contable: resumen por periodo, técnico o categoría, y exportación CSV.
- Pagos: listado con filtros y detalle completo (desgloses, historial del proveedor, reembolsos,
  disputas y asientos).
- Reglas de comisión: listado, alta (rechaza reglas que den pérdida), cierre y vista previa.
- Cuentas de técnicos, bandeja de webhooks (reencolar DEAD) y alertas de finanzas.
"""
from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.deps import DbSession, ReqCtx, require_permission, require_roles
from app.audit.writer import write_audit
from app.core.actor import Actor
from app.core.errors import DomainError
from app.kyc.permissions import Permission
from app.models import (
    CommissionRule,
    CommissionScope,
    CommissionTransaction,
    CommissionType,
    LedgerEntry,
    OutboxEvent,
    Payment,
    PaymentDispute,
    PaymentKind,
    PaymentRefund,
    PaymentStatus,
    PaymentTransaction,
    ServiceOrder,
    TechnicianPaymentAccount,
    UserRole,
    WebhookEventStatus,
)
from app.payments import commission, panel, reports
from app.payments.commission import from_cents
from app.schemas.payments import (
    AdminAccountOut,
    AdminPaymentDetailOut,
    AdminPaymentOut,
    AlertOut,
    CloseRuleIn,
    CommissionRuleIn,
    CommissionRuleOut,
    NoteIn,
    QuotePreviewOut,
    SummaryOut,
    WebhookEventOut,
)

router = APIRouter(prefix="/admin", tags=["pagos: panel de finanzas"],
                   dependencies=[Depends(require_roles(UserRole.ADMIN))])
FinanceReader = Annotated[Actor, Depends(require_permission(Permission.FINANCE_READ))]


# ------------------------------------------------------------------ reportes
@router.get("/finance/summary", response_model=SummaryOut, response_model_by_alias=True,
            summary="Resumen: cobrado, comisión, impuestos, técnicos, reembolsos y contracargos (centavos)")
def finance_summary(db: DbSession, _: FinanceReader, date_from: date = Query(alias="from"),
                    date_to: date = Query(alias="to"),
                    group_by: Literal["total", "day", "week", "month", "technician", "category"] = "total"):
    return reports.summary(db, date_from, date_to, group_by)


@router.get("/finance/ledger.csv", summary="Exportar asientos del periodo (CSV para contabilidad)")
def export_ledger(db: DbSession, ctx: ReqCtx, actor: FinanceReader, date_from: date = Query(alias="from"),
                  date_to: date = Query(alias="to")):
    reports._bounds(date_from, date_to)                   # valida el rango antes de empezar a transmitir
    write_audit(db, action="finance.ledger.exported", actor=actor, target_type="ledger",
                changes={"from": date_from.isoformat(), "to": date_to.isoformat()}, ctx=ctx)
    db.commit()
    filename = f"libro-{date_from.isoformat()}-{date_to.isoformat()}.csv"
    return StreamingResponse(reports.ledger_csv(db, date_from, date_to), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ------------------------------------------------------------------ pagos
def _payment_out(p: Payment, model=AdminPaymentOut, **extra):
    return model(id=str(p.id), order_id=str(p.service_order_id), kind=p.kind.value, status=p.status.value,
                 currency=p.currency, amount=from_cents(p.amount_cents), captured=from_cents(p.captured_cents),
                 refunded=from_cents(p.refunded_cents), failure_code=p.failure_code, created_at=p.created_at,
                 authorized_at=p.authorized_at, captured_at=p.captured_at, capture_deadline=p.capture_deadline,
                 **extra)


@router.get("/payments", response_model=list[AdminPaymentOut], summary="Pagos con filtros")
def list_payments(db: DbSession, _: FinanceReader, status_: PaymentStatus | None = Query(None, alias="status"),
                  kind: PaymentKind | None = None, technician_id: uuid.UUID | None = None,
                  order_id: uuid.UUID | None = None, date_from: date | None = Query(None, alias="from"),
                  date_to: date | None = Query(None, alias="to"), limit: int = Query(50, ge=1, le=200),
                  offset: int = Query(0, ge=0, le=100_000)):
    stmt = select(Payment).join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
    if status_:
        stmt = stmt.where(Payment.status == status_)
    if kind:
        stmt = stmt.where(Payment.kind == kind)
    if technician_id:
        stmt = stmt.where(ServiceOrder.technician_id == technician_id)
    if order_id:
        stmt = stmt.where(Payment.service_order_id == order_id)
    if date_from and date_to:
        start, end = reports._bounds(date_from, date_to)
        stmt = stmt.where(Payment.created_at >= start, Payment.created_at < end)
    rows = db.scalars(stmt.order_by(Payment.created_at.desc()).limit(limit).offset(offset))
    return [_payment_out(p) for p in rows]


@router.get("/payments/{payment_id}", response_model=AdminPaymentDetailOut, summary="Detalle completo de un pago")
def payment_detail(db: DbSession, _: FinanceReader, payment_id: uuid.UUID = Path(description="ID del pago")):
    p = db.get(Payment, payment_id)
    if p is None:
        raise DomainError("Pago no encontrado", code="PAYMENT_NOT_FOUND", http_status=404)
    skip = {"_sa_instance_state"}

    def rows(model, *where, order):
        return [{k: (str(v) if isinstance(v, uuid.UUID) else getattr(v, "value", v)) for k, v in vars(r).items()
                 if k not in skip} for r in db.scalars(select(model).where(*where).order_by(order))]

    return _payment_out(
        p, AdminPaymentDetailOut, provider_payment_id=p.provider_payment_id,
        breakdowns=rows(CommissionTransaction, CommissionTransaction.payment_id == p.id, order=CommissionTransaction.id),
        transactions=rows(PaymentTransaction, PaymentTransaction.payment_id == p.id, order=PaymentTransaction.id),
        refunds=rows(PaymentRefund, PaymentRefund.payment_id == p.id, order=PaymentRefund.created_at),
        disputes=rows(PaymentDispute, PaymentDispute.payment_id == p.id, order=PaymentDispute.opened_at),
        ledger=rows(LedgerEntry, LedgerEntry.payment_id == p.id, order=LedgerEntry.id))


# ------------------------------------------------------------------ reglas de comisión
def _rule_out(r: CommissionRule) -> CommissionRuleOut:
    return CommissionRuleOut(id=r.id, scope=r.scope.value, scope_ref=r.scope_ref, type=r.type.value,
                             rate_bp=r.rate_bp, fixed_cents=r.fixed_cents, min_cents=r.min_cents,
                             max_cents=r.max_cents, valid_from=r.valid_from, valid_to=r.valid_to, note=r.note,
                             created_at=r.created_at)


@router.get("/commission-rules", response_model=list[CommissionRuleOut], summary="Reglas de comisión")
def list_rules(db: DbSession, _: FinanceReader, active_only: bool = False):
    stmt = select(CommissionRule)
    if active_only:
        from sqlalchemy import func, or_
        stmt = stmt.where(CommissionRule.valid_from <= func.now(),
                          or_(CommissionRule.valid_to.is_(None), CommissionRule.valid_to > func.now()))
    return [_rule_out(r) for r in db.scalars(stmt.order_by(CommissionRule.scope, CommissionRule.valid_from.desc()))]


@router.post("/commission-rules", response_model=CommissionRuleOut, status_code=201,
             summary="Nueva regla (cierra la anterior del mismo alcance; 422 si da pérdida)")
def create_rule(data: CommissionRuleIn, db: DbSession, ctx: ReqCtx,
                actor: Actor = Depends(require_permission(Permission.COMMISSION_RULES_MANAGE))):
    fields = data.model_dump()
    rule = commission.create_rule(db, actor, scope=CommissionScope(fields.pop("scope")),
                                  type=CommissionType(fields.pop("type")), **fields, ctx=ctx)
    db.commit()
    return _rule_out(rule)


@router.post("/commission-rules/{rule_id}/close", response_model=CommissionRuleOut, summary="Cerrar una regla")
def close_rule(data: CloseRuleIn, db: DbSession, ctx: ReqCtx,
               actor: Actor = Depends(require_permission(Permission.COMMISSION_RULES_MANAGE)),
               rule_id: int = Path(description="ID de la regla")):
    rule = commission.close_rule(db, actor, rule_id, valid_to=data.valid_to, ctx=ctx)
    db.commit()
    return _rule_out(rule)


@router.get("/commission-rules/preview", response_model=QuotePreviewOut,
            summary="Vista previa del cobro y del reparto con la regla vigente")
def preview(db: DbSession, _: FinanceReader, price: str = Query(pattern=r"^\d{1,7}(\.\d{1,2})?$"),
            category_id: int = Query(ge=1), technician_id: uuid.UUID | None = None, has_rfc: bool = True):
    rule = commission.resolve_rule(db, category_id=category_id, technician_id=technician_id)
    b = commission.compute(commission.to_cents(price), commission.RuleTerms.of(rule),
                           commission.TaxRates.current(has_rfc))
    cost = commission.provider_cost_cents(b.price_cents, b.taxes)
    return QuotePreviewOut(rule_id=rule.id, rule_scope=rule.scope.value, price=from_cents(b.price_cents),
                           service_tax=from_cents(b.service_tax_cents), total_charged=from_cents(b.charge_cents),
                           commission=from_cents(b.commission_cents), commission_tax=from_cents(b.commission_tax_cents),
                           withholding_isr=from_cents(b.withholding_isr_cents),
                           withholding_iva=from_cents(b.withholding_iva_cents),
                           technician_net=from_cents(b.technician_cents),
                           application_fee=from_cents(b.application_fee_cents), provider_cost_estimate=from_cents(cost))


# ------------------------------------------------------------------ cuentas de técnicos
@router.get("/payment-accounts", response_model=list[AdminAccountOut], summary="Cuentas de pagos de técnicos")
def list_accounts(db: DbSession, _: FinanceReader, status_: str | None = Query(None, alias="status"),
                  blocked: bool | None = None, limit: int = Query(100, ge=1, le=500)):
    stmt = select(TechnicianPaymentAccount)
    if status_:
        stmt = stmt.where(TechnicianPaymentAccount.status == status_)
    if blocked is not None:
        cond = TechnicianPaymentAccount.blocked_reason.is_not(None)
        stmt = stmt.where(cond if blocked else ~cond)
    rows = db.scalars(stmt.order_by(TechnicianPaymentAccount.updated_at.desc()).limit(limit))
    return [AdminAccountOut(id=str(a.id), technician_id=str(a.technician_id), provider=a.provider,
                            provider_account_id=a.provider_account_id, status=a.status.value,
                            can_receive_payments=a.can_receive_payments, blocked_reason=a.blocked_reason,
                            requirements_due=a.requirements_due or [], name_matches_kyc=a.name_matches_kyc,
                            last_synced_at=a.last_synced_at) for a in rows]


# ------------------------------------------------------------------ webhooks
def _webhook_out(e) -> WebhookEventOut:
    return WebhookEventOut(id=e.id, provider_event_id=e.provider_event_id, type=e.type, status=e.status.value,
                           attempts=e.attempts, last_error=e.last_error, received_at=e.received_at,
                           processed_at=e.processed_at)


@router.get("/payment-webhooks", response_model=list[WebhookEventOut], summary="Bandeja de eventos del proveedor")
def list_webhooks(db: DbSession, _: FinanceReader, status_: WebhookEventStatus | None = Query(None, alias="status"),
                  limit: int = Query(100, ge=1, le=500)):
    return [_webhook_out(e) for e in panel.list_webhooks(db, status=status_, limit=limit)]


@router.post("/payment-webhooks/{event_id}/requeue", response_model=WebhookEventOut,
             summary="Reencolar un evento DEAD o ignorado (tras corregir la causa)")
def requeue_webhook(data: NoteIn, db: DbSession, ctx: ReqCtx,
                    actor: Actor = Depends(require_permission(Permission.WEBHOOKS_MANAGE)),
                    event_id: int = Path(description="ID del evento")):
    ev = panel.requeue_webhook(db, actor, event_id, data.note, ctx)
    db.commit()
    return _webhook_out(ev)


# ------------------------------------------------------------------ alertas
def _alert_out(a: OutboxEvent) -> AlertOut:
    return AlertOut(id=str(a.id), type=a.event_type, payload=a.payload or {}, created_at=a.created_at,
                    acknowledged_at=a.processed_at)


@router.get("/finance/alerts", response_model=list[AlertOut], summary="Alertas de finanzas pendientes")
def list_alerts(db: DbSession, _: FinanceReader, include_acknowledged: bool = False,
                type_: str | None = Query(None, alias="type", max_length=60), limit: int = Query(100, ge=1, le=500)):
    return [_alert_out(a) for a in panel.list_alerts(db, include_acknowledged=include_acknowledged,
                                                     event_type=type_, limit=limit)]


@router.post("/finance/alerts/{alert_id}/ack", response_model=AlertOut, summary="Marcar una alerta como atendida")
def ack_alert(data: NoteIn, db: DbSession, ctx: ReqCtx,
              actor: Actor = Depends(require_permission(Permission.FINANCE_ALERTS_ACK)),
              alert_id: uuid.UUID = Path(description="ID de la alerta")):
    alert = panel.acknowledge(db, actor, alert_id, data.note, ctx)
    db.commit()
    return _alert_out(alert)
