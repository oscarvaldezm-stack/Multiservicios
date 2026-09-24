"""
Reportes financieros (sección 11 del doc de pagos: /admin/finance/summary).

Salen del libro contable de partida doble, NO de sumar columnas de payments: así cuadran con
reembolsos parciales, capturas parciales, contracargos y cargos por cancelación. Los periodos se
cortan en la zona horaria del negocio (REPORT_TIMEZONE, hora del centro de México).

| Métrica            | Asientos                                        |
|--------------------|-------------------------------------------------|
| charged            | − CUSTOMER de los asientos CAPTURE               |
| refunded           | + CUSTOMER de REFUND                             |
| charged_back       | + CUSTOMER de CHARGEBACK                         |
| commission         | PLATFORM_REVENUE (neto de comisiones devueltas)  |
| commission_vat     | VAT_PAYABLE                                      |
| withheld           | TAX_WITHHELD (ISR + IVA retenidos al técnico)    |
| technicians        | TECHNICIAN_PAYABLE (neto de lo recuperado)       |
| platform_absorbed  | − REFUNDS (reembolsos y contracargos absorbidos) |
| platform_net       | commission − platform_absorbed (antes de la comisión del proveedor) |
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import date, datetime, time, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import DomainError
from app.models import LedgerAccount, LedgerEntry, Payment, ServiceCategory, ServiceOrder, User

A = LedgerAccount
GroupBy = Literal["total", "day", "week", "month", "technician", "category"]
MAX_RANGE_DAYS = 366


def _bounds(date_from: date, date_to: date) -> tuple[datetime, datetime]:
    """[date_from 00:00, date_to + 1 día 00:00) en la zona del negocio."""
    if date_to < date_from:
        raise DomainError("El rango de fechas está invertido", code="REPORT_INVALID_RANGE", http_status=422)
    if (date_to - date_from).days > MAX_RANGE_DAYS:
        raise DomainError("El rango máximo es de un año", code="REPORT_RANGE_TOO_LONG", http_status=422)
    tz = ZoneInfo(get_settings().REPORT_TIMEZONE)
    return (datetime.combine(date_from, time.min, tzinfo=tz),
            datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=tz))


def _sum(account: LedgerAccount, entry_types: tuple[str, ...] | None = None, sign: int = 1):
    cond = LedgerEntry.account == account
    if entry_types:
        cond = and_(cond, LedgerEntry.entry_type.in_(entry_types))
    return sign * func.coalesce(func.sum(case((cond, LedgerEntry.amount_cents), else_=0)), 0)


METRICS = {
    "charged": _sum(A.CUSTOMER, ("CAPTURE",), -1),
    "refunded": _sum(A.CUSTOMER, ("REFUND",)),
    "charged_back": _sum(A.CUSTOMER, ("CHARGEBACK",)),
    "commission": _sum(A.PLATFORM_REVENUE),
    "commission_vat": _sum(A.VAT_PAYABLE),
    "withheld": _sum(A.TAX_WITHHELD),
    "technicians": _sum(A.TECHNICIAN_PAYABLE),
    "platform_absorbed": _sum(A.REFUNDS, sign=-1),
}


def summary(db: Session, date_from: date, date_to: date, group_by: GroupBy = "total") -> dict:
    start, end = _bounds(date_from, date_to)
    tz = get_settings().REPORT_TIMEZONE
    local = func.timezone(tz, LedgerEntry.created_at)
    keys = {"total": None, "day": func.date_trunc("day", local), "week": func.date_trunc("week", local),
            "month": func.date_trunc("month", local), "technician": ServiceOrder.technician_id,
            "category": ServiceOrder.category_id}
    if group_by not in keys:
        raise DomainError("Agrupación inválida", code="REPORT_INVALID_GROUP", http_status=422)
    key = keys[group_by]
    captured = func.count(func.distinct(case((LedgerEntry.entry_type == "CAPTURE", LedgerEntry.payment_id))))
    cols = [expr.label(name) for name, expr in METRICS.items()] + [captured.label("captured_payments")]
    stmt = (select(*([key.label("key")] if key is not None else []), *cols)
            .select_from(LedgerEntry)
            .join(Payment, Payment.id == LedgerEntry.payment_id)
            .join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
            .where(LedgerEntry.created_at >= start, LedgerEntry.created_at < end))
    if key is not None:
        stmt = stmt.group_by(key).order_by(key)
    rows = [dict(r._mapping) for r in db.execute(stmt)]
    labels = _labels(db, group_by, [r.get("key") for r in rows])
    groups = []
    for r in rows:
        k = r.pop("key", None)
        r["platform_net"] = r["commission"] - r["platform_absorbed"]
        groups.append({"key": _key_str(k), "label": labels.get(_key_str(k)), **{m: int(v) for m, v in r.items()}})
    totals = {m: sum(g[m] for g in groups) for m in (*METRICS, "platform_net", "captured_payments")}
    if group_by == "total":
        groups = []
    return {"from": date_from.isoformat(), "to": date_to.isoformat(), "timezone": tz, "group_by": group_by,
            "currency": get_settings().PAYMENT_CURRENCY, "totals": totals, "groups": groups}


def _key_str(k) -> str | None:
    if k is None:
        return None
    if isinstance(k, datetime):
        return k.date().isoformat()
    return str(k)


def _labels(db: Session, group_by: str, keys: list) -> dict[str, str]:
    """Nombre visible del técnico (sin correo ni teléfono) o de la categoría."""
    keys = [k for k in keys if k is not None]
    if group_by == "technician" and keys:
        return {str(i): n for i, n in db.execute(select(User.id, User.full_name).where(User.id.in_(keys)))}
    if group_by == "category" and keys:
        return {str(i): n for i, n in db.execute(select(ServiceCategory.id, ServiceCategory.name)
                                                 .where(ServiceCategory.id.in_(keys)))}
    return {}


# =============================================================================
# Exportación del libro (para contabilidad)
# =============================================================================
CSV_HEADER = ["fecha_local", "grupo", "tipo", "cuenta", "monto", "moneda", "pago", "orden", "tecnico", "categoria"]


def ledger_csv(db: Session, date_from: date, date_to: date) -> Iterator[str]:
    """Asientos del periodo, uno por renglón, sin datos personales (solo identificadores)."""
    start, end = _bounds(date_from, date_to)
    tz = ZoneInfo(get_settings().REPORT_TIMEZONE)
    stmt = (select(LedgerEntry, Payment.service_order_id, ServiceOrder.technician_id, ServiceOrder.category_id)
            .join(Payment, Payment.id == LedgerEntry.payment_id)
            .join(ServiceOrder, ServiceOrder.id == Payment.service_order_id)
            .where(LedgerEntry.created_at >= start, LedgerEntry.created_at < end)
            .order_by(LedgerEntry.id))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADER)
    yield _drain(buf)
    for entry, order_id, technician_id, category_id in db.execute(stmt).yield_per(1000):
        writer.writerow([entry.created_at.astimezone(tz).isoformat(timespec="seconds"), entry.transaction_group_id,
                         entry.entry_type, entry.account.value, f"{entry.amount_cents / 100:.2f}", entry.currency,
                         entry.payment_id, order_id, technician_id or "", category_id])
        yield _drain(buf)


def _drain(buf: io.StringIO) -> str:
    value = buf.getvalue()
    buf.seek(0)
    buf.truncate(0)
    return value


__all__ = ["GroupBy", "ledger_csv", "summary"]
