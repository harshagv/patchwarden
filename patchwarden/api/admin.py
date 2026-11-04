"""Admin-only endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from .. import billing
from ..audit_chain import verify
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import Role

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/audit/verify")
def verify_audit_log(db: DbDep, user: CurrentUser) -> dict:
    """Walk the audit log's hash chain and report the first entry that was changed, if any."""
    if user.role != Role.admin:
        raise AppError(403, "admin_only", "Only an administrator can do that.")
    return verify(db)


@router.get("/billing")
def billing_export(month: str, request: Request, db: DbDep, user: CurrentUser, format: str = "json"):
    """What is owed for a month: subscriptions, patch fees (and included patches), accepted migration
    quotes, virtual patches. For the payment system or the accountant; no payment is taken here."""
    from .alerts import parse_month

    if user.role != Role.admin:
        raise AppError(403, "admin_only", "Only an administrator can do that.")
    year, mon = parse_month(month)
    rows = billing.export(db, request.app.state.settings, year, mon)
    if format == "csv":
        return PlainTextResponse(billing.to_csv(rows), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="patchwarden-billing-{month}.csv"'})
    return {"month": month, "currency": request.app.state.settings.currency, "rows": rows,
            "total": sum(r["amount"] for r in rows)}
