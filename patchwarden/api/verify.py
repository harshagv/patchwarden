"""Ownership verification, a read-only connection test, and admin funnel metrics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from .. import verification
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import AuditLog, PatchJob, PatchState, Role, Scan, Site, Subscription, SubscriptionStatus, User
from ..patch.adapters import AdapterError
from ..patch.service import build_adapter
from .patches import owned_site

router = APIRouter(tags=["verification"])


@router.post("/api/sites/{site_id}/verification")
def start_verification(site_id: int, db: DbDep, user: CurrentUser) -> dict:
    """How to prove you own this domain: a DNS TXT record or a file (or connect the WordPress plugin)."""
    return verification.start(db, owned_site(db, site_id, user), user)


@router.get("/api/sites/{site_id}/verification")
def verification_status(site_id: int, db: DbDep, user: CurrentUser) -> dict:
    return verification.instructions(owned_site(db, site_id, user))


@router.post("/api/sites/{site_id}/verification/check")
async def check_verification(site_id: int, request: Request, db: DbDep, user: CurrentUser) -> JSONResponse:
    site = owned_site(db, site_id, user)
    st = request.app.state
    result = await verification.check(db, site, user, resolve_txt=st.txt_resolver, fetcher=st.scanner.fetcher)
    if not result["verified"]:
        raise AppError(409, "not_verified", result["message"])
    return JSONResponse(result)


@router.post("/api/sites/{site_id}/test-connection")
async def test_connection(site_id: int, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Read-only check that the saved token works: asks the host for the site's PHP version. Changes nothing."""
    site = owned_site(db, site_id, user)
    adapter = build_adapter(site, request.app.state.vault, request.app.state.demo_world)
    try:
        version = await adapter.php_version()
        available = await adapter.available_versions()
    except AdapterError as exc:
        raise AppError(502, exc.code, exc.message) from None
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.connection_tested", detail={"ok": True}))
    db.commit()
    return {"ok": True, "access": adapter.display_name, "php_version": version, "available_versions": available}


@router.get("/api/admin/funnel")
def funnel(db: DbDep, user: CurrentUser, days: int = 30) -> dict:
    """Scan -> claim -> verify -> patch -> subscribe, over the last `days`. Admin only."""
    if user.role != Role.admin:
        raise AppError(403, "admin_only", "Only an administrator can do that.")
    since = datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 365)))

    def actions(name: str) -> int:
        return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == name,
                                                               AuditLog.created_at >= since)) or 0

    stages = {
        "free_scans": actions("scan.free"),
        "accounts": db.scalar(select(func.count(User.id)).where(User.created_at >= since)) or 0,
        "claimed_sites": actions("site.claimed"),
        "verified_sites": db.scalar(select(func.count(Site.id)).where(Site.verified_at >= since)) or 0,
        "patch_plans": actions("patch.dry_run"),
        "patches_approved": actions("patch.approved"),
        "patches_succeeded": db.scalar(select(func.count(PatchJob.id)).where(
            PatchJob.state == PatchState.succeeded, PatchJob.created_at >= since)) or 0,
        "active_subscriptions": db.scalar(select(func.count(Subscription.id)).where(
            Subscription.status == SubscriptionStatus.active)) or 0,
    }
    order = list(stages)
    conversion = {f"{a}_to_{b}": (round(stages[b] / stages[a], 3) if stages[a] else None)
                  for a, b in zip(order, order[1:])}
    return {"days": days, "since": since.isoformat(), "stages": stages, "conversion": conversion,
            "scans_total": db.scalar(select(func.count(Scan.id)).where(Scan.created_at >= since)) or 0}
