"""Watchdog endpoints: alerts, monitoring on/off, subscription status, monthly report."""

from __future__ import annotations

import re

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import select

from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import Alert, Role, Site, Subscription, SubscriptionStatus, User
from ..watchdog import service as wd

router = APIRouter(tags=["watchdog"])


def alert_json(a: Alert) -> dict:
    return {"id": a.id, "site_id": a.site_id, "domain": a.site.domain, "cve_id": a.cve_id, "severity": a.severity,
            "message": a.message, "sent_at": a.sent_at.isoformat() if a.sent_at else None, "read": a.read,
            "created_at": a.created_at.isoformat()}


def user_alerts(db, user: User, *, unread_only: bool = False) -> list[Alert]:
    q = select(Alert).join(Site, Site.id == Alert.site_id).where(Site.owner_id == user.id)
    if unread_only:
        q = q.where(Alert.read.is_(False))
    return list(db.scalars(q.order_by(Alert.created_at.desc(), Alert.id.desc())).all())


def owned_alert(db, alert_id: int, user: User) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.site.owner_id != user.id:
        raise AppError(404, "alert_not_found", "We could not find that alert.")
    return alert


@router.get("/api/alerts")
def list_alerts(db: DbDep, user: CurrentUser, unread: bool = False) -> dict:
    return {"alerts": [alert_json(a) for a in user_alerts(db, user, unread_only=unread)]}


@router.post("/api/alerts/{alert_id}/read")
def mark_read(alert_id: int, db: DbDep, user: CurrentUser) -> dict:
    alert = owned_alert(db, alert_id, user)
    alert.read = True
    db.commit()
    return alert_json(alert)


class MonitoringIn(BaseModel):
    enabled: bool


def _owned_site(db, site_id: int, user: User) -> Site:
    site = db.get(Site, site_id)
    if site is None or site.owner_id != user.id:
        raise AppError(404, "site_not_found", "We could not find that site.")
    return site


def monitoring_json(db, site: Site) -> dict:
    sub = wd.watchdog_subscription(db, site)
    return {"site_id": site.id, "monitoring": sub is not None and sub.status in wd.MONITORED,
            "subscription": ({"id": sub.id, "product": sub.product.value, "status": sub.status.value}
                             if sub else None)}


@router.post("/api/sites/{site_id}/monitoring")
def set_monitoring(site_id: int, body: MonitoringIn, db: DbDep, user: CurrentUser) -> dict:
    """Turn the Watchdog on or off for a site. Off cancels the watchdog subscription and stops all checks."""
    site = _owned_site(db, site_id, user)
    wd.set_monitoring(db, site, user, body.enabled)
    return monitoring_json(db, site)


@router.post("/api/watchdog/run")
async def run_now(request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Check your monitored sites now (version check + feed poll), instead of waiting for the schedule."""
    watchdog: wd.Watchdog = request.app.state.watchdog
    ids = [s.id for s in db.scalars(select(Site).where(Site.owner_id == user.id)).all()]
    checked = await watchdog.run_version_checks(site_ids=ids, force=True)
    new = await watchdog.poll_feeds()
    return {"sites_checked": checked, "new_advisories": new,
            "unread_alerts": len(user_alerts(db, user, unread_only=True))}


class StatusIn(BaseModel):
    status: SubscriptionStatus


@router.post("/api/subscriptions/{sub_id}/status")
def change_subscription_status(sub_id: int, body: StatusIn, db: DbDep, user: CurrentUser) -> dict:
    """Billing hook for a later payments phase. Admin only; no payments are taken in this build."""
    if user.role != Role.admin:
        raise AppError(403, "admin_only", "Only an administrator can change billing status.")
    sub = db.get(Subscription, sub_id)
    if sub is None:
        raise AppError(404, "subscription_not_found", "We could not find that subscription.")
    wd.change_status(db, sub, body.status, actor_id=user.id)
    db.commit()
    return {"id": sub.id, "site_id": sub.site_id, "product": sub.product.value, "status": sub.status.value}


_MONTH = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")


def parse_month(month: str) -> tuple[int, int]:
    m = _MONTH.match(month or "")
    if not m:
        raise AppError(422, "invalid_month", "Use a month like 2026-10.")
    return int(m.group(1)), int(m.group(2))


@router.get("/api/sites/{site_id}/monthly-report")
def get_monthly_report(site_id: int, month: str, db: DbDep, user: CurrentUser) -> dict:
    site = db.get(Site, site_id)
    if site is None or (site.owner_id != user.id and user.role != Role.admin):
        raise AppError(404, "site_not_found", "We could not find that site.")
    year, mon = parse_month(month)
    return wd.monthly_report(db, site, year, mon)
