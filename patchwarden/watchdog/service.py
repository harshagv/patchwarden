"""Watchdog agent: scheduled version checks, CVE/release matching, alerts, monthly reports.

Only sites with an active (or past_due) watchdog subscription are checked.
Turning monitoring off cancels the subscription, and its checks stop at once.
"""

from __future__ import annotations

import logging
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..crypto import CredentialVault
from ..errors import AppError
from ..fakes import DemoWorld
from ..models import (
    Advisory,
    Alert,
    AuditLog,
    FeedCursor,
    PatchJob,
    Product,
    Risk,
    Scan,
    Site,
    Subscription,
    SubscriptionStatus,
    User,
    WatchCheck,
)
from ..patch.adapters import AdapterError
from ..patch.service import build_adapter
from ..scanner.service import Scanner, TargetRejected
from ..scanner.versions import assess, parse_version
from .feeds import Advisory as FeedAdvisory
from .feeds import AdvisorySource, FeedError, version_affected
from .notify import Email, Notifier

log = logging.getLogger(__name__)

MONITORED = (SubscriptionStatus.active, SubscriptionStatus.past_due)  # past_due: grace period, keep watching
WATCHED_BY = (Product.watchdog, Product.wp_guard)  # WordPress Guard bundles the Watchdog
TRANSITIONS = {
    SubscriptionStatus.active: {SubscriptionStatus.past_due, SubscriptionStatus.cancelled},
    SubscriptionStatus.past_due: {SubscriptionStatus.active, SubscriptionStatus.cancelled},
    SubscriptionStatus.cancelled: {SubscriptionStatus.active},
}
RISK_RANK = {Risk.safe: 0, Risk.unknown: 0, Risk.patch_now: 2, Risk.must_migrate: 3}
RISK_SEVERITY = {Risk.patch_now: "critical", Risk.must_migrate: "high"}
VERSION_CHECK_EVERY = timedelta(hours=23)  # "daily", with slack for scheduler drift


def utc(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


# --- subscriptions --------------------------------------------------------------

def watchdog_subscription(db: Session, site: Site) -> Subscription | None:
    return db.scalar(select(Subscription).where(Subscription.site_id == site.id,
                                                Subscription.product == Product.watchdog))


def change_status(db: Session, sub: Subscription, new: SubscriptionStatus, *, actor_id: int | None) -> None:
    if new == sub.status:
        return
    if new not in TRANSITIONS[sub.status]:
        raise AppError(409, "invalid_transition",
                       f"A subscription cannot go from {sub.status.value} to {new.value}.")
    old = sub.status
    sub.status = new
    db.add(AuditLog(user_id=actor_id, site_id=sub.site_id, action="subscription.status_changed",
                    detail={"subscription_id": sub.id, "product": sub.product.value, "from": old.value, "to": new.value}))


def set_monitoring(db: Session, site: Site, user: User, enabled: bool) -> Subscription | None:
    sub = watchdog_subscription(db, site)
    if enabled:
        if sub is None:
            sub = Subscription(site_id=site.id, product=Product.watchdog, status=SubscriptionStatus.active)
            db.add(sub)
            db.flush()
        elif sub.status == SubscriptionStatus.cancelled:
            change_status(db, sub, SubscriptionStatus.active, actor_id=user.id)
    elif sub is not None and sub.status != SubscriptionStatus.cancelled:
        change_status(db, sub, SubscriptionStatus.cancelled, actor_id=user.id)
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="monitoring.on" if enabled else "monitoring.off",
                    detail={}))
    db.commit()
    return sub


def is_monitored(db: Session, site: Site) -> bool:
    """Watched by the Watchdog, on its own or as part of WordPress Guard."""
    return db.scalar(select(Subscription.id).where(Subscription.site_id == site.id,
                                                   Subscription.product.in_(WATCHED_BY),
                                                   Subscription.status.in_(MONITORED)).limit(1)) is not None


# --- alerts ---------------------------------------------------------------------

def alert_text(*, changed: str, means: str, todo: str, link: str) -> str:
    return f"What changed: {changed}\nWhat it means: {means}\nWhat to do: {todo}\nOpen your site: {link}"


class Watchdog:
    def __init__(self, settings: Settings, factory: sessionmaker[Session], scanner: Scanner, notifier: Notifier,
                 sources: list[AdvisorySource], vault: CredentialVault, world: DemoWorld | None):
        self.settings, self.factory, self.scanner = settings, factory, scanner
        self.notifier, self.sources, self.vault, self.world = notifier, sources, vault, world

    async def aclose(self) -> None:
        for source in self.sources:
            await source.aclose()

    def site_link(self, site: Site) -> str:
        return f"{self.settings.public_base_url}/dashboard/sites#site-{site.id}"

    # sites

    def monitored_sites(self, db: Session, site_ids: list[int] | None = None) -> list[Site]:
        q = (select(Site).join(Subscription, Subscription.site_id == Site.id)
             .where(Subscription.product.in_(WATCHED_BY), Subscription.status.in_(MONITORED),
                    Site.owner_id.is_not(None)).distinct().order_by(Site.id))
        if site_ids is not None:
            q = q.where(Site.id.in_(site_ids))
        return list(db.scalars(q).all())

    @staticmethod
    def last_version_check(db: Session, site: Site) -> WatchCheck | None:
        return db.scalar(select(WatchCheck).where(WatchCheck.site_id == site.id, WatchCheck.kind == "version")
                         .order_by(WatchCheck.created_at.desc(), WatchCheck.id.desc()).limit(1))

    async def _alert(self, db: Session, site: Site, *, key: str, severity: str, subject: str, message: str,
                     now: datetime) -> Alert | None:
        if db.scalar(select(Alert.id).where(Alert.site_id == site.id, Alert.cve_id == key)):
            return None  # one alert per site per advisory, ever
        alert = Alert(site_id=site.id, cve_id=key, severity=severity, message=message, created_at=now)
        db.add(alert)
        db.flush()
        owner = db.get(User, site.owner_id)
        if owner is not None and await self.notifier.send(Email(owner.email, subject, message)):
            alert.sent_at = utc(None)
        db.add(AuditLog(user_id=None, site_id=site.id, action="alert.created",
                        detail={"alert_id": alert.id, "key": key, "severity": severity,
                                "emailed": alert.sent_at is not None}))
        return alert

    # 1. version checks

    async def _read_version(self, site: Site):
        try:
            outcome = await self.scanner.scan(site.domain)
        except TargetRejected as exc:
            return None, {"error": exc.code, "message": exc.message}
        if outcome.detected_version is None and site.credentials:
            # Hidden from outside: ask the host (read-only) if the owner gave us access.
            try:
                adapter = build_adapter(site, self.vault, self.world)
                version = await adapter.php_version()
                a = assess(parse_version(version))
                outcome.detected_version, outcome.risk = version, a.risk
                outcome.findings.update(version_source="inside", summary=a.summary, next_step=a.next_step,
                                        fixed_version=a.fixed_version)
            except (AppError, AdapterError):
                pass
        return outcome, None

    async def run_version_checks(self, now: datetime | None = None, *, site_ids: list[int] | None = None,
                                 force: bool = False) -> int:
        now = utc(now)
        done = 0
        with self.factory() as db:
            for site in self.monitored_sites(db, site_ids):
                last = self.last_version_check(db, site)
                if not force and last is not None and now - last.created_at < VERSION_CHECK_EVERY:
                    continue
                outcome, error = await self._read_version(site)
                scan = None
                if outcome is not None:
                    scan = Scan(site_id=site.id, detected_version=outcome.detected_version, risk=outcome.risk,
                                raw_headers=outcome.raw_headers, scanned_url=outcome.scanned_url,
                                findings={**outcome.findings, "source": "watchdog"}, created_at=now)
                    db.add(scan)
                    db.flush()
                check = WatchCheck(site_id=site.id, kind="version", scan_id=scan.id if scan else None,
                                   detected_version=scan.detected_version if scan else None,
                                   risk=scan.risk if scan else Risk.unknown,
                                   detail=error or {"version_source": outcome.findings.get("version_source")},
                                   created_at=now)
                db.add(check)
                db.flush()
                done += 1
                if scan is not None:
                    await self._risk_alert(db, site, scan, last, check, now)
                    await self._match_site(db, site, scan.detected_version, now)
                db.commit()
        return done

    async def _risk_alert(self, db: Session, site: Site, scan: Scan, last: WatchCheck | None, check: WatchCheck,
                          now: datetime) -> None:
        new = scan.risk
        if new not in RISK_SEVERITY:
            return
        if last is not None and last.risk is not None and RISK_RANK[last.risk] >= RISK_RANK[new]:
            return
        f = scan.findings or {}
        changed = (f"Our check found PHP {scan.detected_version or 'hidden'} on {site.domain}"
                   + (f" (it was {last.detected_version or 'hidden'} before)." if last else "."))
        await self._alert(
            db, site, key=f"risk:{new.value}:{check.id}", severity=RISK_SEVERITY[new],
            subject=f"Patchwarden: {site.domain} needs attention",
            message=alert_text(changed=changed, means=f.get("summary", ""), todo=f.get("next_step", ""),
                               link=self.site_link(site)),
            now=now)

    # 2. feeds

    async def poll_feeds(self, now: datetime | None = None) -> int:
        """Fetch new advisories from every source, then match them against monitored sites."""
        now = utc(now)
        new = 0
        with self.factory() as db:
            for source in self.sources:
                cursor = db.get(FeedCursor, source.name)
                since = (datetime.fromisoformat(cursor.value) if cursor
                         else now - timedelta(days=self.settings.cve_lookback_days))
                try:
                    advisories = await source.fetch(since, now)
                except FeedError as exc:
                    log.warning("Watchdog feed %s skipped: %s", source.name, exc)
                    continue  # cursor not moved: the next poll retries the same window
                new += self._store_advisories(db, advisories, now)
                if cursor is None:
                    db.add(FeedCursor(name=source.name, value=now.isoformat()))
                else:
                    cursor.value = now.isoformat()
                db.commit()
        await self.match_all(now)
        return new

    @staticmethod
    def _store_advisories(db: Session, advisories: list[FeedAdvisory], now: datetime) -> int:
        new = 0
        for a in advisories:
            row = db.get(Advisory, a.id)
            if row is None:
                db.add(Advisory(id=a.id, source=a.source, severity=a.severity, score=a.score, summary=a.summary,
                                affected=a.affected, fixed_in=a.fixed_in, url=a.url, first_seen=now))
                new += 1
            else:  # NVD revises ranges and scores: keep the latest, keep first_seen
                row.severity, row.score, row.summary = a.severity, a.score, a.summary
                row.affected, row.fixed_in, row.url = a.affected, a.fixed_in, a.url
        db.flush()
        return new

    async def match_all(self, now: datetime | None = None) -> int:
        now = utc(now)
        created = 0
        with self.factory() as db:
            for site in self.monitored_sites(db):
                last = self.last_version_check(db, site)
                version = last.detected_version if last else None
                hits = await self._match_site(db, site, version, now)
                db.add(WatchCheck(site_id=site.id, kind="cve", detected_version=version,
                                  detail={"matched": hits, "version_known": version is not None}, created_at=now))
                created += len(hits)
                db.commit()
        return created

    async def _match_site(self, db: Session, site: Site, version: str | None, now: datetime) -> list[str]:
        if not version:
            return []
        hits = []
        for adv in db.scalars(select(Advisory).order_by(Advisory.id)).all():
            if not version_affected(version, adv.affected):
                continue
            v, fix = parse_version(version), parse_version(adv.fixed_in or "")
            same_line = fix is not None and v is not None and fix.branch == v.branch
            todo = (f"Update PHP to {adv.fixed_in} or newer. You can start the update, with a backup and your "
                    "approval, from your Patchwarden dashboard." if same_line else
                    "Update PHP to the newest release of a supported line. Your Patchwarden dashboard can plan it.")
            label = "PHP security release" if adv.source == "php_release" else f"security flaw ({adv.id})"
            alert = await self._alert(
                db, site, key=adv.id, severity=adv.severity,
                subject=f"Patchwarden: new {adv.severity} risk for {site.domain}",
                message=alert_text(
                    changed=f"A new {label} was published, rated {adv.severity}.",
                    means=f"Your site {site.domain} runs PHP {version}, which is affected. {adv.summary}"[:2000],
                    todo=todo, link=self.site_link(site)),
                now=now)
            if alert is not None:
                hits.append(adv.id)
        return hits

    # 3. the schedule

    async def tick(self, now: datetime | None = None) -> None:
        """Hourly job: version checks for sites that are due, then a feed poll."""
        try:
            await self.run_version_checks(now)
            await self.poll_feeds(now)
        except Exception as exc:  # noqa: BLE001 - a scheduler job must not die silently
            log.error("Watchdog tick failed: %s", type(exc).__name__)

    async def send_monthly_reports(self, now: datetime | None = None) -> int:
        """Monthly job (1st of the month): email each monitored site's owner last month's report."""
        now = utc(now)
        first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        prev = first - timedelta(days=1)
        sent = 0
        with self.factory() as db:
            for site in self.monitored_sites(db):
                report = monthly_report(db, site, prev.year, prev.month)
                owner = db.get(User, site.owner_id)
                link = f"{self.settings.public_base_url}/dashboard/sites/{site.id}/monthly?month={report['month']}"
                body = f"{report['summary']}\n\nRead the full report: {link}"
                if owner and await self.notifier.send(Email(owner.email, f"Patchwarden monthly report: {site.domain}", body)):
                    sent += 1
        return sent


# --- monthly report -------------------------------------------------------------

def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def monthly_report(db: Session, site: Site, year: int, month: int) -> dict[str, Any]:
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=monthrange(year, month)[1])
    in_month = lambda col: (col >= start) & (col < end)  # noqa: E731

    checks = db.scalars(select(WatchCheck).where(WatchCheck.site_id == site.id, in_month(WatchCheck.created_at))
                        .order_by(WatchCheck.created_at)).all()
    version_checks = [c for c in checks if c.kind == "version"]
    latest = db.scalar(select(WatchCheck).where(WatchCheck.site_id == site.id, WatchCheck.kind == "version",
                                                WatchCheck.created_at < end)
                       .order_by(WatchCheck.created_at.desc(), WatchCheck.id.desc()).limit(1))
    alerts = db.scalars(select(Alert).where(Alert.site_id == site.id, in_month(Alert.created_at))
                        .order_by(Alert.created_at)).all()
    jobs = db.scalars(select(PatchJob).where(PatchJob.site_id == site.id, in_month(PatchJob.created_at))
                      .order_by(PatchJob.id)).all()
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.site_id == site.id, Alert.read.is_(False)))

    risk = latest.risk.value if latest and latest.risk else "unknown"
    version = latest.detected_version if latest else None
    days = len({c.created_at.date() for c in version_checks})
    summary = (f"In {start:%B %Y} we checked {site.domain} {_n(len(version_checks), 'time')} on {_n(days, 'day')}. "
               + (f"It runs PHP {version}. " if version else "Its PHP version is hidden from outside. ")
               + (f"We raised {_n(len(alerts), 'alert')}. " if alerts else "No new risks were found. ")
               + (f"{_n(len(jobs), 'PHP update')} planned or run." if jobs else ""))
    return {
        "site_id": site.id,
        "domain": site.domain,
        "month": f"{year:04d}-{month:02d}",
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "current": {"php_version": version, "risk": risk,
                    "checked_at": latest.created_at.isoformat() if latest else None},
        "checks": {"version": len(version_checks), "cve": len(checks) - len(version_checks), "days_checked": days,
                   "days_in_month": monthrange(year, month)[1],
                   "failed": sum(1 for c in version_checks if c.detail.get("error"))},
        "risks_found": [{"id": a.id, "key": a.cve_id, "severity": a.severity, "message": a.message,
                         "created_at": a.created_at.isoformat(), "read": a.read} for a in alerts],
        "actions_taken": [{"patch_job_id": j.id, "from_version": j.from_version, "to_version": j.to_version,
                           "state": j.state.value, "created_at": j.created_at.isoformat()} for j in jobs],
        "open_alerts": open_alerts,
        "summary": summary.strip(),
    }
