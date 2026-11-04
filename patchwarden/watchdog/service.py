"""Watchdog agent: scheduled version checks, CVE/release matching, alerts, monthly reports.

Only sites with an active (or past_due) watchdog subscription are checked.
Turning monitoring off cancels the subscription, and its checks stop at once.
"""

from __future__ import annotations

import asyncio
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
    PatchState,
    Product,
    Risk,
    Scan,
    Site,
    Subscription,
    SubscriptionStatus,
    User,
    WatchCheck,
    WatchCounter,
)
from ..patch.adapters import AdapterError
from ..patch.service import build_adapter
from ..scanner.service import Scanner, TargetRejected
from ..scanner.versions import assess, parse_version
from .feeds import Advisory as FeedAdvisory
from ..branding import brand_for, footer_text
from . import channels
from .feeds import AdvisorySource, EpssClient, FeedError, KevFeed, version_affected
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
    if new == SubscriptionStatus.past_due:
        sub.past_due_since, sub.reminders_sent = datetime.now(timezone.utc), 0
    elif old == SubscriptionStatus.past_due:
        sub.past_due_since = None
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


def priority_for(severity: str, *, kev: bool = False, epss: float | None = None, urgent_epss: float = 0.1) -> str:
    """Alert at once when it is exploited (KEV), likely to be (EPSS), or critical/high; else the daily digest."""
    if kev or (epss is not None and epss >= urgent_epss) or severity in ("critical", "high"):
        return "urgent"
    return "digest"


class Watchdog:
    def __init__(self, settings: Settings, factory: sessionmaker[Session], scanner: Scanner, notifier: Notifier,
                 sources: list[AdvisorySource], vault: CredentialVault, world: DemoWorld | None,
                 kev: KevFeed | None = None, epss: EpssClient | None = None):
        self.settings, self.factory, self.scanner = settings, factory, scanner
        self.notifier, self.sources, self.vault, self.world = notifier, sources, vault, world
        self.kev, self.epss = kev, epss

    async def aclose(self) -> None:
        for source in [*self.sources, self.kev, self.epss]:
            if source is not None:
                await source.aclose()

    def site_link(self, site: Site) -> str:
        return f"{self.settings.public_base_url}/dashboard/sites#site-{site.id}"

    # sites and counters

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

    @staticmethod
    def count(db: Session, site_id: int, now: datetime, *, version: int = 0, cve: int = 0) -> None:
        """One counter row per site per day, instead of one row per site per poll."""
        day = now.astimezone(timezone.utc).strftime("%Y-%m-%d")
        row = db.scalar(select(WatchCounter).where(WatchCounter.site_id == site_id, WatchCounter.day == day))
        if row is None:
            row = WatchCounter(site_id=site_id, day=day, version_checks=0, cve_checks=0)
            db.add(row)
        row.version_checks += version
        row.cve_checks += cve

    # delivery

    @staticmethod
    def _branded(db: Session, site: Site | None, subject: str, text: str) -> tuple[str, str]:
        """A team's white-label name and footer in place of ours (patchwarden/branding.py)."""
        if site is None:
            return subject, text
        brand = brand_for(db, site)
        if brand["name"] != "Patchwarden":
            subject = subject.replace("Patchwarden", brand["name"])
            text = text.replace("Patchwarden", brand["name"])
        return subject, text + footer_text(brand)

    async def _notify(self, db: Session, owner: User, subject: str, text: str, event: dict,
                      site: Site | None = None) -> tuple[bool, dict]:
        subject, text = self._branded(db, site, subject, text)
        emailed = await self.notifier.send(Email(owner.email, subject, text))
        delivered = await channels.deliver(db, self.vault, self.scanner.fetcher, owner.id, f"*{subject}*\n{text}", event)
        return emailed, delivered

    async def _alert(self, db: Session, site: Site, *, key: str, severity: str, subject: str, message: str,
                     now: datetime, priority: str | None = None) -> Alert | None:
        if db.scalar(select(Alert.id).where(Alert.site_id == site.id, Alert.cve_id == key)):
            return None  # one alert per site per advisory, ever
        priority = priority or priority_for(severity, urgent_epss=self.settings.epss_urgent)
        message = self._branded(db, site, "", message)[1]
        alert = Alert(site_id=site.id, cve_id=key, severity=severity, message=message, created_at=now,
                      priority=priority)
        db.add(alert)
        db.flush()
        owner = db.get(User, site.owner_id)
        if owner is not None and priority == "urgent":
            emailed, delivered = await self._notify(
                db, owner, subject, message.removesuffix(footer_text(brand_for(db, site))),
                {"type": "alert", "alert_id": alert.id, "site": site.domain, "key": key, "severity": severity,
                 "priority": priority}, site)
            if emailed:
                alert.sent_at = utc(None)
            alert.delivered = delivered
        db.add(AuditLog(user_id=None, site_id=site.id, action="alert.created",
                        detail={"alert_id": alert.id, "key": key, "severity": severity, "priority": priority,
                                "emailed": alert.sent_at is not None}))
        return alert

    # 1. version checks: fetched in parallel, written in order

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
        with self.factory() as db:
            due = []
            for site in self.monitored_sites(db, site_ids):
                last = self.last_version_check(db, site)
                if force or last is None or now - last.created_at >= VERSION_CHECK_EVERY:
                    _ = site.credentials  # load now: the parallel part below does no database work
                    due.append((site, last))
            limit = asyncio.Semaphore(max(1, self.settings.watchdog_concurrency))

            async def read(site: Site):
                async with limit:
                    return await self._read_version(site)

            results = await asyncio.gather(*(read(site) for site, _ in due))
            for (site, last), (outcome, error) in zip(due, results):
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
                self.count(db, site.id, now, version=1)
                db.flush()
                if scan is not None:
                    await self._risk_alert(db, site, scan, last, check, now)
                    # New advisories were matched when they arrived; a changed version needs a fresh match.
                    if last is None or last.detected_version != scan.detected_version:
                        await self._match_site(db, site, scan.detected_version, now)
                db.commit()
        return len(due)

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

    # 2. feeds: store, enrich with exploitation signals, match only what is new

    async def poll_feeds(self, now: datetime | None = None) -> int:
        """Fetch new advisories from every source, enrich them with KEV/EPSS, then match only what changed."""
        now = utc(now)
        changed: set[str] = set()
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
                changed |= self._store_advisories(db, advisories, now)
                if cursor is None:
                    db.add(FeedCursor(name=source.name, value=now.isoformat()))
                else:
                    cursor.value = now.isoformat()
                db.commit()
            escalate = await self._enrich(db, changed, now)
        await self.match_advisories(sorted(changed), now)
        if escalate:
            await self._escalate(escalate, now)
        return len(changed)

    @staticmethod
    def _store_advisories(db: Session, advisories: list[FeedAdvisory], now: datetime) -> set[str]:
        """Returns the ids that are new, or whose affected versions changed (only those need matching)."""
        changed: set[str] = set()
        for a in advisories:
            row = db.get(Advisory, a.id)
            if row is None:
                db.add(Advisory(id=a.id, source=a.source, severity=a.severity, score=a.score, summary=a.summary,
                                affected=a.affected, fixed_in=a.fixed_in, url=a.url, first_seen=now, updated_at=now))
                changed.add(a.id)
            else:  # NVD revises ranges and scores: keep the latest, keep first_seen
                if row.affected != a.affected:
                    changed.add(a.id)
                row.severity, row.score, row.summary = a.severity, a.score, a.summary
                row.affected, row.fixed_in, row.url, row.updated_at = a.affected, a.fixed_in, a.url, now
        db.flush()
        return changed

    async def _enrich(self, db: Session, changed: set[str], now: datetime) -> set[str]:
        """KEV for every CVE we hold (an old one can become exploited), EPSS for new ones.
        Returns advisory ids that just became exploited (their earlier alerts are escalated)."""
        became_exploited: set[str] = set()
        if self.kev is not None:
            try:
                catalog = await self.kev.exploited()
            except FeedError as exc:
                log.warning("Watchdog KEV skipped: %s", exc)
                catalog = {}
            for adv in db.scalars(select(Advisory).where(Advisory.id.in_(list(catalog)))) if catalog else []:
                if not adv.kev:
                    adv.kev, adv.kev_added = True, catalog[adv.id]
                    if adv.id not in changed:
                        became_exploited.add(adv.id)
        if self.epss is not None and changed:
            try:
                scores = await self.epss.scores(sorted(changed))
            except FeedError as exc:
                log.warning("Watchdog EPSS skipped: %s", exc)
                scores = {}
            for adv_id, score in scores.items():
                adv = db.get(Advisory, adv_id)
                if adv is not None:
                    adv.epss = score
        db.commit()
        return became_exploited

    async def match_advisories(self, advisory_ids: list[str], now: datetime | None = None) -> int:
        """Match the given advisories against every monitored site, evaluating each distinct PHP version once."""
        now = utc(now)
        created = 0
        with self.factory() as db:
            sites = self.monitored_sites(db)
            versions: dict[int, str | None] = {}
            for site in sites:
                last = self.last_version_check(db, site)
                versions[site.id] = last.detected_version if last else None
                self.count(db, site.id, now, cve=1)
            advisories = list(db.scalars(select(Advisory).where(Advisory.id.in_(advisory_ids)))) if advisory_ids else []
            affected_cache: dict[tuple[str, str], bool] = {}
            for site in sites:
                version = versions[site.id]
                if not version:
                    continue
                hits = []
                for adv in advisories:
                    key = (adv.id, version)
                    if key not in affected_cache:
                        affected_cache[key] = version_affected(version, adv.affected)
                    if affected_cache[key] and await self._advisory_alert(db, site, version, adv, now):
                        hits.append(adv.id)
                if hits:  # a check record only when something was found
                    db.add(WatchCheck(site_id=site.id, kind="cve", detected_version=version,
                                      detail={"matched": hits}, created_at=now))
                created += len(hits)
            db.commit()
        return created

    async def match_all(self, now: datetime | None = None) -> int:
        """Full re-match of every stored advisory (maintenance; the scheduler matches only what changed)."""
        with self.factory() as db:
            ids = list(db.scalars(select(Advisory.id)))
        return await self.match_advisories(ids, now)

    async def _match_site(self, db: Session, site: Site, version: str | None, now: datetime) -> list[str]:
        """Every stored advisory against one site's version (used when the version changes)."""
        if not version:
            return []
        hits = []
        for adv in db.scalars(select(Advisory).order_by(Advisory.id)).all():
            if version_affected(version, adv.affected) and await self._advisory_alert(db, site, version, adv, now):
                hits.append(adv.id)
        return hits

    async def _advisory_alert(self, db: Session, site: Site, version: str, adv: Advisory, now: datetime) -> bool:
        v, fix = parse_version(version), parse_version(adv.fixed_in or "")
        same_line = fix is not None and v is not None and fix.branch == v.branch
        todo = (f"Update PHP to {adv.fixed_in} or newer. You can start the update, with a backup and your "
                "approval, from your Patchwarden dashboard." if same_line else
                "Update PHP to the newest release of a supported line. Your Patchwarden dashboard can plan it.")
        label = "PHP security release" if adv.source == "php_release" else f"security flaw ({adv.id})"
        exploited = " Attackers are already using it (CISA lists it as exploited)." if adv.kev else ""
        alert = await self._alert(
            db, site, key=adv.id, severity=adv.severity,
            subject=f"Patchwarden: new {adv.severity} risk for {site.domain}" + (" (being exploited)" if adv.kev else ""),
            message=alert_text(
                changed=f"A new {label} was published, rated {adv.severity}.{exploited}",
                means=f"Your site {site.domain} runs PHP {version}, which is affected. {adv.summary}"[:2000],
                todo=todo, link=self.site_link(site)),
            now=now,
            priority=priority_for(adv.severity, kev=bool(adv.kev), epss=adv.epss, urgent_epss=self.settings.epss_urgent))
        return alert is not None

    async def _escalate(self, advisory_ids: set[str], now: datetime) -> int:
        """An advisory we alerted on earlier is now exploited: tell the owners at once."""
        sent = 0
        with self.factory() as db:
            for alert in db.scalars(select(Alert).where(Alert.cve_id.in_(list(advisory_ids)),
                                                        Alert.escalated_at.is_(None))):
                site = db.get(Site, alert.site_id)
                owner = db.get(User, site.owner_id) if site else None
                if owner is None:
                    continue
                text = alert_text(
                    changed=f"{alert.cve_id}, which we told you about earlier, is now being exploited by attackers "
                            "(CISA added it to its Known Exploited Vulnerabilities list).",
                    means=f"{site.domain} is still exposed until PHP is updated.",
                    todo="Update now. Your Patchwarden dashboard can plan the update with a backup and your approval.",
                    link=self.site_link(site))
                emailed, delivered = await self._notify(
                    db, owner, f"Patchwarden: {alert.cve_id} is now being exploited ({site.domain})", text,
                    {"type": "escalation", "alert_id": alert.id, "site": site.domain, "key": alert.cve_id}, site)
                alert.escalated_at, alert.priority = now, "urgent"
                alert.delivered = {**(alert.delivered or {}), **{f"escalation:{k}": v for k, v in delivered.items()}}
                db.add(AuditLog(user_id=None, site_id=site.id, action="alert.escalated",
                                detail={"alert_id": alert.id, "key": alert.cve_id, "emailed": emailed}))
                sent += 1
            db.commit()
        return sent

    # 3. the schedule

    async def tick(self, now: datetime | None = None) -> None:
        """Hourly job: version checks for sites that are due, then a feed poll."""
        try:
            await self.run_version_checks(now)
            await self.poll_feeds(now)
        except Exception as exc:  # noqa: BLE001 - a scheduler job must not die silently
            log.error("Watchdog tick failed: %s", type(exc).__name__)

    async def send_digests(self, now: datetime | None = None) -> int:
        """Daily: one message per owner with the lower-priority alerts not yet sent."""
        now = utc(now)
        sent = 0
        with self.factory() as db:
            pending = db.scalars(select(Alert).where(Alert.priority == "digest", Alert.digest_sent_at.is_(None))
                                 .order_by(Alert.id)).all()
            by_owner: dict[int, list[Alert]] = {}
            for a in pending:
                site = db.get(Site, a.site_id)
                if site is not None and site.owner_id is not None:
                    by_owner.setdefault(site.owner_id, []).append(a)
            for owner_id, alerts in by_owner.items():
                owner = db.get(User, owner_id)
                lines = [f"- {db.get(Site, a.site_id).domain}: {a.message.splitlines()[0].replace('What changed: ', '')}"
                         for a in alerts]
                text = (f"{len(alerts)} lower-priority finding(s) since yesterday:\n" + "\n".join(lines)
                        + f"\n\nDetails: {self.settings.public_base_url}/dashboard/alerts")
                emailed, delivered = await self._notify(db, owner, "Patchwarden daily digest", text,
                                                        {"type": "digest", "alert_ids": [a.id for a in alerts]})
                for a in alerts:
                    a.digest_sent_at = now
                    if emailed:
                        a.sent_at = now
                    a.delivered = delivered
                sent += 1
            db.commit()
        return sent

    async def dunning_tick(self, now: datetime | None = None) -> dict:
        """Daily: remind past-due owners on day 1, 7 and grace-1; cancel after the grace period."""
        now = utc(now)
        grace = self.settings.dunning_grace_days
        milestones = sorted({1, 7, max(1, grace - 1)})
        reminded = lapsed = 0
        with self.factory() as db:
            for sub in db.scalars(select(Subscription).where(Subscription.status == SubscriptionStatus.past_due,
                                                             Subscription.past_due_since.is_not(None))):
                days = (now - sub.past_due_since).days
                site = db.get(Site, sub.site_id)
                owner = db.get(User, site.owner_id) if site and site.owner_id else None
                if days >= grace:
                    change_status(db, sub, SubscriptionStatus.cancelled, actor_id=None)
                    db.add(AuditLog(user_id=None, site_id=sub.site_id, action="subscription.lapsed",
                                    detail={"subscription_id": sub.id, "days_past_due": days}))
                    if owner is not None:
                        await self.notifier.send(Email(owner.email, f"Patchwarden: monitoring of {site.domain} has stopped",
                                                       "The payment for this site's monitoring did not come through, so "
                                                       "monitoring has stopped. Your reports are still there; reactivate "
                                                       "from the dashboard at any time."))
                    lapsed += 1
                    continue
                due = sum(1 for m in milestones if days >= m)
                if owner is not None and due > (sub.reminders_sent or 0):
                    left = grace - days
                    await self.notifier.send(Email(owner.email, f"Patchwarden: payment needed for {site.domain}",
                                                   f"We could not take the payment for monitoring {site.domain}. "
                                                   f"Monitoring continues for {left} more day(s); after that it stops."))
                    sub.reminders_sent = due
                    reminded += 1
            db.commit()
        return {"reminded": reminded, "lapsed": lapsed}

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
                subject, body = self._branded(db, site, f"Patchwarden monthly report: {site.domain}",
                                              f"{report['summary']}\n\nRead the full report: {link}")
                if owner and await self.notifier.send(Email(owner.email, subject, body)):
                    sent += 1
        return sent


# --- monthly report -------------------------------------------------------------

def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def monthly_report(db: Session, site: Site, year: int, month: int) -> dict[str, Any]:
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=monthrange(year, month)[1])
    in_month = lambda col: (col >= start) & (col < end)  # noqa: E731

    version_checks = db.scalars(select(WatchCheck).where(WatchCheck.site_id == site.id, WatchCheck.kind == "version",
                                                         in_month(WatchCheck.created_at))
                                .order_by(WatchCheck.created_at)).all()
    cve_checks = db.scalar(select(func.coalesce(func.sum(WatchCounter.cve_checks), 0)).where(
        WatchCounter.site_id == site.id, WatchCounter.day >= start.strftime("%Y-%m-%d"),
        WatchCounter.day < end.strftime("%Y-%m-%d"))) or 0
    latest = db.scalar(select(WatchCheck).where(WatchCheck.site_id == site.id, WatchCheck.kind == "version",
                                                WatchCheck.created_at < end)
                       .order_by(WatchCheck.created_at.desc(), WatchCheck.id.desc()).limit(1))
    alerts = db.scalars(select(Alert).where(Alert.site_id == site.id, in_month(Alert.created_at))
                        .order_by(Alert.created_at)).all()
    jobs = db.scalars(select(PatchJob).where(PatchJob.site_id == site.id, in_month(PatchJob.created_at))
                      .order_by(PatchJob.id)).all()
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.site_id == site.id, Alert.read.is_(False)))

    outcomes = _outcomes(db, site, version_checks, alerts, start, end)
    risk = latest.risk.value if latest and latest.risk else "unknown"
    version = latest.detected_version if latest else None
    days = len({c.created_at.date() for c in version_checks})
    summary = (f"In {start:%B %Y} we checked {site.domain} {_n(len(version_checks), 'time')} on {_n(days, 'day')}. "
               + (f"It runs PHP {version}. " if version else "Its PHP version is hidden from outside. ")
               + (f"We raised {_n(len(alerts), 'alert')}. " if alerts else "No new risks were found. ")
               + (f"{_n(len(jobs), 'PHP update')} planned or run. " if jobs else "")
               + (f"The site was exposed on {_n(outcomes['exposure_days'], 'day')}"
                  + (f"; risks were fixed in a median of {outcomes['median_hours_to_patch']} hours."
                     if outcomes["median_hours_to_patch"] is not None else ".")
                  if outcomes["exposure_days"] else ""))
    return {
        "site_id": site.id,
        "domain": site.domain,
        "month": f"{year:04d}-{month:02d}",
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "current": {"php_version": version, "risk": risk,
                    "checked_at": latest.created_at.isoformat() if latest else None},
        "checks": {"version": len(version_checks), "cve": int(cve_checks), "days_checked": days,
                   "days_in_month": monthrange(year, month)[1],
                   "failed": sum(1 for c in version_checks if c.detail.get("error"))},
        "risks_found": [{"id": a.id, "key": a.cve_id, "severity": a.severity, "message": a.message,
                         "created_at": a.created_at.isoformat(), "read": a.read} for a in alerts],
        "actions_taken": [{"patch_job_id": j.id, "from_version": j.from_version, "to_version": j.to_version,
                           "state": j.state.value, "created_at": j.created_at.isoformat()} for j in jobs],
        "open_alerts": open_alerts,
        "outcomes": outcomes,
        "branding": brand_for(db, site),
        "summary": summary.strip(),
    }


EXPOSED = (Risk.patch_now, Risk.must_migrate)


def _outcomes(db: Session, site: Site, version_checks: list[WatchCheck], alerts: list[Alert],
              start: datetime, end: datetime) -> dict[str, Any]:
    """What the service achieved, not just what it did: days exposed, exploited flaws, time to fix."""
    exposed_days = {c.created_at.date() for c in version_checks if c.risk in EXPOSED}
    kev_keys = set(db.scalars(select(Advisory.id).where(Advisory.id.in_([a.cve_id for a in alerts]),
                                                       Advisory.kev.is_(True)))) if alerts else set()
    fixed = db.scalars(select(PatchJob).where(PatchJob.site_id == site.id, PatchJob.state == PatchState.succeeded,
                                              PatchJob.approved_at.is_not(None))
                       .order_by(PatchJob.approved_at)).all()
    hours = []
    for a in alerts:
        done = next((j for j in fixed if j.approved_at >= a.created_at), None)
        finished = (done.report or {}).get("finished_at") if done else None
        if finished:
            hours.append((datetime.fromisoformat(finished) - a.created_at).total_seconds() / 3600)
    hours.sort()
    median = None
    if hours:
        mid = len(hours) // 2
        median = round(hours[mid] if len(hours) % 2 else (hours[mid - 1] + hours[mid]) / 2, 1)
    return {
        "exposure_days": len(exposed_days),
        "exploited_flaws_found": len(kev_keys),
        "patches_succeeded": sum(1 for j in fixed if start <= j.approved_at < end),
        "risks_fixed": len(hours),
        "median_hours_to_patch": median,
    }
