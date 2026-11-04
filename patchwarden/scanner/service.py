"""Scanner agent: fetch a homepage, read the PHP version, score the risk, store the scan."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..fakes import DemoWorld
from ..models import AuditLog, Platform, Risk, Scan, Site, User
from . import demo_sites
from .detect import detect_php_version, detect_wordpress, safe_headers
from .fetch import BlockedTarget, FetchError, SafeFetcher, normalise_target
from .versions import PHP2SHELL_CVES, assess
from .wordpress import VulnFeed, WordPressOrgClient, check_components

log = logging.getLogger(__name__)


class TargetRejected(Exception):
    """The input cannot be scanned at all (bad address, or a private/internal target)."""

    def __init__(self, target: str, code: str, message: str):
        super().__init__(code)
        self.target = target
        self.code = code
        self.message = message


@dataclass
class ScanOutcome:
    domain: str
    scanned_url: str
    detected_version: str | None
    risk: Risk
    raw_headers: dict
    findings: dict


class Scanner:
    def __init__(
        self,
        settings: Settings,
        *,
        site_transport: httpx.AsyncBaseTransport | None = None,
        resolver=None,
        wporg_transport: httpx.AsyncBaseTransport | None = None,
        demo_world: DemoWorld | None = None,
    ):
        self.settings = settings
        demo = settings.demo_sites
        self.fetcher = SafeFetcher(
            settings,
            transport=site_transport,
            resolver=resolver,
            demo_transport=demo_sites.demo_transport(demo_world) if demo else None,
            demo_suffix=demo_sites.DEMO_SUFFIX,
        )
        self.wporg = (
            WordPressOrgClient(transport=wporg_transport) if settings.wporg_api_enabled else None
        )
        self.demo_wporg = WordPressOrgClient(transport=demo_sites.demo_wporg_transport()) if demo else None
        self.feed = VulnFeed.load(settings.wp_vuln_feed_path)

    async def aclose(self) -> None:
        await self.fetcher.aclose()
        for client in (self.wporg, self.demo_wporg):
            if client:
                await client.aclose()

    async def scan(self, target: str, *, wordpress_requested: bool = False, today: date | None = None) -> ScanOutcome:
        try:
            url = normalise_target(target)
            domain = httpx.URL(url).host.rstrip(".").lower()
        except FetchError as exc:
            raise TargetRejected(target, exc.code, exc.message) from None
        except (httpx.InvalidURL, ValueError):
            raise TargetRejected(target, "invalid_url", "That does not look like a website address.") from None
        if not domain:
            raise TargetRejected(target, "invalid_url", "That does not look like a website address.")

        findings: dict = {"cves": list(PHP2SHELL_CVES)}
        try:
            result = await self.fetcher.fetch(url)
        except FetchError as exc:
            if isinstance(exc, BlockedTarget) and not exc.after_redirect:
                raise TargetRejected(target, exc.code, exc.message) from None
            if exc.code == "invalid_url" and not exc.after_redirect:
                raise TargetRejected(target, exc.code, exc.message) from None
            a = assess(None, today=today)
            findings.update(
                error={"code": exc.code, "message": exc.message},
                summary="We could not read this site, so we cannot score it. " + exc.message,
                next_step="Check the address and try again, or install the Patchwarden plugin or agent.",
                php_detected=False,
                version_source=None,
                notes=[],
            )
            return ScanOutcome(domain, url, None, a.risk, {}, findings)

        evidence = detect_php_version(result.headers)
        a = assess(evidence.version, today=today)
        findings.update(
            status_code=result.status_code,
            final_url=result.url,
            redirects=result.redirects,
            version_source=evidence.source,
            php_detected=evidence.php_detected,
            php_hint=evidence.php_hint,
            summary=a.summary,
            next_step=a.next_step,
            fixed_version=a.fixed_version,
            notes=list(a.notes),
        )

        wp = detect_wordpress(result.headers, result.text)
        if wp.is_wordpress or wordpress_requested:
            wporg = self.demo_wporg if domain.endswith(demo_sites.DEMO_SUFFIX) and self.demo_wporg else self.wporg
            components = await check_components(wp.components, self.feed, wporg) if wp.is_wordpress else []
            findings["wordpress"] = {
                "detected": wp.is_wordpress,
                "core_version": wp.core_version,
                "components": components,
                "feed": self.feed.name,
                "issues": sum(len(c["vulnerabilities"]) for c in components),
            }

        version = str(evidence.version) if evidence.version else None
        return ScanOutcome(domain, url, version, a.risk, safe_headers(result.headers), findings)

    async def scan_many(
        self, targets: list[str], *, wordpress_requested: bool = False, today: date | None = None
    ) -> list[ScanOutcome | TargetRejected]:
        sem = asyncio.Semaphore(self.settings.scan_concurrency)

        async def one(t: str) -> ScanOutcome | TargetRejected:
            async with sem:
                try:
                    return await self.scan(t, wordpress_requested=wordpress_requested, today=today)
                except TargetRejected as exc:
                    return exc

        return await asyncio.gather(*(one(t) for t in targets))


def store_scan(db: Session, outcome: ScanOutcome, *, user: User | None, wordpress_requested: bool = False) -> Scan:
    owner_id = user.id if user else None
    same_owner = Site.owner_id.is_(None) if owner_id is None else Site.owner_id == owner_id
    site = db.scalar(select(Site).where(same_owner, Site.domain == outcome.domain))
    if site is None:
        site = Site(owner_id=owner_id, domain=outcome.domain)
        db.add(site)
        db.flush()
    wp = outcome.findings.get("wordpress") or {}
    if wp.get("detected") or wordpress_requested:
        site.platform = Platform.wordpress

    scan = Scan(
        site_id=site.id,
        detected_version=outcome.detected_version,
        risk=outcome.risk,
        raw_headers=outcome.raw_headers,
        scanned_url=outcome.scanned_url,
        findings=outcome.findings,
    )
    db.add(scan)
    db.flush()
    db.add(AuditLog(user_id=owner_id, site_id=site.id, action="scan.created",
                    detail={"scan_id": scan.id, "risk": outcome.risk.value}))
    return scan


BATCH_CHUNK = 25


async def run_batch(factory, scanner: Scanner, batch_id: int, resume: bool = False) -> None:
    """Scan a ScanBatch in chunks. Each chunk's scans and the progress counter commit together,
    so an interrupted batch resumes exactly where it stopped, without duplicate scans."""
    from ..models import ScanBatch

    with factory() as db:
        batch = db.get(ScanBatch, batch_id)
        if batch is None or batch.state in ("done", "failed"):
            return
        owner = db.get(User, batch.owner_id)
        batch.state = "running"
        db.commit()
        while batch.done < batch.total:
            chunk = batch.targets[batch.done:batch.done + BATCH_CHUNK]
            results = await scanner.scan_many(chunk, wordpress_requested=batch.wordpress)
            rejected = list(batch.rejected)
            for target, r in zip(chunk, results):
                if isinstance(r, TargetRejected):
                    rejected.append({"input": target[:200], "error": r.code, "message": r.message})
                else:
                    scan = store_scan(db, r, user=owner, wordpress_requested=batch.wordpress)
                    scan.batch_id = batch.id
            batch.rejected = rejected
            batch.done += len(chunk)
            db.commit()
        batch.state = "done"
        batch.finished_at = datetime.now(timezone.utc)
        db.add(AuditLog(user_id=owner.id if owner else None, action="scan_batch.done",
                        detail={"batch_id": batch.id, "total": batch.total, "rejected": len(batch.rejected)}))
        db.commit()
