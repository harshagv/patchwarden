"""Scanner endpoints: POST /api/scans, GET /api/scans/{id}, GET /api/scans/{id}/share, GET /scans/{id}."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from ..config import Settings
from .. import access
from ..deps import CurrentUser, DbDep, OptionalUser, SettingsDep
from ..errors import AppError
from ..models import AuditLog, Role, Scan, ScanBatch, Site, User
from ..ratelimit import client_ip, too_many
from ..scanner.service import Scanner, TargetRejected, store_scan
from ..security import create_share_token, share_token_allows

router = APIRouter(tags=["scans"])

CSV_MAX_BYTES = 256 * 1024
_CSV_HEADERS = {"domain", "domains", "url", "website", "site"}


class ScanRequest(BaseModel):
    domain: str | None = Field(default=None, max_length=2048, description="One domain or URL")
    domains: list[str] | None = Field(default=None, description="Several domains or URLs")
    wordpress: bool = Field(default=False, description="Ask for the deeper WordPress plugin/theme check")


_REQUEST_DOCS = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {"schema": ScanRequest.model_json_schema()},
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "format": "binary", "description": "CSV, one domain per row"},
                        "wordpress": {"type": "boolean"},
                    },
                    "required": ["file"],
                }
            },
        },
    }
}


def share_url(settings: Settings, scan: Scan) -> tuple[str, str]:
    token, expires = create_share_token(settings, scan.id)
    return f"{settings.public_base_url}/scans/{scan.id}?token={token}", expires.isoformat()


BASIC_FINDINGS = ("summary", "next_step", "fixed_version", "cves", "php_detected", "php_hint", "version_source",
                  "notes", "error", "redirects", "status_code", "final_url", "source")
UNLOCK = ("Verify that you own this site to see the full report: the response headers, and which plugins "
          "or themes have known security problems.")


def detail_level(scan: Scan, user: User | None, via_share_link: bool = False) -> str:
    """'full' for a verified owner (or admin), and for a share link a verified owner sent; else 'basic'.

    Everyone sees the version, the risk and what to do: that is what the site shows the world anyway.
    The details that help an attacker (headers, which plugin is vulnerable) need proof of ownership.
    """
    site = scan.site
    db = object_session(site)
    if user is not None and (user.role == Role.admin or
                             (site.verified_at and site.owner_id is not None and access.can(db, user, site, "view"))):
        return "full"
    if via_share_link and site.owner_id is not None and site.verified_at is not None:
        return "full"
    return "basic"


def scan_json(scan: Scan, *, settings: Settings | None = None, level: str = "full") -> dict[str, Any]:
    f = scan.findings or {}
    if level != "full":
        wp = f.get("wordpress")
        f = {k: f[k] for k in BASIC_FINDINGS if k in f}
        if wp:
            f["wordpress"] = {"detected": wp.get("detected"), "core_version": wp.get("core_version"),
                              "issues": wp.get("issues", 0), "components": len(wp.get("components") or [])}
    out: dict[str, Any] = {
        "id": scan.id,
        "site_id": scan.site_id,
        "domain": scan.site.domain,
        "scanned_url": scan.scanned_url,
        "detected_version": scan.detected_version,
        "risk": scan.risk.value,
        "summary": f.get("summary"),
        "next_step": f.get("next_step"),
        "fixed_version": f.get("fixed_version"),
        "cves": f.get("cves", []),
        "findings": f,
        "raw_headers": scan.raw_headers if level == "full" else {},
        "created_at": scan.created_at.isoformat(),
        "batch_id": scan.batch_id,
        "detail": level,
    }
    if level != "full":
        out["unlock"] = UNLOCK
    if settings is not None:
        out["share_url"], out["share_expires_at"] = share_url(settings, scan)
    return out


def _parse_csv(data: bytes) -> list[str]:
    if len(data) > CSV_MAX_BYTES:
        raise AppError(413, "too_large", "That CSV is too large. Please upload at most 256 KB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise AppError(400, "invalid_csv", "Please upload a plain-text CSV file (UTF-8).") from None
    domains: list[str] = []
    for i, row in enumerate(csv.reader(io.StringIO(text))):
        cell = row[0].strip() if row else ""
        if not cell or cell.startswith("#"):
            continue
        if i == 0 and cell.lower() in _CSV_HEADERS:
            continue
        domains.append(cell)
    return domains


async def _read_request(request: Request) -> tuple[list[str], bool, bool]:
    """Returns (targets, wordpress_requested, is_bulk)."""
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise AppError(400, "missing_file", "Please attach a CSV file with one domain per row.")
        targets = _parse_csv(await upload.read())
        wordpress = str(form.get("wordpress", "")).lower() in {"1", "true", "on", "yes"}
        return targets, wordpress, True

    try:
        body = ScanRequest.model_validate(json.loads(await request.body() or b"{}"))
    except (ValueError, ValidationError):
        raise AppError(422, "invalid_request", "Send JSON with a domain, or a list of domains.") from None
    if body.domain and body.domains:
        raise AppError(422, "invalid_request", "Send either one domain or a list of domains, not both.")
    if body.domain:
        return [body.domain], body.wordpress, False
    if body.domains:
        return body.domains, body.wordpress, True
    raise AppError(422, "invalid_request", "Please enter a website address to scan.")


@router.post("/api/scans", status_code=201, openapi_extra=_REQUEST_DOCS)
async def create_scans(request: Request, tasks: BackgroundTasks, db: DbDep, settings: SettingsDep,
                       user: OptionalUser) -> JSONResponse:
    """Scan one domain (free, no login), or a list (JSON or CSV upload: needs a free account, runs in the
    background, answers 202 with a status URL)."""
    targets, wordpress, bulk = await _read_request(request)
    if bulk:
        if user is None:
            raise AppError(401, "login_required", "Create a free account to scan a list of sites.")
        batch = start_batch(request, tasks, db, settings, user, targets, wordpress)
        return JSONResponse({"batch": batch_json(batch, settings), "status_url": f"/api/scan-batches/{batch.id}"},
                            status_code=202)
    targets = _checked_targets(request, settings, user, targets)

    scanner: Scanner = request.app.state.scanner
    try:
        result = await scanner.scan(targets[0], wordpress_requested=wordpress)
    except TargetRejected as exc:
        raise AppError(400, exc.code, exc.message) from None
    scan = store_scan(db, result, user=user, wordpress_requested=wordpress)
    if user is None:
        db.add(AuditLog(user_id=None, site_id=scan.site_id, action="scan.free", detail={"scan_id": scan.id}))
    db.commit()
    body = {"count": 1, "scans": [scan_json(scan, settings=settings, level=detail_level(scan, user))], "rejected": []}
    return JSONResponse(body, status_code=201)


def _checked_targets(request: Request, settings: Settings, user: User | None, targets: list[str]) -> list[str]:
    targets = list(dict.fromkeys(t.strip() for t in targets if t.strip()))
    if not targets:
        raise AppError(422, "no_domains", "We did not find any website addresses to scan.")
    if len(targets) > settings.scan_bulk_max:
        raise AppError(413, "too_many_domains", f"Please send at most {settings.scan_bulk_max} domains at a time.")
    # Each domain counts: per account when logged in, per connection when not.
    limits = request.app.state.limits
    window, key = ((limits.scan_user, f"user:{user.id}") if user else
                   (limits.scan_ip, f"ip:{client_ip(request, settings)}"))
    wait = window.retry_after(key, len(targets))
    if wait:
        raise too_many(f"That is more scans than we allow at once. Please wait {wait} seconds and try again.", wait)
    window.hit(key, len(targets))
    return targets


def start_batch(request: Request, tasks: BackgroundTasks, db: Session, settings: Settings, user: User,
                targets: list[str], wordpress: bool) -> ScanBatch:
    """Record a list scan as a durable background job and start it (shared by the API and the dashboard)."""
    targets = _checked_targets(request, settings, user, targets)
    batch = ScanBatch(owner_id=user.id, targets=targets, total=len(targets), wordpress=wordpress)
    db.add(batch)
    db.add(AuditLog(user_id=user.id, action="scan_batch.created", detail={"total": len(targets)}))
    db.commit()
    queue = request.app.state.jobs
    tasks.add_task(queue.run_one, queue.enqueue(db, "bulk_scan", batch.id, user.id).id)
    return batch


def batch_json(batch: ScanBatch, settings: Settings) -> dict[str, Any]:
    return {"id": batch.id, "state": batch.state, "total": batch.total, "done": batch.done,
            "rejected": batch.rejected, "created_at": batch.created_at.isoformat(),
            "finished_at": batch.finished_at.isoformat() if batch.finished_at else None}


@router.get("/api/scan-batches/{batch_id}")
def get_batch(batch_id: int, db: DbDep, settings: SettingsDep, user: CurrentUser) -> dict:
    """Progress and results of a background list scan."""
    batch = db.get(ScanBatch, batch_id)
    if batch is None or (batch.owner_id != user.id and user.role != Role.admin):
        raise AppError(404, "batch_not_found", "We could not find that list scan.")
    scans = db.scalars(select(Scan).where(Scan.batch_id == batch.id).order_by(Scan.id)).all()
    return {**batch_json(batch, settings), "count": len(scans),
            "scans": [scan_json(s, settings=settings, level=detail_level(s, user)) for s in scans]}


def _load_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise AppError(404, "scan_not_found", "We could not find that scan.")
    return scan


def _can_read(scan: Scan, user: User | None, token: str | None, settings: Settings) -> bool:
    if token and share_token_allows(settings, token, scan.id, scan.share_revoked_at):
        return True
    if user is None:
        return False
    return user.role == Role.admin or (scan.site.owner_id is not None
                                       and access.can(object_session(scan), user, scan.site, "view"))


def _via_link(scan: Scan, token: str | None, settings: Settings) -> bool:
    return bool(token) and share_token_allows(settings, token, scan.id, scan.share_revoked_at)


def _authorised_scan(db: Session, scan_id: int, user: User | None, token: str | None, settings: Settings) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or not _can_read(scan, user, token, settings):
        if user is None and not token:
            raise AppError(401, "unauthorized", "Please log in, or open the report from its share link.")
        # Same answer for "missing" and "not yours": do not confirm other people's scans exist.
        raise AppError(404, "scan_not_found", "We could not find that scan, or the link has expired.")
    return scan


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: DbDep, settings: SettingsDep, user: OptionalUser, token: str | None = None) -> dict:
    """The risk report as JSON. Needs a login (owner) or a valid share-link token."""
    scan = _authorised_scan(db, scan_id, user, token, settings)
    return scan_json(scan, level=detail_level(scan, user, _via_link(scan, token, settings)))


@router.post("/api/scans/{scan_id}/claim", status_code=201)
def claim_scan(scan_id: int, db: DbDep, settings: SettingsDep, user: CurrentUser, token: str | None = None) -> dict:
    """Add a scanned site to your sites (with this report in its history) and start ownership verification."""
    from .. import verification

    scan = _authorised_scan(db, scan_id, user, token, settings)
    site = db.scalar(select(Site).where(Site.owner_id == user.id, Site.domain == scan.site.domain))
    if site is None:
        site = Site(owner_id=user.id, domain=scan.site.domain, platform=scan.site.platform)
        db.add(site)
        db.flush()
    if scan.site_id != site.id:
        scan = Scan(site_id=site.id, detected_version=scan.detected_version, risk=scan.risk,
                    raw_headers=scan.raw_headers, scanned_url=scan.scanned_url, findings=scan.findings,
                    created_at=scan.created_at)
        db.add(scan)
        db.flush()
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.claimed", detail={"scan_id": scan_id}))
    db.commit()
    return {"site_id": site.id, "scan_id": scan.id, "verification": verification.start(db, site, user),
            "next": f"/dashboard/sites/{site.id}/verify"}


@router.get("/api/scans/{scan_id}/share")
def share_scan(scan_id: int, db: DbDep, settings: SettingsDep, user: CurrentUser) -> dict:
    """A signed, expiring link to the HTML report that works without a login."""
    scan = _load_scan(db, scan_id)
    if not _can_read(scan, user, None, settings):
        raise AppError(404, "scan_not_found", "We could not find that scan.")
    url, expires = share_url(settings, scan)
    return {"url": url, "expires_at": expires}


@router.post("/api/scans/{scan_id}/share/revoke")
def revoke_share_links(scan_id: int, db: DbDep, user: CurrentUser) -> dict:
    """Every share link to this report issued so far stops working. New links can still be made."""
    scan = _load_scan(db, scan_id)
    if scan.site.owner_id is None or not access.can(db, user, scan.site, "edit"):
        raise AppError(404, "scan_not_found", "We could not find that scan.")
    scan.share_revoked_at = datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id, site_id=scan.site_id, action="scan.share_revoked", detail={"scan_id": scan.id}))
    db.commit()
    return {"scan_id": scan.id, "revoked_at": scan.share_revoked_at.isoformat()}


REPORT_HEADERS = {
    "Cache-Control": "no-store",
    # The token is in the URL: never send it on to another site.
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
}


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_report_page(
    scan_id: int, request: Request, db: DbDep, settings: SettingsDep, user: OptionalUser, token: str | None = None
):
    """The 1-page report for a non-technical owner."""
    wants_html = "text/html" in request.headers.get("accept", "")
    try:
        scan = _authorised_scan(db, scan_id, user, token, settings)
    except AppError as exc:
        if not wants_html:
            raise
        return request.app.state.templates.TemplateResponse(
            request, "error.html", {"code": exc.code, "message": exc.message},
            status_code=exc.status_code, headers=REPORT_HEADERS,
        )
    level = detail_level(scan, user, _via_link(scan, token, settings))
    claim_url = f"/dashboard/claim/{scan.id}" + (f"?token={token}" if token else "")
    return request.app.state.templates.TemplateResponse(
        request, "report.html", {"scan": scan, "report": scan_json(scan, level=level), "claim_url": claim_url},
        headers=REPORT_HEADERS
    )
