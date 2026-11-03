"""Scanner endpoints: POST /api/scans, GET /api/scans/{id}, GET /api/scans/{id}/share, GET /scans/{id}."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from ..config import Settings
from ..deps import CurrentUser, DbDep, OptionalUser, SettingsDep
from ..errors import AppError, error_body
from ..models import Role, Scan, User
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


def scan_json(scan: Scan, *, settings: Settings | None = None) -> dict[str, Any]:
    f = scan.findings or {}
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
        "raw_headers": scan.raw_headers,
        "created_at": scan.created_at.isoformat(),
    }
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
async def create_scans(request: Request, db: DbDep, settings: SettingsDep, user: OptionalUser) -> JSONResponse:
    """Scan one domain (JSON) or many (JSON list or CSV upload). No login needed: the scan is free."""
    targets, wordpress, bulk = await _read_request(request)
    targets = list(dict.fromkeys(t.strip() for t in targets if t.strip()))
    if not targets:
        raise AppError(422, "no_domains", "We did not find any website addresses to scan.")
    if len(targets) > settings.scan_bulk_max:
        raise AppError(413, "too_many_domains", f"Please send at most {settings.scan_bulk_max} domains at a time.")

    scanner: Scanner = request.app.state.scanner
    if bulk:
        results = await scanner.scan_many(targets, wordpress_requested=wordpress)
    else:
        try:
            results = [await scanner.scan(targets[0], wordpress_requested=wordpress)]
        except TargetRejected as exc:
            raise AppError(400, exc.code, exc.message) from None

    scans: list[Scan] = []
    rejected: list[dict[str, str]] = []
    for target, r in zip(targets, results):
        if isinstance(r, TargetRejected):
            rejected.append({"input": target[:200], **error_body(r.code, r.message)})
        else:
            scans.append(store_scan(db, r, user=user, wordpress_requested=wordpress))
    db.commit()
    body = {
        "count": len(scans),
        "scans": [scan_json(s, settings=settings) for s in scans],
        "rejected": rejected,
    }
    return JSONResponse(body, status_code=201)


def _load_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise AppError(404, "scan_not_found", "We could not find that scan.")
    return scan


def _can_read(scan: Scan, user: User | None, token: str | None, settings: Settings) -> bool:
    if token and share_token_allows(settings, token, scan.id):
        return True
    if user is None:
        return False
    return user.role == Role.admin or scan.site.owner_id == user.id


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
    return scan_json(_authorised_scan(db, scan_id, user, token, settings))


@router.get("/api/scans/{scan_id}/share")
def share_scan(scan_id: int, db: DbDep, settings: SettingsDep, user: CurrentUser) -> dict:
    """A signed, expiring link to the HTML report that works without a login."""
    scan = _load_scan(db, scan_id)
    if not _can_read(scan, user, None, settings):
        raise AppError(404, "scan_not_found", "We could not find that scan.")
    url, expires = share_url(settings, scan)
    return {"url": url, "expires_at": expires}


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
    return request.app.state.templates.TemplateResponse(
        request, "report.html", {"scan": scan, "report": scan_json(scan)}, headers=REPORT_HEADERS
    )
