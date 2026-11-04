"""Server-rendered dashboard: where the owner adds access, reads reports, approves and rolls back.

Login sets an HttpOnly, SameSite=Strict cookie holding the access token. Every
form POST also carries a CSRF token derived from that cookie, and a foreign
Origin header is refused.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..errors import AppError
from ..fakes import DEMO_SUFFIX
from ..migration import service as migration_service
from ..models import AuditLog, CredentialKind, Migration, PatchJob, Platform, Site, User
from ..patch import service
from ..patch.adapters import AdapterError
from ..scanner.service import TargetRejected, store_scan
from ..security import access, verification
from ..security.auth import create_access_token, read_access_token
from ..watchdog import service as wd
from ..wpguard import service as wpg
from ..wpguard.plugin_zip import build_plugin_zip
from .api.alerts import owned_alert, parse_month, user_alerts
from .api.auth import authenticate, create_account, signup_allowed
from .api.migrations import schedule as schedule_migration
from .api.migrations import visible_migration
from .api.patches import owned_site, schedule, visible_job
from .api.scans import CSV_MAX_BYTES, _authorised_scan, _parse_csv, claim_scan, get_batch, share_url, start_batch
from .api.sites import _domain, add_credential, check_paths
from .deps import DbDep, SettingsDep

router = APIRouter(prefix="/dashboard", include_in_schema=False)

COOKIE = "patchwarden_session"
STATE_LABELS = {
    "dry_run": "Dry run: waiting for your approval",
    "awaiting_approval": "Waiting for your approval",
    "running": "Working on it",
    "succeeded": "Done: site updated",
    "failed": "Stopped",
    "rolled_back": "Rolled back",
}
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src https:; form-action 'self'; "
                               "base-uri 'none'; frame-ancestors 'none'",
}


def _csrf(settings: Settings, session_token: str) -> str:
    return hmac.new(settings.jwt_secret.encode(), b"csrf:" + session_token.encode(), hashlib.sha256).hexdigest()


def _user(request: Request, db: Session, settings: Settings) -> User | None:
    token = request.cookies.get(COOKIE)
    claims = read_access_token(settings, token) if token else None
    user = db.get(User, claims[0]) if claims is not None else None
    if user is not None and claims[1] != (user.token_version or 0):
        return None  # issued before "log out everywhere"
    return user


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return origin is None
    return urlsplit(origin).netloc == request.url.netloc


async def _post_guard(request: Request, db: Session, settings: Settings) -> tuple[User, dict[str, Any]]:
    if not _same_origin(request):
        raise AppError(403, "bad_origin", "This form was sent from another website, so we ignored it.")
    user = _user(request, db, settings)
    if user is None:
        raise AppError(401, "unauthorized", "Please log in first.")
    form = dict(await request.form())
    expected = _csrf(settings, request.cookies[COOKIE])
    if not hmac.compare_digest(str(form.get("csrf", "")), expected):
        raise AppError(403, "bad_csrf", "This form has expired. Reload the page and try again.")
    return user, form


def _render(request: Request, name: str, ctx: dict, status: int = 200) -> HTMLResponse:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(COOKIE)
    unread = 0
    if token and ctx.get("user") is not None:
        with request.app.state.sessionmaker() as db:
            unread = len(user_alerts(db, ctx["user"], unread_only=True))
    ctx = {"csrf": _csrf(settings, token) if token else "", "state_labels": STATE_LABELS, "unread": unread, **ctx}
    return request.app.state.templates.TemplateResponse(request, name, ctx, status_code=status, headers=PAGE_HEADERS)


def _to_login() -> RedirectResponse:
    return RedirectResponse("/dashboard/login", status_code=303)


# --- login --------------------------------------------------------------------

@router.get("")
def home() -> RedirectResponse:
    return RedirectResponse("/dashboard/sites", status_code=303)


@router.get("/login")
def login_page(request: Request, next: str | None = None):
    return _render(request, "dashboard/login.html", {"next": safe_next(next)})


def safe_next(raw: str | None) -> str:
    """Only local dashboard paths: never an open redirect."""
    if raw and raw.startswith("/dashboard/") and not raw.startswith("//") and not any(c in raw for c in "\\\r\n"):
        return raw
    return "/dashboard/sites"


def _start_session(response: Response, settings: Settings, user: User) -> Response:
    response.set_cookie(COOKIE, create_access_token(settings, user.id, user.token_version),
                        max_age=settings.access_token_minutes * 60,
                        httponly=True, samesite="strict", secure=settings.is_production, path="/")
    return response


@router.post("/login")
async def login(request: Request, db: DbDep, settings: SettingsDep):
    if not _same_origin(request):
        raise AppError(403, "bad_origin", "This form was sent from another website, so we ignored it.")
    form = await request.form()
    email = str(form.get("email", "")).strip().lower()[:320]
    try:
        user = authenticate(request, db, settings, email, str(form.get("password", ""))[:72],
                            str(form.get("code", "")).strip()[:20] or None)
    except AppError as exc:
        ctx = {"error": exc.message, "email": email, "need_code": exc.code in {"mfa_required", "invalid_code"},
               "next": safe_next(str(form.get("next", "")))}
        response = _render(request, "dashboard/login.html", ctx, exc.status_code)
        if exc.headers:
            response.headers.update(exc.headers)
        return response
    return _start_session(RedirectResponse(safe_next(str(form.get("next", ""))), status_code=303), settings, user)


@router.post("/logout")
def logout() -> Response:
    response = _to_login()
    response.delete_cookie(COOKIE, path="/")
    return response


# --- sites --------------------------------------------------------------------

def _sites_page(request: Request, db: Session, user: User, *, error: str | None = None, status: int = 200):
    settings: Settings = request.app.state.settings
    sites = db.scalars(select(Site).where(access.visible_sites_clause(db, user)).order_by(Site.id)).all()
    rows = []
    for site in sites:
        latest = site.scans[-1] if site.scans else None
        jobs = db.scalars(select(PatchJob).where(PatchJob.site_id == site.id).order_by(PatchJob.id.desc()).limit(3)).all()
        migrations = db.scalars(select(Migration).where(Migration.site_id == site.id)
                                .order_by(Migration.id.desc()).limit(3)).all()
        rows.append({"site": site, "scan": latest, "report_url": share_url(settings, latest)[0] if latest else None,
                     "jobs": jobs, "monitoring": wd.is_monitored(db, site), "migrations": migrations})
    kinds = [CredentialKind.cpanel_token, CredentialKind.plesk_token, CredentialKind.api_key]
    return _render(request, "dashboard/sites.html",
                   {"user": user, "rows": rows, "kinds": kinds, "error": error}, status)


@router.get("/sites")
def sites_page(request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    return _sites_page(request, db, user)


async def _site_action(request: Request, db: Session, settings: Settings, action) -> Response:
    user, form = await _post_guard(request, db, settings)
    try:
        result = await action(user, form)
    except AppError as exc:
        db.rollback()
        return _sites_page(request, db, user, error=exc.message, status=exc.status_code)
    return result or RedirectResponse("/dashboard/sites", status_code=303)


@router.post("/sites")
async def add_site(request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        platform = Platform.wordpress if form.get("platform") == "wordpress" else Platform.custom
        domain = _domain(str(form.get("domain", ""))[:2048])
        if db.scalar(select(Site.id).where(Site.owner_id == user.id, Site.domain == domain)):
            raise AppError(409, "site_exists", "You have already added this site.")
        site = Site(owner_id=user.id, domain=domain, platform=platform,
                    check_paths=check_paths(str(form.get("login_path", "")).strip() or None,
                                            str(form.get("form_path", "")).strip() or None))
        db.add(site)
        db.flush()
        db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.created", detail={"domain": domain}))
        db.commit()

    return await _site_action(request, db, settings, action)


@router.post("/sites/{site_id}/credentials")
async def add_site_credential(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        site = owned_site(db, site_id, user)
        try:
            kind = CredentialKind(str(form.get("kind", "")))
        except ValueError:
            raise AppError(422, "invalid_kind", "Pick the kind of access token.") from None
        value = str(form.get("value", ""))
        if not 8 <= len(value) <= 4096:
            raise AppError(422, "invalid_token", "That does not look like an API token or key.")
        add_credential(db, request.app.state.vault, site, user, kind, value)

    return await _site_action(request, db, settings, action)


@router.post("/sites/{site_id}/scan")
async def scan_site(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        site = owned_site(db, site_id, user)
        try:
            outcome = await request.app.state.scanner.scan(site.domain)
        except TargetRejected as exc:
            raise AppError(400, exc.code, exc.message) from None
        store_scan(db, outcome, user=user)
        db.commit()

    return await _site_action(request, db, settings, action)


@router.post("/sites/{site_id}/patch")
async def plan_patch(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        site = owned_site(db, site_id, user)
        job = await service.create_dry_run(db, site=site, user=user, to_version=None,
                                           vault=request.app.state.vault, world=request.app.state.demo_world)
        return RedirectResponse(f"/dashboard/patches/{job.id}", status_code=303)

    return await _site_action(request, db, settings, action)


# --- patch report -------------------------------------------------------------

def _patch_page(request: Request, db: Session, job: PatchJob, *, error: str | None = None, status: int = 200):
    approver = db.get(User, job.approved_by) if job.approved_by else None
    before = {c["name"]: c for c in (job.report.get("before") or {}).get("checks", [])}
    after = {c["name"]: c for c in (job.report.get("after") or {}).get("checks", [])}
    planned = job.report.get("plan", {}).get("checks", [])
    checks = [{"label": c["label"], "path": c["path"], "before": before.get(c["name"]), "after": after.get(c["name"])}
              for c in planned]
    return _render(request, "dashboard/patch.html", {"job": job, "report": job.report, "approver": approver,
                                                     "checks": checks, "error": error,
                                                     "user": db.get(User, job.site.owner_id)}, status)


@router.get("/patches/{job_id}")
def patch_page(job_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        job = visible_job(db, job_id, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _patch_page(request, db, job)


async def _patch_action(job_id: int, request: Request, tasks: BackgroundTasks, db: Session,
                        settings: Settings, mode: str) -> Response:
    user, _form = await _post_guard(request, db, settings)
    job = visible_job(db, job_id, user)
    try:
        if mode == "rollback":
            service.request_rollback(db, job, user)
        else:
            service.approve(db, job, user, settings)
    except AppError as exc:
        return _patch_page(request, db, job, error=exc.message, status=exc.status_code)
    schedule(request, tasks, job, user, mode)
    return RedirectResponse(f"/dashboard/patches/{job.id}", status_code=303)


@router.post("/patches/{job_id}/approve")
async def approve_from_dashboard(job_id: int, request: Request, tasks: BackgroundTasks, db: DbDep,
                                 settings: SettingsDep):
    return await _patch_action(job_id, request, tasks, db, settings, "patch")


@router.post("/patches/{job_id}/rollback")
async def rollback_from_dashboard(job_id: int, request: Request, tasks: BackgroundTasks, db: DbDep,
                                  settings: SettingsDep):
    return await _patch_action(job_id, request, tasks, db, settings, "rollback")


# --- watchdog -----------------------------------------------------------------

@router.post("/sites/{site_id}/monitoring")
async def toggle_monitoring(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        site = owned_site(db, site_id, user)
        wd.set_monitoring(db, site, user, form.get("enabled") == "true")

    return await _site_action(request, db, settings, action)


@router.post("/watchdog/run")
async def run_watchdog_now(request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        ids = access.visible_site_ids(db, user)
        await request.app.state.watchdog.run_version_checks(site_ids=ids, force=True)
        await request.app.state.watchdog.poll_feeds()
        return RedirectResponse("/dashboard/alerts", status_code=303)

    return await _site_action(request, db, settings, action)


@router.get("/alerts")
def alerts_page(request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    return _render(request, "dashboard/alerts.html", {"user": user, "alerts": user_alerts(db, user)})


@router.post("/alerts/{alert_id}/read")
async def alert_read(alert_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, _form = await _post_guard(request, db, settings)
    owned_alert(db, alert_id, user).read = True
    db.commit()
    return RedirectResponse("/dashboard/alerts", status_code=303)


@router.get("/sites/{site_id}/monthly")
def monthly_page(site_id: int, request: Request, db: DbDep, settings: SettingsDep, month: str | None = None):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        site = owned_site(db, site_id, user)
        if month is None:
            prev = (datetime.now(timezone.utc).replace(day=1) - timedelta(days=1))
            month = f"{prev.year:04d}-{prev.month:02d}"
        year, mon = parse_month(month)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _render(request, "dashboard/monthly.html",
                   {"user": user, "site": site, "report": wd.monthly_report(db, site, year, mon)})


# --- migrations -----------------------------------------------------------------

MIGRATION_LABELS = {
    "planned": "Planned: nothing changed yet",
    "staging_running": "Testing on staging",
    "staging_failed": "Staging needs fixes",
    "staging_passed": "Staging passed: waiting for sign-off",
    "signed_off": "Signed off: ready to promote",
    "promoting": "Promoting to production",
    "promoted": "Done: production migrated",
    "promotion_failed": "Promotion stopped",
}


@router.post("/sites/{site_id}/migration")
async def plan_migration(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    async def action(user: User, form: dict):
        site = owned_site(db, site_id, user)
        mig = await migration_service.create_migration(db, site=site, user=user, to_version=None,
                                                       vault=request.app.state.vault,
                                                       world=request.app.state.demo_world,
                                                       sandbox=request.app.state.sandbox)
        return RedirectResponse(f"/dashboard/migrations/{mig.id}", status_code=303)

    return await _site_action(request, db, settings, action)


def _migration_page(request: Request, db: Session, mig: Migration, *, error: str | None = None, status: int = 200):
    signer = db.get(User, mig.signed_off_by) if mig.signed_off_by else None
    return _render(request, "dashboard/migration.html",
                   {"mig": mig, "signer": signer, "labels": MIGRATION_LABELS, "error": error,
                    "user": db.get(User, mig.site.owner_id)}, status)


@router.get("/migrations/{mig_id}")
def migration_page(mig_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        mig = visible_migration(db, mig_id, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _migration_page(request, db, mig)


async def _migration_action(mig_id: int, request: Request, tasks: BackgroundTasks, db: Session,
                            settings: Settings, what: str) -> Response:
    user, form = await _post_guard(request, db, settings)
    mig = visible_migration(db, mig_id, user)
    try:
        if what == "staging":
            migration_service.start_staging(db, mig, user)
            schedule_migration(request, tasks, mig, user, "staging")
        elif what == "signoff":
            if form.get("confirm") != "yes":
                raise AppError(422, "confirm_needed", "Tick the box to confirm you checked the staging site.")
            migration_service.sign_off(db, mig, user)
        else:
            migration_service.start_promotion(db, mig, user)
            schedule_migration(request, tasks, mig, user, "promote")
    except AppError as exc:
        return _migration_page(request, db, mig, error=exc.message, status=exc.status_code)
    return RedirectResponse(f"/dashboard/migrations/{mig.id}", status_code=303)


@router.post("/migrations/{mig_id}/staging")
async def migration_staging(mig_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, settings: SettingsDep):
    return await _migration_action(mig_id, request, tasks, db, settings, "staging")


@router.post("/migrations/{mig_id}/signoff")
async def migration_signoff(mig_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, settings: SettingsDep):
    return await _migration_action(mig_id, request, tasks, db, settings, "signoff")


@router.post("/migrations/{mig_id}/promote")
async def migration_promote(mig_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, settings: SettingsDep):
    return await _migration_action(mig_id, request, tasks, db, settings, "promote")


# --- WordPress Guard: one page per site -----------------------------------------

def _wp_guard_page(request: Request, db: Session, site: Site, user: User, *, new_key: str | None = None,
                   error: str | None = None, status: int = 200):
    sub = wpg.wp_guard_subscription(db, site)
    return _render(request, "dashboard/wp_guard.html",
                   {"user": user, "site": site, "s": wpg.safety(db, site), "new_key": new_key, "error": error,
                    "enabled": sub is not None and sub.status.value != "cancelled"}, status)


@router.get("/wp-guard/{site_id}")
def wp_guard_page(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        site = owned_site(db, site_id, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _wp_guard_page(request, db, site, user)


@router.post("/wp-guard/{site_id}/fix")
async def wp_guard_fix(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, _form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    try:
        target = await wpg.fix_it(db, site, user, vault=request.app.state.vault, world=request.app.state.demo_world)
    except AppError as exc:
        db.rollback()
        return _wp_guard_page(request, db, site, user, error=exc.message, status=exc.status_code)
    # Straight to the approval page: nothing has changed yet.
    return RedirectResponse(target["url"], status_code=303)


@router.post("/wp-guard/{site_id}/key")
async def wp_guard_key(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, _form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    key = wpg.generate_key(db, site, user)
    # Rendered once, never stored in clear; the page is no-store.
    return _wp_guard_page(request, db, site, user, new_key=key)


@router.post("/wp-guard/{site_id}/enable")
async def wp_guard_enable(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    wpg.set_wp_guard(db, site, user, form.get("enabled") == "true")
    return RedirectResponse(f"/dashboard/wp-guard/{site_id}", status_code=303)


@router.get("/wp-guard-plugin.zip")
def wp_guard_plugin_zip(request: Request, db: DbDep, settings: SettingsDep):
    if _user(request, db, settings) is None:
        return _to_login()
    return Response(build_plugin_zip(settings.public_base_url), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="patchwarden.zip"', "Cache-Control": "no-store"})


# --- sign-up, claim, verification, guided connection, list scans (Phase B) -------------

@router.get("/signup")
def signup_page(request: Request, next: str | None = None):
    return _render(request, "dashboard/signup.html", {"next": safe_next(next)})


@router.post("/signup")
async def signup(request: Request, db: DbDep, settings: SettingsDep):
    if not _same_origin(request):
        raise AppError(403, "bad_origin", "This form was sent from another website, so we ignored it.")
    form = await request.form()
    email, nxt = str(form.get("email", ""))[:320], safe_next(str(form.get("next", "")))
    try:
        signup_allowed(request, settings)
        user = create_account(db, email, str(form.get("password", ""))[:200])
    except AppError as exc:
        response = _render(request, "dashboard/signup.html", {"error": exc.message, "email": email, "next": nxt},
                           exc.status_code)
        if exc.headers:
            response.headers.update(exc.headers)
        return response
    return _start_session(RedirectResponse(nxt, status_code=303), settings, user)


@router.get("/claim/{scan_id}")
def claim_page(scan_id: int, request: Request, db: DbDep, settings: SettingsDep, token: str | None = None):
    here = f"/dashboard/claim/{scan_id}" + (f"?token={quote(token)}" if token else "")
    user = _user(request, db, settings)
    if user is None:
        return RedirectResponse(f"/dashboard/signup?next={quote(here)}", status_code=303)
    try:
        scan = _authorised_scan(db, scan_id, user, token, settings)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _render(request, "dashboard/claim.html", {"user": user, "scan": scan, "token": token or ""})


@router.post("/claim/{scan_id}")
async def claim_post(scan_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, form = await _post_guard(request, db, settings)
    try:
        result = claim_scan(scan_id, db, settings, user, str(form.get("token", "")) or None)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return RedirectResponse(result["next"], status_code=303)


def _is_demo_site(request: Request, site: Site) -> bool:
    return request.app.state.demo_world is not None and site.domain.endswith(DEMO_SUFFIX)


def _verify_page(request: Request, db: Session, user: User, site: Site, *, result: dict | None = None,
                 status: int = 200):
    return _render(request, "dashboard/verify.html",
                   {"user": user, "site": site, "v": verification.start(db, site, user), "result": result,
                    "demo": _is_demo_site(request, site)}, status)


@router.get("/sites/{site_id}/verify")
def verify_page(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        site = owned_site(db, site_id, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _verify_page(request, db, user, site)


@router.post("/sites/{site_id}/verify")
async def verify_check(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, _form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    st = request.app.state
    result = await verification.check(db, site, user, resolve_txt=st.txt_resolver, fetcher=st.scanner.fetcher)
    return _verify_page(request, db, user, site, result=result, status=200 if result["verified"] else 409)


@router.post("/sites/{site_id}/verify/demo-publish")
async def verify_demo_publish(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    """Demo sites only (make dev): publish the TXT record in the fake DNS, as the owner would at their DNS host."""
    user, _form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    if not _is_demo_site(request, site):
        raise AppError(404, "not_found", "We could not find that.")
    v = verification.start(db, site, user)
    request.app.state.demo_world.txt_records[v["dns"]["name"]] = [v["dns"]["value"]]
    return RedirectResponse(f"/dashboard/sites/{site.id}/verify", status_code=303)


@router.get("/sites/{site_id}/connect")
def connect_page(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        site = owned_site(db, site_id, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _render(request, "dashboard/connect.html", {"user": user, "site": site})


@router.post("/sites/{site_id}/test-connection")
async def connect_test(site_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user, _form = await _post_guard(request, db, settings)
    site = owned_site(db, site_id, user)
    try:
        adapter = service.build_adapter(site, request.app.state.vault, request.app.state.demo_world)
        test = {"ok": True, "message": f"Connected through {adapter.display_name}: the site runs PHP "
                                       f"{await adapter.php_version()}. Nothing was changed."}
    except AppError as exc:
        test = {"ok": False, "message": exc.message}
    except AdapterError as exc:
        test = {"ok": False, "message": exc.message}
    return _render(request, "dashboard/connect.html", {"user": user, "site": site, "test": test},
                   200 if test["ok"] else 409)


@router.post("/scan-batches")
async def upload_batch(request: Request, tasks: BackgroundTasks, db: DbDep, settings: SettingsDep):
    user, form = await _post_guard(request, db, settings)
    upload = form.get("file")
    try:
        if upload is None or isinstance(upload, str):
            raise AppError(400, "missing_file", "Please choose a CSV file with one domain per row.")
        targets = _parse_csv(await upload.read(CSV_MAX_BYTES + 1))
        batch = start_batch(request, tasks, db, settings, user, targets, form.get("wordpress") == "on")
    except AppError as exc:
        db.rollback()
        return _sites_page(request, db, user, error=exc.message, status=exc.status_code)
    return RedirectResponse(f"/dashboard/scan-batches/{batch.id}", status_code=303)


@router.get("/scan-batches/{batch_id}")
def batch_page(batch_id: int, request: Request, db: DbDep, settings: SettingsDep):
    user = _user(request, db, settings)
    if user is None:
        return _to_login()
    try:
        data = get_batch(batch_id, db, settings, user)
    except AppError as exc:
        return _render(request, "error.html", {"code": exc.code, "message": exc.message}, exc.status_code)
    return _render(request, "dashboard/batch.html", {"user": user, "b": data})
