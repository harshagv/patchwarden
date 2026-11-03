"""WordPress Guard endpoints: the plugin's API (key auth) and the owner's (JWT)."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..wpguard import service as wpg
from ..wpguard.plugin_zip import build_plugin_zip
from .patches import owned_site

router = APIRouter(tags=["wordpress guard"])
REPORT_MAX_BYTES = 512 * 1024
NO_STORE = {"Cache-Control": "no-store"}

PluginKeyHeader = Annotated[str | None, Header(alias="X-Patchwarden-Key", include_in_schema=False)]


# --- called by the WordPress plugin ---------------------------------------------

@router.post("/api/plugin/report")
async def plugin_report(request: Request, db: DbDep, x_patchwarden_key: PluginKeyHeader = None) -> dict:
    """The plugin's scheduled report: PHP version, WordPress version, plugins and themes."""
    key = wpg.key_from_request(db, x_patchwarden_key)
    body = await request.body()
    if len(body) > REPORT_MAX_BYTES:
        raise AppError(413, "too_large", "The report is too large.")
    try:
        report = json.loads(body or b"{}")
    except ValueError:
        raise AppError(422, "invalid_report", "The plugin sent a report we could not read.") from None
    if not isinstance(report, dict):
        raise AppError(422, "invalid_report", "The plugin sent a report we could not read.")
    st = request.app.state
    scan = await wpg.ingest_report(db, key, report, st.scanner.feed, st.watchdog)
    return {"received": True, "risk": scan.risk.value, "php_version": scan.detected_version}


@router.get("/api/plugin/actions")
def plugin_actions(db: DbDep, x_patchwarden_key: PluginKeyHeader = None) -> dict:
    """Actions the owner approved, for the plugin to run. Pulled by the plugin; we never push into the site."""
    key = wpg.key_from_request(db, x_patchwarden_key)
    return {"actions": wpg.pull_actions(db, key)}


class ActionResult(BaseModel):
    ok: bool
    detail: str = Field(default="", max_length=2000)
    version: str | None = Field(default=None, max_length=32)


@router.post("/api/plugin/actions/{action_id}/result")
def plugin_action_result(action_id: int, body: ActionResult, db: DbDep, x_patchwarden_key: PluginKeyHeader = None) -> dict:
    key = wpg.key_from_request(db, x_patchwarden_key)
    a = wpg.action_result(db, key, action_id, body.ok, body.detail, body.version)
    return {"id": a.id, "state": a.state}


@router.post("/api/plugin/disconnect")
def plugin_disconnect(db: DbDep, x_patchwarden_key: PluginKeyHeader = None) -> dict:
    """Called by the plugin's uninstall: the key stops working on our side too."""
    key = wpg.key_from_request(db, x_patchwarden_key)
    wpg.disconnect(db, key)
    return {"disconnected": True}


# --- the owner ------------------------------------------------------------------

@router.post("/api/sites/{site_id}/plugin-key", status_code=201)
def create_plugin_key(site_id: int, db: DbDep, user: CurrentUser) -> JSONResponse:
    """A new key for the WordPress plugin. Shown once: we keep only a hash. Any older key stops working."""
    site = owned_site(db, site_id, user)
    key = wpg.generate_key(db, site, user)
    return JSONResponse({"key": key, "hint": key[:7] + "…",
                         "note": "Copy this key into the Patchwarden plugin now. It will not be shown again."},
                        status_code=201, headers=NO_STORE)


class EnableIn(BaseModel):
    enabled: bool


@router.post("/api/sites/{site_id}/wp-guard")
def enable_wp_guard(site_id: int, body: EnableIn, db: DbDep, user: CurrentUser) -> dict:
    """Turn WordPress Guard (scan + patch + daily watch, one product) on or off for a site."""
    site = owned_site(db, site_id, user)
    wpg.set_wp_guard(db, site, user, body.enabled)
    sub = wpg.wp_guard_subscription(db, site)
    return {"site_id": site.id, "wp_guard": sub is not None and sub.status.value != "cancelled",
            "subscription": {"id": sub.id, "product": sub.product.value, "status": sub.status.value} if sub else None}


@router.get("/api/sites/{site_id}/wp-guard")
def wp_guard_view(site_id: int, db: DbDep, user: CurrentUser) -> dict:
    """Safety score and plain-language fix list for one site."""
    return {"site_id": site_id, **wpg.safety(db, owned_site(db, site_id, user))}


@router.post("/api/sites/{site_id}/fix", status_code=201)
async def fix_it(site_id: int, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """"Fix it": creates a plan that waits for your approval. It never changes the site by itself."""
    site = owned_site(db, site_id, user)
    return await wpg.fix_it(db, site, user, vault=request.app.state.vault, world=request.app.state.demo_world)


@router.get("/api/wp-guard/plugin.zip")
def download_plugin(request: Request, user: CurrentUser) -> Response:
    """The WordPress plugin, set up to report to this Patchwarden. Contains no key or secret."""
    data = build_plugin_zip(request.app.state.settings.public_base_url)
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="patchwarden.zip"', **NO_STORE})
