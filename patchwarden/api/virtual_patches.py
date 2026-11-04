"""Virtual patches: block attack requests at the edge (Cloudflare, Akamai, AWS WAF) until PHP is updated."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import access
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import User, VirtualPatch
from ..virtual_patch import service

router = APIRouter(tags=["virtual patches"])


class VirtualPatchIn(BaseModel):
    provider: str = Field(description="cloudflare, akamai, aws_waf, or demo (demo sites only)")
    config: dict = Field(default_factory=dict, description="Cloudflare: zone_id. Akamai: config_id, version, "
                         "policy_id, network. AWS WAF: web_acl_name, web_acl_id, region, scope.")
    secret: str | None = Field(default=None, max_length=4000,
                               description="Cloudflare API token; Akamai EdgeGrid JSON; AWS keys JSON (optional). "
                                           "Stored encrypted, never shown back.")


def visible_vp(db, vp_id: int, user: User) -> VirtualPatch:
    vp = db.get(VirtualPatch, vp_id)
    if vp is None or not access.can(db, user, vp.site, "view"):
        raise AppError(404, "virtual_patch_not_found", "We could not find that virtual patch.")
    return vp


def schedule(request: Request, tasks: BackgroundTasks, vp: VirtualPatch, user: User, kind: str) -> None:
    queue = request.app.state.jobs
    with request.app.state.sessionmaker() as db:
        queued = queue.enqueue(db, kind, vp.id, user.id)
    tasks.add_task(queue.run_one, queued.id)


@router.post("/api/sites/{site_id}/virtual-patches", status_code=201)
async def plan_virtual_patch(site_id: int, body: VirtualPatchIn, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Dry run: check the edge settings and show the rules. Nothing changes until it is approved."""
    site = access.site_for(db, site_id, user, "edit")
    s = request.app.state
    vp = await service.plan(db, s.vault, s.demo_world, site, user, body.provider, body.config, body.secret, state=s)
    return service.vp_json(vp)


@router.get("/api/sites/{site_id}/virtual-patches")
def list_virtual_patches(site_id: int, db: DbDep, user: CurrentUser) -> dict:
    site = access.site_for(db, site_id, user, "view")
    rows = db.scalars(select(VirtualPatch).where(VirtualPatch.site_id == site.id).order_by(VirtualPatch.id)).all()
    return {"virtual_patches": [service.vp_json(v) for v in rows]}


@router.get("/api/virtual-patches/{vp_id}")
def get_virtual_patch(vp_id: int, db: DbDep, user: CurrentUser) -> dict:
    return service.vp_json(visible_vp(db, vp_id, user))


@router.post("/api/virtual-patches/{vp_id}/approve", status_code=202)
def approve_virtual_patch(vp_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    vp = visible_vp(db, vp_id, user)
    service.approve(db, vp, user)
    schedule(request, tasks, vp, user, "vpatch_apply")
    return JSONResponse(service.vp_json(vp), status_code=202)


@router.post("/api/virtual-patches/{vp_id}/remove", status_code=202)
def remove_virtual_patch(vp_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    vp = visible_vp(db, vp_id, user)
    service.request_removal(db, vp, user)
    schedule(request, tasks, vp, user, "vpatch_remove")
    return JSONResponse(service.vp_json(vp), status_code=202)
