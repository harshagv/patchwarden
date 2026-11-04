"""Patch agent endpoints: POST /api/patches, approve, rollback, GET /api/patches/{id}."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import access
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import PatchJob, Role, Site, User
from ..patch import service

router = APIRouter(prefix="/api/patches", tags=["patches"])


class PatchRequest(BaseModel):
    site_id: int
    to_version: str | None = Field(default=None, max_length=32,
                                   description="Defaults to the newest fixed release on the site's PHP line")


def owned_site(db: Session, site_id: int, user: User) -> Site:
    return access.site_for(db, site_id, user, "edit")


def visible_job(db: Session, job_id: int, user: User) -> PatchJob:
    job = db.get(PatchJob, job_id)
    if job is None or not access.can(db, user, job.site, "view"):
        raise AppError(404, "patch_not_found", "We could not find that patch.")
    return job


def schedule(request: Request, tasks: BackgroundTasks, job: PatchJob, user: User, mode: str) -> None:
    """Record a durable job, then start it straight away. If the server dies mid-run, the job queue
    picks it up again and recovers (patchwarden/jobs.py)."""
    queue = request.app.state.jobs
    with request.app.state.sessionmaker() as db:
        queued = queue.enqueue(db, "rollback" if mode == "rollback" else "patch", job.id, user.id)
    tasks.add_task(queue.run_one, queued.id)


@router.post("", status_code=201)
async def create_patch(body: PatchRequest, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Plan a patch as a dry run. Nothing on the site changes until the owner approves."""
    site = owned_site(db, body.site_id, user)
    job = await service.create_dry_run(db, site=site, user=user, to_version=body.to_version,
                                       vault=request.app.state.vault, world=request.app.state.demo_world)
    return service.job_json(job)


@router.get("/{job_id}")
def get_patch(job_id: int, db: DbDep, user: CurrentUser) -> dict:
    return service.job_json(visible_job(db, job_id, user))


@router.post("/{job_id}/approve", status_code=202)
def approve_patch(job_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    """Owner approval. Records who approved and when, then runs the patch."""
    job = visible_job(db, job_id, user)
    service.approve(db, job, user, request.app.state.settings)
    schedule(request, tasks, job, user, "patch")
    return JSONResponse(service.job_json(job), status_code=202)


@router.post("/{job_id}/rollback", status_code=202)
def rollback_patch(job_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    """One-click rollback: restore the backup and switch PHP back."""
    job = visible_job(db, job_id, user)
    service.request_rollback(db, job, user)
    schedule(request, tasks, job, user, "rollback")
    return JSONResponse(service.job_json(job), status_code=202)
