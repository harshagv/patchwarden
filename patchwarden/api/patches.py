"""Patch agent endpoints: POST /api/patches, approve, rollback, GET /api/patches/{id}."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

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
    site = db.get(Site, site_id)
    if site is None or site.owner_id != user.id:
        raise AppError(404, "site_not_found", "We could not find that site.")
    return site


def visible_job(db: Session, job_id: int, user: User) -> PatchJob:
    job = db.get(PatchJob, job_id)
    if job is None or (job.site.owner_id != user.id and user.role != Role.admin):
        raise AppError(404, "patch_not_found", "We could not find that patch.")
    return job


def schedule(request: Request, tasks: BackgroundTasks, job: PatchJob, user: User, mode: str) -> None:
    st = request.app.state
    tasks.add_task(service.run_job, st.sessionmaker, st.settings, st.vault, st.demo_world,
                   st.scanner.fetcher, job.id, user.id, mode)


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
    service.approve(db, job, user)
    schedule(request, tasks, job, user, "patch")
    return JSONResponse(service.job_json(job), status_code=202)


@router.post("/{job_id}/rollback", status_code=202)
def rollback_patch(job_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    """One-click rollback: restore the backup and switch PHP back."""
    job = visible_job(db, job_id, user)
    service.request_rollback(db, job, user)
    schedule(request, tasks, job, user, "rollback")
    return JSONResponse(service.job_json(job), status_code=202)
