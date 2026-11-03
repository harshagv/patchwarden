"""Migration agent endpoints: plan, staging tests, sign-off, promotion."""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..migration import service
from ..models import Migration, Role, User
from .patches import owned_site

router = APIRouter(prefix="/api/migrations", tags=["migrations"])


class MigrationRequest(BaseModel):
    site_id: int
    to_version: str | None = Field(default=None, max_length=32,
                                   description="Defaults to the newest fixed 8.4 release the host offers")


_REQUEST_DOCS = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {"schema": MigrationRequest.model_json_schema()},
            "multipart/form-data": {"schema": {"type": "object", "required": ["site_id", "file"], "properties": {
                "site_id": {"type": "integer"},
                "file": {"type": "string", "format": "binary", "description": "Zip of the site's code"},
                "from_version": {"type": "string"}, "to_version": {"type": "string"},
            }}},
        },
    }
}


def visible_migration(db: Session, mig_id: int, user: User) -> Migration:
    mig = db.get(Migration, mig_id)
    if mig is None or (mig.site.owner_id != user.id and user.role != Role.admin):
        raise AppError(404, "migration_not_found", "We could not find that migration.")
    return mig


def schedule(request: Request, tasks: BackgroundTasks, mig: Migration, user: User, what: str) -> None:
    st = request.app.state
    fn = service.run_staging if what == "staging" else service.run_promotion
    tasks.add_task(fn, st.sessionmaker, st.settings, st.vault, st.demo_world, st.scanner.fetcher, mig.id, user.id)


@router.post("", status_code=201, openapi_extra=_REQUEST_DOCS)
async def create_migration(request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Scan the code for breaking changes and write the migration plan. Read-only: nothing is changed."""
    uploaded = from_version = None
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise AppError(400, "missing_file", "Please attach a zip of the site's code.")
        try:
            body = MigrationRequest(site_id=int(str(form.get("site_id", ""))),
                                    to_version=str(form.get("to_version") or "") or None)
        except (ValueError, ValidationError):
            raise AppError(422, "invalid_request", "Send site_id with the zip.") from None
        uploaded = service.read_zip(await upload.read(service.ZIP_MAX_BYTES + 1))
        from_version = str(form.get("from_version") or "")[:32] or None
    else:
        try:
            body = MigrationRequest.model_validate(json.loads(await request.body() or b"{}"))
        except (ValueError, ValidationError):
            raise AppError(422, "invalid_request", "Send JSON with site_id (and optionally to_version).") from None
    site = owned_site(db, body.site_id, user)
    mig = await service.create_migration(db, site=site, user=user, to_version=body.to_version,
                                         vault=request.app.state.vault, world=request.app.state.demo_world,
                                         uploaded=uploaded, from_version=from_version)
    return service.migration_json(mig)


@router.get("/{mig_id}")
def get_migration(mig_id: int, db: DbDep, user: CurrentUser) -> dict:
    return service.migration_json(visible_migration(db, mig_id, user))


@router.post("/{mig_id}/staging", status_code=202)
def run_staging(mig_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    """Copy the site to staging (or re-use it), apply automatic fixes, switch staging's PHP and test it."""
    mig = visible_migration(db, mig_id, user)
    service.start_staging(db, mig, user)
    schedule(request, tasks, mig, user, "staging")
    return JSONResponse(service.migration_json(mig), status_code=202)


@router.post("/{mig_id}/signoff")
def sign_off(mig_id: int, db: DbDep, user: CurrentUser) -> dict:
    """Owner/IT sign-off after checking staging. Required before promotion."""
    mig = visible_migration(db, mig_id, user)
    service.sign_off(db, mig, user)
    return service.migration_json(mig)


@router.post("/{mig_id}/promote", status_code=202)
def promote(mig_id: int, request: Request, tasks: BackgroundTasks, db: DbDep, user: CurrentUser):
    """Promote the tested staging code to production via the Patch agent's backup/check/rollback flow."""
    mig = visible_migration(db, mig_id, user)
    service.start_promotion(db, mig, user)
    schedule(request, tasks, mig, user, "promote")
    return JSONResponse(service.migration_json(mig), status_code=202)
