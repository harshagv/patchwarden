"""POST /api/sites, GET /api/sites, GET /api/sites/{id}."""

from __future__ import annotations

import re

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..crypto import CredentialVault
from .. import access
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import AccessMethod, AuditLog, Credential, CredentialKind, Platform, Role, Site, User
from ..patch.adapters import CREDENTIAL_FOR_METHOD, METHOD_FOR_CREDENTIAL
from ..scanner.fetch import FetchError, normalise_target

router = APIRouter(prefix="/api/sites", tags=["sites"])


_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,199}$")


class SiteIn(BaseModel):
    domain: str = Field(max_length=2048)
    platform: Platform = Platform.custom
    login_path: str | None = Field(default=None, max_length=200, description="e.g. /wp-login.php or /login")
    form_path: str | None = Field(default=None, max_length=200, description="A checkout or contact form page")


class SiteUpdate(BaseModel):
    login_path: str | None = Field(default=None, max_length=200)
    form_path: str | None = Field(default=None, max_length=200)


class CredentialIn(BaseModel):
    kind: CredentialKind
    value: str = Field(min_length=8, max_length=4096, description="The token or key. Stored encrypted, never shown again.")


# Phase 2 can use these; SSH keys and WordPress application passwords arrive with Phases 4 and 5.
PHASE2_KINDS = set(METHOD_FOR_CREDENTIAL)


def check_paths(login: str | None, form: str | None) -> dict | None:
    paths = {}
    for name, value in (("login", login), ("form", form)):
        if value:
            if not _PATH.match(value) or value.startswith("//"):
                raise AppError(422, "invalid_path", f"The {name} page must be a path on the site, like /login.")
            paths[name] = value
    return paths or None


def site_json(site: Site, *, history: bool = False) -> dict:
    latest = site.scans[-1] if site.scans else None
    out = {
        "id": site.id,
        "domain": site.domain,
        "platform": site.platform.value,
        "access_method": site.access_method.value,
        "status": site.status,
        "created_at": site.created_at.isoformat(),
        "latest_scan": (
            {"id": latest.id, "risk": latest.risk.value, "detected_version": latest.detected_version,
             "created_at": latest.created_at.isoformat()}
            if latest else None
        ),
    }
    out["check_paths"] = site.check_paths or {}
    # Kind and date only: a stored token is never shown again.
    out["credentials"] = [{"id": c.id, "kind": c.kind.value, "created_at": c.created_at.isoformat()}
                          for c in site.credentials]
    if history:
        out["scans"] = [
            {"id": s.id, "risk": s.risk.value, "detected_version": s.detected_version,
             "created_at": s.created_at.isoformat()}
            for s in reversed(site.scans)
        ]
    return out


def _domain(raw: str) -> str:
    try:
        host = httpx.URL(normalise_target(raw)).host.rstrip(".").lower()
    except (FetchError, httpx.InvalidURL, ValueError):
        host = ""
    if not host:
        raise AppError(422, "invalid_domain", "That does not look like a website address.")
    return host


@router.post("", status_code=201)
def create_site(body: SiteIn, db: DbDep, user: CurrentUser) -> dict:
    site = Site(owner_id=user.id, domain=_domain(body.domain), platform=body.platform,
                check_paths=check_paths(body.login_path, body.form_path))
    db.add(site)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "site_exists", "You have already added this site.") from None
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.created", detail={"domain": site.domain}))
    db.commit()
    return site_json(site)


@router.get("")
def list_sites(db: DbDep, user: CurrentUser) -> dict:
    sites = db.scalars(select(Site).where(access.visible_sites_clause(db, user)).order_by(Site.id)).all()
    return {"sites": [site_json(s) for s in sites]}


def _visible(db: Session, site_id: int, user: User, *, write: bool = False) -> Site:
    return access.site_for(db, site_id, user, "edit" if write else "view")


@router.get("/{site_id}")
def get_site(site_id: int, db: DbDep, user: CurrentUser) -> dict:
    return site_json(_visible(db, site_id, user), history=True)


@router.patch("/{site_id}")
def update_site(site_id: int, body: SiteUpdate, db: DbDep, user: CurrentUser) -> dict:
    site = _visible(db, site_id, user, write=True)
    site.check_paths = check_paths(body.login_path, body.form_path)
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.check_paths_set", detail=site.check_paths or {}))
    db.commit()
    return site_json(site)


def add_credential(db: Session, vault: CredentialVault, site: Site, user: User, kind: CredentialKind,
                   value: str) -> Credential:
    if kind not in PHASE2_KINDS:
        raise AppError(422, "kind_not_supported_yet",
                       "This kind of access arrives in a later phase. Use a cPanel or Plesk API token, or the agent API key.")
    if not value.strip() or any(ch.isspace() for ch in value.strip()):
        raise AppError(422, "invalid_token", "That does not look like an API token or key.")
    cred = Credential(site_id=site.id, kind=kind, encrypted_value=vault.encrypt(value.strip()))
    db.add(cred)
    site.access_method = METHOD_FOR_CREDENTIAL[kind]
    db.flush()
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="credential.added",
                    detail={"credential_id": cred.id, "kind": kind.value}))
    db.commit()
    db.refresh(site)
    return cred


@router.post("/{site_id}/credentials", status_code=201)
def create_credential(site_id: int, body: CredentialIn, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """Store an owner-created API token or key, Fernet-encrypted. Passwords are not accepted."""
    site = _visible(db, site_id, user, write=True)
    cred = add_credential(db, request.app.state.vault, site, user, body.kind, body.value)
    return {"id": cred.id, "kind": cred.kind.value, "created_at": cred.created_at.isoformat(),
            "access_method": site.access_method.value}


@router.delete("/{site_id}/credentials/{credential_id}", status_code=200)
def revoke_credential(site_id: int, credential_id: int, db: DbDep, user: CurrentUser) -> dict:
    """Remove stored access. Revocable anytime by the owner."""
    site = _visible(db, site_id, user, write=True)
    cred = db.get(Credential, credential_id)
    if cred is None or cred.site_id != site.id:
        raise AppError(404, "credential_not_found", "We could not find that access token.")
    db.delete(cred)
    db.flush()
    db.refresh(site)
    if CREDENTIAL_FOR_METHOD.get(site.access_method) not in {c.kind for c in site.credentials}:
        site.access_method = AccessMethod.external
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="credential.revoked",
                    detail={"credential_id": credential_id, "kind": cred.kind.value}))
    db.commit()
    return {"revoked": credential_id, "access_method": site.access_method.value}
