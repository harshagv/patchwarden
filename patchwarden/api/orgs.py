"""Teams: organisations, members and roles, the four-eyes rule, and white-label branding."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .. import access
from ..deps import CurrentUser, DbDep
from ..errors import AppError
from ..models import AuditLog, Membership, Organization, OrgRole, Site, User

router = APIRouter(tags=["teams"])

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def org_json(db, org: Organization, user: User | None = None) -> dict:
    members = db.scalars(select(Membership).where(Membership.org_id == org.id).order_by(Membership.id)).all()
    out = {"id": org.id, "name": org.name, "require_separate_approver": org.require_separate_approver,
           "hourly_rate": org.hourly_rate,
           "branding": {"name": org.brand_name, "color": org.brand_color, "logo_url": org.brand_logo_url,
                        "footer": org.brand_footer},
           "members": [{"user_id": m.user_id, "email": db.get(User, m.user_id).email, "role": m.role.value}
                       for m in members],
           "sites": list(db.scalars(select(Site.id).where(Site.org_id == org.id).order_by(Site.id)))}
    if user is not None:
        role = access.org_role(db, org.id, user)
        out["your_role"] = role.value if role else None
    return out


def _audit(db, user: User, action: str, **detail) -> None:
    db.add(AuditLog(user_id=user.id, action=action, detail=detail))


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


@router.post("/api/orgs", status_code=201)
def create_org(body: OrgIn, db: DbDep, user: CurrentUser) -> dict:
    org = Organization(name=body.name.strip())
    db.add(org)
    db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role=OrgRole.owner))
    _audit(db, user, "org.created", org_id=org.id)
    db.commit()
    return org_json(db, org, user)


@router.get("/api/orgs")
def list_orgs(db: DbDep, user: CurrentUser) -> dict:
    ids = db.scalars(select(Membership.org_id).where(Membership.user_id == user.id).order_by(Membership.org_id))
    return {"orgs": [org_json(db, db.get(Organization, i), user) for i in ids]}


@router.get("/api/orgs/{org_id}")
def get_org(org_id: int, db: DbDep, user: CurrentUser) -> dict:
    return org_json(db, access.org_for(db, org_id, user), user)


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    require_separate_approver: bool | None = None
    hourly_rate: int | None = Field(default=None, ge=1, le=100000)
    brand_name: str | None = Field(default=None, max_length=80)
    brand_color: str | None = None
    brand_logo_url: str | None = Field(default=None, max_length=500)
    brand_footer: str | None = Field(default=None, max_length=300)


@router.patch("/api/orgs/{org_id}")
def update_org(org_id: int, body: OrgUpdate, db: DbDep, user: CurrentUser) -> dict:
    org = access.org_for(db, org_id, user, "manage")
    changes = body.model_dump(exclude_unset=True)
    if changes.get("brand_color") and not _COLOR.match(changes["brand_color"]):
        raise AppError(422, "invalid_color", "Use a colour like #1f6feb.")
    if changes.get("brand_logo_url"):
        u = urlsplit(changes["brand_logo_url"])
        if u.scheme != "https" or not u.hostname or u.username or u.password:
            raise AppError(422, "invalid_logo_url", "The logo must be an https:// image address.")
    for field, value in changes.items():
        setattr(org, field, value.strip() if isinstance(value, str) else value)
    _audit(db, user, "org.updated", org_id=org.id, fields=sorted(changes))
    db.commit()
    return org_json(db, org, user)


class MemberIn(BaseModel):
    email: str = Field(max_length=254)
    role: OrgRole


@router.post("/api/orgs/{org_id}/members", status_code=201)
def add_member(org_id: int, body: MemberIn, db: DbDep, user: CurrentUser) -> dict:
    """Add someone who already has a Patchwarden account (no invitation emails in this build)."""
    org = access.org_for(db, org_id, user, "manage")
    if body.role == OrgRole.owner and access.org_role(db, org.id, user) != OrgRole.owner:
        raise AppError(403, "manage_not_allowed", "Only an owner can add another owner.")
    member = db.scalar(select(User).where(func.lower(User.email) == body.email.strip().lower()))
    if member is None:
        raise AppError(404, "user_not_found", "There is no Patchwarden account with that email. Ask them to sign up first.")
    existing = db.scalar(select(Membership).where(Membership.org_id == org.id, Membership.user_id == member.id))
    if existing is not None:
        _ensure_owner_left(db, org.id, existing, body.role)
        existing.role = body.role
    else:
        db.add(Membership(org_id=org.id, user_id=member.id, role=body.role))
    _audit(db, user, "org.member_set", org_id=org.id, member_id=member.id, role=body.role.value)
    db.commit()
    return org_json(db, org, user)


def _ensure_owner_left(db, org_id: int, membership: Membership, new_role: OrgRole | None) -> None:
    if membership.role != OrgRole.owner or new_role == OrgRole.owner:
        return
    owners = db.scalar(select(func.count(Membership.id)).where(Membership.org_id == org_id,
                                                               Membership.role == OrgRole.owner))
    if owners <= 1:
        raise AppError(409, "last_owner", "A team needs at least one owner. Add another owner first.")


@router.delete("/api/orgs/{org_id}/members/{member_id}")
def remove_member(org_id: int, member_id: int, db: DbDep, user: CurrentUser) -> dict:
    org = access.org_for(db, org_id, user, "manage")
    m = db.scalar(select(Membership).where(Membership.org_id == org.id, Membership.user_id == member_id))
    if m is None:
        raise AppError(404, "member_not_found", "That person is not in this team.")
    _ensure_owner_left(db, org.id, m, None)
    db.delete(m)
    _audit(db, user, "org.member_removed", org_id=org.id, member_id=member_id)
    db.commit()
    return org_json(db, org, user)


class SiteTeamIn(BaseModel):
    org_id: int | None


@router.post("/api/sites/{site_id}/team")
def set_site_team(site_id: int, body: SiteTeamIn, db: DbDep, user: CurrentUser) -> dict:
    """Share a site with a team (or stop sharing). Only the site's owner can; they must manage that team."""
    site = access.site_for(db, site_id, user, "view")
    if site.owner_id != user.id:
        raise AppError(403, "owner_only", "Only the site's owner can change which team it belongs to.")
    if body.org_id is not None:
        access.org_for(db, body.org_id, user, "manage")
    site.org_id = body.org_id
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.team_set", detail={"org_id": body.org_id}))
    db.commit()
    return {"site_id": site.id, "org_id": site.org_id}
