"""Who may do what to a site: one place for every access decision.

A site belongs to one user (its owner) and, optionally, to an organisation. The owner can do everything.
Organisation members get what their role allows:

| Action    | owner | admin | member | approver | viewer |
|-----------|:-----:|:-----:|:------:|:--------:|:------:|
| view      |  yes  |  yes  |  yes   |   yes    |  yes   |
| edit      |  yes  |  yes  |  yes   |          |        |   plan patches, connect hosts, monitoring, staging
| approve   |  yes  |  yes  |        |   yes    |        |   approve patches, roll back, sign off, promote
| manage    |  yes  |  yes  |        |          |        |   members, branding, billing details

A platform administrator (users.role = admin) may view everything, as before; it never approves.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import Membership, Organization, OrgRole, Role, Site, User

Action = Literal["view", "edit", "approve", "manage"]

ALLOWED: dict[Action, set[OrgRole]] = {
    "view": set(OrgRole),
    "edit": {OrgRole.owner, OrgRole.admin, OrgRole.member},
    "approve": {OrgRole.owner, OrgRole.admin, OrgRole.approver},
    "manage": {OrgRole.owner, OrgRole.admin},
}


def org_role(db: Session, org_id: int | None, user: User) -> OrgRole | None:
    if org_id is None:
        return None
    return db.scalar(select(Membership.role).where(Membership.org_id == org_id, Membership.user_id == user.id))


def can(db: Session, user: User, site: Site, action: Action) -> bool:
    if site.owner_id is not None and site.owner_id == user.id:
        return True
    role = org_role(db, site.org_id, user)
    if role is not None and role in ALLOWED[action]:
        return True
    return action == "view" and user.role == Role.admin


def site_for(db: Session, site_id: int, user: User, action: Action = "view") -> Site:
    """The site, if this user may do `action` to it. Not visible at all: 404. Visible but not allowed: 403."""
    site = db.get(Site, site_id)
    if site is None or site.owner_id is None or not can(db, user, site, "view"):
        raise AppError(404, "site_not_found", "We could not find that site.")
    if not can(db, user, site, action):
        raise denied(action)
    return site


def require(db: Session, user: User, site: Site, action: Action) -> None:
    if not can(db, user, site, action):
        raise denied(action)


def denied(action: Action) -> AppError:
    return AppError(403, f"{action}_not_allowed", {
        "view": "You do not have access to this site.",
        "edit": "Your role can look at this site but not change it. Ask an owner or admin of your team.",
        "approve": "Your role cannot approve changes to this site. Ask the site owner or a team approver.",
        "manage": "Only an owner or admin of the team can do that.",
    }[action])


def visible_sites_clause(db: Session, user: User):
    """A WHERE clause for the sites this user can see (their own, and their organisations')."""
    org_ids = list(db.scalars(select(Membership.org_id).where(Membership.user_id == user.id)))
    return or_(Site.owner_id == user.id, Site.org_id.in_(org_ids)) if org_ids else Site.owner_id == user.id


def visible_site_ids(db: Session, user: User) -> list[int]:
    return list(db.scalars(select(Site.id).where(visible_sites_clause(db, user)).order_by(Site.id)))


def org_for(db: Session, org_id: int, user: User, action: Action = "view") -> Organization:
    org = db.get(Organization, org_id)
    role = org_role(db, org_id, user) if org else None
    if org is None or role is None:
        raise AppError(404, "org_not_found", "We could not find that team.")
    if role not in ALLOWED[action]:
        raise denied(action)
    return org


def separate_approver_required(db: Session, site: Site) -> bool:
    if site.org_id is None:
        return False
    org = db.get(Organization, site.org_id)
    return bool(org and org.require_separate_approver)
