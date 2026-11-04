"""Virtual patch flow: dry run, approval, apply at the edge (a durable job), remove.

Same rules as a PHP patch:
- nothing changes at the edge until someone with the approve role says yes (four-eyes rule respected);
- every step is in the audit log;
- the provider token is encrypted and never shown back;
- apply and remove are safe to repeat, so a job interrupted by a crash just runs again.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from .. import access
from ..config import Settings
from ..crypto import CredentialVault
from ..errors import AppError
from ..fakes import DemoWorld
from ..models import AuditLog, Site, User, VirtualPatch
from . import providers
from .signatures import SIGNATURES

log = logging.getLogger(__name__)

PROVIDER_LABELS = {"cloudflare": "Cloudflare", "akamai": "Akamai", "aws_waf": "AWS WAF", "demo": "Demo WAF"}
RETRYABLE = ("provider_unreachable", "provider_busy")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _audit(db: Session, user_id: int | None, vp: VirtualPatch, action: str, **detail) -> None:
    db.add(AuditLog(user_id=user_id, site_id=vp.site_id, action=action,
                    detail={"virtual_patch_id": vp.id, "provider": vp.provider, **detail}))


def vp_json(vp: VirtualPatch) -> dict:
    return {"id": vp.id, "site_id": vp.site_id, "provider": vp.provider, "state": vp.state, "config": vp.config,
            "plan": vp.plan, "report": vp.report, "has_secret": vp.secret_encrypted is not None,
            "approved_at": vp.approved_at.isoformat() if vp.approved_at else None,
            "activated_at": vp.activated_at.isoformat() if vp.activated_at else None,
            "removed_at": vp.removed_at.isoformat() if vp.removed_at else None,
            "created_at": vp.created_at.isoformat()}


def _provider(vp: VirtualPatch, site: Site, vault: CredentialVault, world: DemoWorld | None, state=None):
    secret = vault.decrypt(vp.secret_encrypted) if vp.secret_encrypted else ""
    return providers.build(vp.provider, vp.config, secret, domain=site.domain, world=world,
                           http_transport=getattr(state, "vpatch_http_transport", None),
                           aws_factory=getattr(state, "vpatch_aws_factory", None))


async def plan(db: Session, vault: CredentialVault, world: DemoWorld | None, site: Site, user: User,
               provider: str, config: dict, secret: str | None, state=None) -> VirtualPatch:
    """The dry run: check the settings and describe the rules. Nothing is sent to the provider."""
    if provider not in providers.KINDS:
        raise AppError(422, "invalid_provider", "Pick cloudflare, akamai or aws_waf (or demo for demo sites).")
    if db.scalar(select(VirtualPatch.id).where(VirtualPatch.site_id == site.id,
                                               VirtualPatch.state.in_(("planned", "applying", "active", "removing")))):
        raise AppError(409, "virtual_patch_exists", "This site already has a virtual patch. Remove it first.")
    vp = VirtualPatch(site_id=site.id, provider=provider, config=dict(config or {}),
                      secret_encrypted=vault.encrypt(secret) if secret else None)
    try:
        p = _provider(vp, site, vault, world, state)
    except providers.ProviderError as exc:
        raise AppError(422, exc.code, exc.message) from None
    try:
        described = p.describe()
        vp.config = dict(getattr(p, "config", {}))  # normalised ids only: the secret is not in here
    finally:
        await p.aclose()
    vp.requested_by, vp.state = user.id, "planned"
    vp.plan = {
        "provider": PROVIDER_LABELS[provider], **described,
        "blocks": [{"id": s.id, "why": s.why} for s in SIGNATURES],
        "steps": ["Add the rule at the edge, in front of the site.",
                  "Requests that match are blocked before they reach PHP.",
                  "The rule stays until you remove it: update PHP as soon as you can, then remove it."],
        "changes_made": "None yet. Nothing changes until it is approved.",
    }
    db.add(vp)
    db.flush()
    _audit(db, user.id, vp, "virtual_patch.planned")
    db.commit()
    return vp


def _claim(db: Session, vp: VirtualPatch, allowed: tuple[str, ...], new: str, **values) -> None:
    r = db.execute(update(VirtualPatch).where(VirtualPatch.id == vp.id, VirtualPatch.state.in_(allowed))
                   .values(state=new, **values))
    if r.rowcount != 1:
        db.rollback()
        raise AppError(409, "not_allowed_now", f"This virtual patch is {vp.state}, so that is not possible now.")
    db.commit()
    db.refresh(vp)


def approve(db: Session, vp: VirtualPatch, user: User) -> None:
    access.require(db, user, vp.site, "approve")
    if access.separate_approver_required(db, vp.site) and vp.requested_by == user.id:
        raise AppError(403, "separate_approver_required",
                       "Your team requires a second person to approve changes. Ask an approver to approve this one.")
    _claim(db, vp, ("planned",), "applying", approved_by=user.id, approved_at=utcnow())
    _audit(db, user.id, vp, "virtual_patch.approved")
    db.commit()


def request_removal(db: Session, vp: VirtualPatch, user: User) -> None:
    access.require(db, user, vp.site, "approve")
    _claim(db, vp, ("active", "failed"), "removing")
    _audit(db, user.id, vp, "virtual_patch.removal_requested")
    db.commit()


async def run(factory: sessionmaker[Session], vault: CredentialVault, world: DemoWorld | None, vp_id: int,
              actor_id: int | None, mode: str, *, state=None) -> None:
    """The job: apply (mode "apply") or remove (mode "remove") the rule at the edge."""
    with factory() as db:
        vp = db.get(VirtualPatch, vp_id)
        if vp is None or vp.state != ("applying" if mode == "apply" else "removing"):
            return  # already finished (a repeated job)
        tag = providers.tag_for(vp.id)
        p = None
        try:
            p = _provider(vp, vp.site, vault, world, state)
            if mode == "apply":
                vp.remote_ref = await p.apply(tag)
                vp.state, vp.activated_at = "active", utcnow()
                vp.report = {"outcome": "active", "message": f"The virtual patch is live on "
                             f"{PROVIDER_LABELS[vp.provider]}. Update PHP as soon as you can, then remove it.",
                             "finished_at": utcnow().isoformat()}
            else:
                result = await p.remove(tag, vp.remote_ref or {})
                vp.state, vp.removed_at = "removed", utcnow()
                vp.report = {"outcome": "removed", "message": "The virtual patch was removed.", **result,
                             "finished_at": utcnow().isoformat()}
            _audit(db, actor_id, vp, f"virtual_patch.{vp.state}", ref=vp.remote_ref)
            db.commit()
        except providers.ProviderError as exc:
            if exc.code in RETRYABLE:
                raise  # the job queue retries with backoff, then gives up and marks it failed
            vp.state = "failed"  # a refusal (wrong token or ids) will not fix itself
            vp.report = {"outcome": "failed", "error": exc.code, "message": exc.message,
                         "finished_at": utcnow().isoformat()}
            _audit(db, actor_id, vp, "virtual_patch.failed", error=exc.code)
            db.commit()
        finally:
            if p is not None:
                await p.aclose()


def billing_rows(db: Session, settings: Settings, start: datetime, end: datetime):
    """Virtual patches that were live at any time in the month: one monthly charge each."""
    q = select(VirtualPatch).where(VirtualPatch.activated_at.is_not(None), VirtualPatch.activated_at < end,
                                   or_(VirtualPatch.removed_at.is_(None), VirtualPatch.removed_at >= start))
    for vp in db.scalars(q.order_by(VirtualPatch.id)):
        yield (vp.site, settings.price_virtual_patch, f"virtual_patch:{vp.id}", max(vp.activated_at, start),
               PROVIDER_LABELS.get(vp.provider, vp.provider))
