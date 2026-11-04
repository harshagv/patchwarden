"""Things customers pay for or show off: signed attestations and badges, migration quotes, the SBOM."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ...commerce import attest, sbom
from ...errors import AppError
from ...migration import quote as quotes
from ...models import Attestation, AuditLog
from ...security import access
from ..deps import CurrentUser, DbDep
from .migrations import visible_migration

router = APIRouter(tags=["attestations and quotes"])


# --- attestations ---------------------------------------------------------------------

@router.post("/api/sites/{site_id}/attestations", status_code=201)
def issue_attestation(site_id: int, request: Request, db: DbDep, user: CurrentUser) -> dict:
    site = access.site_for(db, site_id, user, "edit")
    state = request.app.state
    att = attest.issue(db, state.settings, state.signer, site, user)
    out = attest.public_json(att, state.signer)
    base = state.settings.public_base_url
    out["links"] = {"verify": f"{base}/api/attestations/{att.id}", "badge": f"{base}/api/attestations/{att.id}/badge.svg",
                    "public_key": f"{base}/.well-known/patchwarden-attestation-keys.json"}
    return out


@router.get("/api/attestations/{att_id}")
def verify_attestation(att_id: str, request: Request, db: DbDep) -> dict:
    """Public: anyone holding the link can check the statement and its signature."""
    att = db.get(Attestation, att_id[:32])
    if att is None:
        raise AppError(404, "attestation_not_found", "We could not find that statement.")
    return attest.public_json(att, request.app.state.signer)


@router.get("/api/attestations/{att_id}/badge.svg")
def attestation_badge(att_id: str, request: Request, db: DbDep) -> Response:
    att = db.get(Attestation, att_id[:32])
    return Response(attest.badge_svg(att, request.app.state.signer), media_type="image/svg+xml",
                    headers={"Cache-Control": "max-age=300", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})


@router.post("/api/attestations/{att_id}/revoke")
def revoke_attestation(att_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict:
    att = db.get(Attestation, att_id[:32])
    if att is None:
        raise AppError(404, "attestation_not_found", "We could not find that statement.")
    access.site_for(db, att.site_id, user, "edit")
    if att.revoked_at is None:
        att.revoked_at = datetime.now(timezone.utc)
        db.add(AuditLog(user_id=user.id, site_id=att.site_id, action="attestation.revoked",
                        detail={"attestation_id": att.id}))
        db.commit()
    return attest.public_json(att, request.app.state.signer)


@router.get("/.well-known/patchwarden-attestation-keys.json", include_in_schema=False)
def attestation_keys(request: Request) -> dict:
    return request.app.state.signer.jwks()


# --- migration quotes ------------------------------------------------------------------

@router.get("/api/migrations/{mig_id}/quote")
def get_quote(mig_id: int, request: Request, db: DbDep, user: CurrentUser) -> dict:
    """The fixed-price quote. Made once, from the breakage scan, then kept as it was offered."""
    mig = visible_migration(db, mig_id, user)
    if mig.quote is None:
        mig.quote = quotes.build(db, request.app.state.settings, mig)
        db.add(AuditLog(user_id=user.id, site_id=mig.site_id, action="migration.quoted",
                        detail={"migration_id": mig.id, "hours": mig.quote["hours"], "total": mig.quote["total"]}))
        db.commit()
    return {**mig.quote, "accepted_at": mig.quote_accepted_at.isoformat() if mig.quote_accepted_at else None}


@router.post("/api/migrations/{mig_id}/quote/accept")
def accept_quote(mig_id: int, db: DbDep, user: CurrentUser) -> dict:
    mig = visible_migration(db, mig_id, user)
    access.require(db, user, mig.site, "approve")
    if mig.quote is None:
        raise AppError(409, "no_quote", "Open the quote first, so you accept the price you saw.")
    if mig.quote_accepted_at is not None:
        raise AppError(409, "already_accepted", "This quote was already accepted.")
    now = datetime.now(timezone.utc)
    if now > datetime.fromisoformat(mig.quote["valid_until"]):
        raise AppError(409, "quote_expired", "This quote has expired. Ask for a new one.")
    mig.quote_accepted_at, mig.quote_accepted_by = now, user.id
    db.add(AuditLog(user_id=user.id, site_id=mig.site_id, action="migration.quote_accepted",
                    detail={"migration_id": mig.id, "total": mig.quote["total"], "currency": mig.quote["currency"]}))
    db.commit()
    return {**mig.quote, "accepted_at": now.isoformat()}


# --- software inventory (SBOM) ----------------------------------------------------------

@router.get("/api/sites/{site_id}/sbom")
async def site_sbom(site_id: int, request: Request, db: DbDep, user: CurrentUser) -> Response:
    """CycloneDX 1.5 inventory: PHP, WordPress core/plugins/themes, Composer packages, known flaws.
    For verified sites only: the inventory tells an attacker exactly what to aim at."""
    from ...patch.adapters import AdapterError
    from ...patch.service import build_adapter

    site = access.site_for(db, site_id, user, "view")
    if site.verified_at is None:
        raise AppError(403, "verification_required", "Verify that you own this site to download its inventory.")
    lock = None
    if site.credentials:  # read-only: we only read composer.lock
        try:
            files = await build_adapter(site, request.app.state.vault, request.app.state.demo_world).read_code()
            lock = files.get("composer.lock")
        except (AppError, AdapterError):
            lock = None
    doc = sbom.build(db, site, composer_lock=lock)
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.sbom_exported",
                    detail={"components": len(doc["components"]), "vulnerabilities": len(doc["vulnerabilities"])}))
    db.commit()
    return JSONResponse(doc, media_type="application/vnd.cyclonedx+json",
                        headers={"Content-Disposition": f'attachment; filename="{site.domain}.cdx.json"'})
