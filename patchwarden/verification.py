"""Domain ownership verification: prove you control a site before you see its full report.

Three ways, any one is enough:
- DNS:    a TXT record  _patchwarden-challenge.<domain>  =  patchwarden-verification=<token>
- File:   https://<domain>/.well-known/patchwarden-verification.txt  containing the token
          (fetched with the SSRF-safe fetcher, like every scan)
- Plugin: the Patchwarden WordPress plugin reporting from that domain with this site's key

The token is per site and per owner, so verifying your copy of a site never verifies someone else's.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .fakes import DEMO_SUFFIX, DemoWorld
from .models import AuditLog, Site, User
from .scanner.fetch import FetchError, SafeFetcher

log = logging.getLogger(__name__)

TXT_PREFIX = "patchwarden-verification="
WELL_KNOWN = "/.well-known/patchwarden-verification.txt"

TxtResolver = Callable[[str], Awaitable[list[str]]]


def challenge_name(domain: str) -> str:
    return f"_patchwarden-challenge.{domain}"


async def dns_txt(name: str) -> list[str]:
    """TXT records for a name, from the system's DNS resolver. Empty on any failure."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.exception.DNSException, OSError):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def make_txt_resolver(world: DemoWorld | None) -> TxtResolver:
    """Demo domains (*.demo.patchwarden.test) answer from the fake world; everything else from real DNS."""
    async def resolve(name: str) -> list[str]:
        if world is not None and name.endswith(DEMO_SUFFIX):
            return list(world.txt_records.get(name, []))
        return await dns_txt(name)
    return resolve


def instructions(site: Site) -> dict:
    return {
        "site_id": site.id,
        "domain": site.domain,
        "verified": site.verified_at is not None,
        "verified_at": site.verified_at.isoformat() if site.verified_at else None,
        "method": site.verify_method,
        "token": site.verify_token,
        "dns": {"type": "TXT", "name": challenge_name(site.domain), "value": TXT_PREFIX + (site.verify_token or "")},
        "file": {"url": f"https://{site.domain}{WELL_KNOWN}", "contents": site.verify_token},
        "plugin": "Or connect the Patchwarden WordPress plugin with this site's key (WordPress sites).",
    }


def start(db: Session, site: Site, user: User) -> dict:
    if site.verify_token is None:
        site.verify_token = secrets.token_urlsafe(24)
        db.add(AuditLog(user_id=user.id, site_id=site.id, action="site.verification_started", detail={}))
        db.commit()
    return instructions(site)


def mark_verified(db: Session, site: Site, method: str, user_id: int | None) -> None:
    if site.verified_at is None:
        site.verified_at, site.verify_method = datetime.now(timezone.utc), method
        db.add(AuditLog(user_id=user_id, site_id=site.id, action="site.verified", detail={"method": method}))
        db.commit()


def _same(found: str, token: str) -> bool:
    return hmac.compare_digest(found.strip().encode(), token.encode())


async def check(db: Session, site: Site, user: User, *, resolve_txt: TxtResolver, fetcher: SafeFetcher) -> dict:
    """Look for the token by DNS, then by file. Returns what was found, in plain words."""
    if site.verified_at is not None:
        return {"verified": True, "method": site.verify_method, "message": "This site is already verified."}
    if site.verify_token is None:
        start(db, site, user)
    token = site.verify_token
    seen: list[str] = []

    records = await resolve_txt(challenge_name(site.domain))
    if any(r.startswith(TXT_PREFIX) and _same(r[len(TXT_PREFIX):], token) for r in records):
        mark_verified(db, site, "dns", user.id)
        return {"verified": True, "method": "dns", "message": "Verified by DNS. You can remove the TXT record now."}
    seen.append("a TXT record with this token was not found" if not records else
                "a TXT record was found, but not with this site's token")

    try:
        r = await fetcher.fetch(f"https://{site.domain}{WELL_KNOWN}")
        if r.status_code == 200 and _same(r.text[:200], token):
            mark_verified(db, site, "file", user.id)
            return {"verified": True, "method": "file", "message": "Verified by the file. You can delete it now."}
        seen.append(f"the verification file was not there (HTTP {r.status_code})" if r.status_code != 200 else
                    "the verification file did not contain this site's token")
    except FetchError as exc:
        seen.append(f"the verification file could not be fetched ({exc.message.rstrip('.').lower()})")

    return {"verified": False, "method": None,
            "message": "Not verified yet: " + "; ".join(seen) + ". DNS changes can take a few minutes to appear."}
