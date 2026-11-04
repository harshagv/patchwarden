"""Signed attestations: "this site ran a patched PHP when we checked it", that anyone can verify.

An owner can put the badge on their site, or send the link to a customer, insurer or auditor. The
statement is signed with Ed25519. Anyone can check it, either through the public verify endpoint or
offline with the public key at /.well-known/patchwarden-attestation-keys.json (JWK, OKP/Ed25519).

Signed bytes: the payload as canonical JSON (sorted keys, no spaces, UTF-8).
Signature: base64url, no padding.

The key comes from ATTESTATION_KEY (base64url, the 32-byte private seed). Without it, the key is
derived from the first CREDENTIAL_KEY, so a dev install works out of the box. Rotating CREDENTIAL_KEY
then changes the attestation key, and older attestations stop verifying: set ATTESTATION_KEY in
production.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from html import escape

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import ConfigError, Settings, split_keys
from ..errors import AppError
from ..models import Attestation, AuditLog, Risk, Scan, Site, User


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Signer:
    def __init__(self, settings: Settings):
        if settings.attestation_key:
            try:
                seed = _unb64(settings.attestation_key.strip())
                assert len(seed) == 32
            except (ValueError, AssertionError):
                raise ConfigError("ATTESTATION_KEY must be 32 bytes, base64url-encoded.") from None
        else:
            seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"patchwarden attestation signing key"
                        ).derive(split_keys(settings.credential_key)[0].encode())
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(self.public_raw).hexdigest()[:16]

    def sign(self, payload: dict) -> str:
        return _b64(self._key.sign(canonical(payload)))

    def verify(self, payload: dict, signature: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.public_raw).verify(_unb64(signature), canonical(payload))
            return True
        except (InvalidSignature, ValueError):
            return False

    def jwks(self) -> dict:
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64(self.public_raw), "kid": self.key_id,
                          "use": "sig", "alg": "EdDSA"}]}


def latest_scan(db: Session, site: Site) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.site_id == site.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1))


def issue(db: Session, settings: Settings, signer: Signer, site: Site, user: User,
          now: datetime | None = None) -> Attestation:
    now = now or datetime.now(timezone.utc)
    if site.verified_at is None:
        raise AppError(403, "verification_required", "Verify that you own this site first, so the statement is about your site.")
    scan = latest_scan(db, site)
    if scan is None or scan.risk != Risk.safe or not scan.detected_version:
        raise AppError(409, "not_attestable",
                       "We can only sign a statement for a site whose latest check found a patched PHP version. "
                       "Run a new check after updating.")
    if now - scan.created_at > timedelta(days=2):
        raise AppError(409, "check_too_old", "The latest check is more than two days old. Run a new check first.")
    expires = now + timedelta(days=settings.attestation_days)
    att_id = secrets.token_hex(16)
    payload = {
        "v": 1, "id": att_id, "issuer": settings.public_base_url, "site": site.domain,
        "claim": "php_patched", "php_version": scan.detected_version, "risk": scan.risk.value,
        "checked_at": scan.created_at.isoformat(), "issued_at": now.isoformat(), "expires_at": expires.isoformat(),
        "ownership_verified_by": site.verify_method,
    }
    att = Attestation(id=att_id, site_id=site.id, payload=payload, signature=signer.sign(payload),
                      key_id=signer.key_id, issued_at=now, expires_at=expires)
    db.add(att)
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="attestation.issued",
                    detail={"attestation_id": att_id, "php_version": scan.detected_version}))
    db.commit()
    return att


def status(att: Attestation, signer: Signer, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if not signer.verify(att.payload, att.signature):
        return "invalid"
    if att.revoked_at is not None:
        return "revoked"
    if now >= att.expires_at:
        return "expired"
    return "valid"


def public_json(att: Attestation, signer: Signer) -> dict:
    s = status(att, signer)
    return {"status": s, "valid": s == "valid", "payload": att.payload, "signature": att.signature,
            "key_id": att.key_id, "algorithm": "Ed25519",
            "revoked_at": att.revoked_at.isoformat() if att.revoked_at else None}


def badge_svg(att: Attestation | None, signer: Signer) -> str:
    s = status(att, signer) if att else "unknown"
    label, color = {"valid": (f"PHP {att.payload['php_version']} patched" if att else "", "#2da44e"),
                    "expired": ("expired", "#9a6700"), "revoked": ("revoked", "#cf222e"),
                    "invalid": ("invalid", "#cf222e")}.get(s, ("unknown", "#6e7781"))
    left, right = "Patchwarden", escape(label)
    lw, rw = 86, max(60, 7 * len(label) + 12)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" '
            f'aria-label="{left}: {right}"><title>{left}: {right}</title>'
            f'<rect width="{lw}" height="20" fill="#24292f"/><rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="8" y="14">{left}</text><text x="{lw + 6}" y="14">{right}</text></g></svg>')
