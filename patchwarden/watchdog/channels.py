"""Alert channels besides email: Slack, Microsoft Teams, and signed generic webhooks.

- A webhook URL is a credential (anyone holding it can post into the workspace), so it is stored
  Fernet-encrypted and only its host is ever shown back.
- Every delivery goes through the SSRF-safe fetcher: https only, public addresses only, no redirects.
- Generic webhooks are signed: header X-Patchwarden-Signature = "sha256=" + HMAC-SHA256(secret,
  "<timestamp>.<body>"), with X-Patchwarden-Timestamp, so the receiver can reject forgeries and replays.
  The signing secret is shown once, when the channel is created.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import CredentialVault
from ..errors import AppError
from ..models import AuditLog, NotificationChannel, User
from ..scanner.fetch import FetchError, SafeFetcher

log = logging.getLogger(__name__)

KINDS = ("slack", "teams", "webhook")


def _host_ok(kind: str, host: str) -> bool:
    if kind == "slack":
        return host == "hooks.slack.com"
    if kind == "teams":  # Teams incoming webhooks and Power Automate workflow webhooks
        return host.endswith(".webhook.office.com") or host.endswith(".logic.azure.com")
    return True


def add_channel(db: Session, vault: CredentialVault, user: User, kind: str, url: str) -> tuple[NotificationChannel, str | None]:
    if kind not in KINDS:
        raise AppError(422, "invalid_kind", "Pick slack, teams or webhook.")
    parts = urlsplit((url or "").strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password:
        raise AppError(422, "invalid_url", "Use the https:// address your workspace gave you.")
    if not _host_ok(kind, host):
        raise AppError(422, "invalid_url", f"That does not look like a {kind} webhook address.")
    secret = secrets.token_urlsafe(32) if kind == "webhook" else None
    channel = NotificationChannel(owner_id=user.id, kind=kind, url_encrypted=vault.encrypt(url.strip()),
                                  url_hint=host[:128], secret_encrypted=vault.encrypt(secret) if secret else None)
    db.add(channel)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="channel.added", detail={"channel_id": channel.id, "kind": kind,
                                                                     "host": channel.url_hint}))
    db.commit()
    return channel, secret


def channel_json(c: NotificationChannel) -> dict:
    return {"id": c.id, "kind": c.kind, "host": c.url_hint, "enabled": c.enabled, "created_at": c.created_at.isoformat()}


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def _payload(kind: str, text: str, event: dict) -> dict:
    if kind in ("slack", "teams"):
        return {"text": text}
    return {"event": event.get("type", "alert"), "data": event, "text": text}


async def deliver(db: Session, vault: CredentialVault, fetcher: SafeFetcher, owner_id: int, text: str,
                  event: dict, *, only: int | None = None) -> dict[str, str]:
    """Send to every enabled channel of the owner. Returns channel id -> "ok" or a short failure reason."""
    results: dict[str, str] = {}
    q = select(NotificationChannel).where(NotificationChannel.owner_id == owner_id,
                                          NotificationChannel.enabled.is_(True))
    if only is not None:
        q = q.where(NotificationChannel.id == only)
    for c in db.scalars(q):
        body = json.dumps(_payload(c.kind, text, event), separators=(",", ":"), sort_keys=True).encode()
        headers = {"Content-Type": "application/json"}
        if c.kind == "webhook" and c.secret_encrypted:
            ts = str(int(time.time()))
            headers.update({"X-Patchwarden-Timestamp": ts,
                            "X-Patchwarden-Signature": sign(vault.decrypt(c.secret_encrypted), ts, body)})
        try:
            status = await fetcher.post_json(vault.decrypt(c.url_encrypted), body, headers)
            results[str(c.id)] = "ok" if 200 <= status < 300 else f"HTTP {status}"
        except FetchError as exc:
            results[str(c.id)] = exc.code
        if results[str(c.id)] != "ok":
            log.warning("Alert channel %s (%s) delivery failed: %s", c.id, c.kind, results[str(c.id)])
    return results
