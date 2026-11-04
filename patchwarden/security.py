"""Password hashing, JWT access tokens and signed share links."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import Settings

ALGORITHM = "HS256"
ACCESS_PURPOSE = "access"
SHARE_PURPOSE = "scan_share"


def hash_password(password: str) -> str:
    # bcrypt only reads the first 72 bytes; the API caps input length to match.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def _encode(settings: Settings, subject: str, purpose: str, ttl: timedelta,
            extra: dict | None = None) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires = now + ttl
    claims = {"sub": subject, "purpose": purpose, "exp": expires, "iatm": int(now.timestamp() * 1000)}
    claims.update(extra or {})
    return jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITHM), expires


def _decode(settings: Settings, token: str, purpose: str) -> dict | None:
    try:
        claims = jwt.decode(
            token, settings.jwt_secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]}
        )
    except jwt.PyJWTError:
        return None
    # A share link must never work as a login token, and the other way round.
    if claims.get("purpose") != purpose:
        return None
    return claims


def create_access_token(settings: Settings, user_id: int, token_version: int | None = 0) -> str:
    token, _ = _encode(settings, str(user_id), ACCESS_PURPOSE, timedelta(minutes=settings.access_token_minutes),
                       {"tv": token_version or 0})
    return token


def read_access_token(settings: Settings, token: str) -> tuple[int, int] | None:
    """(user id, token version), or None. The caller compares the version with the user's current one."""
    claims = _decode(settings, token, ACCESS_PURPOSE)
    sub = str(claims["sub"]) if claims else ""
    if not sub.isdigit():
        return None
    return int(sub), int(claims.get("tv", 0))


def create_share_token(settings: Settings, scan_id: int) -> tuple[str, datetime]:
    return _encode(settings, f"scan:{scan_id}", SHARE_PURPOSE, timedelta(hours=settings.share_link_hours))


def share_token_allows(settings: Settings, token: str, scan_id: int, revoked_at: datetime | None = None) -> bool:
    claims = _decode(settings, token, SHARE_PURPOSE)
    if claims is None or claims.get("sub") != f"scan:{scan_id}":
        return False
    if revoked_at is not None:
        # Links issued before the owner revoked sharing stop working.
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)
        if int(claims.get("iatm", 0)) <= int(revoked_at.timestamp() * 1000):
            return False
    return True
