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


def _encode(settings: Settings, subject: str, purpose: str, ttl: timedelta) -> tuple[str, datetime]:
    expires = datetime.now(timezone.utc) + ttl
    token = jwt.encode(
        {"sub": subject, "purpose": purpose, "exp": expires},
        settings.jwt_secret,
        algorithm=ALGORITHM,
    )
    return token, expires


def _decode(settings: Settings, token: str, purpose: str) -> str | None:
    try:
        claims = jwt.decode(
            token, settings.jwt_secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]}
        )
    except jwt.PyJWTError:
        return None
    # A share link must never work as a login token, and the other way round.
    if claims.get("purpose") != purpose:
        return None
    return str(claims["sub"])


def create_access_token(settings: Settings, user_id: int) -> str:
    token, _ = _encode(settings, str(user_id), ACCESS_PURPOSE, timedelta(minutes=settings.access_token_minutes))
    return token


def read_access_token(settings: Settings, token: str) -> int | None:
    sub = _decode(settings, token, ACCESS_PURPOSE)
    return int(sub) if sub and sub.isdigit() else None


def create_share_token(settings: Settings, scan_id: int) -> tuple[str, datetime]:
    return _encode(settings, f"scan:{scan_id}", SHARE_PURPOSE, timedelta(hours=settings.share_link_hours))


def share_token_allows(settings: Settings, token: str, scan_id: int) -> bool:
    return _decode(settings, token, SHARE_PURPOSE) == f"scan:{scan_id}"
