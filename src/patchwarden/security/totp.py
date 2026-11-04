"""Time-based one-time passwords (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits) and recovery codes.

Works with any authenticator app (Google Authenticator, 1Password, Authy, ...).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def code_at(secret: str, when: float | None = None) -> str:
    return _code(secret, int((time.time() if when is None else when) // STEP))


def verify(secret: str, code: str, *, last_step: int | None = None, when: float | None = None,
           window: int = 1) -> int | None:
    """The time step the code belongs to, or None. A step at or before `last_step` is refused (no replay)."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    now_step = int((time.time() if when is None else when) // STEP)
    for step in range(now_step - window, now_step + window + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, email: str, issuer: str = "Patchwarden") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def new_recovery_codes(n: int = 10) -> list[str]:
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return f"{raw[:5]}-{raw[5:]}"
    return [one() for _ in range(n)]


def hash_recovery(code: str) -> str:
    # Recovery codes are random (about 49 bits each), so a plain SHA-256 is enough to store them safely.
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()
