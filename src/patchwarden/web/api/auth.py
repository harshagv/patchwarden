"""Accounts: register, login (with optional TOTP second factor), log out everywhere."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings
from ...errors import AppError
from ...models import AuditLog, Role, User
from ...security import totp
from ...security.auth import create_access_token, hash_password, verify_password
from ...security.ratelimit import client_ip, too_many
from ..deps import CurrentUser, DbDep, SettingsDep

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = logging.getLogger(__name__)

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,63}$")
# Compared against when the email is unknown, so both paths take bcrypt time.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


class Credentials(BaseModel):
    email: str = Field(max_length=320)
    # bcrypt reads at most 72 bytes; refuse longer instead of silently truncating.
    password: str = Field(min_length=12, max_length=72)


class LoginBody(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(min_length=1, max_length=72)


class UserOut(BaseModel):
    id: int
    email: str
    role: Role


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def _clean_email(raw: str) -> str:
    email = raw.strip().lower()
    if not _EMAIL.match(email):
        raise AppError(422, "invalid_email", "Please enter a valid email address.")
    return email


def create_account(db: Session, email_raw: str, password: str) -> User:
    """Shared by the API and the dashboard sign-up page."""
    email = _clean_email(email_raw)
    if len(password) < 12:
        raise AppError(422, "password_too_short", "Please use a password of at least 12 characters.")
    if len(password.encode()) > 72:
        raise AppError(422, "password_too_long", "Please use a password of at most 72 bytes.")
    user = User(email=email, password_hash=hash_password(password), role=Role.owner)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "email_taken", "An account with this email already exists. Try logging in.") from None
    db.add(AuditLog(user_id=user.id, action="user.registered", detail={}))
    db.commit()
    log.info("user registered id=%s", user.id)
    return user


@router.post("/register", status_code=201, response_model=UserOut)
def register(body: Credentials, request: Request, db: DbDep, settings: SettingsDep) -> UserOut:
    signup_allowed(request, settings)
    user = create_account(db, body.email, body.password)
    return UserOut(id=user.id, email=user.email, role=user.role)


def signup_allowed(request: Request, settings: Settings) -> None:
    window, key = request.app.state.limits.signup, f"ip:{client_ip(request, settings)}"
    wait = window.retry_after(key)
    if wait:
        raise too_many(f"Too many new accounts from your connection. Please wait {max(1, wait // 60)} minute(s).", wait)
    window.hit(key)


def authenticate(request: Request, db: Session, settings: Settings, email: str, password: str,
                 code: str | None) -> User:
    """The one login check, for the API and the dashboard: rate limit, password, then second factor."""
    limits = request.app.state.limits
    email = (email or "").strip().lower()[:320]
    keys = [f"ip:{client_ip(request, settings)}", f"email:{email}"]
    wait = max(limits.login.retry_after(k) for k in keys)
    if wait:
        raise too_many(f"Too many failed attempts. Please wait {max(1, wait // 60)} minute(s) and try again.", wait)

    def fail(code_: str, message: str) -> AppError:
        for k in keys:
            limits.login.hit(k)
        return AppError(401, code_, message)

    user = db.scalar(select(User).where(User.email == email)) if email else None
    ok = verify_password(password or "", user.password_hash if user else _DUMMY_HASH)
    if user is None or not ok:
        raise fail("invalid_login", "That email and password do not match.")
    if user.mfa_enabled:
        if not code:
            raise AppError(401, "mfa_required", "Enter the 6-digit code from your authenticator app.")
        if not _check_second_factor(db, request, user, code):
            raise fail("invalid_code", "That code is not right. Use a new code, or one of your recovery codes.")
    return user


def _check_second_factor(db: Session, request: Request, user: User, code: str) -> bool:
    secret = request.app.state.vault.decrypt(user.mfa_secret)
    step = totp.verify(secret, code, last_step=user.mfa_last_step)
    if step is not None:
        user.mfa_last_step = step  # this code (and older ones) can't be used again
        db.commit()
        return True
    hashed = totp.hash_recovery(code)
    remaining = list(user.mfa_recovery or [])
    if hashed in remaining:
        remaining.remove(hashed)  # single use
        user.mfa_recovery = remaining
        db.add(AuditLog(user_id=user.id, action="mfa.recovery_code_used", detail={"remaining": len(remaining)}))
        db.commit()
        return True
    return False


class LoginWithCode(LoginBody):
    code: str | None = Field(default=None, max_length=20, description="6-digit code, if two-step login is on")


@router.post("/login", response_model=TokenOut)
def login(body: LoginWithCode, request: Request, db: DbDep, settings: SettingsDep) -> TokenOut:
    user = authenticate(request, db, settings, body.email, body.password, body.code)
    log.info("user logged in id=%s", user.id)
    return TokenOut(
        access_token=create_access_token(settings, user.id, user.token_version),
        expires_in=settings.access_token_minutes * 60,
    )


@router.post("/logout-all")
def logout_everywhere(db: DbDep, user: CurrentUser) -> dict:
    """Every token issued so far stops working (all devices, all browsers)."""
    user.token_version = (user.token_version or 0) + 1
    db.add(AuditLog(user_id=user.id, action="user.logged_out_everywhere", detail={}))
    db.commit()
    return {"logged_out": True}


# --- two-step login (TOTP) --------------------------------------------------------

NO_STORE = {"Cache-Control": "no-store"}


class CodeBody(BaseModel):
    code: str = Field(min_length=6, max_length=20)


@router.post("/mfa/setup", status_code=201)
def mfa_setup(request: Request, db: DbDep, user: CurrentUser) -> JSONResponse:
    """Start two-step login. The secret is shown once: add it to an authenticator app, then call /mfa/enable."""
    if user.mfa_enabled:
        raise AppError(409, "mfa_already_on", "Two-step login is already on.")
    secret = totp.new_secret()
    user.mfa_secret = request.app.state.vault.encrypt(secret)
    user.mfa_last_step = None
    db.commit()
    return JSONResponse({"secret": secret, "otpauth_uri": totp.otpauth_uri(secret, user.email),
                         "note": "Add this to your authenticator app, then confirm with a code."},
                        status_code=201, headers=NO_STORE)


@router.post("/mfa/enable")
def mfa_enable(body: CodeBody, request: Request, db: DbDep, user: CurrentUser) -> JSONResponse:
    if user.mfa_enabled:
        raise AppError(409, "mfa_already_on", "Two-step login is already on.")
    if user.mfa_secret is None:
        raise AppError(409, "mfa_not_set_up", "Start with /api/auth/mfa/setup.")
    step = totp.verify(request.app.state.vault.decrypt(user.mfa_secret), body.code)
    if step is None:
        raise AppError(422, "invalid_code", "That code is not right. Check the time on your phone and try again.")
    codes = totp.new_recovery_codes()
    user.mfa_enabled, user.mfa_last_step = True, step
    user.mfa_recovery = [totp.hash_recovery(c) for c in codes]
    db.add(AuditLog(user_id=user.id, action="mfa.enabled", detail={}))
    db.commit()
    return JSONResponse({"enabled": True, "recovery_codes": codes,
                         "note": "Keep these somewhere safe. Each works once if you lose your phone."},
                        headers=NO_STORE)


@router.post("/mfa/disable")
def mfa_disable(body: CodeBody, request: Request, db: DbDep, user: CurrentUser) -> dict:
    if not user.mfa_enabled:
        raise AppError(409, "mfa_off", "Two-step login is not on.")
    if not _check_second_factor(db, request, user, body.code):
        raise AppError(401, "invalid_code", "That code is not right.")
    user.mfa_enabled, user.mfa_secret, user.mfa_recovery, user.mfa_last_step = False, None, None, None
    db.add(AuditLog(user_id=user.id, action="mfa.disabled", detail={}))
    db.commit()
    return {"enabled": False}
