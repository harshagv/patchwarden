"""POST /api/auth/register and POST /api/auth/login."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..deps import DbDep, SettingsDep
from ..errors import AppError
from ..models import AuditLog, Role, User
from ..security import create_access_token, hash_password, verify_password

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


@router.post("/register", status_code=201, response_model=UserOut)
def register(body: Credentials, db: DbDep) -> UserOut:
    email = _clean_email(body.email)
    if len(body.password.encode()) > 72:
        raise AppError(422, "password_too_long", "Please use a password of at most 72 bytes.")
    user = User(email=email, password_hash=hash_password(body.password), role=Role.owner)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "email_taken", "An account with this email already exists. Try logging in.") from None
    db.add(AuditLog(user_id=user.id, action="user.registered", detail={}))
    db.commit()
    log.info("user registered id=%s", user.id)
    return UserOut(id=user.id, email=user.email, role=user.role)


@router.post("/login", response_model=TokenOut)
def login(body: LoginBody, db: DbDep, settings: SettingsDep) -> TokenOut:
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not ok:
        raise AppError(401, "invalid_login", "That email and password do not match.")
    log.info("user logged in id=%s", user.id)
    return TokenOut(
        access_token=create_access_token(settings, user.id),
        expires_in=settings.access_token_minutes * 60,
    )
