"""FastAPI dependencies: settings, DB session, current user."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import Settings
from .errors import AppError
from .models import User
from .security import read_access_token

bearer = HTTPBearer(auto_error=False, description="Paste the access_token from POST /api/auth/login")


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    session = request.app.state.sessionmaker()
    try:
        yield session
    finally:
        session.close()


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[Session, Depends(get_db)]


def optional_user(
    settings: SettingsDep,
    db: DbDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> User | None:
    if creds is None:
        return None
    claims = read_access_token(settings, creds.credentials)
    user = db.get(User, claims[0]) if claims is not None else None
    if user is not None and claims[1] != (user.token_version or 0):
        user = None  # issued before "log out everywhere"
    if user is None:
        raise AppError(401, "invalid_token", "Your login has expired or is not valid. Please log in again.")
    return user


def require_user(user: Annotated[User | None, Depends(optional_user)]) -> User:
    if user is None:
        raise AppError(401, "unauthorized", "Please log in first.")
    return user


OptionalUser = Annotated[User | None, Depends(optional_user)]
CurrentUser = Annotated[User, Depends(require_user)]
