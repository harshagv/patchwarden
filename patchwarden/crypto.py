"""Fernet encryption for stored credentials. The key comes from CREDENTIAL_KEY in .env."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from .config import Settings


class CredentialVault:
    def __init__(self, settings: Settings):
        self._fernet = Fernet(settings.credential_key.encode())

    def encrypt(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode())

    def decrypt(self, token: bytes) -> str:
        try:
            return self._fernet.decrypt(token).decode()
        except InvalidToken:
            # Wrong or rotated CREDENTIAL_KEY. Say so without echoing anything.
            raise ValueError("stored credential cannot be decrypted with the current CREDENTIAL_KEY") from None
