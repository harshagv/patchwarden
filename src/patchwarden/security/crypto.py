"""Fernet encryption for stored credentials, with a key ring for rotation.

CREDENTIAL_KEY may hold several comma-separated keys. The first one encrypts; every key in the
ring can decrypt. To rotate: put the new key first, run `python -m patchwarden rotate-credentials`
(everything is re-encrypted with the new key), then drop the old key.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ..config import Settings, split_keys


def keyring(raw: str) -> MultiFernet:
    return MultiFernet([Fernet(k.encode()) for k in split_keys(raw)])


class CredentialVault:
    def __init__(self, settings: Settings):
        self._fernet = keyring(settings.credential_key)

    def encrypt(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode())

    def decrypt(self, token: bytes) -> str:
        try:
            return self._fernet.decrypt(token).decode()
        except InvalidToken:
            # Wrong or rotated CREDENTIAL_KEY. Say so without echoing anything.
            raise ValueError("stored credential cannot be decrypted with the current CREDENTIAL_KEY") from None

    def rotate(self, token: bytes) -> bytes:
        """Re-encrypt with the newest key (the first in the ring)."""
        return self._fernet.rotate(token)
