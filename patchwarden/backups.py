"""Encrypted backup storage with retention.

A backup holds a customer's files and database, so it is the most sensitive data Patchwarden keeps.
Each backup is encrypted at rest with its own random AES-256-GCM key (envelope encryption). That
data key is wrapped by the backup key ring (BACKUP_KEY, or keys derived from CREDENTIAL_KEY), and
the file header is authenticated with the content, so any change to the file fails to decrypt.
Backups expire after BACKUP_RETENTION_DAYS and are then deleted, with an audit entry.

File layout:  b"PWBK1\\n" + header JSON + b"\\n" + ciphertext (AES-GCM, header as associated data)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, split_keys
from .models import AuditLog, Backup, PatchJob, PatchState

log = logging.getLogger(__name__)

MAGIC = b"PWBK1\n"


class BackupError(Exception):
    """The backup could not be stored or read. `message` is safe to show the owner."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class StoredBackup:
    location: str
    checksum: str  # SHA-256 of the archive (before encryption)
    size: int
    host_checksum_ok: bool  # the archive matches the checksum the host reported


def derive_backup_key(credential_key: str) -> str:
    """A separate backup key derived from a credential key, used when BACKUP_KEY is not set."""
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"patchwarden backup key-encryption key").derive(credential_key.encode())
    return base64.urlsafe_b64encode(raw).decode()


def backup_keyring(settings: Settings) -> MultiFernet:
    keys = split_keys(settings.backup_key) or [derive_backup_key(k) for k in split_keys(settings.credential_key)]
    return MultiFernet([Fernet(k.encode()) for k in keys])


class BackupStore:
    def __init__(self, settings: Settings):
        self.root = Path(settings.backup_dir)
        self.retention = timedelta(days=settings.backup_retention_days)
        self._kek = backup_keyring(settings)

    def put(self, domain: str, archive: bytes, host_checksum: str) -> StoredBackup:
        checksum = hashlib.sha256(archive).hexdigest()
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        header = json.dumps({
            "v": 1, "alg": "AES-256-GCM", "domain": domain, "sha256": checksum,
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_key": self._kek.encrypt(data_key).decode(),
            "created": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True).encode()
        ciphertext = AESGCM(data_key).encrypt(nonce, archive, header)

        folder = self.root / _safe_name(domain)
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = folder / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}.pwbak"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(MAGIC + header + b"\n" + ciphertext)
        return StoredBackup(location=str(path), checksum=checksum, size=len(archive),
                            host_checksum_ok=secrets.compare_digest(checksum, host_checksum or ""))

    def read(self, location: str, checksum: str) -> bytes:
        """Decrypt a backup and prove it is the one we stored."""
        try:
            blob = Path(location).read_bytes()
        except OSError:
            raise BackupError("The backup file is missing.") from None
        if not blob.startswith(MAGIC):
            raise BackupError("The backup file is not a Patchwarden backup.")
        try:
            header, ciphertext = blob[len(MAGIC):].split(b"\n", 1)
            meta = json.loads(header)
            data_key = self._kek.decrypt(meta["wrapped_key"].encode())
            archive = AESGCM(data_key).decrypt(base64.b64decode(meta["nonce"]), ciphertext, header)
        except (ValueError, KeyError, InvalidToken, InvalidTag):
            raise BackupError("The backup could not be decrypted: it was changed, or the backup key is wrong.") from None
        if not secrets.compare_digest(hashlib.sha256(archive).hexdigest(), checksum):
            raise BackupError("The backup checksum does not match.")
        return archive

    def delete(self, location: str) -> None:
        try:
            Path(location).unlink()
        except FileNotFoundError:
            pass

    def expiry(self, created: datetime) -> datetime:
        return created + self.retention


def _safe_name(domain: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in domain)[:200] or "site"


def purge_expired(db: Session, store: BackupStore, now: datetime | None = None) -> int:
    """Delete backups past their retention date. A backup that a running change still needs is kept."""
    now = now or datetime.now(timezone.utc)
    in_use = set(db.scalars(select(PatchJob.backup_id).where(PatchJob.state == PatchState.running,
                                                             PatchJob.backup_id.is_not(None))))
    purged = 0
    for b in db.scalars(select(Backup).where(Backup.deleted_at.is_(None), Backup.expires_at.is_not(None),
                                            Backup.expires_at < now)):
        if b.id in in_use:
            continue
        store.delete(b.location)
        b.deleted_at = now
        db.add(AuditLog(user_id=None, site_id=b.site_id, action="backup.purged",
                        detail={"backup_id": b.id, "reason": "retention period ended"}))
        purged += 1
    db.commit()
    if purged:
        log.info("Purged %s expired backup(s)", purged)
    return purged
