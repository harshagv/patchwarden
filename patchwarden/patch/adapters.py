"""How the Patch agent talks to a site: one interface, one adapter per access method.

Every adapter authenticates with an owner-created API token or key, never a
password. Adapter errors carry a `message` that is safe to show the owner and
never includes the token.

Real adapters (cPanel/WHM, Plesk, the Patchwarden server agent) are interface
stubs in this build: they refuse to run rather than pretend. The fake adapter
in patchwarden/fakes.py implements the same interface for tests and `make dev`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..models import AccessMethod, CredentialKind


class AdapterError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(code)
        self.code = code
        self.message = message


class AdapterUnavailable(AdapterError):
    pass


@dataclass(frozen=True)
class BackupArtifact:
    location: str
    checksum: str  # sha256 hex of the backup archive


@dataclass(frozen=True)
class RestoreCheck:
    ok: bool
    detail: str


class HostingAdapter(ABC):
    """What every access method must provide. All calls are async and may raise AdapterError."""

    display_name: str

    @abstractmethod
    async def php_version(self) -> str:
        """The PHP version the site is running now (read-only)."""

    @abstractmethod
    async def available_versions(self) -> list[str]:
        """PHP versions the host can switch this site to (read-only)."""

    @abstractmethod
    async def create_backup(self, dest_dir: Path) -> BackupArtifact:
        """Full backup: files + database."""

    @abstractmethod
    async def verify_restore(self, backup: BackupArtifact) -> RestoreCheck:
        """Restore dry-run: prove the backup can be restored, without restoring it."""

    @abstractmethod
    async def set_php_version(self, version: str) -> None:
        """Switch the site's PHP version. Takes effect after restart_php()."""

    @abstractmethod
    async def restart_php(self) -> None:
        """Restart PHP workers (FPM pool / panel restart action)."""

    @abstractmethod
    async def restore_backup(self, backup: BackupArtifact) -> None:
        """Put files + database back from the backup."""

    # Migration agent (Phase 4)

    @abstractmethod
    async def read_code(self) -> dict[str, str]:
        """The site's code files, path -> text (read-only)."""

    @abstractmethod
    async def create_staging(self) -> tuple[str, HostingAdapter]:
        """Copy the site (files, database, PHP version) to a staging site. Returns its domain and an adapter for it."""

    @abstractmethod
    async def open_staging(self) -> tuple[str, HostingAdapter] | None:
        """The staging site made earlier by create_staging(), if it still exists."""

    @abstractmethod
    async def write_files(self, files: dict[str, str]) -> None:
        """Write code files (on staging, or on production during a promotion)."""


# Which stored credential each access method uses.
CREDENTIAL_FOR_METHOD: dict[AccessMethod, CredentialKind] = {
    AccessMethod.cpanel: CredentialKind.cpanel_token,
    AccessMethod.plesk: CredentialKind.plesk_token,
    AccessMethod.plugin: CredentialKind.api_key,
}
METHOD_FOR_CREDENTIAL = {kind: method for method, kind in CREDENTIAL_FOR_METHOD.items()}


class _NotConnectedAdapter(HostingAdapter):
    """Base for the real adapters until they are built and tested against a real panel."""

    def __init__(self, domain: str, token: str):
        self.domain = domain
        self._token = token  # used for the Authorization header once built; never logged

    def __repr__(self) -> str:
        return f"<{type(self).__name__} domain={self.domain}>"

    def _refuse(self):
        raise AdapterUnavailable(
            "adapter_not_connected",
            f"The {self.display_name} connection is not available in this build yet, so nothing was changed.",
        )

    async def php_version(self) -> str:
        self._refuse()

    async def available_versions(self) -> list[str]:
        self._refuse()

    async def create_backup(self, dest_dir: Path) -> BackupArtifact:
        self._refuse()

    async def verify_restore(self, backup: BackupArtifact) -> RestoreCheck:
        self._refuse()

    async def set_php_version(self, version: str) -> None:
        self._refuse()

    async def restart_php(self) -> None:
        self._refuse()

    async def restore_backup(self, backup: BackupArtifact) -> None:
        self._refuse()

    async def read_code(self) -> dict[str, str]:
        self._refuse()

    async def create_staging(self) -> tuple[str, HostingAdapter]:
        self._refuse()

    async def open_staging(self) -> tuple[str, HostingAdapter] | None:
        self._refuse()

    async def write_files(self, files: dict[str, str]) -> None:
        self._refuse()


class CpanelAdapter(_NotConnectedAdapter):
    """cPanel/WHM via its API with an owner-created API token (Authorization: cpanel <user>:<token>).

    To build: read the site's PHP version and switch it through cPanel's
    MultiPHP API, run a full backup through the Backup API, and restart
    PHP-FPM. Confirm each endpoint against the panel's API docs and test on
    a staging account before enabling.
    """

    display_name = "cPanel"


class PleskAdapter(_NotConnectedAdapter):
    """Plesk via its REST API with an owner-created API key (X-API-Key header).

    To build: read and change the domain's PHP handler, run a backup through
    the backup manager, and restart the PHP-FPM service. Confirm against the
    Plesk API docs and a staging subscription first.
    """

    display_name = "Plesk"


class AgentAdapter(_NotConnectedAdapter):
    """The Patchwarden server agent / WordPress plugin, with the dashboard-issued API key.

    The agent side ships in a later phase (WordPress plugin in Phase 5).
    """

    display_name = "Patchwarden agent"


REAL_ADAPTERS: dict[AccessMethod, type[_NotConnectedAdapter]] = {
    AccessMethod.cpanel: CpanelAdapter,
    AccessMethod.plesk: PleskAdapter,
    AccessMethod.plugin: AgentAdapter,
}
