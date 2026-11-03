"""Settings loaded from the environment (and .env at the project root).

Production refuses to start when a required secret is missing and names it.
Development fills missing secrets with throwaway values so `make dev` works
with nothing beyond the .env.example values.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_URL = f"sqlite:///{PROJECT_ROOT / 'data' / 'patchwarden.db'}"

REQUIRED_SECRETS = ("DATABASE_URL", "JWT_SECRET", "CREDENTIAL_KEY")

log = logging.getLogger(__name__)


class ConfigError(RuntimeError):
    """Raised when the app must not start. The message never contains a secret value."""


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str
    jwt_secret: str = field(repr=False)
    credential_key: str = field(repr=False)
    public_base_url: str
    access_token_minutes: int
    share_link_hours: int
    demo_sites: bool
    # Scanner fetch limits (SSRF and abuse protection).
    scan_timeout_seconds: float
    scan_max_redirects: int
    scan_max_body_bytes: int
    scan_allowed_ports: frozenset[int]
    scan_bulk_max: int
    scan_concurrency: int
    wporg_api_enabled: bool
    wp_vuln_feed_path: Path
    # Patch agent: local-disk backups (the default; S3 is optional and not built yet).
    backup_dir: Path
    # Watchdog
    watchdog_scheduler: bool  # run the APScheduler jobs inside the app
    cve_feed: str  # "nvd" (NVD API + php.net releases) or "fixture" (local JSON file)
    cve_fixture_path: Path
    cve_lookback_days: int
    nvd_api_key: str = field(repr=False, default="")
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = field(repr=False, default="")
    alert_from_email: str = "alerts@patchwarden.local"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def _normalise_db_url(url: str) -> str:
    # The .env.example uses the plain postgresql:// form; we ship psycopg 3.
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    return url


def load_settings(*, load_dotenv_file: bool = True) -> Settings:
    if load_dotenv_file:
        # Real environment variables win over .env.
        load_dotenv(PROJECT_ROOT / ".env", override=False)

    app_env = _env("APP_ENV", "development").lower()
    if app_env not in {"development", "test", "production"}:
        raise ConfigError(f"APP_ENV must be development, test or production (got {app_env!r}).")

    values = {name: _env(name) for name in REQUIRED_SECRETS}

    if app_env == "production":
        missing = [name for name, value in values.items() if not value]
        if missing:
            noun, pronoun = ("secret", "it") if len(missing) == 1 else ("secrets", "them")
            raise ConfigError(
                f"Refusing to start in production: missing required {noun} {', '.join(missing)}. "
                f"Set {pronoun} in .env (see .env.example for where to get {pronoun})."
            )
    else:
        if not values["DATABASE_URL"]:
            values["DATABASE_URL"] = DEFAULT_SQLITE_URL
        if not values["JWT_SECRET"]:
            log.warning("JWT_SECRET not set: using a throwaway dev value (sessions reset on restart).")
            values["JWT_SECRET"] = secrets.token_hex(32)
        if not values["CREDENTIAL_KEY"]:
            log.warning("CREDENTIAL_KEY not set: using a throwaway dev key.")
            values["CREDENTIAL_KEY"] = Fernet.generate_key().decode()

    if len(values["JWT_SECRET"]) < 32:
        raise ConfigError("JWT_SECRET is too short: use at least 32 characters (openssl rand -hex 32).")
    try:
        Fernet(values["CREDENTIAL_KEY"].encode())
    except (ValueError, TypeError):
        raise ConfigError(
            "CREDENTIAL_KEY is not a valid Fernet key. Generate one with "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from None

    demo_sites = _env_bool("DEMO_SITES", default=app_env != "production")
    if demo_sites and app_env == "production":
        raise ConfigError("DEMO_SITES must be off in production.")

    cve_feed = _env("CVE_FEED", "fixture" if demo_sites else "nvd").lower()
    if cve_feed not in {"nvd", "fixture"}:
        raise ConfigError("CVE_FEED must be nvd or fixture.")

    ports = _env("SCAN_ALLOWED_PORTS", "80,443")
    return Settings(
        app_env=app_env,
        database_url=_normalise_db_url(values["DATABASE_URL"]),
        jwt_secret=values["JWT_SECRET"],
        credential_key=values["CREDENTIAL_KEY"],
        public_base_url=_env("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/"),
        access_token_minutes=_env_int("ACCESS_TOKEN_MINUTES", 60),
        share_link_hours=_env_int("SHARE_LINK_HOURS", 168),
        demo_sites=demo_sites,
        scan_timeout_seconds=float(_env("SCAN_TIMEOUT_SECONDS", "10")),
        scan_max_redirects=_env_int("SCAN_MAX_REDIRECTS", 3),
        scan_max_body_bytes=_env_int("SCAN_MAX_BODY_BYTES", 1_000_000),
        scan_allowed_ports=frozenset(int(p) for p in ports.split(",") if p.strip()),
        scan_bulk_max=_env_int("SCAN_BULK_MAX", 100),
        scan_concurrency=_env_int("SCAN_CONCURRENCY", 5),
        wporg_api_enabled=_env_bool("WPORG_API_ENABLED", default=True),
        wp_vuln_feed_path=Path(_env("WP_VULN_FEED_PATH") or PROJECT_ROOT / "patchwarden" / "data" / "wp_vuln_feed.json"),
        backup_dir=Path(_env("BACKUP_DIR") or PROJECT_ROOT / "data" / "backups"),
        watchdog_scheduler=_env_bool("WATCHDOG_SCHEDULER", default=app_env != "test"),
        cve_feed=cve_feed,
        cve_fixture_path=Path(_env("CVE_FIXTURE_PATH") or PROJECT_ROOT / "patchwarden" / "data" / "cve_feed.demo.json"),
        cve_lookback_days=_env_int("CVE_LOOKBACK_DAYS", 7),
        nvd_api_key=_env("NVD_API_KEY"),
        smtp_host=_env("SMTP_HOST"),
        smtp_port=_env_int("SMTP_PORT", 587),
        smtp_user=_env("SMTP_USER"),
        smtp_password=_env("SMTP_PASSWORD"),
        alert_from_email=_env("ALERT_FROM_EMAIL", "alerts@patchwarden.local"),
    )
