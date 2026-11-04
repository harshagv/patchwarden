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


def split_keys(raw: str) -> list[str]:
    return [k.strip() for k in raw.split(",") if k.strip()]


def _check_keyring(name: str, raw: str) -> None:
    keys = split_keys(raw)
    if not keys:
        raise ConfigError(f"{name} is empty.")
    for key in keys:
        try:
            Fernet(key.encode())
        except (ValueError, TypeError):
            raise ConfigError(
                f"{name} is not a valid Fernet key (or comma-separated list of keys). Generate one with "
                "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            ) from None


def _env_choice(name: str, default: str, choices: tuple[str, ...]) -> str:
    value = (_env(name) or default).strip().lower()
    if value not in choices:
        raise ConfigError(f"{name} must be one of: {', '.join(choices)}.")
    return value


def _env_fraction(name: str, default: float) -> float:
    raw = _env(name)
    try:
        value = float(raw) if raw else default
    except ValueError:
        raise ConfigError(f"{name} must be a number between 0 and 1.") from None
    if not 0 <= value <= 1:
        raise ConfigError(f"{name} must be a number between 0 and 1.")
    return value


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
    # Phase A: trust fixes
    backup_key: str = field(repr=False, default="")  # empty: derived from CREDENTIAL_KEY
    backup_retention_days: int = 30
    jobs_poller: bool = True  # background worker that picks up queued and interrupted jobs
    jobs_lease_seconds: int = 60
    jobs_poll_seconds: int = 5
    scan_rate_limit: int = 30  # free scans (domains) per window, per connection
    scan_rate_limit_user: int = 1000  # per logged-in account (a bulk list counts every domain)
    scan_rate_window: int = 60
    login_failure_limit: int = 10  # failed logins per window, per connection and per email
    login_failure_window: int = 900
    signup_limit: int = 10  # new accounts per hour, per connection
    # Phase C: Watchdog at scale
    watchdog_concurrency: int = 20  # sites checked at the same time
    epss_urgent: float = 0.1  # EPSS at or above this alerts at once (otherwise: severity decides)
    dunning_grace_days: int = 14  # past_due -> cancelled after this many days
    # Phase D: prices for the billing export (no payment is taken here) and signed attestations
    currency: str = "USD"
    price_patch: int = 149  # one-time fee per patch on a site with no active subscription
    price_watchdog: int = 29  # per site per month
    price_wp_guard: int = 9  # per site per month
    price_virtual_patch: int = 19  # per site per month while a virtual patch is active
    migration_hourly_rate: int = 95  # default for quotes; a team can set its own
    attestation_key: str = ""  # base64url Ed25519 private key (32 bytes); derived from CREDENTIAL_KEY if empty
    attestation_days: int = 30  # how long a signed attestation stays valid
    # Phase F: real PHP tooling for migrations, in a sandbox
    migration_tools: str = "off"  # off, docker (production), local (development only)
    sandbox_image: str = "patchwarden/php-tools:1"
    sandbox_timeout: int = 300
    trusted_proxies: frozenset[str] = frozenset()  # reverse proxies allowed to set X-Forwarded-For

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
    # CREDENTIAL_KEY (and BACKUP_KEY) may hold several comma-separated keys: the first encrypts,
    # all of them decrypt. That is how a key is rotated without losing what the old one protects.
    _check_keyring("CREDENTIAL_KEY", values["CREDENTIAL_KEY"])
    backup_key = _env("BACKUP_KEY")
    if backup_key:
        _check_keyring("BACKUP_KEY", backup_key)

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
        scan_bulk_max=_env_int("SCAN_BULK_MAX", 1000),
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
        backup_key=backup_key,
        backup_retention_days=_env_int("BACKUP_RETENTION_DAYS", 30),
        jobs_poller=_env_bool("JOBS_POLLER", default=app_env != "test"),
        jobs_lease_seconds=_env_int("JOBS_LEASE_SECONDS", 60),
        jobs_poll_seconds=_env_int("JOBS_POLL_SECONDS", 5),
        scan_rate_limit=_env_int("SCAN_RATE_LIMIT", 30),
        scan_rate_limit_user=_env_int("SCAN_RATE_LIMIT_USER", 1000),
        scan_rate_window=_env_int("SCAN_RATE_WINDOW", 60),
        login_failure_limit=_env_int("LOGIN_FAILURE_LIMIT", 10),
        login_failure_window=_env_int("LOGIN_FAILURE_WINDOW", 900),
        signup_limit=_env_int("SIGNUP_LIMIT", 10),
        watchdog_concurrency=_env_int("WATCHDOG_CONCURRENCY", 20),
        epss_urgent=_env_fraction("EPSS_URGENT", 0.1),
        dunning_grace_days=_env_int("DUNNING_GRACE_DAYS", 14),
        currency=(_env("CURRENCY", "USD").upper() or "USD")[:3],
        price_patch=_env_int("PRICE_PATCH", 149),
        price_watchdog=_env_int("PRICE_WATCHDOG", 29),
        price_wp_guard=_env_int("PRICE_WP_GUARD", 9),
        price_virtual_patch=_env_int("PRICE_VIRTUAL_PATCH", 19),
        migration_hourly_rate=_env_int("MIGRATION_HOURLY_RATE", 95),
        attestation_key=_env("ATTESTATION_KEY"),
        attestation_days=_env_int("ATTESTATION_DAYS", 30),
        migration_tools=_env_choice("MIGRATION_TOOLS", "off", ("off", "docker", "local")),
        sandbox_image=_env("SANDBOX_IMAGE", "patchwarden/php-tools:1"),
        sandbox_timeout=_env_int("SANDBOX_TIMEOUT", 300),
        trusted_proxies=frozenset(p.strip() for p in _env("TRUSTED_PROXIES").split(",") if p.strip()),
    )
