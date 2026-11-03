"""SQLAlchemy models (spec section 9).

Phase 1: users, sites, scans, audit_log. Phase 2: credentials, backups, patch_jobs.
Phase 3: alerts, subscriptions, plus watch_checks, advisories and feed_cursors (not in the
spec's list: the check history, the CVE/release records we match, and where each feed poll stopped).
Phase 4: migrations. Phase 5: plugin_keys and plugin_actions (not in the spec's list: the
WordPress plugin's key, stored as a hash, and the approved actions it pulls).
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC on the way in and out. SQLite drops the zone; PostgreSQL keeps it."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc) if value is not None else None

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class Role(str, enum.Enum):
    owner = "owner"
    admin = "admin"
    agency = "agency"


class Platform(str, enum.Enum):
    wordpress = "wordpress"
    custom = "custom"


class AccessMethod(str, enum.Enum):
    external = "external"
    plugin = "plugin"
    cpanel = "cpanel"
    plesk = "plesk"
    ssh = "ssh"


class Risk(str, enum.Enum):
    safe = "safe"
    patch_now = "patch_now"
    must_migrate = "must_migrate"
    unknown = "unknown"


class CredentialKind(str, enum.Enum):
    cpanel_token = "cpanel_token"
    plesk_token = "plesk_token"
    ssh_key = "ssh_key"
    wp_app_password = "wp_app_password"
    api_key = "api_key"


class PatchState(str, enum.Enum):
    dry_run = "dry_run"
    awaiting_approval = "awaiting_approval"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    rolled_back = "rolled_back"


class MigrationState(str, enum.Enum):
    planned = "planned"
    staging_running = "staging_running"
    staging_failed = "staging_failed"
    staging_passed = "staging_passed"
    signed_off = "signed_off"
    promoting = "promoting"
    promoted = "promoted"
    promotion_failed = "promotion_failed"


class Product(str, enum.Enum):
    watchdog = "watchdog"
    wp_guard = "wp_guard"


class SubscriptionStatus(str, enum.Enum):
    active = "active"
    past_due = "past_due"
    cancelled = "cancelled"


def _enum(e: type[enum.Enum]) -> Enum:
    return Enum(e, native_enum=False, validate_strings=True, length=32)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[Role] = mapped_column(_enum(Role), default=Role.owner)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    sites: Mapped[list[Site]] = relationship(back_populates="owner")


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("owner_id", "domain", name="uq_site_owner_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Null owner = a free, anonymous scan (the lead-magnet flow).
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    platform: Mapped[Platform] = mapped_column(_enum(Platform), default=Platform.custom)
    access_method: Mapped[AccessMethod] = mapped_column(_enum(AccessMethod), default=AccessMethod.external)
    status: Mapped[str] = mapped_column(String(32), default="active")
    # Not in the spec's column list: the pages the Patch agent checks before and
    # after a change, e.g. {"login": "/wp-login.php", "form": "/checkout"}.
    check_paths: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    owner: Mapped[User | None] = relationship(back_populates="sites")
    scans: Mapped[list[Scan]] = relationship(back_populates="site", order_by="Scan.id")
    credentials: Mapped[list[Credential]] = relationship(back_populates="site", order_by="Credential.id")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    # Null when the version is hidden: we never store a guess.
    detected_version: Mapped[str | None] = mapped_column(String(64))
    risk: Mapped[Risk] = mapped_column(_enum(Risk))
    raw_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    # Not in the spec's column list: the URL actually fetched and the evidence
    # behind the score (version source, WordPress findings, fetch errors).
    scanned_url: Mapped[str] = mapped_column(String(2048))
    findings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    site: Mapped[Site] = relationship(back_populates="scans")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Credential(Base):
    """An owner-created token or key, Fernet-encrypted. Never logged, never returned by any API."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    kind: Mapped[CredentialKind] = mapped_column(_enum(CredentialKind))
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    site: Mapped[Site] = relationship(back_populates="credentials")

    def __repr__(self) -> str:  # never show the ciphertext either
        return f"<Credential id={self.id} site_id={self.site_id} kind={self.kind.value}>"


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    location: Mapped[str] = mapped_column(String(1024))
    checksum: Mapped[str] = mapped_column(String(128))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class PatchJob(Base):
    __tablename__ = "patch_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    from_version: Mapped[str] = mapped_column(String(64))
    to_version: Mapped[str] = mapped_column(String(64))
    state: Mapped[PatchState] = mapped_column(_enum(PatchState), default=PatchState.dry_run, index=True)
    backup_id: Mapped[int | None] = mapped_column(ForeignKey("backups.id", ondelete="SET NULL"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    site: Mapped[Site] = relationship()
    backup: Mapped[Backup | None] = relationship()


class Subscription(Base):
    """Billing hook only: payments arrive in Phase 6 (Stripe). Monitoring runs while active or past_due."""

    __tablename__ = "subscriptions"
    __table_args__ = (UniqueConstraint("site_id", "product", name="uq_subscription_site_product"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    product: Mapped[Product] = mapped_column(_enum(Product))
    status: Mapped[SubscriptionStatus] = mapped_column(_enum(SubscriptionStatus), default=SubscriptionStatus.active)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    site: Mapped[Site] = relationship()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("site_id", "cve_id", name="uq_alert_site_cve"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    # The advisory id (CVE-..., PHP-8.4.28 for a release, or risk:<risk>:<check id> for a risk change).
    cve_id: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    message: Mapped[str] = mapped_column(String(4000))
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # null until an email went out
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    site: Mapped[Site] = relationship()


class WatchCheck(Base):
    """One Watchdog check of one site: a version check or a CVE match run."""

    __tablename__ = "watch_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # "version" or "cve"
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    detected_version: Mapped[str | None] = mapped_column(String(64))
    risk: Mapped[Risk | None] = mapped_column(_enum(Risk), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)


class Advisory(Base):
    """A CVE from NVD, or a PHP security release from php.net, with the PHP versions it affects."""

    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(16))  # "nvd", "php_release" or "fixture"
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[float | None] = mapped_column(nullable=True)
    summary: Mapped[str] = mapped_column(String(4000))
    affected: Mapped[list] = mapped_column(JSON, default=list)  # version ranges
    fixed_in: Mapped[str | None] = mapped_column(String(64))
    url: Mapped[str | None] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class FeedCursor(Base):
    __tablename__ = "feed_cursors"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))


class Migration(Base):
    __tablename__ = "migrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    from_version: Mapped[str] = mapped_column(String(64))
    to_version: Mapped[str] = mapped_column(String(64))
    breakage: Mapped[dict] = mapped_column(JSON, default=dict)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    staging_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    signed_off_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    state: Mapped[MigrationState] = mapped_column(_enum(MigrationState), default=MigrationState.planned)
    # Not in the spec's column list: when sign-off happened, where the code came from,
    # and the production promotion record (it points at the Phase 2 patch job).
    signed_off_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    source: Mapped[str] = mapped_column(String(16), default="host")  # "host" (read via access) or "upload"
    promotion: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    patch_job_id: Mapped[int | None] = mapped_column(ForeignKey("patch_jobs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    site: Mapped[Site] = relationship()


class PluginKey(Base):
    """The WordPress plugin's API key. Only a SHA-256 hash is stored: the key is shown once, at creation."""

    __tablename__ = "plugin_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_hint: Mapped[str] = mapped_column(String(16))  # "pw_ab12…" so the owner can tell keys apart
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    inventory: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # the last report from the plugin

    site: Mapped[Site] = relationship()


class PluginAction(Base):
    """An approved action for the plugin to run (it pulls them). Created only by an approved patch job."""

    __tablename__ = "plugin_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    patch_job_id: Mapped[int | None] = mapped_column(ForeignKey("patch_jobs.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(32))  # "update_component" or "report_now"
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(16), default="queued")  # queued, sent, done, failed
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
