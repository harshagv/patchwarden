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
    # Bumped by "log out everywhere": every token issued before it stops working.
    token_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    # TOTP second factor. The secret is Fernet-encrypted; recovery codes are stored as SHA-256 hashes.
    mfa_secret: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    mfa_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # stops a code being replayed
    mfa_recovery: Mapped[list | None] = mapped_column(JSON, nullable=True)
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
    # Proof that this owner controls the domain (DNS TXT record, a file in /.well-known/, or the plugin).
    verify_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    verify_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Shared with a team (agency or company): members get access by their role in the organisation.
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True,
                                               index=True)

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
    # Share links issued before this moment stop working.
    share_revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("scan_batches.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    site: Mapped[Site] = relationship(back_populates="scans")


class AuditLog(Base):
    """Append-only, hash-chained: each entry stores the hash of the one before it (see audit_chain.py)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


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
    checksum: Mapped[str] = mapped_column(String(128))  # SHA-256 of the archive before encryption
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    encrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


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
    # Who planned it (a separate-approval policy needs a different approver), and how it is billed.
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    billing: Mapped[dict | None] = mapped_column(JSON, nullable=True)

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
    past_due_since: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    reminders_sent: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)

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
    # "urgent" goes out at once (exploited, likely to be exploited, or critical/high); "digest" waits for the daily digest.
    priority: Mapped[str | None] = mapped_column(String(16), nullable=True)
    digest_sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)  # became exploited later
    delivered: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # channel -> outcome
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
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)  # in CISA's exploited list
    kev_added: Mapped[str | None] = mapped_column(String(16), nullable=True)
    epss: Mapped[float | None] = mapped_column(nullable=True)  # FIRST EPSS: chance of exploitation in 30 days
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
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
    # The fixed-price quote (hours, rate, statement of work) and when the customer accepted it.
    quote: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    quote_accepted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    quote_accepted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

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


class Job(Base):
    """A durable unit of background work (patch, rollback, staging, promotion).

    A worker claims a job by taking a lease and keeps it alive with heartbeats. If the process dies,
    the lease runs out and any worker (or the next start-up) claims the job again and resumes it.
    """

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    ref_id: Mapped[int] = mapped_column(Integer, index=True)  # the patch job or migration it drives
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    state: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued, running, done, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    lease_owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class ScanBatch(Base):
    """A list of domains scanned in the background (a CSV upload, or a JSON list)."""

    __tablename__ = "scan_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    targets: Mapped[list] = mapped_column(JSON, default=list)
    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)  # targets processed (scanned or rejected)
    rejected: Mapped[list] = mapped_column(JSON, default=list)
    wordpress: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class WatchCounter(Base):
    """Per site, per day: how many checks ran. Replaces one row per site per hourly poll."""

    __tablename__ = "watch_counters"
    __table_args__ = (UniqueConstraint("site_id", "day", name="uq_watch_counter_site_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    day: Mapped[str] = mapped_column(String(10))  # YYYY-MM-DD (UTC)
    version_checks: Mapped[int] = mapped_column(Integer, default=0)
    cve_checks: Mapped[int] = mapped_column(Integer, default=0)


class NotificationChannel(Base):
    """Where a user's alerts go besides email. The URL is a secret (it posts into their workspace): encrypted."""

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # slack, teams, webhook
    url_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    url_hint: Mapped[str] = mapped_column(String(128))  # host only, for display
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # webhook HMAC key
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class OrgRole(str, enum.Enum):
    owner = "owner"        # everything, including members and billing
    admin = "admin"        # everything except removing the last owner
    member = "member"      # plans changes, connects hosts; cannot approve
    approver = "approver"  # approves and signs off; cannot plan
    viewer = "viewer"      # reads reports and alerts


class Organization(Base):
    """A team (an agency and its clients, or a company's IT). Also carries its white-label branding."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    # Four-eyes rule: the person who planned a change cannot also approve it.
    require_separate_approver: Mapped[bool] = mapped_column(Boolean, default=False)
    brand_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    brand_color: Mapped[str | None] = mapped_column(String(7), nullable=True)
    brand_logo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    brand_footer: Mapped[str | None] = mapped_column(String(300), nullable=True)
    hourly_rate: Mapped[int | None] = mapped_column(Integer, nullable=True)  # migration quotes, whole currency units
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_membership"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[OrgRole] = mapped_column(_enum(OrgRole))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Attestation(Base):
    """A signed, public statement that a site was patched and checked at a point in time."""

    __tablename__ = "attestations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # random, used in public links
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(String(128))  # base64url Ed25519 signature over the canonical payload
    key_id: Mapped[str] = mapped_column(String(32))
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class VirtualPatch(Base):
    """A WAF rule at the site's edge that blocks attack requests until PHP itself is updated."""

    __tablename__ = "virtual_patches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(16))  # cloudflare, akamai, aws_waf, demo
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # zone / web ACL / security config ids (not secret)
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # API token, Fernet
    # planned -> applying -> active -> removing -> removed; failed from applying or removing
    state: Mapped[str] = mapped_column(String(16), default="planned", index=True)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    remote_ref: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    site: Mapped[Site] = relationship()
