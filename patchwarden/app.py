"""FastAPI app factory: API + server-rendered pages from one app."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from . import audit_chain  # noqa: F401  (registers the audit hash-chain hook)
from . import dashboard
from .api import (admin, alerts, auth, commerce, migrations, orgs, patches, scans, sites, verify, virtual_patches,
                  wpguard)
from .attest import Signer
from .migration.sandbox import make_sandbox
from .config import Settings, load_settings
from .backups import BackupStore, purge_expired
from .crypto import CredentialVault
from .db import create_schema, make_engine, make_sessionmaker
from .errors import install_error_handlers
from .fakes import DemoWorld
from .jobs import JobQueue, make_handlers
from .logging_setup import configure_logging
from .ratelimit import Limits
from .verification import make_txt_resolver
from .scanner.service import Scanner
from .watchdog.feeds import EpssClient, FixtureSource, KevFeed, NvdSource, PhpReleaseSource
from .watchdog.notify import Notifier, make_notifier
from .watchdog.service import Watchdog

TEMPLATES_DIR = Path(__file__).parent / "templates"

RISK_LABELS = {
    "safe": "Safe",
    "patch_now": "Patch now",
    "must_migrate": "Must migrate",
    "unknown": "Unknown",
}


def default_signals(settings: Settings) -> tuple[KevFeed, EpssClient]:
    """Exploitation signals: CISA KEV and FIRST EPSS (read from the fixture file in fixture mode)."""
    fixture = settings.cve_fixture_path if settings.cve_feed == "fixture" else None
    return KevFeed(fixture=fixture), EpssClient(fixture=fixture)


def default_sources(settings: Settings) -> list:
    if settings.cve_feed == "fixture":
        return [FixtureSource(settings.cve_fixture_path)]
    return [NvdSource(settings.nvd_api_key), PhpReleaseSource()]


def create_app(settings: Settings | None = None, *, scanner: Scanner | None = None,
               demo_world: DemoWorld | None = None, notifier: Notifier | None = None, signals: tuple | None = None,
               sources: list | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(settings)

    engine = make_engine(settings.database_url)
    create_schema(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Anything a crash or restart left half-done gets a recovery job before new work starts.
        app.state.jobs.reconcile_orphans()
        poller = None
        if settings.jobs_poller:
            poller = asyncio.create_task(app.state.jobs.poll_forever(settings.jobs_poll_seconds))
        scheduler = None
        if settings.watchdog_scheduler:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler

            scheduler = AsyncIOScheduler(timezone="UTC")
            # Hourly: version checks for sites that are due (daily) + CVE/release feed poll.
            scheduler.add_job(app.state.watchdog.tick, "interval", hours=1, id="watchdog_tick",
                              next_run_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                              max_instances=1, coalesce=True)
            # Monthly safety reports on the 1st.
            scheduler.add_job(app.state.watchdog.send_monthly_reports, "cron", day=1, hour=6, id="monthly_reports",
                              max_instances=1, coalesce=True)
            # Daily: the lower-priority alerts as one digest per owner, and payment reminders / lapses.
            scheduler.add_job(app.state.watchdog.send_digests, "cron", hour=8, id="daily_digest",
                              max_instances=1, coalesce=True)
            scheduler.add_job(app.state.watchdog.dunning_tick, "cron", hour=9, id="dunning",
                              max_instances=1, coalesce=True)
            # Daily: delete backups past BACKUP_RETENTION_DAYS.
            scheduler.add_job(purge_backups, "cron", hour=3, id="backup_retention", max_instances=1, coalesce=True)
            scheduler.start()
        app.state.scheduler = scheduler
        yield
        if poller is not None:
            app.state.jobs.stop()
            poller.cancel()
        if scheduler is not None:
            scheduler.shutdown(wait=False)
        await app.state.watchdog.aclose()
        await app.state.scanner.aclose()
        engine.dispose()

    app = FastAPI(
        title="Patchwarden",
        version="0.1.0",
        description="Scanner, Patch, Watchdog, Migration and WordPress Guard for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    # Fake hosting panels for *.demo.patchwarden.test: development and tests only.
    app.state.demo_world = (demo_world or DemoWorld.seeded()) if settings.demo_sites else None
    app.state.scanner = scanner or Scanner(settings, demo_world=app.state.demo_world)
    app.state.vault = CredentialVault(settings)
    app.state.signer = Signer(settings)
    app.state.sandbox = make_sandbox(settings)  # Rector / PHPStan / php -l for migrations (MIGRATION_TOOLS)
    # Edge providers for virtual patches; tests swap these for mocks (httpx transport, boto3 client factory).
    app.state.vpatch_http_transport = None
    app.state.vpatch_aws_factory = None
    app.state.backup_store = BackupStore(settings)
    app.state.limits = Limits(settings)
    app.state.txt_resolver = make_txt_resolver(app.state.demo_world)
    app.state.jobs = JobQueue(app.state.sessionmaker, make_handlers(app.state), lease_seconds=settings.jobs_lease_seconds)

    def purge_backups() -> None:
        with app.state.sessionmaker() as db:
            purge_expired(db, app.state.backup_store)
    app.state.notifier = notifier or make_notifier(settings)
    app.state.watchdog = Watchdog(settings, app.state.sessionmaker, app.state.scanner, app.state.notifier,
                                  sources if sources is not None else default_sources(settings),
                                  app.state.vault, app.state.demo_world, *(signals or default_signals(settings)))

    templates = Jinja2Templates(directory=TEMPLATES_DIR)
    templates.env.globals["risk_labels"] = RISK_LABELS
    app.state.templates = templates

    install_error_handlers(app)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(sites.router)
    app.include_router(scans.router)
    app.include_router(patches.router)
    app.include_router(alerts.router)
    app.include_router(migrations.router)
    app.include_router(wpguard.router)
    app.include_router(admin.router)
    app.include_router(verify.router)
    app.include_router(orgs.router)
    app.include_router(commerce.router)
    app.include_router(virtual_patches.router)
    app.include_router(dashboard.router)
    return app
