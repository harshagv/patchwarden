"""Migration agent: breakage scan + plan, staging tests, owner/IT sign-off, promotion to production.

Production is never migrated directly. Fixes are applied and tested on a
staging copy. Promotion needs a sign-off record, refuses if the staging code
changed after the tests, and runs through the Phase 2 runner (backup,
before-checks, deploy, switch, restart, after-checks, automatic rollback),
so it produces the same before/after report as a patch.
"""

from __future__ import annotations

import io
import logging
import posixpath
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..errors import AppError
from ..fakes import DemoWorld
from ..models import AuditLog, Migration, MigrationState, PatchJob, PatchState, Scan, Site, User
from ..patch.adapters import AdapterError, HostingAdapter
from ..patch.backups import BackupStore
from ..patch.service import CHECK_LABELS, PatchRunner, build_adapter, check_targets, run_checks
from ..scanner.fetch import SafeFetcher
from ..scanner.versions import FIXED_VERSIONS, fmt, parse_version
from ..security import access
from ..security.crypto import CredentialVault
from .scanner import apply_auto_fixes, build_plan, code_hash, is_code, is_config, scan_files

log = logging.getLogger(__name__)

TARGET_LINES = [(8, 4), (8, 3), (8, 5)]  # default preference: 8.4 (supported to end of 2028), then 8.3, then 8.5
RESTAGE_FROM = (MigrationState.planned, MigrationState.staging_failed, MigrationState.staging_passed,
                MigrationState.signed_off, MigrationState.promotion_failed)

ZIP_MAX_BYTES = 20 * 1024 * 1024
ZIP_MAX_TOTAL = 100 * 1024 * 1024
ZIP_MAX_FILE = 2 * 1024 * 1024
ZIP_MAX_FILES = 20_000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(db: Session, user_id: int | None, mig: Migration, action: str, **detail: Any) -> None:
    db.add(AuditLog(user_id=user_id, site_id=mig.site_id, action=action, detail={"migration_id": mig.id, **detail}))


# --- inputs -------------------------------------------------------------------

def read_zip(data: bytes) -> dict[str, str]:
    """PHP files from an uploaded zip, read in memory with size limits; nothing is written or run."""
    if len(data) > ZIP_MAX_BYTES:
        raise AppError(413, "too_large", "Please upload a zip of at most 20 MB (code only, no media).")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise AppError(400, "invalid_zip", "That file is not a zip archive.") from None
    entries = [i for i in archive.infolist() if not i.is_dir()]
    if len(entries) > ZIP_MAX_FILES:
        raise AppError(413, "too_many_files", "That zip has too many files.")
    files: dict[str, str] = {}
    total = 0
    for info in entries:
        path = posixpath.normpath(info.filename.replace("\\", "/")).lstrip("/")
        if path.startswith("..") or not is_code(path):
            continue
        if info.file_size > ZIP_MAX_FILE:
            continue
        total += info.file_size
        if total > ZIP_MAX_TOTAL:
            raise AppError(413, "too_large", "The code in that zip is too large to scan.")
        with archive.open(info) as fh:
            files[path] = fh.read(ZIP_MAX_FILE + 1)[:ZIP_MAX_FILE].decode("utf-8", errors="replace")
    # A zip of a folder: drop the shared top-level folder name.
    tops = {p.split("/", 1)[0] for p in files}
    if len(tops) == 1 and all("/" in p for p in files):
        files = {p.split("/", 1)[1]: t for p, t in files.items()}
    if not files:
        raise AppError(422, "no_php_files", "We found no PHP files in that zip.")
    return files


def _pick_target(current: str, requested: str | None, available: list[str] | None) -> str:
    cur = parse_version(current)
    if cur is None or cur.patch is None:
        raise AppError(409, "version_unreadable", "We need the exact current PHP version to plan a migration.")
    if cur.branch >= (8, 3):
        raise AppError(409, "patch_not_migrate",
                       f"PHP {current} is on a supported line. Use the Patch agent to update it instead.")

    def fixed_ok(v: str) -> bool:
        p = parse_version(v)
        fixed = FIXED_VERSIONS.get(p.branch) if p and p.patch is not None else None
        return bool(fixed and p.branch >= (8, 3) and (p.major, p.minor, p.patch) >= fixed and not p.suffix)

    if requested:
        if not fixed_ok(requested):
            raise AppError(422, "invalid_target",
                           "Pick a PHP 8.3, 8.4 or 8.5 release that includes the PHP2Shell fix "
                           "(8.3.36, 8.4.27, 8.5.12 or newer).")
        if available is not None and requested not in available:
            raise AppError(422, "target_unavailable", f"The host does not offer PHP {requested} for this site.")
        return requested
    candidates = [v for v in (available if available is not None else
                              [fmt(f) for b, f in FIXED_VERSIONS.items() if b >= (8, 3)]) if fixed_ok(v)]
    for line in TARGET_LINES:
        on_line = [v for v in candidates if parse_version(v).branch == line]
        if on_line:
            return max(on_line, key=lambda v: parse_version(v).patch)
    raise AppError(409, "no_target", "The host does not offer a supported PHP version with the fix yet.")


async def create_migration(db: Session, *, site: Site, user: User, to_version: str | None, vault: CredentialVault,
                           world: DemoWorld | None, uploaded: dict[str, str] | None = None,
                           from_version: str | None = None, sandbox=None) -> Migration:
    adapter: HostingAdapter | None = None
    available = None
    try:
        if uploaded is None:
            adapter = build_adapter(site, vault, world)
            current = await adapter.php_version()
            available = await adapter.available_versions()
            files = await adapter.read_code()  # read-only
        else:
            files = uploaded
            last = db.scalar(select(Scan).where(Scan.site_id == site.id, Scan.detected_version.is_not(None))
                             .order_by(Scan.id.desc()).limit(1))
            current = from_version or (last.detected_version if last else None)
            if not current:
                raise AppError(422, "from_version_needed",
                               "Tell us the site's current PHP version (from_version), or scan the site first.")
    except AdapterError as exc:
        raise AppError(502, exc.code, exc.message) from None
    target = _pick_target(current, to_version, available)
    breakage = scan_files(files, current, target)
    plan = build_plan(breakage)
    if sandbox is not None:  # Rector, PHPStan and php -l in a sandbox (src/patchwarden/migration/sandbox.py)
        from .sandbox import plan_additions, tool_scan

        breakage["tools"] = await tool_scan(sandbox, files, target)
        extra = plan_additions(breakage["tools"])
        for n, step in enumerate(extra, start=len(plan["fixes"]) + 1):
            plan["fixes"].append({"step": n, "since": target, **step})
    mig = Migration(site_id=site.id, from_version=current, to_version=target, breakage=breakage,
                    plan=plan, state=MigrationState.planned,
                    source="host" if uploaded is None else "upload")
    db.add(mig)
    db.flush()
    audit(db, user.id, mig, "migration.planned", from_version=current, to_version=target,
          errors=breakage["errors"], warnings=breakage["warnings"], effort=mig.plan["effort"])
    db.commit()
    return mig


# --- staging ------------------------------------------------------------------

def _claim(db: Session, mig: Migration, allowed: tuple[MigrationState, ...], new: MigrationState,
           values: dict | None = None) -> None:
    result = db.execute(update(Migration).where(Migration.id == mig.id, Migration.state.in_(allowed))
                        .values(state=new, **(values or {})))
    if result.rowcount != 1:
        db.rollback()
        raise AppError(409, "not_allowed_now",
                       f"This migration is {mig.state.value.replace('_', ' ')}, so that is not possible now.")
    db.commit()
    db.refresh(mig)


def start_staging(db: Session, mig: Migration, user: User) -> None:
    access.require(db, user, mig.site, "edit")
    # A new staging run makes any earlier sign-off stale.
    _claim(db, mig, RESTAGE_FROM, MigrationState.staging_running, {"signed_off_by": None, "signed_off_at": None})
    audit(db, user.id, mig, "migration.staging_started")
    db.commit()


def _staging_site(site: Site, domain: str):
    return SimpleNamespace(domain=domain, check_paths=site.check_paths, platform=site.platform)


async def run_staging(factory: sessionmaker[Session], settings: Settings, vault: CredentialVault,
                      world: DemoWorld | None, fetcher: SafeFetcher, store: BackupStore, mig_id: int,
                      actor_id: int, resume: bool = False) -> None:
    """Staging touches only the staging copy, so an interrupted run is simply run again (`resume` is ignored)."""
    with factory() as db:
        mig = db.get(Migration, mig_id)
        if mig is None or mig.state != MigrationState.staging_running:
            return
        report: dict[str, Any] = {"started_at": now_iso(), "target_version": mig.to_version, "steps": []}

        def step(name: str, ok: bool, detail: str) -> None:
            report["steps"].append({"step": name, "ok": ok, "detail": detail, "at": now_iso()})

        def finish(passed: bool, message: str) -> None:
            report.update(passed=passed, message=message, finished_at=now_iso())
            mig.staging_report = report
            mig.state = MigrationState.staging_passed if passed else MigrationState.staging_failed
            audit(db, actor_id, mig, "migration.staging_tested", passed=passed, code_hash=report.get("code_hash"))
            db.commit()

        try:
            prod = build_adapter(mig.site, vault, world)
            existing = await prod.open_staging()
            if existing is None:
                domain, staging = await prod.create_staging()
                report["staging_created"] = True
                step("staging", True, f"Copied the site to {domain}. Production was not changed.")
                baseline = await run_checks(fetcher, _staging_site(mig.site, domain))
                report["baseline"] = {"php_version": await staging.php_version(), "checks": baseline}
                if not all(c["ok"] for c in baseline):
                    step("baseline", False, "The staging copy did not work even before any change.")
                    return finish(False, "The staging copy does not work on the current PHP version, "
                                         "so we cannot test the move. Check the staging site.")
                step("baseline", True, "Staging works on the current PHP version.")
            else:
                domain, staging = existing
                report["staging_created"] = False
                step("staging", True, f"Re-using {domain}, with any changes your developer made there.")
            report["staging_domain"] = domain

            code = await staging.read_code()
            changed, applied = apply_auto_fixes(code, mig.from_version, mig.to_version)
            if changed:
                await staging.write_files(changed)
            report["auto_fixes"] = applied
            step("auto_fixes", True, f"Applied {len(applied)} automatic fix(es) in {len(changed)} file(s)."
                 if applied else "No automatic fixes were needed.")

            await staging.set_php_version(mig.to_version)
            await staging.restart_php()
            version = await staging.php_version()
            checks = await run_checks(fetcher, _staging_site(mig.site, domain))
            code = await staging.read_code()
            remaining = scan_files(code, mig.from_version, mig.to_version)
            report.update(php_version=version, checks=checks, remaining=remaining, code_hash=code_hash(code))
            failing = [c for c in checks if not c["ok"]]
            step("switch", version == mig.to_version, f"Staging runs PHP {version}.")
            step("checks", not failing, "All checks passed on staging." if not failing else
                 "Failing on staging: " + ", ".join(f"{c['label'].lower()} {c['path']} ({c['status']})" for c in failing))
            step("rescan", remaining["errors"] == 0,
                 "No breaking code left." if remaining["errors"] == 0 else
                 f"{remaining['errors']} breaking change(s) still need a developer fix on staging.")
            passed = version == mig.to_version and not failing and remaining["errors"] == 0
            if passed:
                finish(True, f"Staging passed on PHP {mig.to_version}. Check {domain} yourself, then sign off.")
            else:
                finish(False, "Staging is not ready yet. Fix the items listed on staging, then run the staging tests again.")
        except (AdapterError, AppError) as exc:
            step("error", False, exc.message)
            finish(False, exc.message)
        except Exception as exc:  # noqa: BLE001 - never leave it stuck in staging_running
            log.error("Staging run for migration %s crashed: %s", mig_id, type(exc).__name__)
            db.rollback()
            mig = db.get(Migration, mig_id)
            finish(False, "Something went wrong on our side during the staging run.")


# --- sign-off and promotion ---------------------------------------------------

def sign_off(db: Session, mig: Migration, user: User) -> None:
    access.require(db, user, mig.site, "approve")
    if mig.state != MigrationState.staging_passed:
        raise AppError(409, "staging_not_passed", "Staging has to pass its tests before you can sign off.")
    signed_at = datetime.now(timezone.utc)
    _claim(db, mig, (MigrationState.staging_passed,), MigrationState.signed_off,
           {"signed_off_by": user.id, "signed_off_at": signed_at})
    audit(db, user.id, mig, "migration.signed_off", code_hash=(mig.staging_report or {}).get("code_hash"),
          signed_off_at=signed_at.isoformat())
    db.commit()


def start_promotion(db: Session, mig: Migration, user: User) -> PatchJob:
    access.require(db, user, mig.site, "approve")
    if mig.state in (MigrationState.promoting, MigrationState.promoted):
        raise AppError(409, "not_allowed_now", f"This migration is already {mig.state.value}.")
    if mig.state != MigrationState.signed_off or mig.signed_off_by is None:
        raise AppError(403, "signoff_required",
                       "Promotion to production needs the owner's or IT's sign-off in the dashboard first.")
    checks = [{"name": n, "label": CHECK_LABELS[n], "path": p} for n, p in check_targets(mig.site)]
    job = PatchJob(
        site_id=mig.site_id, from_version=mig.from_version, to_version=mig.to_version, state=PatchState.running,
        approved_by=mig.signed_off_by, approved_at=mig.signed_off_at, requested_by=user.id,
        billing={"item": "included", "covered_by": "migration", "migration_id": mig.id, "amount": 0},
        report={"kind": "migration", "migration_id": mig.id, "dry_run_at": mig.created_at.isoformat(), "steps": [],
                "plan": {"access": "migration promotion", "from_version": mig.from_version, "to_version": mig.to_version,
                         "checks": checks, "steps": mig.plan.get("steps", []),
                         "changes_made": "Signed off from the tested staging site."}},
    )
    db.add(job)
    db.flush()
    _claim(db, mig, (MigrationState.signed_off,), MigrationState.promoting,
           {"patch_job_id": job.id, "promotion": {"patch_job_id": job.id, "requested_by": user.id,
                                                   "requested_at": now_iso()}})
    audit(db, user.id, mig, "migration.promotion_started", patch_job_id=job.id)
    db.commit()
    return job


async def run_promotion(factory: sessionmaker[Session], settings: Settings, vault: CredentialVault,
                        world: DemoWorld | None, fetcher: SafeFetcher, store: BackupStore, mig_id: int,
                        actor_id: int, resume: bool = False) -> None:
    with factory() as db:
        mig = db.get(Migration, mig_id)
        if mig is None or mig.state != MigrationState.promoting or mig.patch_job_id is None:
            return
        job = db.get(PatchJob, mig.patch_job_id)
        promotion = dict(mig.promotion or {})

        def settle() -> None:
            db.refresh(job)
            ok = job.state == PatchState.succeeded
            promotion.update(outcome=job.state.value, message=job.report.get("message"), finished_at=now_iso())
            mig.promotion = promotion
            mig.state = MigrationState.promoted if ok else MigrationState.promotion_failed
            audit(db, actor_id, mig, "migration.promoted" if ok else "migration.promotion_failed",
                  patch_job_id=job.id, outcome=job.state.value)
            db.commit()

        if resume and job.state != PatchState.running:
            return settle()  # the production run finished; only the migration record was left behind
        if resume and job.report.get("changing"):
            # Interrupted while production was changing: put production back from the backup.
            prod = build_adapter(mig.site, vault, world)
            await PatchRunner(db, job, prod, fetcher, settings, actor_id, store).recover()
            return settle()

        def stop(message: str, state: MigrationState = MigrationState.promotion_failed) -> None:
            job.state = PatchState.failed
            job.report = {**job.report, "outcome": "failed", "message": message, "finished_at": now_iso()}
            promotion.update(outcome="failed", message=message, finished_at=now_iso())
            mig.promotion, mig.state = promotion, state
            if state == MigrationState.staging_failed:  # the sign-off was for code that no longer exists
                mig.signed_off_by = mig.signed_off_at = None
            audit(db, actor_id, mig, "migration.promotion_failed", message=message)
            db.commit()

        try:
            prod = build_adapter(mig.site, vault, world)
            staging = await prod.open_staging()
            if staging is None:
                return stop("The staging site is gone, so there is nothing tested to promote. Nothing was changed.")
            staging_code = await staging[1].read_code()
            if code_hash(staging_code) != (mig.staging_report or {}).get("code_hash"):
                return stop("The staging code changed after it was tested and signed off. Nothing was changed. "
                            "Run the staging tests again and sign off again.", MigrationState.staging_failed)
            prod_code = await prod.read_code()
        except (AdapterError, AppError) as exc:
            return stop(exc.message + " Nothing was changed.")

        # Code only: production keeps its own database and config files.
        deploy = {p: t for p, t in staging_code.items() if is_code(p) and not is_config(p) and prod_code.get(p) != t}
        promotion["files"] = sorted(deploy)
        runner = PatchRunner(db, job, prod, fetcher, settings, actor_id, store)
        await runner.run_patch(deploy=deploy)
        settle()


def migration_json(mig: Migration) -> dict:
    return {
        "id": mig.id, "site_id": mig.site_id, "domain": mig.site.domain, "state": mig.state.value,
        "source": mig.source, "from_version": mig.from_version, "to_version": mig.to_version,
        "breakage": mig.breakage, "plan": mig.plan, "staging_report": mig.staging_report,
        "signed_off_by": mig.signed_off_by,
        "signed_off_at": mig.signed_off_at.isoformat() if mig.signed_off_at else None,
        "promotion": mig.promotion, "patch_job_id": mig.patch_job_id,
        "report_url": f"/dashboard/migrations/{mig.id}",
        "created_at": mig.created_at.isoformat(),
    }
