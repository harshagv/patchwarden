"""Patch agent: dry run, owner approval, backup -> before-checks -> switch -> restart -> after-checks.

The order is fixed and no step can be skipped. Nothing changes on a site
without an approval record. If anything fails after the switch, the backup
is restored and the old version put back automatically. Every action writes
an audit_log entry; no entry, report or log line ever contains a credential.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.attributes import flag_modified

from ..config import Settings
from ..crypto import CredentialVault
from ..errors import AppError
from ..fakes import DemoWorld, FakeHostingAdapter
from ..models import AuditLog, Backup, Credential, PatchJob, PatchState, Platform, Site, User
from ..scanner.fetch import FetchError, SafeFetcher
from ..scanner.versions import FIXED_VERSIONS, LAST_DEAD_BRANCH, fmt, parse_version
from .adapters import (
    CREDENTIAL_FOR_METHOD,
    REAL_ADAPTERS,
    AdapterError,
    BackupArtifact,
    HostingAdapter,
)

log = logging.getLogger(__name__)

CHECK_LABELS = {"homepage": "Homepage", "login": "Login page", "form": "Checkout / form page"}
APPROVABLE = (PatchState.dry_run, PatchState.awaiting_approval)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(db: Session, *, user_id: int | None, site_id: int, action: str, **detail: Any) -> None:
    db.add(AuditLog(user_id=user_id, site_id=site_id, action=action, detail=detail))


# --- access -------------------------------------------------------------------

def build_adapter(site: Site, vault: CredentialVault, world: DemoWorld | None) -> HostingAdapter:
    kind = CREDENTIAL_FOR_METHOD.get(site.access_method)
    cred: Credential | None = None
    if kind is not None:
        cred = next((c for c in reversed(site.credentials) if c.kind == kind), None)
    if cred is None:
        raise AppError(409, "no_access",
                       "Add a hosting panel API token (cPanel or Plesk) or the agent API key for this site first.")
    try:
        token = vault.decrypt(cred.encrypted_value)
    except ValueError:
        raise AppError(409, "credential_unreadable",
                       "The saved access token can no longer be read. Please add it again.") from None
    adapter_cls = REAL_ADAPTERS[site.access_method]
    fake_host = world.get(site.domain) if world else None
    if fake_host is not None:
        return FakeHostingAdapter(fake_host, adapter_cls.display_name, token, world)
    return adapter_cls(site.domain, token)


# --- checks -------------------------------------------------------------------

def check_targets(site: Site) -> list[tuple[str, str]]:
    paths = dict(site.check_paths or {})
    if site.platform == Platform.wordpress:
        paths.setdefault("login", "/wp-login.php")
    targets = [("homepage", "/")]
    targets += [(name, paths[name]) for name in ("login", "form") if paths.get(name)]
    return targets


async def run_checks(fetcher: SafeFetcher, site: Site) -> list[dict]:
    results = []
    for name, path in check_targets(site):
        entry = {"name": name, "label": CHECK_LABELS[name], "path": path}
        try:
            r = await fetcher.fetch(f"https://{site.domain}{path}")
            entry.update(status=r.status_code, ok=r.status_code < 400)
        except FetchError as exc:
            entry.update(status=None, ok=False, detail=exc.message)
        results.append(entry)
    return results


# --- dry run ------------------------------------------------------------------

def _pick_target(current: str, requested: str | None, available: list[str]) -> str:
    cur = parse_version(current)
    if cur is None or cur.patch is None:
        raise AppError(409, "version_unreadable", "We could not read the exact PHP version from the host.")
    if cur.branch <= LAST_DEAD_BRANCH:
        raise AppError(409, "must_migrate",
                       f"PHP {fmt(cur.branch)} has no official patch. This site needs the Migration agent instead.")
    fixed = FIXED_VERSIONS.get(cur.branch)
    if fixed is None:
        raise AppError(409, "unsupported_version", f"PHP {current} is not in our release table yet.")

    def ok(v: str) -> bool:
        p = parse_version(v)
        return bool(p and p.patch is not None and p.branch == cur.branch
                    and (p.major, p.minor, p.patch) >= fixed and not p.suffix)

    current_t = (cur.major, cur.minor, cur.patch)
    if requested:
        if not ok(requested):
            raise AppError(422, "invalid_target",
                           f"Pick PHP {fmt(fixed)} or a newer {fmt(cur.branch)} release. "
                           "Moving to another PHP line is a migration, not a patch.")
        if requested not in available:
            raise AppError(422, "target_unavailable", f"The host does not offer PHP {requested} for this site.")
        target = requested
    else:
        candidates = [v for v in available if ok(v)]
        if not candidates:
            raise AppError(409, "no_fixed_version",
                           f"The host does not offer PHP {fmt(fixed)} or newer yet. Ask your host to add it.")
        target = max(candidates, key=lambda v: tuple(int(x) for x in v.split(".")))
    t = parse_version(target)
    if (t.major, t.minor, t.patch) <= current_t:
        raise AppError(409, "already_patched", f"This site already runs PHP {current}, which includes the fix.")
    return target


def _plan(site: Site, adapter: HostingAdapter, from_v: str, to_v: str) -> dict:
    checks = [{"name": n, "label": CHECK_LABELS[n], "path": p} for n, p in check_targets(site)]
    check_text = ", ".join(f"{c['label'].lower()} ({c['path']})" for c in checks)
    return {
        "access": adapter.display_name,
        "from_version": from_v,
        "to_version": to_v,
        "checks": checks,
        "steps": [
            f"Make a full backup of {site.domain} (files and database) through {adapter.display_name}, "
            "and prove it can be restored. If the backup fails, stop: nothing is changed.",
            f"Check that the site works now: {check_text}.",
            f"Switch PHP for {site.domain} from {from_v} to {to_v}.",
            "Restart the PHP workers so the new version is live.",
            f"Check {check_text} again, and confirm PHP {to_v} is running.",
            f"If any check fails: restore the backup and switch back to PHP {from_v} automatically.",
        ],
        "changes_made": "None. This is a dry run: nothing has been changed on the site.",
    }


async def create_dry_run(db: Session, *, site: Site, user: User, to_version: str | None,
                         vault: CredentialVault, world: DemoWorld | None,
                         state: PatchState = PatchState.dry_run, components: list[dict] | None = None,
                         origin: str | None = None) -> PatchJob:
    """A plan that changes nothing. WordPress Guard's "Fix it" creates it as awaiting_approval and may add
    plugin/theme updates that the plugin runs after approval."""
    busy = db.scalar(select(PatchJob.id).where(PatchJob.site_id == site.id, PatchJob.state == PatchState.running))
    if busy:
        raise AppError(409, "patch_in_progress", "A change is already running on this site. Wait for it to finish.")
    adapter = build_adapter(site, vault, world)
    try:
        # Read-only calls: a dry run never changes anything.
        current = await adapter.php_version()
        available = await adapter.available_versions()
    except AdapterError as exc:
        raise AppError(502, exc.code, exc.message) from None
    target = _pick_target(current, to_version, available)
    plan = _plan(site, adapter, current, target)
    if components:
        plan["components"] = components
        plan["steps"] = plan["steps"] + [f"After PHP is updated, ask the Patchwarden plugin to update the {c['type']} "
                                         f"{c['slug']} to {c['fixed_in']} or newer." for c in components]
    report = {"plan": plan, "dry_run_at": now_iso(), "steps": []}
    if origin:
        report["origin"] = origin
    job = PatchJob(site_id=site.id, from_version=current, to_version=target, state=state, report=report)
    db.add(job)
    db.flush()
    audit(db, user_id=user.id, site_id=site.id, action="patch.dry_run", patch_job_id=job.id,
          from_version=current, to_version=target, origin=origin)
    db.commit()
    return job


# --- approval and rollback ----------------------------------------------------

def _claim(db: Session, job: PatchJob, allowed: tuple[PatchState, ...], values: dict) -> None:
    """Atomically move a job to running, so a double click cannot start it twice."""
    result = db.execute(
        update(PatchJob).where(PatchJob.id == job.id, PatchJob.state.in_(allowed))
        .values(state=PatchState.running, **values)
    )
    if result.rowcount != 1:
        db.rollback()
        raise AppError(409, "not_allowed_now", f"This change is {job.state.value.replace('_', ' ')}, so that is not possible now.")
    db.commit()
    db.refresh(job)


def approve(db: Session, job: PatchJob, user: User) -> None:
    if job.site.owner_id != user.id:
        # Only the site owner approves changes to their site.
        raise AppError(403, "owner_only", "Only the site owner can approve this change.")
    approved_at = datetime.now(timezone.utc)
    _claim(db, job, APPROVABLE, {"approved_by": user.id, "approved_at": approved_at})
    audit(db, user_id=user.id, site_id=job.site_id, action="patch.approved", patch_job_id=job.id,
          from_version=job.from_version, to_version=job.to_version, approved_at=approved_at.isoformat())
    db.commit()


def request_rollback(db: Session, job: PatchJob, user: User) -> None:
    if job.site.owner_id != user.id:
        raise AppError(403, "owner_only", "Only the site owner can roll back this change.")
    if job.backup_id is None:
        raise AppError(409, "no_backup", "There is no backup for this change, so there is nothing to roll back to.")
    _claim(db, job, (PatchState.succeeded,), {})
    audit(db, user_id=user.id, site_id=job.site_id, action="patch.rollback_requested", patch_job_id=job.id,
          backup_id=job.backup_id)
    db.commit()


# --- execution ----------------------------------------------------------------

class PatchRunner:
    def __init__(self, db: Session, job: PatchJob, adapter: HostingAdapter, fetcher: SafeFetcher,
                 settings: Settings, actor_id: int):
        self.db, self.job, self.adapter, self.fetcher = db, job, adapter, fetcher
        self.settings, self.actor_id = settings, actor_id
        self.site = job.site
        self.report = dict(job.report or {})
        self.report.setdefault("steps", [])

    # bookkeeping
    def _save(self) -> None:
        self.job.report = self.report
        flag_modified(self.job, "report")
        self.db.commit()

    def step(self, name: str, ok: bool, detail: str) -> None:
        self.report["steps"].append({"step": name, "ok": ok, "detail": detail, "at": now_iso()})
        self._save()

    def audit(self, action: str, **detail: Any) -> None:
        audit(self.db, user_id=self.actor_id, site_id=self.site.id, action=action,
              patch_job_id=self.job.id, backup_id=self.job.backup_id, **detail)
        self.db.commit()

    def finish(self, state: PatchState, message: str) -> None:
        self.job.state = state
        self.report.update(outcome=state.value, message=message, finished_at=now_iso())
        self._save()
        self.audit(f"patch.{state.value}", message=message)

    def _artifact(self) -> BackupArtifact:
        b = self.job.backup
        return BackupArtifact(location=b.location, checksum=b.checksum)

    # the patch
    async def run_patch(self, deploy: dict[str, str] | None = None) -> None:
        """The Phase 2 run. A migration promotion passes `deploy`: the tested staging code, copied
        to production after the before-checks and before the PHP switch (rolled back with the backup)."""
        job, adapter = self.job, self.adapter
        self.report.update(started_at=now_iso(), approved_by=job.approved_by,
                           approved_at=job.approved_at.isoformat() if job.approved_at else None)
        changed = False
        try:
            current = await adapter.php_version()
            if current != job.from_version:
                self.step("precheck", False, f"The site now runs PHP {current}, not {job.from_version} as in the dry run.")
                return self.finish(PatchState.failed, "The site changed since the dry run. Nothing was changed. "
                                                      "Start a new dry run.")

            # 1. backup, verified, or stop
            try:
                artifact = await adapter.create_backup(self.settings.backup_dir)
                check = await adapter.verify_restore(artifact)
            except AdapterError as exc:
                self.step("backup", False, exc.message)
                return self.finish(PatchState.failed, "The backup failed, so we stopped. Nothing was changed.")
            backup = Backup(site_id=self.site.id, location=artifact.location, checksum=artifact.checksum,
                            verified=check.ok)
            self.db.add(backup)
            self.db.flush()
            job.backup_id = backup.id
            self.report["backup"] = {"id": backup.id, "location": artifact.location, "checksum": artifact.checksum,
                                     "verified": check.ok, "restore_dry_run": check.detail}
            self.audit("backup.created", location=artifact.location, checksum=artifact.checksum,
                       verified=check.ok, restore_dry_run=check.detail)
            if not check.ok:
                self.step("backup", False, check.detail)
                return self.finish(PatchState.failed, "The backup could not be verified, so we stopped. "
                                                      "Nothing was changed.")
            self.step("backup", True, check.detail)

            # 2. before-state
            before = await run_checks(self.fetcher, self.site)
            self.report["before"] = {"php_version": current, "checks": before, "at": now_iso()}
            failing = [c for c in before if not c["ok"]]
            if failing:
                self.step("before_checks", False, _describe(failing))
                return self.finish(PatchState.failed, "The site was not working properly before the change ("
                                   + _describe(failing) + "), so we stopped. Nothing was changed.")
            self.step("before_checks", True, "All checks passed.")

            changed = True
            if deploy:
                await adapter.write_files(deploy)
                self.audit("code.deployed", files=sorted(deploy))
                self.step("deploy", True, f"Copied {len(deploy)} tested file(s) from staging: "
                          + ", ".join(sorted(deploy)) + ".")

            # 3. switch, 4. restart
            await adapter.set_php_version(job.to_version)
            self.audit("php.version_changed", from_version=job.from_version, to_version=job.to_version)
            self.step("switch", True, f"PHP set to {job.to_version}.")
            await adapter.restart_php()
            self.audit("php.restarted")
            self.step("restart", True, "PHP workers restarted.")

            # 5. after-state
            after_version = await adapter.php_version()
            after = await run_checks(self.fetcher, self.site)
            self.report["after"] = {"php_version": after_version, "checks": after, "at": now_iso()}
            failing = [c for c in after if not c["ok"]]
            problems = []
            if after_version != job.to_version:
                problems.append(f"the site runs PHP {after_version} instead of {job.to_version}")
            if failing:
                problems.append(_describe(failing))
            if problems:
                reason = "; ".join(problems)
                self.step("after_checks", False, reason)
                return await self._rollback(trigger="automatic", reason=reason)
            self.step("after_checks", True, "All checks passed.")

            # 6. report
            self.finish(PatchState.succeeded,
                        f"PHP updated from {job.from_version} to {job.to_version}. All checks passed.")
        except AdapterError as exc:
            self.step("error", False, exc.message)
            if changed:
                return await self._rollback(trigger="automatic", reason=exc.message)
            self.finish(PatchState.failed, exc.message + " Nothing was changed.")
        except Exception as exc:  # noqa: BLE001 - never leave a job stuck in running
            log.error("Patch job %s crashed: %s", job.id, type(exc).__name__)
            self.db.rollback()
            if changed and job.backup_id:
                return await self._rollback(trigger="automatic", reason="an unexpected error during the change")
            self.finish(PatchState.failed, "Something went wrong on our side. Nothing was changed.")

    async def run_rollback(self) -> None:
        await self._rollback(trigger="owner", reason="the site owner asked for it")

    async def _rollback(self, *, trigger: str, reason: str) -> None:
        job, adapter = self.job, self.adapter
        info: dict[str, Any] = {"trigger": trigger, "reason": reason, "started_at": now_iso(),
                                "backup_id": job.backup_id}
        self.report["rollback"] = info
        try:
            await adapter.restore_backup(self._artifact())
            self.audit("backup.restored", trigger=trigger)
            await adapter.set_php_version(job.from_version)
            await adapter.restart_php()
            self.audit("php.version_changed", from_version=job.to_version, to_version=job.from_version,
                       trigger=trigger)
            version = await adapter.php_version()
            checks = await run_checks(self.fetcher, self.site)
        except AdapterError as exc:
            info.update(ok=False, detail=exc.message)
            self.step("rollback", False, exc.message)
            return self.finish(PatchState.failed, "The rollback did not finish: " + exc.message
                               + " Please contact your host now; the backup is kept at the location below.")
        info.update(php_version=version, checks=checks, finished_at=now_iso())
        failing = [c for c in checks if not c["ok"]]
        info["ok"] = version == job.from_version and not failing
        self.step("rollback", info["ok"], "Backup restored and PHP switched back to " + version + "."
                  + (" Still failing: " + _describe(failing) if failing else ""))
        why = "automatically because " if trigger == "automatic" else "because "
        if info["ok"]:
            self.finish(PatchState.rolled_back,
                        f"The change was rolled back {why}{reason}. The site is back on PHP {job.from_version} "
                        "and its checks pass.")
        else:
            self.finish(PatchState.failed,
                        f"The change was rolled back {why}{reason}, but the site is still not healthy. "
                        "Please contact your host.")


def _describe(failing: list[dict]) -> str:
    parts = []
    for c in failing:
        what = f"returned {c['status']}" if c.get("status") else (c.get("detail") or "did not answer")
        parts.append(f"{c['label'].lower()} {c['path']} {what}")
    return ", ".join(parts)


async def run_job(factory: sessionmaker[Session], settings: Settings, vault: CredentialVault,
                  world: DemoWorld | None, fetcher: SafeFetcher, job_id: int, actor_id: int, mode: str) -> None:
    """Background task: runs after the approve/rollback request has returned."""
    with factory() as db:
        job = db.get(PatchJob, job_id)
        if job is None or job.state != PatchState.running:
            return
        components = (job.report.get("plan") or {}).get("components") or []
        if mode == "patch" and components and job.from_version == job.to_version:
            # WordPress Guard "Fix it" with plugin/theme updates only: no PHP change, no panel needed.
            _queue_components(db, job, "Approved. Waiting for the Patchwarden plugin to run the updates (it checks in hourly).")
            return
        try:
            adapter = build_adapter(job.site, vault, world)
        except AppError as exc:
            # Access was revoked between approval and run.
            job.state = PatchState.failed
            job.report = {**job.report, "outcome": "failed", "message": exc.message + " Nothing was changed.",
                          "finished_at": now_iso()}
            audit(db, user_id=actor_id, site_id=job.site_id, action="patch.failed", patch_job_id=job.id,
                  message=exc.message)
            db.commit()
            return
        runner = PatchRunner(db, job, adapter, fetcher, settings, actor_id)
        if mode == "rollback":
            await runner.run_rollback()
        else:
            await runner.run_patch()
            db.refresh(job)
            if components and job.state == PatchState.succeeded:
                _queue_components(db, job, job.report.get("message", "") +
                                  " Plugin/theme updates are queued for the Patchwarden plugin.")


def _queue_components(db: Session, job: PatchJob, message: str) -> None:
    from ..wpguard.service import queue_component_updates

    queue_component_updates(db, job)
    job.state = PatchState.running  # finished when the plugin reports back
    job.report = {**job.report, "message": message, "started_at": job.report.get("started_at") or now_iso()}
    db.commit()


def job_json(job: PatchJob) -> dict:
    b = job.backup
    return {
        "id": job.id,
        "site_id": job.site_id,
        "domain": job.site.domain,
        "state": job.state.value,
        "from_version": job.from_version,
        "to_version": job.to_version,
        "backup": ({"id": b.id, "location": b.location, "checksum": b.checksum, "verified": b.verified,
                    "created_at": b.created_at.isoformat()} if b else None),
        "approved_by": job.approved_by,
        "approved_at": job.approved_at.isoformat() if job.approved_at else None,
        "report": job.report,
        "report_url": f"/dashboard/patches/{job.id}",
        "created_at": job.created_at.isoformat(),
    }
