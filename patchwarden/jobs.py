"""Durable job queue: patch, rollback, staging and promotion runs survive crashes and restarts.

- enqueue() writes a job row in the same database as the work it drives.
- A worker claims a job with an atomic UPDATE that takes a lease, and keeps the lease alive with a
  heartbeat while the job runs.
- If the process dies, the lease runs out. Any worker (the poller, or the next start-up) claims the
  job again and runs it with `resume=True`. The runners then recover safely: see PatchRunner.recover().
- An unexpected error retries with backoff, up to max_attempts. After that the job is failed, and the
  patch or migration is marked as needing attention, so it never stays "running" forever.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from .models import (AuditLog, Job, Migration, MigrationState, PatchJob, PatchState, PluginAction, ScanBatch,
                     VirtualPatch)

log = logging.getLogger(__name__)

KINDS = ("patch", "rollback", "staging", "promotion", "bulk_scan", "vpatch_apply", "vpatch_remove")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class JobQueue:
    def __init__(self, factory: sessionmaker[Session], handlers: dict[str, Callable[..., Awaitable[None]]], *,
                 lease_seconds: int = 60, worker_id: str | None = None,
                 clock: Callable[[], datetime] = utcnow):
        self.factory = factory
        self.handlers = handlers
        self.lease = timedelta(seconds=lease_seconds)
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.clock = clock
        self._stopping = asyncio.Event()

    # --- producing ---------------------------------------------------------------

    def enqueue(self, db: Session, kind: str, ref_id: int, actor_id: int | None, *, attempts: int = 0) -> Job:
        if kind not in KINDS:
            raise ValueError(f"unknown job kind {kind}")
        job = Job(kind=kind, ref_id=ref_id, actor_id=actor_id, state="queued", attempts=attempts,
                  created_at=self.clock())
        db.add(job)
        db.commit()
        return job

    # --- consuming ---------------------------------------------------------------

    def _claim(self, db: Session, job_id: int) -> Job | None:
        now = self.clock()
        claimable = and_(
            Job.id == job_id,
            Job.state.in_(("queued", "running")),
            # queued and not backing off, or running with a lease that has run out (its worker died)
            or_(Job.lease_until.is_(None), Job.lease_until < now),
        )
        result = db.execute(update(Job).where(claimable).values(
            state="running", lease_owner=self.worker_id, lease_until=now + self.lease,
            attempts=Job.attempts + 1, updated_at=now))
        db.commit()
        if result.rowcount != 1:
            return None
        return db.get(Job, job_id)

    async def _heartbeat(self, job_id: int) -> None:
        while True:
            await asyncio.sleep(max(1.0, self.lease.total_seconds() / 3))
            with self.factory() as db:
                db.execute(update(Job).where(Job.id == job_id, Job.lease_owner == self.worker_id,
                                             Job.state == "running")
                           .values(lease_until=self.clock() + self.lease, updated_at=self.clock()))
                db.commit()

    async def run_one(self, job_id: int) -> bool:
        """Claim and run one job. Returns False if another worker has it (or it is done)."""
        with self.factory() as db:
            job = self._claim(db, job_id)
            if job is None:
                return False
            kind, ref_id, actor_id, attempts, max_attempts = (job.kind, job.ref_id, job.actor_id, job.attempts,
                                                              job.max_attempts)
            if attempts > max_attempts:
                self._give_up(db, job, "Gave up after repeated failures.")
                return True

        beat = asyncio.create_task(self._heartbeat(job_id))
        try:
            await self.handlers[kind](ref_id=ref_id, actor_id=actor_id, resume=attempts > 1)
        except Exception as exc:  # noqa: BLE001 - retried with backoff; the runners keep their own state safe
            log.error("Job %s (%s) failed on attempt %s: %s", job_id, kind, attempts, type(exc).__name__)
            with self.factory() as db:
                db.execute(update(Job).where(Job.id == job_id).values(
                    state="queued", lease_owner=None, last_error=type(exc).__name__[:500],
                    lease_until=self.clock() + timedelta(seconds=min(300, 15 * attempts)), updated_at=self.clock()))
                db.commit()
            return True
        finally:
            # A BaseException (process shutdown, a simulated crash) skips the code below on purpose:
            # the lease stays, runs out, and the job is picked up again and resumed.
            beat.cancel()
        with self.factory() as db:
            db.execute(update(Job).where(Job.id == job_id).values(
                state="done", lease_owner=None, lease_until=None, finished_at=self.clock(), updated_at=self.clock()))
            db.commit()
        return True

    def _give_up(self, db: Session, job: Job, why: str) -> None:
        job.state, job.finished_at, job.lease_owner, job.last_error = "failed", self.clock(), None, why
        message = ("We could not finish this change after several attempts. The site may need attention: "
                   "check it, and roll back from the report page if needed.")
        if job.kind in ("patch", "rollback", "promotion"):
            pj = db.get(PatchJob, job.ref_id) if job.kind != "promotion" else None
            if job.kind == "promotion":
                mig = db.get(Migration, job.ref_id)
                pj = db.get(PatchJob, mig.patch_job_id) if mig and mig.patch_job_id else None
                if mig is not None:
                    mig.state = MigrationState.promotion_failed
            if pj is not None and pj.state == PatchState.running:
                pj.state = PatchState.failed
                pj.report = {**(pj.report or {}), "outcome": "failed", "message": message,
                             "finished_at": self.clock().isoformat()}
        elif job.kind == "staging":
            mig = db.get(Migration, job.ref_id)
            if mig is not None and mig.state == MigrationState.staging_running:
                mig.state = MigrationState.staging_failed
        elif job.kind == "bulk_scan":
            batch = db.get(ScanBatch, job.ref_id)
            if batch is not None and batch.state in ("queued", "running"):
                batch.state, batch.finished_at = "failed", self.clock()
        elif job.kind in ("vpatch_apply", "vpatch_remove"):
            vp = db.get(VirtualPatch, job.ref_id)
            if vp is not None and vp.state in ("applying", "removing"):
                vp.state = "failed"
                vp.report = {**(vp.report or {}), "outcome": "failed", "error": "gave_up",
                             "message": "We could not reach the provider after several attempts. Check the edge "
                                        "settings, then try removing or planning again.",
                             "finished_at": self.clock().isoformat()}
        db.add(AuditLog(user_id=job.actor_id, action="job.gave_up",
                        detail={"job_id": job.id, "kind": job.kind, "ref_id": job.ref_id, "attempts": job.attempts}))
        db.commit()

    async def run_pending(self, limit: int = 50) -> int:
        """Run every job that is ready now: queued ones, and running ones whose worker died."""
        now = self.clock()
        with self.factory() as db:
            ids = list(db.scalars(select(Job.id).where(
                Job.state.in_(("queued", "running")),
                or_(Job.lease_until.is_(None), Job.lease_until < now)).order_by(Job.id).limit(limit)))
        ran = 0
        for job_id in ids:
            ran += await self.run_one(job_id)
        return ran

    async def poll_forever(self, interval: float) -> None:
        while not self._stopping.is_set():
            try:
                await self.run_pending()
            except Exception as exc:  # noqa: BLE001 - the poller must keep going
                log.error("Job poller error: %s", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stopping.set()

    # --- start-up ----------------------------------------------------------------

    def reconcile_orphans(self) -> int:
        """Give every patch or migration left 'running' without a live job a recovery job."""
        created = 0
        with self.factory() as db:
            active = {(j.kind, j.ref_id) for j in db.scalars(select(Job).where(Job.state.in_(("queued", "running"))))}
            waiting_on_plugin = set(db.scalars(select(PluginAction.patch_job_id).where(
                PluginAction.state.in_(("queued", "sent")), PluginAction.patch_job_id.is_not(None))))
            promoting = {m.patch_job_id for m in db.scalars(select(Migration).where(
                Migration.state == MigrationState.promoting))}
            for pj in db.scalars(select(PatchJob).where(PatchJob.state == PatchState.running)):
                if pj.id in waiting_on_plugin or pj.id in promoting:
                    continue  # waiting on the WordPress plugin, or driven by a promotion job
                if ("patch", pj.id) not in active and ("rollback", pj.id) not in active:
                    self.enqueue(db, "patch", pj.id, pj.approved_by, attempts=1)  # attempts=1: resume
                    created += 1
            for batch in db.scalars(select(ScanBatch).where(ScanBatch.state.in_(("queued", "running")))):
                if ("bulk_scan", batch.id) not in active:
                    self.enqueue(db, "bulk_scan", batch.id, batch.owner_id, attempts=1)
                    created += 1
            for vp in db.scalars(select(VirtualPatch).where(VirtualPatch.state.in_(("applying", "removing")))):
                kind = "vpatch_apply" if vp.state == "applying" else "vpatch_remove"
                if (kind, vp.id) not in active:
                    self.enqueue(db, kind, vp.id, vp.approved_by, attempts=1)
                    created += 1
            for mig in db.scalars(select(Migration).where(
                    Migration.state.in_((MigrationState.staging_running, MigrationState.promoting)))):
                kind = "staging" if mig.state == MigrationState.staging_running else "promotion"
                if (kind, mig.id) not in active:
                    self.enqueue(db, kind, mig.id, mig.signed_off_by, attempts=1)
                    created += 1
        if created:
            log.warning("Recovered %s interrupted job(s) at start-up", created)
        return created


def make_handlers(state: Any) -> dict[str, Callable[..., Awaitable[None]]]:
    """Bind the runners to the app's shared services (app.state)."""
    from .migration import service as migrations
    from .patch import service as patches

    def deps():
        return (state.sessionmaker, state.settings, state.vault, state.demo_world, state.scanner.fetcher,
                state.backup_store)

    async def patch(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        await patches.run_job(*deps(), ref_id, actor_id, "patch", resume=resume)

    async def rollback(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        await patches.run_job(*deps(), ref_id, actor_id, "rollback", resume=resume)

    async def staging(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        await migrations.run_staging(*deps(), ref_id, actor_id, resume=resume)

    async def promotion(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        await migrations.run_promotion(*deps(), ref_id, actor_id, resume=resume)

    async def bulk_scan(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        from .scanner.service import run_batch

        await run_batch(state.sessionmaker, state.scanner, ref_id, resume=resume)

    async def vpatch_apply(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        from .virtual_patch import service as vpatches

        await vpatches.run(state.sessionmaker, state.vault, state.demo_world, ref_id, actor_id, "apply", state=state)

    async def vpatch_remove(*, ref_id: int, actor_id: int | None, resume: bool) -> None:
        from .virtual_patch import service as vpatches

        await vpatches.run(state.sessionmaker, state.vault, state.demo_world, ref_id, actor_id, "remove", state=state)

    return {"patch": patch, "rollback": rollback, "staging": staging, "promotion": promotion,
            "bulk_scan": bulk_scan, "vpatch_apply": vpatch_apply, "vpatch_remove": vpatch_remove}
