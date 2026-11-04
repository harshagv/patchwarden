"""Phase A: durable jobs. A crash or restart at any point leaves the site safe, and the job finishes."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from patchwarden.fakes import SimulatedCrash
from patchwarden.jobs import JobQueue, make_handlers
from patchwarden.migration import service as migrations
from patchwarden.models import AuditLog, Job, Migration, PatchJob, User
from patchwarden.patch import service as patches

from ..conftest import demo
from ..spec.test_phase2_acceptance import add_site, dry_run
from ..spec.test_phase4_acceptance import plan, staging


def later(minutes: int = 5):
    """A clock past every lease: what a worker sees after the crashed one's lease ran out."""
    return lambda: datetime.now(timezone.utc) + timedelta(minutes=minutes)


def approve_and_queue(client, job_id: int) -> int:
    """Approve as the owner and record the durable job, without running it yet."""
    with client.app.state.sessionmaker() as db:
        job, owner = db.get(PatchJob, job_id), db.query(User).filter_by(email="owner@example.com").one()
        patches.approve(db, job, owner)
        return client.app.state.jobs.enqueue(db, "patch", job_id, owner.id).id


def run(coro):
    return asyncio.run(coro)


def restarted_worker(client) -> JobQueue:
    """A second worker, as after a restart: same database, clock past the dead worker's lease."""
    return JobQueue(client.app.state.sessionmaker, make_handlers(client.app.state), worker_id="after-restart",
                    clock=later())


def get(client, model, id_):
    with client.app.state.sessionmaker() as db:
        return db.get(model, id_)


def test_crash_mid_change_is_recovered_by_restoring_the_backup(client, auth_headers, world):
    host = world.get(demo("shop84"))
    files_before = dict(host.files)
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    queued = approve_and_queue(client, job["id"])

    host.crash_on = "restart_php"  # PHP was switched, workers not yet restarted: the worst moment
    with pytest.raises(SimulatedCrash):
        run(client.app.state.jobs.run_one(queued))

    # The process "died": the job is still leased and running, the site is half-changed.
    assert get(client, PatchJob, job["id"]).state.value == "running"
    assert get(client, Job, queued).state == "running"
    assert host.configured_version == "8.4.27"

    # Nobody can take it over while the dead worker's lease is still valid...
    assert run(client.app.state.jobs.run_one(queued)) is False
    # ...and after it runs out, the next worker recovers it.
    assert run(restarted_worker(client).run_pending()) == 1

    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "rolled_back"
    assert "after an interruption" in done["report"]["message"]
    assert done["report"]["rollback"]["trigger"] == "recovery" and done["report"]["rollback"]["ok"] is True
    assert host.php_version == "8.4.13" and host.configured_version is None and host.files == files_before
    finished = get(client, Job, queued)
    assert finished.state == "done" and finished.attempts == 2
    with client.app.state.sessionmaker() as db:
        assert db.query(AuditLog).filter_by(action="job.recovered").count() == 1


def test_crash_before_any_change_simply_runs_again(client, auth_headers, world):
    host = world.get(demo("shop84"))
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    queued = approve_and_queue(client, job["id"])
    host.crash_on = "create_backup"
    with pytest.raises(SimulatedCrash):
        run(client.app.state.jobs.run_one(queued))
    assert host.mutations == []  # nothing happened to the site

    run(restarted_worker(client).run_pending())
    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "succeeded" and host.php_version == "8.4.27"


def test_crash_during_the_automatic_rollback_still_ends_rolled_back(client, auth_headers, world):
    host = world.get(demo("fragile84"))  # its checkout breaks on 8.4.27, so it rolls back
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "fragile84"))
    queued = approve_and_queue(client, job["id"])
    host.crash_on = "restart_php#2"  # the rollback's restart
    with pytest.raises(SimulatedCrash):
        run(client.app.state.jobs.run_one(queued))

    run(restarted_worker(client).run_pending())
    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "rolled_back" and host.php_version == "8.4.13"


def test_startup_gives_orphaned_work_a_recovery_job(client, auth_headers, world):
    """A patch left 'running' by an older version (no job row at all) is picked up at start-up."""
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    with client.app.state.sessionmaker() as db:
        patches.approve(db, db.get(PatchJob, job["id"]), db.query(User).filter_by(email="owner@example.com").one())
    assert client.app.state.jobs.reconcile_orphans() == 1
    assert client.app.state.jobs.reconcile_orphans() == 0  # not twice
    run(client.app.state.jobs.run_pending())
    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "succeeded" and world.get(demo("shop84")).php_version == "8.4.27"


def test_a_job_that_keeps_failing_is_given_up_and_flagged(client, auth_headers):
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    queued = approve_and_queue(client, job["id"])

    async def boom(**_):
        raise RuntimeError("panel API timed out")

    clock = {"now": datetime.now(timezone.utc)}
    queue = JobQueue(client.app.state.sessionmaker, {"patch": boom}, clock=lambda: clock["now"])
    for _ in range(6):
        run(queue.run_one(queued))
        clock["now"] += timedelta(minutes=10)  # past the retry backoff
    j = get(client, Job, queued)
    assert j.state == "failed" and j.attempts == 6 and j.last_error
    pj = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert pj["state"] == "failed" and "may need attention" in pj["report"]["message"]


def test_interrupted_promotion_puts_production_back(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "legacy81")
    mig = plan(client, auth_headers, site_id)
    assert staging(client, auth_headers, mig["id"])["state"] == "staging_passed"
    client.post(f"/api/migrations/{mig['id']}/signoff", headers=auth_headers)
    prod = world.get(demo("legacy81"))
    files_before = dict(prod.files)

    with client.app.state.sessionmaker() as db:
        m, owner = db.get(Migration, mig["id"]), db.query(User).filter_by(email="owner@example.com").one()
        migrations.start_promotion(db, m, owner)
        queued = client.app.state.jobs.enqueue(db, "promotion", m.id, owner.id).id
    prod.crash_on = "restart_php"
    with pytest.raises(SimulatedCrash):
        run(client.app.state.jobs.run_one(queued))
    assert prod.configured_version == "8.4.27" and prod.files != files_before  # code deployed, half-switched

    run(restarted_worker(client).run_pending())
    done = client.get(f"/api/migrations/{mig['id']}", headers=auth_headers).json()
    assert done["state"] == "promotion_failed"
    assert prod.php_version == "8.1.31" and prod.files == files_before
    report = client.get(f"/api/patches/{done['patch_job_id']}", headers=auth_headers).json()
    assert report["state"] == "rolled_back" and "after an interruption" in report["report"]["message"]


def test_the_api_path_records_a_job_and_finishes_it(client, auth_headers, world):
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    client.post(f"/api/patches/{job['id']}/approve", headers=auth_headers)
    with client.app.state.sessionmaker() as db:
        jobs = db.query(Job).all()
    assert [(j.kind, j.ref_id, j.state) for j in jobs] == [("patch", job["id"], "done")]


def test_retention_never_deletes_a_backup_an_interrupted_change_still_needs(client, auth_headers, world):
    from patchwarden.patch.backups import purge_expired

    host = world.get(demo("shop84"))
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    queued = approve_and_queue(client, job["id"])
    host.crash_on = "restart_php"
    with pytest.raises(SimulatedCrash):
        run(client.app.state.jobs.run_one(queued))
    with client.app.state.sessionmaker() as db:  # the retention job runs while the patch is still interrupted
        assert purge_expired(db, client.app.state.backup_store, datetime.now(timezone.utc) + timedelta(days=60)) == 0
    run(restarted_worker(client).run_pending())
    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "rolled_back" and host.php_version == "8.4.13"
