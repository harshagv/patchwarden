"""Patch agent safety rules beyond the acceptance tests: stop early, owner-only, no double runs."""

from __future__ import annotations

from patchwarden.fakes import FakeHost
from patchwarden.models import AuditLog, Backup

from ..conftest import demo
from ..spec.test_phase2_acceptance import add_site, approve, dry_run


def _other_user(client) -> dict:
    client.post("/api/auth/register", json={"email": "stranger@example.com", "password": "another long password"})
    token = client.post("/api/auth/login", json={"email": "stranger@example.com",
                                                  "password": "another long password"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_backup_failure_stops_before_any_change(client, auth_headers, world):
    host = world.get(demo("shop84"))
    host.fail_backup = True
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed"
    assert "backup failed" in done["report"]["message"] and "Nothing was changed" in done["report"]["message"]
    assert host.php_version == "8.4.13" and host.mutations == []
    assert done["backup"] is None


def test_unverifiable_backup_stops_before_any_change(client, auth_headers, world):
    host = world.get(demo("shop84"))
    host.corrupt_backup = True
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed"
    assert "could not be verified" in done["report"]["message"]
    assert done["backup"]["verified"] is False
    assert "checksum does not match" in done["report"]["backup"]["restore_dry_run"]
    assert host.mutations == ["create_backup"] and host.php_version == "8.4.13"


def test_unhealthy_site_is_not_patched(client, auth_headers, world):
    host = world.get(demo("shop84"))
    host.pages["/login"] = 500
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed"
    assert "not working properly before the change" in done["report"]["message"]
    assert host.mutations == ["create_backup"]  # backup taken, nothing switched
    assert host.php_version == "8.4.13"


def test_stale_dry_run_is_refused(client, auth_headers, world):
    host = world.get(demo("shop84"))
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    host.php_version = "8.4.20"  # someone changed the site after the dry run
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed" and "changed since the dry run" in done["report"]["message"]
    assert host.mutations == []


def test_owner_can_roll_back_a_successful_patch(client, auth_headers, world):
    host = world.get(demo("shop84"))
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    assert approve(client, auth_headers, job["id"])["state"] == "succeeded"
    host.files["app.php"] = "<?php echo 'changed after patch';"

    r = client.post(f"/api/patches/{job['id']}/rollback", headers=auth_headers)
    assert r.status_code == 202
    done = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert done["state"] == "rolled_back"
    assert done["report"]["rollback"]["trigger"] == "owner"
    assert host.php_version == "8.4.13"
    assert host.files["app.php"] == "<?php echo 'shop';"  # restored from the backup
    with client.app.state.sessionmaker() as db:
        assert db.query(AuditLog).filter_by(action="patch.rollback_requested").count() == 1
        assert db.query(AuditLog).filter_by(action="backup.restored").one().detail["backup_id"] == done["backup"]["id"]


def test_failed_rollback_is_reported_not_hidden(client, auth_headers, world):
    host = world.get(demo("fragile84"))
    host.fail_restore = True
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "fragile84"))
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed"
    assert "rollback did not finish" in done["report"]["message"]
    assert done["report"]["rollback"]["ok"] is False
    assert done["backup"]["location"]  # kept for the host to restore by hand


def test_approval_is_owner_only_and_runs_once(client, auth_headers, world):
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    stranger = _other_user(client)
    assert client.post(f"/api/patches/{job['id']}/approve").status_code == 401
    assert client.post(f"/api/patches/{job['id']}/approve", headers=stranger).status_code == 404
    assert client.get(f"/api/patches/{job['id']}", headers=stranger).status_code == 404
    assert world.get(demo("shop84")).mutations == []

    assert approve(client, auth_headers, job["id"])["state"] == "succeeded"
    again = client.post(f"/api/patches/{job['id']}/approve", headers=auth_headers)
    assert again.status_code == 409 and again.json()["error"] == "not_allowed_now"
    assert world.get(demo("shop84")).mutations.count("set_php_version:8.4.27") == 1


def test_rollback_only_after_success(client, auth_headers):
    job = dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))
    r = client.post(f"/api/patches/{job['id']}/rollback", headers=auth_headers)
    assert r.status_code == 409


def test_revoked_access_stops_an_approved_job(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    job = dry_run(client, auth_headers, site_id)
    cred_id = client.get(f"/api/sites/{site_id}", headers=auth_headers).json()["credentials"][0]["id"]
    r = client.delete(f"/api/sites/{site_id}/credentials/{cred_id}", headers=auth_headers)
    assert r.json() == {"revoked": cred_id, "access_method": "external"}
    done = approve(client, auth_headers, job["id"])
    assert done["state"] == "failed" and world.get(demo("shop84")).mutations == []


def test_dry_run_needs_access(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("shop84")}, headers=auth_headers).json()["id"]
    r = client.post("/api/patches", json={"site_id": site_id}, headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "no_access"


def test_real_panel_is_not_faked(client, auth_headers):
    """Outside the demo world the real cPanel adapter is used, and it refuses rather than pretends."""
    site_id = client.post("/api/sites", json={"domain": "example.com"}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "x" * 20},
                headers=auth_headers)
    r = client.post("/api/patches", json={"site_id": site_id}, headers=auth_headers)
    assert r.status_code == 502
    assert r.json()["error"] == "adapter_not_connected"


def test_target_version_rules(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    for target, code in (("8.5.12", "invalid_target"), ("8.4.20", "invalid_target"), ("8.4.99", "target_unavailable")):
        r = client.post("/api/patches", json={"site_id": site_id, "to_version": target}, headers=auth_headers)
        assert r.status_code == 422 and r.json()["error"] == code

    world.hosts[demo("old81")] = FakeHost(domain=demo("old81"), php_version="8.1.31", available_versions=["8.1.31"])
    old = add_site(client, auth_headers, "old81")
    r = client.post("/api/patches", json={"site_id": old}, headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "must_migrate"

    world.get(demo("shop84")).php_version = "8.4.27"
    r = client.post("/api/patches", json={"site_id": site_id}, headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "already_patched"


def test_credentials_are_tokens_only_and_never_returned(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("shop84")}, headers=auth_headers).json()["id"]
    r = client.post(f"/api/sites/{site_id}/credentials", json={"kind": "wp_app_password", "value": "abcd efgh ijkl"},
                    headers=auth_headers)
    assert r.status_code == 422 and r.json()["error"] == "kind_not_supported_yet"
    r = client.post(f"/api/sites/{site_id}/credentials", json={"kind": "plesk_token", "value": "plesk-key-value-1"},
                    headers=auth_headers)
    assert set(r.json()) == {"id", "kind", "created_at", "access_method"}
    site = client.get(f"/api/sites/{site_id}", headers=auth_headers).json()
    assert site["access_method"] == "plesk"
    assert site["credentials"] == [{"id": r.json()["id"], "kind": "plesk_token", "created_at": r.json()["created_at"]}]
    stranger = _other_user(client)
    assert client.post(f"/api/sites/{site_id}/credentials", json={"kind": "plesk_token", "value": "z" * 12},
                       headers=stranger).status_code == 404


def test_no_backup_rows_from_a_dry_run(client, auth_headers):
    dry_run(client, auth_headers, add_site(client, auth_headers, "shop83"))
    with client.app.state.sessionmaker() as db:
        assert db.query(Backup).count() == 0
