"""Phase 2 acceptance tests, one per bullet in SPEC.md section 5."""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path

from patchwarden.models import AuditLog, Backup, Credential, PatchJob

from .conftest import demo


def add_site(client, auth, label: str, *, token: str = "demo-panel-token-123", kind: str = "cpanel_token") -> int:
    r = client.post("/api/sites", json={"domain": demo(label), "login_path": "/login", "form_path": "/checkout"},
                    headers=auth)
    assert r.status_code == 201, r.text
    site_id = r.json()["id"]
    r = client.post(f"/api/sites/{site_id}/credentials", json={"kind": kind, "value": token}, headers=auth)
    assert r.status_code == 201, r.text
    return site_id


def dry_run(client, auth, site_id: int, **extra) -> dict:
    r = client.post("/api/patches", json={"site_id": site_id, **extra}, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()


def approve(client, auth, job_id: int) -> dict:
    r = client.post(f"/api/patches/{job_id}/approve", headers=auth)
    assert r.status_code == 202, r.text
    # The patch runs as a background task; TestClient waits for it before returning.
    return client.get(f"/api/patches/{job_id}", headers=auth).json()


def scan_risk(client, label: str) -> str:
    return client.post("/api/scans", json={"domain": demo(label)}).json()["scans"][0]["risk"]


def test_dry_run_changes_nothing(client, auth_headers, world, settings):
    host = world.get(demo("shop84"))
    before = host.snapshot()
    site_id = add_site(client, auth_headers, "shop84")

    job = dry_run(client, auth_headers, site_id)

    assert job["state"] == "dry_run"
    assert (job["from_version"], job["to_version"]) == ("8.4.13", "8.4.27")
    assert job["report"]["plan"]["changes_made"].startswith("None.")
    assert any("8.4.13 to 8.4.27" in step for step in job["report"]["plan"]["steps"])
    # Nothing on the site moved: no backup, no switch, no restart, same files and data.
    assert host.mutations == [] and host.restarts == 0
    assert host.snapshot() == before
    assert not Path(settings.backup_dir).exists()
    with client.app.state.sessionmaker() as db:
        assert db.query(Backup).count() == 0
        assert db.get(PatchJob, job["id"]).approved_by is None
    assert scan_risk(client, "shop84") == "patch_now"


def test_approved_patch_moves_php84_to_fixed_version_and_checks_pass(client, auth_headers, world):
    host = world.get(demo("shop84"))
    site_id = add_site(client, auth_headers, "shop84")
    job = dry_run(client, auth_headers, site_id)
    assert scan_risk(client, "shop84") == "patch_now"

    done = approve(client, auth_headers, job["id"])

    assert done["state"] == "succeeded", done["report"]
    assert host.php_version == "8.4.27"
    assert host.mutations == ["create_backup", "set_php_version:8.4.27", "restart_php"]
    report = done["report"]
    assert report["before"]["php_version"] == "8.4.13" and report["after"]["php_version"] == "8.4.27"
    assert [c["path"] for c in report["after"]["checks"]] == ["/", "/login", "/checkout"]
    assert all(c["ok"] for c in report["before"]["checks"] + report["after"]["checks"])
    assert [s["step"] for s in report["steps"]] == ["backup", "before_checks", "switch", "restart", "after_checks"]

    # The backup was taken first, is encrypted on disk, and decrypts to exactly the checksummed archive.
    backup = done["backup"]
    assert backup["verified"] is True and backup["encrypted"] is True and backup["expires_at"]
    on_disk = Path(backup["location"]).read_bytes()
    assert b"wp-config.php" not in on_disk and b"orders" not in on_disk
    archive = client.app.state.backup_store.read(backup["location"], backup["checksum"])
    assert hashlib.sha256(archive).hexdigest() == backup["checksum"] and b"wp-config.php" in archive
    assert done["approved_by"] is not None and done["approved_at"]

    with client.app.state.sessionmaker() as db:
        actions = [a.action for a in db.query(AuditLog).filter(AuditLog.site_id == site_id).order_by(AuditLog.id)]
        approved = db.query(AuditLog).filter_by(action="patch.approved").one()
        changed = db.query(AuditLog).filter_by(action="php.version_changed").one()
    assert actions[-5:] == ["patch.approved", "backup.created", "php.version_changed", "php.restarted",
                            "patch.succeeded"]
    assert approved.user_id == done["approved_by"]
    assert changed.detail["backup_id"] == backup["id"]
    assert changed.detail["from_version"] == "8.4.13" and changed.detail["to_version"] == "8.4.27"

    assert scan_risk(client, "shop84") == "safe"


def test_failing_post_check_rolls_back_automatically_and_report_says_so(client, auth_headers, world):
    host = world.get(demo("fragile84"))  # its checkout page breaks on 8.4.27
    files_before = host.snapshot()["files"]
    site_id = add_site(client, auth_headers, "fragile84")
    job = dry_run(client, auth_headers, site_id)

    done = approve(client, auth_headers, job["id"])

    assert done["state"] == "rolled_back"
    rollback = done["report"]["rollback"]
    assert rollback["trigger"] == "automatic" and rollback["ok"] is True
    assert "/checkout returned 500" in rollback["reason"]
    assert "rolled back automatically" in done["report"]["message"]
    after = {c["path"]: c for c in done["report"]["after"]["checks"]}
    assert after["/checkout"]["ok"] is False and after["/"]["ok"] is True
    assert all(c["ok"] for c in rollback["checks"])
    # The site is back where it started.
    assert host.php_version == "8.4.13"
    assert host.files == files_before
    assert host.mutations == ["create_backup", "set_php_version:8.4.27", "restart_php",
                              "restore_backup", "set_php_version:8.4.13", "restart_php"]

    # The printable report says it too.
    _login_cookie(client)  # the client keeps the session cookie
    page = client.get(f"/dashboard/patches/{job['id']}")
    assert page.status_code == 200
    assert "Rolled back" in page.text and "Started automatically" in page.text
    assert "/checkout returned 500" in page.text


def test_no_credential_in_logs_reports_or_responses(client, auth_headers, world, settings, caplog):
    canary = f"CANARY-{uuid.uuid4().hex}"
    seen: list[str] = []

    def call(method, url, **kw):
        r = client.request(method, url, **kw)
        seen.append(r.text)
        seen.extend(f"{k}: {v}" for k, v in r.headers.items())
        return r

    _login_cookie(client)
    with caplog.at_level(logging.DEBUG):
        site = call("POST", "/api/sites", json={"domain": demo("shop84"), "login_path": "/login"},
                    headers=auth_headers).json()
        call("POST", f"/api/sites/{site['id']}/credentials", json={"kind": "cpanel_token", "value": canary},
             headers=auth_headers)
        call("GET", f"/api/sites/{site['id']}", headers=auth_headers)
        call("GET", "/api/sites", headers=auth_headers)
        job = call("POST", "/api/patches", json={"site_id": site["id"]}, headers=auth_headers).json()
        call("GET", f"/dashboard/patches/{job['id']}")
        call("POST", f"/api/patches/{job['id']}/approve", headers=auth_headers)
        call("GET", f"/api/patches/{job['id']}", headers=auth_headers)
        call("GET", f"/dashboard/patches/{job['id']}")
        call("GET", "/dashboard/sites")
        call("POST", f"/api/patches/{job['id']}/rollback", headers=auth_headers)
        call("GET", f"/api/patches/{job['id']}", headers=auth_headers)

        # A token the panel rejects: the error must not echo it.
        fragile = call("POST", "/api/sites", json={"domain": demo("fragile84")}, headers=auth_headers).json()
        world.get(demo("fragile84")).expected_token = "the-real-token-value"
        call("POST", f"/api/sites/{fragile['id']}/credentials", json={"kind": "plesk_token", "value": canary},
             headers=auth_headers)
        r = call("POST", "/api/patches", json={"site_id": fragile["id"]}, headers=auth_headers)
        assert r.status_code == 502 and r.json()["error"] == "auth_failed"
        # Validation errors on the credential endpoint do not echo it either.
        call("POST", f"/api/sites/{site['id']}/credentials", json={"kind": "ssh_key", "value": canary},
             headers=auth_headers)
        call("POST", f"/api/sites/{site['id']}/credentials", json={"kind": "nope", "value": canary},
             headers=auth_headers)

    final = client.get(f"/api/patches/{job['id']}", headers=auth_headers).json()
    assert final["state"] == "rolled_back"

    blob = "\n".join(seen)
    logs = caplog.text + "\n".join(str(r.__dict__) for r in caplog.records)
    assert canary not in blob
    assert canary not in logs
    with client.app.state.sessionmaker() as db:
        for row in db.query(PatchJob).all():
            assert canary not in str(row.report)
        for row in db.query(AuditLog).all():
            assert canary not in str(row.detail)
        for cred in db.query(Credential).all():
            assert canary.encode() not in cred.encrypted_value
            assert canary not in repr(cred)
        # ...but it is stored, encrypted, and decrypts back for the adapter.
        assert any(client.app.state.vault.decrypt(c.encrypted_value) == canary for c in db.query(Credential).all())
    for f in Path(settings.backup_dir).rglob("*"):
        if f.is_file():
            assert canary.encode() not in f.read_bytes()


def _login_cookie(client) -> None:
    r = client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
