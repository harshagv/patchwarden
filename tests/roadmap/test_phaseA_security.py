"""Phase A: encrypted backups and retention, key rotation, the audit hash chain, rate limits, MFA, revocation."""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

from patchwarden.__main__ import rotate_credentials, verify_audit
from patchwarden.app import create_app
from patchwarden.models import AuditLog, Backup, Credential, Role, User
from patchwarden.patch.backups import BackupError, BackupStore, purge_expired
from patchwarden.security import totp
from patchwarden.security.crypto import CredentialVault

from ..conftest import demo
from ..spec.test_phase2_acceptance import add_site, approve, dry_run


def patched(client, auth, label="shop84") -> dict:
    return approve(client, auth, dry_run(client, auth, add_site(client, auth, label))["id"])


# --- encrypted backups ----------------------------------------------------------

def test_backups_are_encrypted_and_tampering_is_caught(client, auth_headers):
    done = patched(client, auth_headers)
    b = done["backup"]
    blob = Path(b["location"]).read_bytes()
    assert blob.startswith(b"PWBK1\n") and b"orders" not in blob and b"app.php" not in blob
    assert oct(Path(b["location"]).stat().st_mode)[-3:] == "600"

    damaged = bytearray(blob)
    damaged[-5] ^= 0xFF
    Path(b["location"]).write_bytes(bytes(damaged))
    with pytest.raises(BackupError, match="could not be decrypted"):
        client.app.state.backup_store.read(b["location"], b["checksum"])
    # A rollback from a damaged backup stops and says so, rather than restoring garbage.
    client.post(f"/api/patches/{done['id']}/rollback", headers=auth_headers)
    after = client.get(f"/api/patches/{done['id']}", headers=auth_headers).json()
    assert after["state"] == "failed" and "could not be decrypted" in after["report"]["message"]


def test_backup_key_rotation(settings, tmp_path):
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    s_old = replace(settings, backup_key=old, backup_dir=tmp_path)
    stored = BackupStore(s_old).put("x.example", b"archive bytes", "")
    assert BackupStore(replace(s_old, backup_key=f"{new},{old}")).read(stored.location, stored.checksum) == b"archive bytes"
    with pytest.raises(BackupError):
        BackupStore(replace(s_old, backup_key=new)).read(stored.location, stored.checksum)


def test_expired_backups_are_purged_and_rollback_is_refused(client, auth_headers):
    done = patched(client, auth_headers)
    location = Path(done["backup"]["location"])
    with client.app.state.sessionmaker() as db:
        assert purge_expired(db, client.app.state.backup_store) == 0  # still within retention
        assert purge_expired(db, client.app.state.backup_store, datetime.now(timezone.utc) + timedelta(days=31)) == 1
        b = db.get(Backup, done["backup"]["id"])
        assert b.deleted_at is not None
        assert db.query(AuditLog).filter_by(action="backup.purged").count() == 1
    assert not location.exists()
    r = client.post(f"/api/patches/{done['id']}/rollback", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "backup_expired"


# --- credential key rotation ------------------------------------------------------

def test_credential_key_rotation_end_to_end(settings, scanner, world, tmp_path):
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    s = replace(settings, credential_key=old, database_url=f"sqlite:///{tmp_path / 'rot.db'}")
    with TestClient(create_app(s, demo_world=world)) as c:
        c.post("/api/auth/register", json={"email": "o@example.com", "password": "correct horse battery"})
        auth = {"Authorization": "Bearer " + c.post("/api/auth/login", json={
            "email": "o@example.com", "password": "correct horse battery"}).json()["access_token"]}
        sid = c.post("/api/sites", json={"domain": demo("shop84")}, headers=auth).json()["id"]
        c.post(f"/api/sites/{sid}/credentials", json={"kind": "cpanel_token", "value": "panel-token-123"}, headers=auth)

    rotated = replace(s, credential_key=f"{new},{old}")
    assert rotate_credentials(rotated) == 0
    with TestClient(create_app(rotated, demo_world=world)) as c:
        with c.app.state.sessionmaker() as db:
            token = db.query(Credential).one().encrypted_value
    assert CredentialVault(replace(s, credential_key=new)).decrypt(token) == "panel-token-123"  # old key can go


# --- tamper-evident audit log ------------------------------------------------------

def test_audit_log_hash_chain_detects_tampering(client, auth_headers, settings, tmp_path):
    patched(client, auth_headers)
    with client.app.state.sessionmaker() as db:
        db.query(User).filter_by(email="owner@example.com").one().role = Role.admin
        db.commit()
        n = db.query(AuditLog).count()
    ok = client.get("/api/admin/audit/verify", headers=auth_headers).json()
    assert ok["ok"] is True and ok["checked"] == n and ok["first_broken_entry"] is None

    with client.app.state.sessionmaker() as db:
        victim = db.query(AuditLog).filter_by(action="patch.approved").one().id
        db.execute(text("UPDATE audit_log SET detail = '{\"approved_at\": \"never\"}' WHERE id = :i"), {"i": victim})
        db.commit()
    broken = client.get("/api/admin/audit/verify", headers=auth_headers).json()
    assert broken["ok"] is False and broken["first_broken_entry"] == victim


def test_audit_verify_cli_and_admin_only(client, auth_headers, settings, scanner, world, tmp_path):
    s = replace(settings, database_url=f"sqlite:///{tmp_path / 'audit.db'}")
    with TestClient(create_app(s, demo_world=world)) as c:
        c.post("/api/auth/register", json={"email": "a@example.com", "password": "correct horse battery"})
    assert verify_audit(s) == 0
    with TestClient(create_app(s, demo_world=world)) as c:
        with c.app.state.sessionmaker() as db:
            db.execute(text("DELETE FROM audit_log"))
            db.add(AuditLog(user_id=None, action="later", detail={}))
            db.commit()
            db.execute(text("UPDATE audit_log SET action = 'edited'"))
            db.commit()
    assert verify_audit(s) == 1
    assert client.get("/api/admin/audit/verify", headers=auth_headers).status_code == 403


# --- rate limits ----------------------------------------------------------------

def _client(settings, scanner, world, **overrides) -> TestClient:
    # Each app gets its own scanner: an app closes its scanner's HTTP client when it shuts down.
    return TestClient(create_app(replace(settings, **overrides), demo_world=world))


def test_free_scans_are_rate_limited_per_connection(settings, scanner, world):
    with _client(settings, scanner, world, scan_rate_limit=3) as c:
        for _ in range(3):
            assert c.post("/api/scans", json={"domain": demo("php84-fixed")}).status_code == 201
        r = c.post("/api/scans", json={"domain": demo("php84-fixed")})
        assert r.status_code == 429 and r.json()["error"] == "rate_limited"
        assert int(r.headers["Retry-After"]) >= 1
    with _client(settings, scanner, world, scan_rate_limit_user=3) as c:  # a list counts every domain
        c.post("/api/auth/register", json={"email": "o@example.com", "password": "correct horse battery"})
        auth = {"Authorization": "Bearer " + c.post("/api/auth/login", json={
            "email": "o@example.com", "password": "correct horse battery"}).json()["access_token"]}
        r = c.post("/api/scans", json={"domains": [demo(f"bulk-0{i}") for i in range(1, 6)]}, headers=auth)
        assert r.status_code == 429


def test_forwarded_for_is_only_trusted_from_configured_proxies(settings, scanner, world):
    body = {"domain": demo("php84-fixed")}
    with _client(settings, scanner, world, scan_rate_limit=1) as c:  # not a trusted proxy: header ignored
        assert c.post("/api/scans", json=body, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 201
        assert c.post("/api/scans", json=body, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429
    with _client(settings, scanner, world, scan_rate_limit=1, trusted_proxies=frozenset({"testclient"})) as c:
        assert c.post("/api/scans", json=body, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 201
        assert c.post("/api/scans", json=body, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 201
        assert c.post("/api/scans", json=body, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429


def test_failed_logins_lock_out_for_a_while(settings, scanner, world):
    with _client(settings, scanner, world, login_failure_limit=3) as c:
        c.post("/api/auth/register", json={"email": "o@example.com", "password": "correct horse battery"})
        for _ in range(3):
            assert c.post("/api/auth/login", json={"email": "o@example.com", "password": "wrong password!"}).status_code == 401
        r = c.post("/api/auth/login", json={"email": "o@example.com", "password": "correct horse battery"})
        assert r.status_code == 429 and "Retry-After" in r.headers  # even the right password waits
        page = c.post("/dashboard/login", data={"email": "o@example.com", "password": "correct horse battery"})
        assert page.status_code == 429 and "Too many failed attempts" in page.text


# --- two-step login ----------------------------------------------------------------

def test_two_step_login(client, auth_headers, caplog):
    with caplog.at_level(logging.DEBUG):
        setup = client.post("/api/auth/mfa/setup", headers=auth_headers)
        secret = setup.json()["secret"]
        assert setup.headers["cache-control"] == "no-store" and "otpauth://totp/Patchwarden:" in setup.json()["otpauth_uri"]
        assert client.post("/api/auth/mfa/enable", json={"code": "000000"}, headers=auth_headers).status_code == 422
        enabled = client.post("/api/auth/mfa/enable", json={"code": totp.code_at(secret)}, headers=auth_headers).json()
        recovery = enabled["recovery_codes"]
        assert len(recovery) == 10

        creds = {"email": "owner@example.com", "password": "correct horse battery"}
        r = client.post("/api/auth/login", json=creds)
        assert r.status_code == 401 and r.json()["error"] == "mfa_required"
        code = totp.code_at(secret, time.time() + 30)  # a fresh step (the enable step is used up)
        assert client.post("/api/auth/login", json={**creds, "code": code}).status_code == 200
        assert client.post("/api/auth/login", json={**creds, "code": code}).json()["error"] == "invalid_code"  # no replay
        assert client.post("/api/auth/login", json={**creds, "code": recovery[0]}).status_code == 200
        assert client.post("/api/auth/login", json={**creds, "code": recovery[0]}).status_code == 401  # used once

        page = client.post("/dashboard/login", data=creds)
        assert page.status_code == 401 and 'name="code"' in page.text
    with client.app.state.sessionmaker() as db:
        user = db.query(User).filter_by(email="owner@example.com").one()
        assert secret.encode() not in user.mfa_secret and recovery[1] not in str(user.mfa_recovery)
    assert secret not in caplog.text and recovery[1] not in caplog.text


def test_totp_matches_rfc_6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()  # the RFC 6238 test key
    assert totp.code_at(secret, 59) == "287082"
    assert totp.code_at(secret, 1111111109) == "081804"
    assert totp.verify(secret, "287082", when=59) == 1
    assert totp.verify(secret, "287082", when=59, last_step=1) is None


# --- revocation -------------------------------------------------------------------

def test_share_links_can_be_revoked(client, auth_headers):
    scan = client.post("/api/scans", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["scans"][0]
    old = urlsplit(client.get(f"/api/scans/{scan['id']}/share", headers=auth_headers).json()["url"])
    anon = TestClient(client.app)
    assert anon.get(f"{old.path}?{old.query}").status_code == 200
    time.sleep(0.01)
    assert client.post(f"/api/scans/{scan['id']}/share/revoke", headers=auth_headers).status_code == 200
    assert anon.get(f"{old.path}?{old.query}").status_code == 404
    time.sleep(0.01)
    new = urlsplit(client.get(f"/api/scans/{scan['id']}/share", headers=auth_headers).json()["url"])
    assert anon.get(f"{new.path}?{new.query}").status_code == 200


def test_log_out_everywhere(client, auth_headers):
    assert client.get("/api/sites", headers=auth_headers).status_code == 200
    assert client.post("/api/auth/logout-all", headers=auth_headers).status_code == 200
    r = client.get("/api/sites", headers=auth_headers)
    assert r.status_code == 401 and r.json()["error"] == "invalid_token"
    fresh = client.post("/api/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"})
    assert client.get("/api/sites", headers={"Authorization": "Bearer " + fresh.json()["access_token"]}).status_code == 200
