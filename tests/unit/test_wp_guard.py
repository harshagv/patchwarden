"""WordPress Guard details beyond the acceptance tests."""

from __future__ import annotations

import io
import logging
import subprocess
import zipfile
from datetime import datetime, timezone

import pytest

from patchwarden.models import Alert, PluginAction, PluginKey, WatchCheck
from patchwarden.wpguard.plugin_zip import build_plugin_zip

from ..conftest import demo
from ..spec.test_phase3_acceptance import nvd_item, run
from ..support.wp_support import PHP, LiveServer, WordPress, needs_php, php_version

BLOG = demo("blog")


def _connected(live, tmp_path, *, monitor=False):
    auth = live.owner()
    site_id = live.http.post("/api/sites", json={"domain": BLOG, "platform": "wordpress"}, headers=auth).json()["id"]
    if monitor:
        live.http.post(f"/api/sites/{site_id}/wp-guard", json={"enabled": True}, headers=auth)
    key = live.http.post(f"/api/sites/{site_id}/plugin-key", headers=auth).json()["key"]
    wp = WordPress(tmp_path, live.url, f"https://{BLOG}")
    wp.run("activate")
    wp.run("save_key", key)
    return auth, site_id, key, wp


@needs_php
def test_plugin_updates_run_only_after_approval(settings, world, nvd, notifier, tmp_path):
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth, site_id, key, wp = _connected(live, tmp_path)
        before = live.http.get(f"/api/sites/{site_id}/wp-guard", headers=auth).json()["score"]

        fix = live.http.post(f"/api/sites/{site_id}/fix", headers=auth).json()
        assert fix["kind"] == "patch"
        job = live.http.get(f"/api/patches/{fix['id']}", headers=auth).json()
        assert job["state"] == "awaiting_approval"
        assert job["report"]["plan"]["components"] == [{"type": "plugin", "slug": "demo-contact-form",
                                                         "file": "demo-contact-form/demo-contact-form.php",
                                                         "from_version": "2.3.0", "fixed_in": "2.4.1"}]

        # Not approved yet: the plugin finds nothing to do.
        state = wp.run("cron", "patchwarden_actions_event")
        assert state["plugins"]["demo-contact-form/demo-contact-form.php"]["Version"] == "2.3.0"

        assert live.http.post(f"/api/patches/{fix['id']}/approve", headers=auth).status_code == 202
        job = live.http.get(f"/api/patches/{fix['id']}", headers=auth).json()
        assert job["state"] == "running" and "Waiting for the Patchwarden plugin" in job["report"]["message"]

        state = wp.run("cron", "patchwarden_actions_event")
        assert state["plugins"]["demo-contact-form/demo-contact-form.php"]["Version"] == "2.5.0"
        job = live.http.get(f"/api/patches/{fix['id']}", headers=auth).json()
        assert job["state"] == "succeeded" and job["report"]["components"][0]["result"]["version"] == "2.5.0"
        after = live.http.get(f"/api/sites/{site_id}/wp-guard", headers=auth).json()
        assert after["score"] > before
        assert not any("known security problem" in f["what"] for f in after["fixes"])

        # Nothing is sent twice.
        wp.run("cron", "patchwarden_actions_event")
        with live.app.state.sessionmaker() as db:
            assert [a.state for a in db.query(PluginAction)] == ["done"]


@needs_php
def test_plugin_refuses_actions_it_does_not_know(settings, world, nvd, notifier, tmp_path):
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth, site_id, key, wp = _connected(live, tmp_path)
        with live.app.state.sessionmaker() as db:
            db.add(PluginAction(site_id=site_id, kind="run_shell", payload={"cmd": "rm -rf /"}))
            db.add(PluginAction(site_id=site_id, kind="update_component",
                                payload={"type": "plugin", "slug": "evil", "file": "../../wp-config.php"}))
            db.commit()
        wp.run("cron", "patchwarden_actions_event")
        with live.app.state.sessionmaker() as db:
            results = {a.kind: a.result for a in db.query(PluginAction)}
        assert results["run_shell"]["ok"] is False and "does not support" in results["run_shell"]["detail"]
        assert results["update_component"] == {"ok": False, "detail": "That plugin is not installed on this site.",
                                                "version": None}


@needs_php
def test_settings_form_needs_an_admin_and_a_nonce(settings, world, nvd, notifier, tmp_path):
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        wp = WordPress(tmp_path, live.url, f"https://{BLOG}")
        wp.run("activate")
        key = "pw_" + "a" * 43
        assert "not allowed" in wp.run("save_key", key, admin=False)["died"]
        assert "expired" in wp.run("save_key", key, "bad-nonce")["died"]
        state = wp.run("save_key", "my-hosting-password")
        assert "patchwarden_api_key" not in state["options"]
        assert "does not look like a Patchwarden key" in state["options"]["patchwarden_status"]["message"]
        assert state["http_log"] == []


@needs_php
def test_plugin_only_talks_https_except_to_localhost(tmp_path):
    wp = WordPress(tmp_path, "http://patchwarden.example", f"https://{BLOG}")
    wp.run("activate")
    state = wp.run("save_key", "pw_" + "b" * 43)
    assert state["http_log"] == []
    assert state["options"]["patchwarden_status"]["message"] == "The Patchwarden address must use https."


@needs_php
def test_a_key_only_works_for_its_own_site(settings, world, nvd, notifier, tmp_path):
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth = live.owner()
        site_id = live.http.post("/api/sites", json={"domain": BLOG}, headers=auth).json()["id"]
        key = live.http.post(f"/api/sites/{site_id}/plugin-key", headers=auth).json()["key"]
        wp = WordPress(tmp_path, live.url, "https://someone-else.example")
        wp.run("activate")
        state = wp.run("save_key", key)
        assert state["http_log"][-1]["status"] == 409
        assert state["options"]["patchwarden_status"]["message"].startswith("This key belongs to a different site")


@needs_php
def test_plugin_report_feeds_the_watchdog(settings, world, nvd, notifier, tmp_path):
    version = php_version()
    nvd.items.append(nvd_item("CVE-2026-999050", start=version, end_excl="99.0.0"))
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth, site_id, key, wp = _connected(live, tmp_path, monitor=True)
        run(live.app.state.watchdog.poll_feeds(datetime.now(timezone.utc)))
        wp.run("cron", "patchwarden_report_event")
        with live.app.state.sessionmaker() as db:
            assert db.query(Alert).filter_by(site_id=site_id, cve_id="CVE-2026-999050").count() == 1
            checks = db.query(WatchCheck).filter_by(site_id=site_id, kind="version").all()
            assert checks and all(c.detail["version_source"] == "plugin" for c in checks)


@needs_php
def test_the_key_is_shown_once_and_stored_only_as_a_hash(settings, world, nvd, notifier, tmp_path, caplog):
    with caplog.at_level(logging.DEBUG), LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth, site_id, key, wp = _connected(live, tmp_path)
        seen = [live.http.get(p, headers=auth).text for p in
                (f"/api/sites/{site_id}/wp-guard", f"/api/sites/{site_id}", "/api/sites")]
        wp.run("cron", "patchwarden_report_event")
        wp.run("cron", "patchwarden_actions_event")
        new_key = live.http.post(f"/api/sites/{site_id}/plugin-key", headers=auth).json()["key"]
        with live.app.state.sessionmaker() as db:
            rows = db.query(PluginKey).filter_by(site_id=site_id).all()
            stored = " ".join(str(r.__dict__) for r in rows)
        old = wp.run("cron", "patchwarden_report_event")["http_log"][-1]
    assert key not in "\n".join(seen) and key not in stored and new_key not in stored
    assert key not in caplog.text and new_key not in caplog.text
    assert [r.revoked_at is not None for r in rows] == [True, False]
    assert old["status"] == 401  # regenerating the key switched the old one off


def test_plugin_zip_has_the_address_and_no_secret(settings, tmp_path):
    data = build_plugin_zip("https://guard.example.com")
    z = zipfile.ZipFile(io.BytesIO(data))
    names = set(z.namelist())
    assert {"patchwarden/patchwarden.php", "patchwarden/uninstall.php", "patchwarden/readme.txt",
            "patchwarden/includes/class-patchwarden-client.php", "patchwarden/includes/config.php"} <= names
    config = z.read("patchwarden/includes/config.php").decode()
    assert "define( 'PATCHWARDEN_API_URL', 'https://guard.example.com' );" in config
    assert "pw_" not in config and settings.jwt_secret not in data.decode("latin-1")
    with pytest.raises(Exception):
        build_plugin_zip("https://x.example/'); system('id'); //")
    if PHP:
        z.extractall(tmp_path)
        for name in names:
            if name.endswith(".php"):
                r = subprocess.run([PHP, "-l", str(tmp_path / name)], capture_output=True, text=True)
                assert r.returncode == 0, r.stdout + r.stderr


def test_wp_guard_bundles_the_watchdog(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["id"]
    watchdog = client.app.state.watchdog
    r = client.post(f"/api/sites/{site_id}/wp-guard", json={"enabled": True}, headers=auth_headers).json()
    assert r["wp_guard"] is True and r["subscription"]["product"] == "wp_guard"
    assert run(watchdog.run_version_checks(force=True)) == 1
    client.post(f"/api/sites/{site_id}/wp-guard", json={"enabled": False}, headers=auth_headers)
    assert run(watchdog.run_version_checks(force=True)) == 0


def test_score_and_plain_language_without_the_plugin(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("php84-unpatched"), "platform": "wordpress"},
                          headers=auth_headers).json()["id"]
    client.post("/api/scans", json={"domain": demo("php84-unpatched")}, headers=auth_headers)
    view = client.get(f"/api/sites/{site_id}/wp-guard", headers=auth_headers).json()
    assert view["score"] == 50 and view["grade"] == "At risk"  # 100 - 40 (unpatched PHP) - 10 (not watched)
    whats = " ".join(f["what"] for f in view["fixes"])
    assert "serious flaw" in whats and "Nobody is watching" in whats and "plugin is not connected" in whats
    for jargon in ("CVE", "CVSS", "RCE", "patch_now"):
        assert jargon not in whats


def test_fix_it_explains_what_it_needs(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("php84-unpatched"), "platform": "wordpress"},
                          headers=auth_headers).json()["id"]
    client.post("/api/scans", json={"domain": demo("php84-unpatched")}, headers=auth_headers)
    r = client.post(f"/api/sites/{site_id}/fix", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "panel_token_needed"
    assert "the WordPress plugin cannot change PHP" in r.json()["message"]

    safe = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["id"]
    client.post("/api/scans", json={"domain": demo("php84-fixed")}, headers=auth_headers)
    r = client.post(f"/api/sites/{safe}/fix", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "nothing_to_fix"


def test_old_php_wordpress_fix_it_goes_to_a_migration_plan(client, auth_headers, world):
    site_id = client.post("/api/sites", json={"domain": demo("wp74"), "platform": "wordpress"},
                          headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "wp74-token-x"},
                headers=auth_headers)
    client.post("/api/scans", json={"domain": demo("wp74")}, headers=auth_headers)
    r = client.post(f"/api/sites/{site_id}/fix", headers=auth_headers).json()
    assert r["kind"] == "migration" and r["url"].startswith("/dashboard/migrations/")
    assert world.get(demo("wp74")).mutations == []
