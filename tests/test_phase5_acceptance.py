"""Phase 5 acceptance tests, one per bullet in SPEC.md section 8."""

from __future__ import annotations

import re

from patchwarden.models import PatchJob, PluginAction

from .conftest import demo
from .test_phase2_acceptance import approve
from .wp_support import LiveServer, WordPress, needs_php, php_version

BLOG = demo("blog")


@needs_php
def test_plugin_installs_reports_correctly_and_uninstalls_leaving_nothing(settings, world, nvd, notifier, tmp_path):
    with LiveServer(settings, world, nvd, notifier, tmp_path) as live:
        auth = live.owner()
        site_id = live.http.post("/api/sites", json={"domain": BLOG, "platform": "wordpress"}, headers=auth).json()["id"]
        live.http.post(f"/api/sites/{site_id}/wp-guard", json={"enabled": True}, headers=auth)
        key = live.http.post(f"/api/sites/{site_id}/plugin-key", headers=auth).json()["key"]

        wp = WordPress(tmp_path, live.url, f"https://{BLOG}")
        # Install + activate: the schedule is set, nothing is sent yet (no key).
        state = wp.run("activate")
        assert set(state["cron"]) == {"patchwarden_report_event", "patchwarden_actions_event"}
        assert state["http_log"] == []

        # Paste the key in Settings > Patchwarden: saved, and the first report goes out at once.
        state = wp.run("save_key", key)
        assert state["options"]["patchwarden_api_key"] == key
        assert [(c["method"], c["url"].removeprefix(live.url), c["status"]) for c in state["http_log"]] == [
            ("POST", "/api/plugin/report", 200)]
        assert state["options"]["patchwarden_status"]["ok"] is True
        assert state["redirect"].endswith("options-general.php?page=patchwarden")

        # It reported correctly.
        view = live.http.get(f"/api/sites/{site_id}/wp-guard", headers=auth).json()
        assert view["evidence"] == "plugin" and view["php_version"] == php_version()
        inv = view["plugin"]["inventory"]
        assert inv["wp_version"] == "6.6.2" and inv["plugin_version"] == "0.1.0"
        assert {(p["slug"], p["version"], p["active"]) for p in inv["plugins"]} == {
            ("akismet", "5.3.3", True), ("demo-contact-form", "2.3.0", True), ("hello", "1.7.2", False),
            ("patchwarden", "0.1.0", True)}
        assert {(t["slug"], t["version"], t["active"]) for t in inv["themes"]} == {
            ("demo-storefront", "3.4.0", True), ("twentytwentyfour", "1.2", False)}
        assert next(p for p in inv["plugins"] if p["slug"] == "demo-contact-form")["update_available"] == "2.5.0"
        assert any('"Demo Contact Form" has a known security problem' in i["what"] for i in view["fixes"])

        # The scheduled report runs too, and the settings page never prints the key.
        state = wp.run("cron", "patchwarden_report_event")
        assert state["http_log"][-1]["status"] == 200
        page = wp.run("settings_page")["output"]
        assert key not in page and key[:7] + "…" in page

        # Delete the plugin: no data or keys left behind, here or on the server.
        state = wp.run("uninstall")
        assert not [k for k in state["options"] if k.startswith("patchwarden")]
        assert not state["cron"]  # PHP writes an empty table as []
        assert state["options"] == {"blogname": "Demo Bakery"}  # WordPress's own data untouched
        assert state["http_log"][-1]["url"].endswith("/api/plugin/disconnect") and state["http_log"][-1]["status"] == 200
        assert key not in wp.state_file.read_text()
        r = live.http.post("/api/plugin/report", json={"site_url": f"https://{BLOG}", "php_version": "8.4.27"},
                           headers={"X-Patchwarden-Key": key})
        assert r.status_code == 401 and r.json()["error"] == "invalid_plugin_key"


def test_fix_it_routes_into_the_phase2_approval_flow_not_a_direct_patch(client, auth_headers, world):
    host = world.get(demo("wpshop84"))
    site_id = client.post("/api/sites", json={"domain": demo("wpshop84"), "platform": "wordpress",
                                              "form_path": "/checkout"}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "wpshop-panel-token"},
                headers=auth_headers)
    client.post(f"/api/sites/{site_id}/wp-guard", json={"enabled": True}, headers=auth_headers)
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/dashboard/sites").text).group(1)
    client.post(f"/dashboard/sites/{site_id}/scan", data={"csrf": csrf})

    page = client.get(f"/dashboard/wp-guard/{site_id}")
    assert page.text.count(">Fix it</button>") == 1  # one button
    assert "has the serious flaw" in page.text

    r = client.post(f"/dashboard/wp-guard/{site_id}/fix", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    job_id = int(re.search(r"/dashboard/patches/(\d+)$", r.headers["location"]).group(1))

    # Nothing changed: the job waits for the owner's approval in the Phase 2 flow.
    with client.app.state.sessionmaker() as db:
        job = db.get(PatchJob, job_id)
        assert job.state.value == "awaiting_approval" and job.approved_by is None
        assert job.report["origin"] == "fix_it"
        assert db.query(PluginAction).count() == 0
    assert host.mutations == [] and host.php_version == "8.4.13"
    approval = client.get(r.headers["location"])
    assert "Waiting for your approval" in approval.text and "Approve and run" in approval.text

    # Only the Phase 2 approval moves it forward.
    done = approve(client, auth_headers, job_id)
    assert done["state"] == "succeeded" and done["approved_by"] is not None
    assert host.php_version == "8.4.27"
    assert host.mutations == ["create_backup", "set_php_version:8.4.27", "restart_php"]
