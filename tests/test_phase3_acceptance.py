"""Phase 3 acceptance tests, one per bullet in SPEC.md section 6."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from patchwarden.models import Alert, WatchCheck

from .conftest import demo

OCT = datetime(2026, 10, 1, 6, 0, tzinfo=timezone.utc)


def nvd_item(cve_id: str, *, start: str, end_excl: str, severity: str = "HIGH", score: float = 8.1) -> dict:
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"Test-only flaw {cve_id} in PHP {start} before {end_excl}."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
            "versionStartIncluding": start, "versionEndExcluding": end_excl}]}]}],
    }}


def monitored_site(client, auth, label: str, *, monitor: bool = True) -> int:
    site_id = client.post("/api/sites", json={"domain": demo(label)}, headers=auth).json()["id"]
    if monitor:
        r = client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth)
        assert r.status_code == 200 and r.json()["monitoring"] is True, r.text
    return site_id


def run(coro):
    return asyncio.run(coro)


def cve_alerts(client, cve_id: str) -> list[Alert]:
    with client.app.state.sessionmaker() as db:
        return db.query(Alert).filter(Alert.cve_id == cve_id).all()


def test_fake_cve_alerts_matching_sites_only_not_patched_ones(client, auth_headers, nvd, notifier):
    watchdog = client.app.state.watchdog
    unpatched = monitored_site(client, auth_headers, "php84-unpatched")  # PHP 8.4.13
    patched = monitored_site(client, auth_headers, "php84-fixed")  # PHP 8.4.27
    other_line = monitored_site(client, auth_headers, "php83-unpatched")  # PHP 8.3.20
    unmonitored = monitored_site(client, auth_headers, "bulk-01", monitor=False)  # PHP 8.4.13, no Watchdog
    run(watchdog.run_version_checks(OCT))

    run(watchdog.poll_feeds(OCT + timedelta(hours=1)))
    assert cve_alerts(client, "CVE-2026-999001") == []  # not in the feed yet

    # Add a fake CVE to the feed: PHP 8.4.0 up to (not including) 8.4.27.
    nvd.items.append(nvd_item("CVE-2026-999001", start="8.4.0", end_excl="8.4.27"))
    emails_before = len(notifier.sent)
    run(watchdog.poll_feeds(OCT + timedelta(hours=2)))

    alerts = cve_alerts(client, "CVE-2026-999001")
    assert [a.site_id for a in alerts] == [unpatched]
    assert patched not in {a.site_id for a in alerts} and other_line not in {a.site_id for a in alerts}
    assert unmonitored not in {a.site_id for a in alerts}
    alert = alerts[0]
    assert alert.severity == "high" and alert.sent_at is not None and alert.read is False
    assert "What changed:" in alert.message and "What it means:" in alert.message and "What to do:" in alert.message
    assert "PHP 8.4.13, which is affected" in alert.message and "Update PHP to 8.4.27 or newer" in alert.message
    assert f"/dashboard/sites#site-{unpatched}" in alert.message  # link into the Phase 2 patch flow
    new_emails = notifier.sent[emails_before:]
    assert [e.to for e in new_emails] == ["owner@example.com"]
    assert "CVE-2026-999001" in new_emails[0].body

    # The next poll does not repeat it.
    run(watchdog.poll_feeds(OCT + timedelta(hours=3)))
    assert len(cve_alerts(client, "CVE-2026-999001")) == 1

    # It is on the dashboard and in the API.
    body = client.get("/api/alerts", headers=auth_headers).json()["alerts"]
    assert "CVE-2026-999001" in {a["cve_id"] for a in body}
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    page = client.get("/dashboard/alerts")
    assert page.status_code == 200 and "CVE-2026-999001" in page.text and "What to do:" in page.text


def test_monthly_report_for_a_site_with_30_days_of_checks(client, auth_headers, nvd):
    watchdog = client.app.state.watchdog
    site_id = monitored_site(client, auth_headers, "php84-unpatched")
    nvd.items.append(nvd_item("CVE-2026-999002", start="8.4.0", end_excl="8.4.27", severity="CRITICAL", score=9.8))
    for day in range(30):
        now = OCT + timedelta(days=day)
        run(watchdog.run_version_checks(now))
        if day == 10:
            run(watchdog.poll_feeds(now + timedelta(hours=1)))

    r = client.get(f"/api/sites/{site_id}/monthly-report", params={"month": "2026-10"}, headers=auth_headers)
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["checks"]["version"] == 30 and report["checks"]["days_checked"] == 30
    assert report["checks"]["cve"] == 1 and report["checks"]["failed"] == 0
    assert report["current"] == {"php_version": "8.4.13", "risk": "patch_now",
                                 "checked_at": (OCT + timedelta(days=29)).isoformat()}
    keys = {r["key"] for r in report["risks_found"]}
    assert "CVE-2026-999002" in keys and any(k.startswith("risk:patch_now") for k in keys)
    assert report["actions_taken"] == []
    assert report["summary"].startswith(f"In October 2026 we checked {demo('php84-unpatched')} 30 times on 30 days.")

    # A different month is empty, not an error.
    empty = client.get(f"/api/sites/{site_id}/monthly-report", params={"month": "2026-09"}, headers=auth_headers).json()
    assert empty["checks"]["version"] == 0

    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    page = client.get(f"/dashboard/sites/{site_id}/monthly", params={"month": "2026-10"})
    assert page.status_code == 200
    assert "30 version checks on 30 of 31 days" in page.text and "CVE-2026-999002" in page.text


def test_monitoring_off_stops_checks(client, auth_headers, nvd):
    watchdog = client.app.state.watchdog
    site_id = monitored_site(client, auth_headers, "php84-unpatched")
    run(watchdog.run_version_checks(OCT))
    run(watchdog.poll_feeds(OCT))

    def checks() -> int:
        with client.app.state.sessionmaker() as db:
            return db.query(WatchCheck).filter(WatchCheck.site_id == site_id).count()

    def alerts() -> int:
        with client.app.state.sessionmaker() as db:
            return db.query(Alert).filter(Alert.site_id == site_id).count()

    assert checks() == 2  # one version check, one CVE check
    r = client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": False}, headers=auth_headers)
    assert r.json() == {"site_id": site_id, "monitoring": False,
                        "subscription": {"id": r.json()["subscription"]["id"], "product": "watchdog",
                                         "status": "cancelled"}}
    before_checks, before_alerts = checks(), alerts()

    nvd.items.append(nvd_item("CVE-2026-999003", start="8.4.0", end_excl="8.4.27"))
    for day in range(1, 4):
        now = OCT + timedelta(days=day)
        run(watchdog.run_version_checks(now))
        run(watchdog.run_version_checks(now, force=True))
        run(watchdog.poll_feeds(now))
        run(watchdog.tick(now))
    client.post("/api/watchdog/run", headers=auth_headers)

    assert checks() == before_checks  # zero new checks after off
    assert alerts() == before_alerts

    # Turning it back on resumes checks.
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(watchdog.run_version_checks(OCT + timedelta(days=5)))
    assert checks() == before_checks + 1
