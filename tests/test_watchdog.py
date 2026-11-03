"""Watchdog details beyond the acceptance tests: feeds, matching, risk alerts, subscriptions, schedule, email."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from patchwarden.app import create_app
from patchwarden.config import PROJECT_ROOT
from patchwarden.models import Alert, FeedCursor, Role, User, WatchCheck
from patchwarden.watchdog.feeds import (
    FixtureSource,
    NvdSource,
    PhpReleaseSource,
    parse_nvd,
    release_advisory,
    version_affected,
)
from patchwarden.watchdog.notify import Email, OutboxNotifier, SmtpNotifier

from .conftest import demo
from .test_phase2_acceptance import add_site
from .test_phase3_acceptance import OCT, monitored_site, nvd_item, run


@pytest.mark.parametrize("version,ranges,hit", [
    ("8.4.13", [{"start_incl": "8.4.0", "end_excl": "8.4.27"}], True),
    ("8.4.27", [{"start_incl": "8.4.0", "end_excl": "8.4.27"}], False),
    ("8.4.27", [{"start_incl": "8.4.0", "end_incl": "8.4.27"}], True),
    ("8.3.20", [{"start_incl": "8.4.0", "end_excl": "8.4.27"}], False),
    ("8.1.2-1ubuntu2.14", [{"end_excl": "8.1.30"}], True),
    ("8.4", [{"start_incl": "8.4.0", "end_excl": "8.4.27"}], False),  # no patch number: no guess
    ("8.3.1", [{"exact": "8.3.1"}], True),
    ("8.3.2", [{"exact": "8.3.1"}], False),
    ("8.4.13", [{"start_excl": "8.4.13"}], False),
])
def test_version_ranges(version, ranges, hit):
    assert version_affected(version, ranges) is hit


def test_nvd_parsing_keeps_php_ranges_only():
    items = [
        nvd_item("CVE-1", start="8.4.0", end_excl="8.4.27"),
        {"cve": {"id": "CVE-2", "descriptions": [], "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "versionEndExcluding": "6.0"}]}]}]}},
        {"cve": {"id": "CVE-3", "descriptions": [], "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]}]}]}},  # "all versions": too vague
        {"cve": {"id": "CVE-4", "descriptions": [], "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}]},
                 "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:8.3.1:*:*:*:*:*:*:*"}]}]}]}},
    ]
    advisories = {a.id: a for a in parse_nvd({"vulnerabilities": items})}
    assert set(advisories) == {"CVE-1", "CVE-4"}
    assert advisories["CVE-1"].fixed_in == "8.4.27" and advisories["CVE-1"].severity == "high"
    assert advisories["CVE-4"].affected == [{"exact": "8.3.1"}] and advisories["CVE-4"].score == 9.3


def test_nvd_key_goes_in_a_header_not_the_url():
    seen = []
    key = f"NVDKEY-{uuid.uuid4().hex}"
    source = NvdSource(api_key=key, transport=httpx.MockTransport(
        lambda r: seen.append(r) or httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})))
    until = datetime(2026, 11, 2, tzinfo=timezone.utc)
    run(source.fetch(until - timedelta(days=400), until))
    request = seen[0]
    assert request.headers["apiKey"] == key and key not in str(request.url)
    assert request.url.params["virtualMatchString"] == "cpe:2.3:a:php:php"
    start = datetime.strptime(request.url.params["lastModStartDate"], "%Y-%m-%dT%H:%M:%S.000Z")
    assert (until.replace(tzinfo=None) - start).days <= 120  # NVD's maximum window


def test_feed_failure_is_skipped_and_retried(client, auth_headers, caplog):
    watchdog = client.app.state.watchdog
    watchdog.sources = [NvdSource(transport=httpx.MockTransport(lambda r: httpx.Response(503)))]
    with caplog.at_level(logging.WARNING):
        run(watchdog.poll_feeds(OCT))
    assert "Watchdog feed nvd skipped: NVD answered HTTP 503" in caplog.text
    with client.app.state.sessionmaker() as db:
        assert db.get(FeedCursor, "nvd") is None  # same window is retried next time


def test_php_security_release_becomes_an_advisory():
    adv = release_advisory({"version": "8.4.28", "tags": ["security"], "date": "4 Nov 2026"})
    assert adv.id == "PHP-8.4.28" and adv.affected == [{"start_incl": "8.4.0", "end_excl": "8.4.28"}]
    assert release_advisory({"version": "8.4.28", "tags": []}) is None  # bug-fix only: no alert

    def handler(request):
        branch = request.url.params["version"]
        return httpx.Response(200, json={"version": f"{branch}.99", "tags": ["security"], "date": "today"})

    source = PhpReleaseSource(transport=httpx.MockTransport(handler), branches=("8.4",))
    advisories = run(source.fetch(OCT, OCT))
    assert [a.id for a in advisories] == ["PHP-8.4.99"]


def test_release_alert_for_sites_on_older_releases(client, auth_headers):
    watchdog = client.app.state.watchdog
    unpatched = monitored_site(client, auth_headers, "php84-unpatched")
    patched = monitored_site(client, auth_headers, "php84-fixed")
    run(watchdog.run_version_checks(OCT))
    watchdog.sources = [PhpReleaseSource(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"version": "8.4.28", "tags": ["security"], "date": "4 Nov 2026"})),
        branches=("8.4",))]
    run(watchdog.poll_feeds(OCT))
    with client.app.state.sessionmaker() as db:
        hits = {a.site_id for a in db.query(Alert).filter_by(cve_id="PHP-8.4.28")}
    assert hits == {unpatched, patched}  # 8.4.27 fixed PHP2Shell but misses 8.4.28's fixes


def test_demo_fixture_feed_alerts_php83_sites(client, auth_headers, settings):
    watchdog = client.app.state.watchdog
    watchdog.sources = [FixtureSource(PROJECT_ROOT / "patchwarden" / "data" / "cve_feed.demo.json")]
    site = monitored_site(client, auth_headers, "php83-unpatched")
    other = monitored_site(client, auth_headers, "php84-fixed")
    run(watchdog.run_version_checks(OCT))
    run(watchdog.poll_feeds(OCT))
    with client.app.state.sessionmaker() as db:
        assert {a.site_id for a in db.query(Alert).filter_by(cve_id="PHPG-DEMO-2026-0101")} == {site}
    assert other != site


def test_default_sources_follow_settings(settings):
    from patchwarden.app import default_sources
    assert [s.name for s in default_sources(replace(settings, cve_feed="fixture"))] == ["fixture"]
    assert [s.name for s in default_sources(replace(settings, cve_feed="nvd"))] == ["nvd", "php_release"]


def test_risk_alert_when_a_site_gets_worse(client, auth_headers, world):
    watchdog = client.app.state.watchdog
    host = world.get(demo("shop84"))
    host.php_version = "8.4.27"
    site_id = monitored_site(client, auth_headers, "shop84")
    run(watchdog.run_version_checks(OCT))
    host.php_version = "8.4.13"  # someone downgraded PHP
    run(watchdog.run_version_checks(OCT + timedelta(days=1)))
    run(watchdog.run_version_checks(OCT + timedelta(days=2)))  # still bad: no repeat
    with client.app.state.sessionmaker() as db:
        alerts = db.query(Alert).filter(Alert.site_id == site_id).all()
    assert len(alerts) == 1 and alerts[0].cve_id.startswith("risk:patch_now:")
    assert alerts[0].severity == "critical"
    assert "found PHP 8.4.13" in alerts[0].message and "(it was 8.4.27 before)" in alerts[0].message


def test_daily_schedule_skips_sites_checked_recently(client, auth_headers):
    watchdog = client.app.state.watchdog
    monitored_site(client, auth_headers, "php84-fixed")
    assert run(watchdog.run_version_checks(OCT)) == 1
    assert run(watchdog.run_version_checks(OCT + timedelta(hours=5))) == 0
    assert run(watchdog.run_version_checks(OCT + timedelta(hours=24))) == 1


def test_hidden_version_is_read_from_the_inside_when_access_exists(client, auth_headers, world):
    watchdog = client.app.state.watchdog
    world.get(demo("shop84")).hide_version = True
    site_id = add_site(client, auth_headers, "shop84")
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(watchdog.run_version_checks(OCT))
    with client.app.state.sessionmaker() as db:
        check = db.query(WatchCheck).filter_by(site_id=site_id, kind="version").one()
    assert check.detected_version == "8.4.13" and check.detail["version_source"] == "inside"
    assert world.get(demo("shop84")).mutations == []  # read-only


def _admin(client) -> dict:
    client.post("/api/auth/register", json={"email": "admin@example.com", "password": "admin password long"})
    with client.app.state.sessionmaker() as db:
        db.query(User).filter_by(email="admin@example.com").one().role = Role.admin
        db.commit()
    token = client.post("/api/auth/login", json={"email": "admin@example.com",
                                                  "password": "admin password long"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_subscription_status_transitions(client, auth_headers):
    watchdog = client.app.state.watchdog
    site_id = monitored_site(client, auth_headers, "php84-fixed")
    sub_id = client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True},
                         headers=auth_headers).json()["subscription"]["id"]
    admin = _admin(client)

    r = client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "past_due"}, headers=auth_headers)
    assert r.status_code == 403 and r.json()["error"] == "admin_only"

    assert client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "past_due"},
                       headers=admin).json()["status"] == "past_due"
    assert run(watchdog.run_version_checks(OCT)) == 1  # grace period: still watched
    assert client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "active"}, headers=admin).status_code == 200
    assert client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "cancelled"}, headers=admin).status_code == 200
    assert run(watchdog.run_version_checks(OCT + timedelta(days=1))) == 0
    r = client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "past_due"}, headers=admin)
    assert r.status_code == 409 and r.json()["error"] == "invalid_transition"
    r = client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "paid"}, headers=admin)
    assert r.status_code == 422


def test_alerts_api_is_owner_only_and_tracks_read(client, auth_headers):
    watchdog = client.app.state.watchdog
    monitored_site(client, auth_headers, "php84-unpatched")
    run(watchdog.run_version_checks(OCT))
    alerts = client.get("/api/alerts", params={"unread": True}, headers=auth_headers).json()["alerts"]
    assert len(alerts) == 1
    stranger = _admin(client)  # an admin still cannot read another owner's alert through this API
    assert client.post(f"/api/alerts/{alerts[0]['id']}/read", headers=stranger).status_code == 404
    assert client.post(f"/api/alerts/{alerts[0]['id']}/read", headers=auth_headers).json()["read"] is True
    assert client.get("/api/alerts", params={"unread": True}, headers=auth_headers).json()["alerts"] == []


def test_alert_without_email_says_not_sent(client, auth_headers):
    watchdog = client.app.state.watchdog
    watchdog.notifier = OutboxNotifier(delivered=False)  # SMTP not configured
    site_id = monitored_site(client, auth_headers, "php84-unpatched")
    run(watchdog.run_version_checks(OCT))
    with client.app.state.sessionmaker() as db:
        alert = db.query(Alert).filter_by(site_id=site_id).one()
    assert alert.sent_at is None
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    assert "Not emailed (email is not set up)" in client.get("/dashboard/alerts").text


def test_monthly_emails_go_to_monitored_owners(client, auth_headers, notifier):
    watchdog = client.app.state.watchdog
    site_id = monitored_site(client, auth_headers, "php84-fixed")
    run(watchdog.run_version_checks(OCT))
    notifier.sent.clear()
    assert run(watchdog.send_monthly_reports(datetime(2026, 11, 1, 6, tzinfo=timezone.utc))) == 1
    email = notifier.sent[0]
    assert email.to == "owner@example.com" and "monthly report" in email.subject
    assert f"/dashboard/sites/{site_id}/monthly?month=2026-10" in email.body


def test_scheduler_runs_inside_the_app(settings, scanner, world):
    app = create_app(replace(settings, watchdog_scheduler=True), scanner=scanner, demo_world=world,
                     notifier=OutboxNotifier(), sources=[])
    with TestClient(app):
        jobs = {j.id: j for j in app.state.scheduler.get_jobs()}
        assert set(jobs) == {"watchdog_tick", "monthly_reports"}
        assert jobs["watchdog_tick"].trigger.interval == timedelta(hours=1)
    assert not app.state.scheduler.running


class FakeSMTP:
    instances: list = []
    fail = False

    def __init__(self, host, port, timeout):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user))
        if FakeSMTP.fail:
            raise smtplib.SMTPAuthenticationError(535, f"bad password {password}".encode())

    def send_message(self, msg):
        self.calls.append(("send", msg["To"], msg["Subject"]))


def test_smtp_notifier_uses_tls_and_never_logs_the_password(settings, monkeypatch, caplog):
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    password = f"SMTPPASS-{uuid.uuid4().hex}"
    smtp = SmtpNotifier(replace(settings, smtp_host="smtp.example.com", smtp_user="mailer", smtp_password=password))
    assert password not in repr(smtp)
    assert run(smtp.send(Email("owner@example.com", "Hello", "Body"))) is True
    assert FakeSMTP.instances[-1].calls == ["starttls", ("login", "mailer"), ("send", "owner@example.com", "Hello")]

    FakeSMTP.fail = True
    with caplog.at_level(logging.DEBUG):
        assert run(smtp.send(Email("owner@example.com", "Hello", "Body"))) is False
    FakeSMTP.fail = False
    assert "Alert email not sent: SMTPAuthenticationError" in caplog.text
    assert password not in caplog.text


def test_watchdog_secrets_never_leak(settings, scanner, world, nvd, caplog):
    nvd_key, smtp_password = f"NVDKEY-{uuid.uuid4().hex}", f"SMTPPASS-{uuid.uuid4().hex}"
    s = replace(settings, nvd_api_key=nvd_key, smtp_password=smtp_password)
    notifier = OutboxNotifier(delivered=True)
    app = create_app(s, scanner=scanner, demo_world=world, notifier=notifier,
                     sources=[NvdSource(api_key=nvd_key, transport=httpx.MockTransport(nvd.handler))])
    seen = []
    with TestClient(app) as c, caplog.at_level(logging.DEBUG):
        c.post("/api/auth/register", json={"email": "owner@example.com", "password": "correct horse battery"})
        auth = {"Authorization": "Bearer " + c.post("/api/auth/login", json={
            "email": "owner@example.com", "password": "correct horse battery"}).json()["access_token"]}
        site_id = c.post("/api/sites", json={"domain": demo("php84-unpatched")}, headers=auth).json()["id"]
        nvd.items.append(nvd_item("CVE-2026-999009", start="8.4.0", end_excl="8.4.27"))
        for method, url, kw in [
            ("POST", f"/api/sites/{site_id}/monitoring", {"json": {"enabled": True}}),
            ("POST", "/api/watchdog/run", {}),
            ("GET", "/api/alerts", {}),
            ("GET", f"/api/sites/{site_id}/monthly-report?month=2026-11", {}),
        ]:
            r = c.request(method, url, headers=auth, **kw)
            seen.append(r.text + str(dict(r.headers)))
        c.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
        seen += [c.get("/dashboard/alerts").text, c.get("/dashboard/sites").text]
        run(app.state.watchdog.send_monthly_reports())
        with app.state.sessionmaker() as db:
            stored = [a.message for a in db.query(Alert)]
    assert nvd.requests and all(r.headers["apiKey"] == nvd_key for r in nvd.requests)  # used where it belongs
    everything = "\n".join(seen + stored + [e.body + e.subject for e in notifier.sent]) + caplog.text
    everything += "\n".join(str(r.__dict__) for r in caplog.records)
    assert stored and notifier.sent
    for secret in (nvd_key, smtp_password):
        assert secret not in everything
