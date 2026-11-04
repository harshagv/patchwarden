"""Phase C: the Watchdog at scale. Exploitation-aware priority, digests, escalation, channels, dunning."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from patchwarden.app import create_app
from patchwarden.models import (
    Advisory,
    Alert,
    AuditLog,
    NotificationChannel,
    Subscription,
    SubscriptionStatus,
    WatchCheck,
    WatchCounter,
)
from patchwarden.scanner import demo_sites
from patchwarden.scanner.service import Scanner
from patchwarden.watchdog import channels
from patchwarden.watchdog.feeds import EpssClient, KevFeed, NvdSource

from ..spec.test_phase3_acceptance import OCT, monitored_site, nvd_item, run
from ..unit.test_watchdog import _admin

CANARY = "canaryWebhookPath7Q2"  # must never come back in a response


class FakeSignals:
    """Stands in for CISA KEV and FIRST EPSS: tests edit `kev` and `epss` between polls."""

    def __init__(self):
        self.kev: dict[str, str] = {}
        self.epss: dict[str, float] = {}

    async def exploited(self) -> dict[str, str]:
        return dict(self.kev)

    async def scores(self, ids: list[str]) -> dict[str, float]:
        return {i: self.epss[i] for i in ids if i in self.epss}

    async def aclose(self) -> None:
        return None


class Receiver:
    """Every webhook POST that got past the SSRF checks lands here."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text="ok")


PUBLIC_DNS = {"hooks.slack.com": ["34.1.2.3"], "alerts.example.com": ["34.1.2.4"],
              "intranet.example.com": ["10.0.0.5"]}


@pytest.fixture
def signals():
    return FakeSignals()


@pytest.fixture
def receiver():
    return Receiver()


@pytest.fixture
def scanner(settings, world, receiver):
    async def resolve(host: str, port: int) -> list[str]:
        if host not in PUBLIC_DNS:
            raise OSError("no such host")
        return PUBLIC_DNS[host]
    return Scanner(settings, wporg_transport=demo_sites.demo_wporg_transport(), demo_world=world,
                   site_transport=httpx.MockTransport(receiver.handler), resolver=resolve)


@pytest.fixture
def client(settings, scanner, world, nvd, notifier, signals):
    sources = [NvdSource(api_key=settings.nvd_api_key, transport=httpx.MockTransport(nvd.handler))]
    app = create_app(settings, scanner=scanner, demo_world=world, notifier=notifier, sources=sources,
                     signals=(signals, signals))
    with TestClient(app) as c:
        yield c


def alerts_for(client, key: str) -> list[Alert]:
    with client.app.state.sessionmaker() as db:
        return db.query(Alert).filter(Alert.cve_id == key).all()


def emails_about(notifier, text: str) -> list:
    return [e for e in notifier.sent if text in e.subject or text in e.body]


def unpatched_site(client, auth) -> int:
    site_id = monitored_site(client, auth, "php84-unpatched")  # PHP 8.4.13
    run(client.app.state.watchdog.run_version_checks(OCT))
    return site_id


# --- priority ------------------------------------------------------------------------

def test_a_medium_finding_waits_for_the_daily_digest(client, auth_headers, nvd, notifier):
    unpatched_site(client, auth_headers)
    nvd.items.append(nvd_item("CVE-2026-999101", start="8.4.0", end_excl="8.4.27", severity="MEDIUM", score=5.3))
    run(client.app.state.watchdog.poll_feeds(OCT + timedelta(hours=1)))

    [alert] = alerts_for(client, "CVE-2026-999101")
    assert alert.priority == "digest" and alert.sent_at is None
    assert emails_about(notifier, "CVE-2026-999101") == []  # no email at 3am for a medium

    assert run(client.app.state.watchdog.send_digests(OCT + timedelta(days=1))) == 1
    [digest] = emails_about(notifier, "daily digest")
    assert digest.to == "owner@example.com" and demo("php84-unpatched") in digest.body
    assert "CVE-2026-999101" in digest.body
    assert run(client.app.state.watchdog.send_digests(OCT + timedelta(days=2))) == 0  # sent once
    api = client.get("/api/alerts", headers=auth_headers).json()["alerts"]
    assert {a["cve_id"]: a["priority"] for a in api}["CVE-2026-999101"] == "digest"


def test_a_likely_exploited_medium_finding_is_sent_at_once(client, auth_headers, nvd, notifier, signals):
    unpatched_site(client, auth_headers)
    signals.epss["CVE-2026-999102"] = 0.42  # 42% chance of exploitation in 30 days
    nvd.items.append(nvd_item("CVE-2026-999102", start="8.4.0", end_excl="8.4.27", severity="MEDIUM", score=5.3))
    run(client.app.state.watchdog.poll_feeds(OCT + timedelta(hours=1)))

    [alert] = alerts_for(client, "CVE-2026-999102")
    assert alert.priority == "urgent" and alert.sent_at is not None
    assert len(emails_about(notifier, "CVE-2026-999102")) == 1
    with client.app.state.sessionmaker() as db:
        assert db.get(Advisory, "CVE-2026-999102").epss == pytest.approx(0.42)


def test_an_already_exploited_flaw_says_so_in_the_first_alert(client, auth_headers, nvd, notifier, signals):
    unpatched_site(client, auth_headers)
    signals.kev["CVE-2026-999103"] = "2026-10-01"
    nvd.items.append(nvd_item("CVE-2026-999103", start="8.4.0", end_excl="8.4.27", severity="LOW", score=3.1))
    run(client.app.state.watchdog.poll_feeds(OCT + timedelta(hours=1)))

    [alert] = alerts_for(client, "CVE-2026-999103")
    assert alert.priority == "urgent" and alert.escalated_at is None  # first alert, not an escalation
    [email] = emails_about(notifier, "CVE-2026-999103")
    assert "being exploited" in email.subject and "CISA" in email.body


def test_a_flaw_that_becomes_exploited_later_is_escalated_once(client, auth_headers, nvd, notifier, signals):
    unpatched_site(client, auth_headers)
    nvd.items.append(nvd_item("CVE-2026-999104", start="8.4.0", end_excl="8.4.27", severity="MEDIUM", score=5.3))
    wd = client.app.state.watchdog
    run(wd.poll_feeds(OCT + timedelta(hours=1)))
    assert alerts_for(client, "CVE-2026-999104")[0].priority == "digest"

    signals.kev["CVE-2026-999104"] = "2026-10-03"  # CISA adds it two days later
    run(wd.poll_feeds(OCT + timedelta(days=2)))
    [alert] = alerts_for(client, "CVE-2026-999104")
    assert alert.priority == "urgent" and alert.escalated_at is not None
    [email] = emails_about(notifier, "is now being exploited")
    assert "CVE-2026-999104" in email.subject and email.to == "owner@example.com"

    run(wd.poll_feeds(OCT + timedelta(days=3)))  # still in KEV: no second escalation
    assert len(emails_about(notifier, "is now being exploited")) == 1
    assert run(wd._escalate({"CVE-2026-999104"}, OCT + timedelta(days=4))) == 0  # even when asked directly
    with client.app.state.sessionmaker() as db:
        assert db.query(AuditLog).filter_by(action="alert.escalated").count() == 1


# --- matching cost -------------------------------------------------------------------

def test_only_new_or_changed_advisories_are_matched(client, auth_headers, nvd):
    site_id = unpatched_site(client, auth_headers)
    wd = client.app.state.watchdog
    nvd.items.append(nvd_item("CVE-2026-999105", start="8.4.0", end_excl="8.4.27"))
    run(wd.poll_feeds(OCT + timedelta(hours=1)))
    assert len(alerts_for(client, "CVE-2026-999105")) == 1

    with client.app.state.sessionmaker() as db:  # forget the alert: an unchanged advisory is not matched again
        db.query(Alert).filter_by(cve_id="CVE-2026-999105").delete()
        db.commit()
    run(wd.poll_feeds(OCT + timedelta(hours=2)))
    assert alerts_for(client, "CVE-2026-999105") == []

    nvd.items[-1] = nvd_item("CVE-2026-999105", start="8.4.0", end_excl="8.4.30")  # NVD revises the range
    run(wd.poll_feeds(OCT + timedelta(hours=3)))
    assert len(alerts_for(client, "CVE-2026-999105")) == 1

    with client.app.state.sessionmaker() as db:
        counter = db.query(WatchCounter).filter_by(site_id=site_id, day="2026-10-01").one()
        assert counter.version_checks == 1 and counter.cve_checks == 3  # every poll counted...
        rows = db.query(WatchCheck).filter_by(site_id=site_id, kind="cve").count()
        assert rows == 2  # ...but a row only for the polls that found something


def test_a_version_change_rechecks_every_stored_advisory(client, auth_headers, nvd, monkeypatch):
    site_id = monitored_site(client, auth_headers, "php84-fixed")  # PHP 8.4.27
    wd = client.app.state.watchdog
    run(wd.run_version_checks(OCT))
    nvd.items.append(nvd_item("CVE-2026-999106", start="8.4.0", end_excl="8.4.27"))
    run(wd.poll_feeds(OCT + timedelta(hours=1)))
    assert alerts_for(client, "CVE-2026-999106") == []

    # Someone downgrades PHP on the server; the next daily check sees it.
    monkeypatch.setitem(demo_sites._SITES, "php84-fixed",
                        ({"X-Powered-By": "PHP/8.4.13"}, "<html><body>downgraded</body></html>"))
    run(wd.run_version_checks(OCT + timedelta(days=1)))
    assert [a.site_id for a in alerts_for(client, "CVE-2026-999106")] == [site_id]


def test_version_checks_run_in_parallel_up_to_the_limit(client, auth_headers):
    wd = client.app.state.watchdog
    ids = [monitored_site(client, auth_headers, f"bulk-{i:02d}") for i in range(1, 9)]
    wd.settings = replace(wd.settings, watchdog_concurrency=3)
    original, state = wd._read_version, {"now": 0, "peak": 0}

    async def tracked(site):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.02)
        try:
            return await original(site)
        finally:
            state["now"] -= 1

    wd._read_version = tracked
    assert run(wd.run_version_checks(OCT)) == 8
    assert state["peak"] == 3
    with client.app.state.sessionmaker() as db:
        checked = [c.site_id for c in db.query(WatchCheck).filter_by(kind="version").order_by(WatchCheck.id)]
    assert checked == ids  # written in a stable order


# --- channels ------------------------------------------------------------------------

@pytest.mark.parametrize("kind,url,code", [
    ("slack", "https://example.com/services/T0/B0/x", "invalid_url"),
    ("teams", "https://hooks.slack.com/services/T0/B0/x", "invalid_url"),
    ("webhook", "http://alerts.example.com/hook", "invalid_url"),
    ("webhook", "https://user:pw@alerts.example.com/hook", "invalid_url"),
    ("pager", "https://alerts.example.com/hook", "invalid_kind"),
])
def test_channel_addresses_are_checked(client, auth_headers, kind, url, code):
    r = client.post("/api/channels", json={"kind": kind, "url": url}, headers=auth_headers)
    assert r.status_code == 422 and r.json()["error"] == code and r.json()["message"]


def test_channel_urls_are_stored_encrypted_and_never_shown(client, auth_headers):
    url = f"https://hooks.slack.com/services/T0/B0/{CANARY}"
    r = client.post("/api/channels", json={"kind": "slack", "url": url}, headers=auth_headers)
    assert r.status_code == 201 and r.json()["host"] == "hooks.slack.com" and "signing_secret" not in r.json()
    listed = client.get("/api/channels", headers=auth_headers)
    assert CANARY not in r.text + listed.text
    with client.app.state.sessionmaker() as db:
        row = db.query(NotificationChannel).one()
        assert CANARY.encode() not in row.url_encrypted.encode() if isinstance(row.url_encrypted, str) \
            else CANARY.encode() not in row.url_encrypted
        assert all(CANARY not in json.dumps(a.detail) for a in db.query(AuditLog))


def test_urgent_alerts_reach_slack_and_a_signed_webhook(client, auth_headers, nvd, receiver):
    unpatched_site(client, auth_headers)
    slack = client.post("/api/channels", json={"kind": "slack", "url": "https://hooks.slack.com/services/T0/B0/x"},
                        headers=auth_headers).json()
    hook = client.post("/api/channels", json={"kind": "webhook", "url": "https://alerts.example.com/hook"},
                       headers=auth_headers).json()
    secret = hook["signing_secret"]
    assert "signing_secret" not in json.dumps(client.get("/api/channels", headers=auth_headers).json())

    nvd.items.append(nvd_item("CVE-2026-999107", start="8.4.0", end_excl="8.4.27", severity="CRITICAL", score=9.8))
    run(client.app.state.watchdog.poll_feeds(OCT + timedelta(hours=1)))

    by_host = {r.headers["host"]: r for r in receiver.requests}
    assert str(by_host["hooks.slack.com"].url).startswith("https://34.1.2.3/")  # pinned to the checked address
    assert "CVE-2026-999107" in json.loads(by_host["hooks.slack.com"].content)["text"]
    signed = by_host["alerts.example.com"]
    ts, body = signed.headers["x-patchwarden-timestamp"], signed.content
    assert signed.headers["x-patchwarden-signature"] == channels.sign(secret, ts, body)
    assert channels.sign("wrong-secret", ts, body) != signed.headers["x-patchwarden-signature"]
    assert json.loads(body)["data"]["key"] == "CVE-2026-999107"
    [alert] = alerts_for(client, "CVE-2026-999107")
    assert alert.delivered == {str(slack["id"]): "ok", str(hook["id"]): "ok"}


def test_a_webhook_pointing_inside_the_network_is_refused(client, auth_headers, receiver):
    hook = client.post("/api/channels", json={"kind": "webhook", "url": "https://intranet.example.com/hook"},
                       headers=auth_headers).json()
    r = client.post(f"/api/channels/{hook['id']}/test", headers=auth_headers).json()
    assert r == {"channel_id": hook["id"], "ok": False, "result": "blocked_private"}
    assert receiver.requests == []


def test_channels_belong_to_their_owner(client, auth_headers, receiver):
    hook = client.post("/api/channels", json={"kind": "webhook", "url": "https://alerts.example.com/hook"},
                       headers=auth_headers).json()
    client.post("/api/channels", json={"kind": "slack", "url": "https://hooks.slack.com/services/T0/B0/x"},
                headers=auth_headers)
    assert client.post(f"/api/channels/{hook['id']}/test", headers=auth_headers).json()["ok"] is True
    assert [r.headers["host"] for r in receiver.requests] == ["alerts.example.com"]  # only the one tested
    other = _admin(client)
    assert client.post(f"/api/channels/{hook['id']}/test", headers=other).json()["error"] == "channel_not_found"
    assert client.delete(f"/api/channels/{hook['id']}", headers=other).status_code == 404
    assert client.delete(f"/api/channels/{hook['id']}", headers=auth_headers).json() == {"removed": hook["id"]}


# --- dunning -------------------------------------------------------------------------

def monitored(client, site_id: int) -> bool:
    with client.app.state.sessionmaker() as db:
        return site_id in [s.id for s in client.app.state.watchdog.monitored_sites(db)]


def past_due(client, auth, site_id: int) -> Subscription:
    sub_id = client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True},
                         headers=auth).json()["subscription"]["id"]
    r = client.post(f"/api/subscriptions/{sub_id}/status", json={"status": "past_due"}, headers=_admin(client))
    assert r.json()["status"] == "past_due"
    with client.app.state.sessionmaker() as db:
        return db.get(Subscription, sub_id)


def test_past_due_owners_are_reminded_then_monitoring_lapses(client, auth_headers, notifier):
    site_id = monitored_site(client, auth_headers, "php84-unpatched")
    sub = past_due(client, auth_headers, site_id)
    assert sub.past_due_since is not None and sub.reminders_sent == 0
    wd, start = client.app.state.watchdog, sub.past_due_since

    for day in (0, 1, 1, 2, 7, 8, 13):
        run(wd.dunning_tick(start + timedelta(days=day, hours=1)))
    reminders = emails_about(notifier, "payment needed")
    assert len(reminders) == 3  # day 1, day 7, day 13: not every day
    assert "1 more day" in reminders[-1].body
    assert monitored(client, site_id)

    assert run(wd.dunning_tick(start + timedelta(days=14, hours=1))) == {"reminded": 0, "lapsed": 1}
    assert not monitored(client, site_id)
    assert len(emails_about(notifier, "has stopped")) == 1
    with client.app.state.sessionmaker() as db:
        assert db.query(AuditLog).filter_by(action="subscription.lapsed").count() == 1
        assert db.get(Subscription, sub.id).status == SubscriptionStatus.cancelled


def test_paying_again_stops_the_reminders(client, auth_headers, notifier):
    site_id = monitored_site(client, auth_headers, "php84-unpatched")
    sub = past_due(client, auth_headers, site_id)
    client.post(f"/api/subscriptions/{sub.id}/status", json={"status": "active"}, headers=_admin(client))
    with client.app.state.sessionmaker() as db:
        assert db.get(Subscription, sub.id).past_due_since is None
    assert run(client.app.state.watchdog.dunning_tick(sub.past_due_since + timedelta(days=20))) == \
        {"reminded": 0, "lapsed": 0}
    assert emails_about(notifier, "payment") == []


def demo(label: str) -> str:
    return f"{label}{demo_sites.DEMO_SUFFIX}"
