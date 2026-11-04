"""Phase B: the scanner funnel. Background list scans, ownership verification, verified-only detail,
claiming a site, guided hosting connection, funnel metrics."""

from __future__ import annotations

import asyncio
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from patchwarden.app import create_app
from patchwarden.dashboard import safe_next
from patchwarden.fakes import SimulatedCrash
from patchwarden.jobs import JobQueue, make_handlers
from patchwarden.models import AuditLog, Role, Scan, ScanBatch, Site, User
from patchwarden.scanner import service as scanner_service

from .conftest import demo, verify_site
from .test_phase2_acceptance import add_site


def login(client, email="owner@example.com", password="correct horse battery") -> None:
    r = client.post("/dashboard/login", data={"email": email, "password": password}, follow_redirects=False)
    assert r.status_code == 303


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


# --- background list scans --------------------------------------------------------

def test_list_scan_survives_a_crash_without_duplicates(client, auth_headers, monkeypatch):
    monkeypatch.setattr(scanner_service, "BATCH_CHUNK", 3)
    targets = [demo(f"bulk-0{i}") for i in range(1, 8)]
    with client.app.state.sessionmaker() as db:
        owner = db.query(User).filter_by(email="owner@example.com").one()
        batch = ScanBatch(owner_id=owner.id, targets=targets, total=len(targets))
        db.add(batch)
        db.commit()
        queued = client.app.state.jobs.enqueue(db, "bulk_scan", batch.id, owner.id).id
        batch_id = batch.id

    real = client.app.state.scanner.scan_many
    calls = {"n": 0}

    async def dies_on_second_chunk(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise SimulatedCrash("worker died mid-list")
        return await real(*a, **kw)

    monkeypatch.setattr(client.app.state.scanner, "scan_many", dies_on_second_chunk)
    with pytest.raises(SimulatedCrash):
        asyncio.run(client.app.state.jobs.run_one(queued))
    progress = client.get(f"/api/scan-batches/{batch_id}", headers=auth_headers).json()
    assert progress["state"] == "running" and progress["done"] == 3 and progress["count"] == 3

    later = JobQueue(client.app.state.sessionmaker, make_handlers(client.app.state),
                     clock=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    asyncio.run(later.run_pending())
    done = client.get(f"/api/scan-batches/{batch_id}", headers=auth_headers).json()
    assert done["state"] == "done" and done["done"] == 7 and done["count"] == 7
    with client.app.state.sessionmaker() as db:
        assert db.query(Scan).filter(Scan.batch_id == batch_id).count() == 7  # nothing scanned twice


def test_an_unstarted_list_is_picked_up_at_startup(client, auth_headers):
    with client.app.state.sessionmaker() as db:
        owner = db.query(User).filter_by(email="owner@example.com").one()
        db.add(ScanBatch(owner_id=owner.id, targets=[demo("php84-fixed")], total=1))
        db.commit()
    assert client.app.state.jobs.reconcile_orphans() == 1
    asyncio.run(client.app.state.jobs.run_pending())
    with client.app.state.sessionmaker() as db:
        assert db.query(ScanBatch).one().state == "done"


def test_list_scan_from_the_dashboard(client, auth_headers):
    login(client)
    token = csrf(client.get("/dashboard/sites").text)
    rows = "\n".join(demo(f"bulk-{i:02d}") for i in range(1, 11)).encode()
    r = client.post("/dashboard/scan-batches", data={"csrf": token},
                    files={"file": ("sites.csv", rows, "text/csv")}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get(r.headers["location"]).text
    assert "10 of 10 checked" in page and "<strong>done</strong>" in page


def test_other_people_cannot_see_your_list(client, auth_headers):
    r = client.post("/api/scans", json={"domains": [demo("php84-fixed")]}, headers=auth_headers)
    client.post("/api/auth/register", json={"email": "other@example.com", "password": "another long password"})
    other = {"Authorization": "Bearer " + client.post("/api/auth/login", json={
        "email": "other@example.com", "password": "another long password"}).json()["access_token"]}
    assert client.get(r.json()["status_url"], headers=other).status_code == 404


# --- ownership verification -------------------------------------------------------

def test_verification_by_dns_explains_what_is_missing(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    v = client.post(f"/api/sites/{site_id}/verification", headers=auth_headers).json()
    assert v["dns"]["name"] == f"_patchwarden-challenge.{demo('shop84')}"
    assert v["dns"]["value"].startswith("patchwarden-verification=") and v["verified"] is False

    r = client.post(f"/api/sites/{site_id}/verification/check", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "not_verified"
    assert "TXT record with this token was not found" in r.json()["message"]
    assert "verification file was not there (HTTP 404)" in r.json()["message"]

    world.txt_records[v["dns"]["name"]] = ["patchwarden-verification=someone-elses-token"]
    r = client.post(f"/api/sites/{site_id}/verification/check", headers=auth_headers)
    assert r.status_code == 409 and "not with this site's token" in r.json()["message"]

    world.txt_records[v["dns"]["name"]].append(v["dns"]["value"])
    r = client.post(f"/api/sites/{site_id}/verification/check", headers=auth_headers)
    assert r.status_code == 200 and r.json()["method"] == "dns"
    with client.app.state.sessionmaker() as db:
        assert db.get(Site, site_id).verified_at is not None
        assert db.query(AuditLog).filter_by(action="site.verified").count() == 1


def test_verification_by_file(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    token = client.post(f"/api/sites/{site_id}/verification", headers=auth_headers).json()["file"]["contents"]
    host = world.get(demo("shop84"))
    # A file that exists but holds something else (a catch-all page, say) must not count.
    host.well_known["/.well-known/patchwarden-verification.txt"] = "<html>Welcome to our shop</html>"
    r = client.post(f"/api/sites/{site_id}/verification/check", headers=auth_headers)
    assert r.status_code == 409 and "did not contain this site's token" in r.json()["message"]
    world.get(demo("shop84")).well_known["/.well-known/patchwarden-verification.txt"] = token + "\n"
    r = client.post(f"/api/sites/{site_id}/verification/check", headers=auth_headers)
    assert r.status_code == 200 and r.json()["method"] == "file"


def test_your_token_never_verifies_someone_elses_copy(client, auth_headers, world):
    mine = add_site(client, auth_headers, "shop84")
    client.post("/api/auth/register", json={"email": "rival@example.com", "password": "another long password"})
    rival = {"Authorization": "Bearer " + client.post("/api/auth/login", json={
        "email": "rival@example.com", "password": "another long password"}).json()["access_token"]}
    theirs = client.post("/api/sites", json={"domain": demo("shop84")}, headers=rival).json()["id"]
    verify_site(client, rival, world, theirs)  # the rival controls DNS for this demo domain
    r = client.post(f"/api/sites/{mine}/verification/check", headers=auth_headers)
    assert r.status_code == 409  # their record carries their token, not mine


def test_a_connected_plugin_proves_ownership(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("blog"), "platform": "wordpress"},
                          headers=auth_headers).json()["id"]
    key = client.post(f"/api/sites/{site_id}/plugin-key", headers=auth_headers).json()["key"]
    r = client.post("/api/plugin/report", headers={"X-Patchwarden-Key": key},
                    json={"site_url": f"https://{demo('blog')}", "php_version": "8.4.27", "plugins": [], "themes": []})
    assert r.status_code == 200
    v = client.get(f"/api/sites/{site_id}/verification", headers=auth_headers).json()
    assert v["verified"] is True and v["method"] == "plugin"


# --- what each viewer sees -----------------------------------------------------------

def test_anonymous_and_unverified_viewers_get_the_basic_report(client, auth_headers, world):
    anon = client.post("/api/scans", json={"domain": demo("php84-unpatched")}).json()["scans"][0]
    assert anon["detail"] == "basic" and anon["raw_headers"] == {} and anon["unlock"]
    assert anon["detected_version"] == "8.4.13" and anon["risk"] == "patch_now"  # what the site shows anyway

    mine = client.post("/api/scans", json={"domain": demo("php84-unpatched")}, headers=auth_headers).json()["scans"][0]
    assert mine["detail"] == "basic"  # owner, but not verified yet
    link = client.get(f"/api/scans/{mine['id']}/share", headers=auth_headers).json()["url"]
    token = parse_qs(urlsplit(link).query)["token"][0]
    assert TestClient(client.app).get(f"/api/scans/{mine['id']}", params={"token": token}).json()["detail"] == "basic"

    verify_site(client, auth_headers, world, mine["site_id"])
    full = client.get(f"/api/scans/{mine['id']}", headers=auth_headers).json()
    assert full["detail"] == "full" and full["raw_headers"]["x-powered-by"] == "PHP/8.4.13" and "unlock" not in full
    # A link the verified owner sends shows the full report.
    shared = TestClient(client.app).get(f"/api/scans/{mine['id']}", params={"token": token}).json()
    assert shared["detail"] == "full"


def test_admins_see_full_detail(client, auth_headers):
    scan = client.post("/api/scans", json={"domain": demo("php84-unpatched")}).json()["scans"][0]
    with client.app.state.sessionmaker() as db:
        db.query(User).filter_by(email="owner@example.com").one().role = Role.admin
        db.commit()
    assert client.get(f"/api/scans/{scan['id']}", headers=auth_headers).json()["detail"] == "full"


def test_report_page_invites_the_owner_to_claim(client):
    for label, cta in (("php84-unpatched", "Is this your site?"), ("hidden", "See your real version")):
        scan = client.post("/api/scans", json={"domain": demo(label)}).json()["scans"][0]
        url = urlsplit(scan["share_url"])
        page = TestClient(client.app).get(f"{url.path}?{url.query}", headers={"Accept": "text/html"}).text
        assert cta in page and f'href="/dashboard/claim/{scan["id"]}?token=' in page


# --- claiming a site -------------------------------------------------------------

def test_claim_by_api_copies_the_report_and_starts_verification(client, auth_headers):
    anon = client.post("/api/scans", json={"domain": demo("php84-unpatched")}).json()["scans"][0]
    token = parse_qs(urlsplit(anon["share_url"]).query)["token"][0]
    assert client.post(f"/api/scans/{anon['id']}/claim", headers=auth_headers).status_code == 404  # needs the link
    r = client.post(f"/api/scans/{anon['id']}/claim", params={"token": token}, headers=auth_headers)
    assert r.status_code == 201
    claimed = r.json()
    assert claimed["scan_id"] != anon["id"] and claimed["verification"]["dns"]["value"].startswith("patchwarden-verification=")
    again = client.post(f"/api/scans/{anon['id']}/claim", params={"token": token}, headers=auth_headers).json()
    assert again["site_id"] == claimed["site_id"]  # same site, not a duplicate
    with client.app.state.sessionmaker() as db:
        site = db.get(Site, claimed["site_id"])
        assert site.owner_id is not None and site.domain == demo("php84-unpatched")
        assert db.get(Scan, claimed["scan_id"]).risk.value == "patch_now"


def test_claim_from_the_report_through_sign_up_to_verified(client, world):
    anon = client.post("/api/scans", json={"domain": demo("php84-unpatched")}).json()["scans"][0]
    url = urlsplit(anon["share_url"])
    claim = f"/dashboard/claim/{anon['id']}?{url.query}"

    r = client.get(claim, follow_redirects=False)  # not logged in: off to sign-up, coming back after
    assert r.status_code == 303 and r.headers["location"].startswith("/dashboard/signup?next=")
    nxt = parse_qs(urlsplit(r.headers["location"]).query)["next"][0]
    r = client.post("/dashboard/signup", data={"email": "new@example.com", "password": "a brand new password",
                                               "next": nxt}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == claim

    page = client.get(claim)
    assert "Add it to my sites" in page.text
    r = client.post(f"/dashboard/claim/{anon['id']}", data={"csrf": csrf(page.text), "token": parse_qs(url.query)["token"][0]},
                    follow_redirects=False)
    verify_url = r.headers["location"]
    assert r.status_code == 303 and verify_url.endswith("/verify")
    page = client.get(verify_url).text
    name = re.search(r"<code>(_patchwarden-challenge\.[^<]+)</code>", page).group(1)
    value = re.search(r"<code>(patchwarden-verification=[^<]+)</code>", page).group(1)
    world.txt_records[name] = [value]
    done = client.post(verify_url, data={"csrf": csrf(page)})
    assert done.status_code == 200 and "Verified by DNS" in done.text


@pytest.mark.parametrize("raw,expected", [
    ("/dashboard/claim/3?token=x", "/dashboard/claim/3?token=x"),
    ("//evil.example/x", "/dashboard/sites"), ("https://evil.example", "/dashboard/sites"),
    ("/api/auth/logout-all", "/dashboard/sites"), ("/dashboard/\\evil", "/dashboard/sites"), (None, "/dashboard/sites"),
])
def test_sign_up_never_redirects_off_the_dashboard(raw, expected):
    assert safe_next(raw) == expected


# --- guided hosting connection -------------------------------------------------------

def test_test_connection_is_read_only_and_honest(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    r = client.post(f"/api/sites/{site_id}/test-connection", headers=auth_headers).json()
    assert r == {"ok": True, "access": "cPanel", "php_version": "8.4.13",
                 "available_versions": ["8.3.36", "8.4.13", "8.4.27", "8.5.12"]}
    assert world.get(demo("shop84")).mutations == []

    real = client.post("/api/sites", json={"domain": "example.com"}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{real}/credentials", json={"kind": "cpanel_token", "value": "x" * 20}, headers=auth_headers)
    r = client.post(f"/api/sites/{real}/test-connection", headers=auth_headers)
    assert r.status_code == 502 and r.json()["error"] == "adapter_not_connected"

    login(client)
    page = client.get(f"/dashboard/sites/{site_id}/connect")
    assert "Security → Manage API Tokens" in page.text and "never your password" in page.text
    tested = client.post(f"/dashboard/sites/{site_id}/test-connection", data={"csrf": csrf(page.text)})
    assert tested.status_code == 200 and "the site runs PHP 8.4.13. Nothing was changed." in tested.text


# --- funnel metrics and sign-up limits ---------------------------------------------

def test_funnel_metrics_for_admins(client, auth_headers, world):
    anon = client.post("/api/scans", json={"domain": demo("php84-unpatched")}).json()["scans"][0]
    token = parse_qs(urlsplit(anon["share_url"]).query)["token"][0]
    claimed = client.post(f"/api/scans/{anon['id']}/claim", params={"token": token}, headers=auth_headers).json()
    verify_site(client, auth_headers, world, claimed["site_id"])
    assert client.get("/api/admin/funnel", headers=auth_headers).status_code == 403
    with client.app.state.sessionmaker() as db:
        db.query(User).filter_by(email="owner@example.com").one().role = Role.admin
        db.commit()
    f = client.get("/api/admin/funnel", headers=auth_headers).json()
    assert f["stages"]["free_scans"] == 1 and f["stages"]["claimed_sites"] == 1 and f["stages"]["verified_sites"] == 1
    assert f["conversion"]["claimed_sites_to_verified_sites"] == 1.0


def test_sign_ups_are_rate_limited(settings, world):
    with TestClient(create_app(replace(settings, signup_limit=2), demo_world=world)) as c:
        for i in range(2):
            assert c.post("/api/auth/register", json={"email": f"u{i}@example.com",
                                                      "password": "correct horse battery"}).status_code == 201
        r = c.post("/api/auth/register", json={"email": "u9@example.com", "password": "correct horse battery"})
        assert r.status_code == 429 and "Retry-After" in r.headers


def test_demo_publish_button_only_for_demo_domains(client, auth_headers):
    demo_site = add_site(client, auth_headers, "shop84")
    real = client.post("/api/sites", json={"domain": "example.com"}, headers=auth_headers).json()["id"]
    login(client)
    page = client.get(f"/dashboard/sites/{demo_site}/verify").text
    assert "publish the DNS record for me" in page
    client.post(f"/dashboard/sites/{demo_site}/verify/demo-publish", data={"csrf": csrf(page)})
    assert "Verified by DNS" in client.post(f"/dashboard/sites/{demo_site}/verify", data={"csrf": csrf(page)}).text
    real_page = client.get(f"/dashboard/sites/{real}/verify").text
    assert "publish the DNS record for me" not in real_page
    assert client.post(f"/dashboard/sites/{real}/verify/demo-publish", data={"csrf": csrf(real_page)}).status_code == 404
