"""Phase 1 acceptance tests, one per bullet in SPEC.md section 4."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import jwt
from fastapi.testclient import TestClient

from patchwarden.models import Scan

from ..conftest import TEST_JWT_SECRET, demo


def _scan(client, domain: str, headers=None) -> dict:
    r = client.post("/api/scans", json={"domain": domain}, headers=headers or {})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["count"] == 1 and body["rejected"] == []
    return body["scans"][0]


def test_php84_unpatched_returns_patch_now(client):
    scan = _scan(client, demo("php84-unpatched"))
    assert scan["risk"] == "patch_now"
    assert scan["detected_version"] == "8.4.13"
    assert scan["fixed_version"] == "8.4.27"


def test_fixed_version_returns_safe(client):
    scan = _scan(client, demo("php84-fixed"))
    assert scan["risk"] == "safe"
    assert scan["detected_version"] == "8.4.27"
    assert _scan(client, demo("php85-fixed"))["risk"] == "safe"


def test_php81_returns_must_migrate(client):
    scan = _scan(client, demo("php81"))
    assert scan["risk"] == "must_migrate"
    # Read from the Server header of a distro build, reported as-is.
    assert scan["detected_version"] == "8.1.2-1ubuntu2.14"
    assert scan["findings"]["version_source"] == "server"


def test_hidden_version_returns_unknown_not_a_guess(client):
    scan = _scan(client, demo("hidden"))
    assert scan["risk"] == "unknown"
    assert scan["detected_version"] is None
    assert scan["fixed_version"] is None
    # PHP is visible (session cookie) but we still do not invent a version.
    assert scan["findings"]["php_detected"] is True
    # The site's cookie value is not stored, only its name.
    assert "demo-session-value" not in str(scan["raw_headers"])


def test_bulk_csv_of_10_domains_stores_10_scans(client, auth_headers):
    rows = ["domain"] + [demo(f"bulk-{i:02d}") for i in range(1, 11)]
    csv_bytes = ("\n".join(rows) + "\n").encode()
    # Since Phase B a list runs in the background (202 + a status URL) and needs a free account.
    assert client.post("/api/scans", files={"file": ("sites.csv", csv_bytes, "text/csv")}).status_code == 401
    r = client.post("/api/scans", files={"file": ("sites.csv", csv_bytes, "text/csv")}, headers=auth_headers)
    assert r.status_code == 202, r.text
    body = client.get(r.json()["status_url"], headers=auth_headers).json()
    assert body["state"] == "done" and body["total"] == body["done"] == 10
    assert body["count"] == 10
    assert body["rejected"] == []
    assert {s["domain"] for s in body["scans"]} == {demo(f"bulk-{i:02d}") for i in range(1, 11)}

    with client.app.state.sessionmaker() as db:
        assert db.query(Scan).count() == 10
        assert db.query(Scan).filter(Scan.batch_id == body["id"]).count() == 10
    risks = {s["risk"] for s in body["scans"]}
    assert risks == {"safe", "patch_now", "must_migrate", "unknown"}


def test_html_report_renders_via_signed_link_without_login(client, auth_headers):
    scan = _scan(client, demo("php84-unpatched"), headers=auth_headers)
    r = client.get(f"/api/scans/{scan['id']}/share", headers=auth_headers)
    assert r.status_code == 200, r.text
    link = urlsplit(r.json()["url"])

    anonymous = TestClient(client.app)  # no Authorization header, no cookies
    page = anonymous.get(f"{link.path}?{link.query}", headers={"Accept": "text/html"})
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    html = page.text
    for text in ("Your version", "Your risk", "What to do next", demo("php84-unpatched"),
                 "PHP 8.4.13", "Patch now", "8.4.27"):
        assert text in html
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["cache-control"] == "no-store"

    # Without the token, or with a tampered or expired one, the report stays private.
    assert anonymous.get(link.path).status_code == 401
    assert anonymous.get(f"{link.path}?token=nope").status_code == 404
    expired = jwt.encode(
        {"sub": f"scan:{scan['id']}", "purpose": "scan_share", "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
        TEST_JWT_SECRET, algorithm="HS256",
    )
    assert anonymous.get(f"{link.path}?token={expired}").status_code == 404
