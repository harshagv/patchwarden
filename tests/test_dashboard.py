"""Dashboard: cookie login, CSRF on every form, approve and one-click rollback from the report page."""

from __future__ import annotations

import re

from .conftest import demo
from .test_phase2_acceptance import add_site


def _login(client) -> None:
    r = client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"},
                    follow_redirects=False)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie


def _csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


def test_pages_need_login(client):
    for path in ("/dashboard/sites", "/dashboard/patches/1"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/dashboard/login"


def test_bad_login_is_plain_and_generic(client, auth_headers):
    r = client.post("/dashboard/login", data={"email": "owner@example.com", "password": "wrong password!"})
    assert r.status_code == 401 and "That email and password do not match." in r.text


def test_full_flow_plan_approve_rollback_from_dashboard(client, auth_headers, world):
    add_site(client, auth_headers, "shop84")
    _login(client)
    page = client.get("/dashboard/sites")
    assert demo("shop84") in page.text
    site_id = re.search(r'/dashboard/sites/(\d+)/patch', page.text).group(1)
    csrf = _csrf(page.text)

    # Forms without the CSRF token, or from another origin, are refused.
    assert client.post(f"/dashboard/sites/{site_id}/patch", data={}).status_code == 403
    r = client.post(f"/dashboard/sites/{site_id}/patch", data={"csrf": csrf}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert world.get(demo("shop84")).mutations == []

    r = client.post(f"/dashboard/sites/{site_id}/patch", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    job_url = r.headers["location"]
    page = client.get(job_url)
    assert "Dry run: waiting for your approval" in page.text and "Approve and run" in page.text
    assert world.get(demo("shop84")).mutations == []

    r = client.post(f"{job_url}/approve", data={"csrf": _csrf(page.text)}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get(job_url)
    assert "Done: site updated" in page.text
    assert "Approved by: owner@example.com" in page.text
    assert "Roll back to PHP 8.4.13" in page.text
    assert world.get(demo("shop84")).php_version == "8.4.27"

    client.post(f"{job_url}/rollback", data={"csrf": _csrf(page.text)})
    page = client.get(job_url)
    assert "Rolled back" in page.text and "Started by the owner" in page.text
    assert world.get(demo("shop84")).php_version == "8.4.13"


def test_add_site_and_token_from_dashboard(client, auth_headers):
    _login(client)
    csrf = _csrf(client.get("/dashboard/sites").text)
    r = client.post("/dashboard/sites", data={"csrf": csrf, "domain": demo("shop83"), "platform": "custom",
                                              "login_path": "/login"}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/dashboard/sites")
    site_id = re.search(r'/dashboard/sites/(\d+)/credentials', page.text).group(1)
    client.post(f"/dashboard/sites/{site_id}/credentials",
                data={"csrf": csrf, "kind": "cpanel_token", "value": "dash-token-value-9"})
    page = client.get("/dashboard/sites")
    assert "cpanel_token saved" in page.text and "dash-token-value-9" not in page.text
    r = client.post(f"/dashboard/sites/{site_id}/patch", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303


def test_dashboard_errors_render_in_page(client, auth_headers):
    _login(client)
    csrf = _csrf(client.get("/dashboard/sites").text)
    client.post("/dashboard/sites", data={"csrf": csrf, "domain": demo("shop84")})
    page = client.get("/dashboard/sites")
    site_id = re.search(r'/dashboard/sites/(\d+)/patch', page.text).group(1)
    r = client.post(f"/dashboard/sites/{site_id}/patch", data={"csrf": csrf})
    assert r.status_code == 409 and "Add a hosting panel API token" in r.text
