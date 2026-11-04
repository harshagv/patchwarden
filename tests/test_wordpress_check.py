"""WordPress plugin/theme check against the mocked WordPress.org API and the fixture feed."""

from __future__ import annotations

from patchwarden.models import Platform, Site

from .conftest import demo, verify_site


def test_wordpress_site_lists_components_and_flags_known_problems(client, auth_headers, world):
    r = client.post("/api/scans", json={"domain": demo("wordpress"), "wordpress": True}, headers=auth_headers)
    assert r.status_code == 201
    scan = r.json()["scans"][0]
    assert scan["risk"] == "patch_now"  # PHP 8.3.20
    # Before ownership is proved: the count, not which plugin is vulnerable.
    assert scan["detail"] == "basic" and scan["findings"]["wordpress"]["issues"] == 2
    assert scan["findings"]["wordpress"]["components"] == 3 and scan["raw_headers"] == {}
    verify_site(client, auth_headers, world, scan["site_id"])
    scan = client.get(f"/api/scans/{scan['id']}", headers=auth_headers).json()
    assert scan["detail"] == "full"

    wp = scan["findings"]["wordpress"]
    assert wp["detected"] and wp["core_version"] == "6.6.2"
    by_slug = {c["slug"]: c for c in wp["components"]}
    assert set(by_slug) == {"demo-contact-form", "demo-gallery", "demo-storefront"}

    # 2.3.0 < fixed 2.4.1: affected.
    form = by_slug["demo-contact-form"]
    assert form["wordpress_org"] == {"lookup": "ok", "name": "Demo Contact Form", "latest_version": "2.5.0"}
    assert [v["status"] for v in form["vulnerabilities"]] == ["affected"]
    # 1.9.2 >= fixed 1.9.0: not flagged.
    assert by_slug["demo-gallery"]["vulnerabilities"] == []
    # No visible version: flagged as "check needed", never claimed as affected.
    assert [v["status"] for v in by_slug["demo-storefront"]["vulnerabilities"]] == ["check_needed"]
    assert wp["issues"] == 2

    with client.app.state.sessionmaker() as db:
        assert db.get(Site, scan["site_id"]).platform == Platform.wordpress


def test_wordpress_section_in_report_is_plain_language(client, auth_headers, world):
    scan = client.post("/api/scans", json={"domain": demo("wordpress")}, headers=auth_headers).json()["scans"][0]
    basic = client.get(f"/scans/{scan['id']}", headers={**auth_headers, "Accept": "text/html"}).text
    assert "2 known security problem(s)" in basic and "Demo Contact Form" not in basic
    verify_site(client, auth_headers, world, scan["site_id"])
    html = client.get(f"/scans/{scan['id']}", headers={**auth_headers, "Accept": "text/html"}).text
    assert "Demo Contact Form</strong> (plugin): has a known security problem (critical). Update it to 2.4.1 or newer." in html
    assert "We could not see its version" in html


def test_wordpress_requested_but_not_detected(client):
    scan = client.post("/api/scans", json={"domain": demo("php84-fixed"), "wordpress": True}).json()["scans"][0]
    assert scan["findings"]["wordpress"]["detected"] is False


def test_non_wordpress_site_has_no_wordpress_section(client):
    scan = client.post("/api/scans", json={"domain": demo("php84-fixed")}).json()["scans"][0]
    assert "wordpress" not in scan["findings"]
