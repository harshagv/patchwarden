"""Phase D: teams and roles, entitlements and the billing export, outcome reports, signed attestations,
instant migration quotes, white-label branding."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from patchwarden.commerce.attest import canonical
from patchwarden.models import Alert, AuditLog, PatchJob, User

from ..conftest import demo, verify_site
from ..spec.test_phase2_acceptance import add_site, dry_run
from ..spec.test_phase3_acceptance import nvd_item
from ..spec.test_phase4_acceptance import add_wp74, plan
from ..unit.test_watchdog import _admin


def run(coro):
    return asyncio.run(coro)


def user(client, email: str) -> dict:
    client.post("/api/auth/register", json={"email": email, "password": "a long test password"})
    token = client.post("/api/auth/login", json={"email": email, "password": "a long test password"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def team(client, owner: dict, members: dict[str, str] | None = None) -> int:
    """A team owned by `owner`, with members as {email: role}."""
    org = client.post("/api/orgs", json={"name": "Agency"}, headers=owner).json()
    for email, role in (members or {}).items():
        r = client.post(f"/api/orgs/{org['id']}/members", json={"email": email, "role": role},
                        headers=owner)
        assert r.status_code == 201, r.text
    return org["id"]


def share(client, owner: dict, site_id: int, org_id: int) -> None:
    r = client.post(f"/api/sites/{site_id}/team", json={"org_id": org_id}, headers=owner)
    assert r.json() == {"site_id": site_id, "org_id": org_id}, r.text


# --- teams and roles -----------------------------------------------------------------

def test_team_roles_decide_what_each_member_can_do(client, auth_headers, world):
    member, approver, viewer = (user(client, "dev@example.com"), user(client, "lead@example.com"),
                                user(client, "client@example.com"))
    outsider = user(client, "outsider@example.com")
    org = team(client, auth_headers, {"dev@example.com": "member", "lead@example.com": "approver", "client@example.com": "viewer"})
    site_id = add_site(client, auth_headers, "shop84")
    share(client, auth_headers, site_id, org)

    # Everyone in the team sees the site; nobody else does.
    for h in (member, approver, viewer):
        assert client.get(f"/api/sites/{site_id}", headers=h).status_code == 200
        assert site_id in [s["id"] for s in client.get("/api/sites", headers=h).json()["sites"]]
    assert client.get(f"/api/sites/{site_id}", headers=outsider).status_code == 404

    # A viewer cannot plan; an approver cannot plan; a member can.
    for h in (viewer, approver):
        r = client.post("/api/patches", json={"site_id": site_id}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "edit_not_allowed", r.text
    job = dry_run(client, member, site_id)

    # A member cannot approve; a viewer cannot approve; the approver can.
    for h in (member, viewer):
        r = client.post(f"/api/patches/{job['id']}/approve", headers=h)
        assert r.status_code == 403 and r.json()["error"] == "approve_not_allowed"
    assert world.get(demo("shop84")).mutations == []
    r = client.post(f"/api/patches/{job['id']}/approve", headers=approver)
    assert r.status_code == 202 and client.get(f"/api/patches/{job['id']}", headers=viewer).json()["state"] == "succeeded"


def test_four_eyes_rule_needs_a_second_person(client, auth_headers, world):
    lead = user(client, "lead@example.com")
    org = team(client, auth_headers, {"lead@example.com": "approver"})
    site_id = add_site(client, auth_headers, "shop84")
    share(client, auth_headers, site_id, org)
    client.patch(f"/api/orgs/{org}", json={"require_separate_approver": True}, headers=auth_headers)

    job = dry_run(client, auth_headers, site_id)  # the owner plans it...
    r = client.post(f"/api/patches/{job['id']}/approve", headers=auth_headers)  # ...so cannot approve it
    assert r.status_code == 403 and r.json()["error"] == "separate_approver_required"
    assert world.get(demo("shop84")).mutations == []
    assert client.post(f"/api/patches/{job['id']}/approve", headers=lead).status_code == 202


def test_only_managers_change_the_team_and_a_team_keeps_an_owner(client, auth_headers):
    member = user(client, "dev@example.com")
    org = team(client, auth_headers, {"dev@example.com": "member"})
    r = client.post(f"/api/orgs/{org}/members", json={"email": "dev@example.com", "role": "admin"}, headers=member)
    assert r.status_code == 403 and r.json()["error"] == "manage_not_allowed"
    assert client.patch(f"/api/orgs/{org}", json={"name": "x"}, headers=member).status_code == 403
    me = client.get("/api/orgs", headers=auth_headers).json()["orgs"][0]
    owner_id = next(m["user_id"] for m in me["members"] if m["role"] == "owner")
    r = client.delete(f"/api/orgs/{org}/members/{owner_id}", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "last_owner"
    r = client.post(f"/api/orgs/{org}/members", json={"email": "nobody@example.com", "role": "viewer"}, headers=auth_headers)
    assert r.status_code == 404 and r.json()["error"] == "user_not_found"
    # A site can only be put in a team by its owner, and only into a team they manage.
    site_id = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=member).json()["id"]
    r = client.post(f"/api/sites/{site_id}/team", json={"org_id": org}, headers=member)
    assert r.status_code == 403 and r.json()["error"] == "manage_not_allowed"


# --- entitlements and billing ---------------------------------------------------------

def approve(client, auth, job_id: int) -> dict:
    assert client.post(f"/api/patches/{job_id}/approve", headers=auth).status_code == 202
    with client.app.state.sessionmaker() as db:
        return db.get(PatchJob, job_id).billing


def test_a_patch_is_a_fee_unless_a_subscription_covers_it(client, auth_headers):
    first = add_site(client, auth_headers, "shop84")
    assert approve(client, auth_headers, dry_run(client, auth_headers, first)["id"]) == \
        {"item": "patch_fee", "amount": 149, "currency": "USD"}

    covered = add_site(client, auth_headers, "fragile84")
    client.post(f"/api/sites/{covered}/monitoring", json={"enabled": True}, headers=auth_headers)
    billing = approve(client, auth_headers, dry_run(client, auth_headers, covered)["id"])
    assert billing["item"] == "included" and billing["covered_by"] == "watchdog" and billing["amount"] == 0


def test_the_admin_billing_export_lists_what_is_owed(client, auth_headers):
    site_id = add_site(client, auth_headers, "shop84")
    approve(client, auth_headers, dry_run(client, auth_headers, site_id)["id"])
    monitored = add_site(client, auth_headers, "fragile84")
    client.post(f"/api/sites/{monitored}/monitoring", json={"enabled": True}, headers=auth_headers)
    month = datetime.now(timezone.utc).strftime("%Y-%m")

    assert client.get("/api/admin/billing", params={"month": month}, headers=auth_headers).status_code == 403
    admin = _admin(client)
    data = client.get("/api/admin/billing", params={"month": month}, headers=admin).json()
    items = sorted((r["domain"], r["item"], r["amount"]) for r in data["rows"])
    assert items == [(demo("fragile84"), "subscription:watchdog", 29), (demo("shop84"), "patch_fee", 149)]
    assert data["total"] == 178
    csv = client.get("/api/admin/billing", params={"month": month, "format": "csv"}, headers=admin)
    assert csv.headers["content-type"].startswith("text/csv")
    assert csv.text.splitlines()[0] == "date,site_id,domain,team,item,amount,currency,ref,note"
    assert "'-" not in csv.text and len(csv.text.splitlines()) == 3


# --- outcome-based monthly report ----------------------------------------------------

def test_the_monthly_report_shows_outcomes(client, auth_headers, nvd):
    site_id = add_site(client, auth_headers, "shop84")  # PHP 8.4.13
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    wd = client.app.state.watchdog
    run(wd.run_version_checks())
    nvd.items.append(nvd_item("CVE-2026-999201", start="8.4.0", end_excl="8.4.27"))
    with client.app.state.sessionmaker() as db:  # it is also in CISA KEV
        from patchwarden.models import Advisory
        run(wd.poll_feeds())
        db.get(Advisory, "CVE-2026-999201").kev = True
        db.commit()
    approve(client, auth_headers, dry_run(client, auth_headers, site_id)["id"])

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    report = client.get(f"/api/sites/{site_id}/monthly-report", params={"month": month}, headers=auth_headers).json()
    o = report["outcomes"]
    assert o["exposure_days"] == 1 and o["exploited_flaws_found"] == 1 and o["patches_succeeded"] == 1
    assert o["risks_fixed"] == 2 and o["median_hours_to_patch"] is not None and o["median_hours_to_patch"] < 1
    assert "exposed on 1 day" in report["summary"]


# --- white-label ---------------------------------------------------------------------

def test_a_team_brand_replaces_ours_on_alerts_and_reports(client, auth_headers, nvd, notifier):
    org = team(client, auth_headers)
    r = client.patch(f"/api/orgs/{org}", json={"brand_name": "Acme Web Care", "brand_color": "#123456",
                                               "brand_footer": "Acme Web Care, 1 Main St"}, headers=auth_headers)
    assert r.json()["branding"]["name"] == "Acme Web Care"
    assert client.patch(f"/api/orgs/{org}", json={"brand_color": "red"}, headers=auth_headers).json()["error"] == "invalid_color"
    assert client.patch(f"/api/orgs/{org}", json={"brand_logo_url": "javascript:alert(1)"},
                        headers=auth_headers).json()["error"] == "invalid_logo_url"
    site_id = client.post("/api/sites", json={"domain": demo("php84-unpatched")}, headers=auth_headers).json()["id"]
    share(client, auth_headers, site_id, org)
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(client.app.state.watchdog.run_version_checks())

    [email] = [e for e in notifier.sent if demo("php84-unpatched") in e.subject]
    assert email.subject.startswith("Acme Web Care:") and "Patchwarden" not in email.subject + email.body
    assert email.body.endswith("Acme Web Care, 1 Main St")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    page = client.get(f"/dashboard/sites/{site_id}/monthly", params={"month": month})
    assert "Acme Web Care monthly safety report" in page.text and "#123456" in page.text


# --- signed attestations -------------------------------------------------------------

def patched_verified_site(client, auth, world) -> int:
    site_id = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth).json()["id"]
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth)
    run(client.app.state.watchdog.run_version_checks())
    verify_site(client, auth, world, site_id)
    return site_id


def test_an_attestation_is_signed_and_anyone_can_verify_it(client, auth_headers, world):
    site_id = patched_verified_site(client, auth_headers, world)
    r = client.post(f"/api/sites/{site_id}/attestations", headers=auth_headers)
    assert r.status_code == 201, r.text
    att = r.json()
    assert att["status"] == "valid" and att["payload"]["php_version"] == "8.4.27"

    public = client.get(f"/api/attestations/{att['payload']['id']}")  # no login
    assert public.json()["valid"] is True
    # Offline check with the published key, as a third party would do it.
    [jwk] = client.get("/.well-known/patchwarden-attestation-keys.json").json()["keys"]
    assert jwk["kid"] == att["key_id"] and jwk["crv"] == "Ed25519"
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="))
    key.verify(base64.urlsafe_b64decode(att["signature"] + "=="), canonical(att["payload"]))

    badge = client.get(f"/api/attestations/{att['payload']['id']}/badge.svg")
    assert badge.headers["content-type"].startswith("image/svg+xml") and "PHP 8.4.27 patched" in badge.text


def test_a_tampered_expired_or_revoked_attestation_does_not_verify(client, auth_headers, world):
    site_id = patched_verified_site(client, auth_headers, world)
    att_id = client.post(f"/api/sites/{site_id}/attestations", headers=auth_headers).json()["payload"]["id"]
    from patchwarden.models import Attestation

    with client.app.state.sessionmaker() as db:
        row = db.get(Attestation, att_id)
        row.payload = {**row.payload, "php_version": "9.9.9"}
        db.commit()
    assert client.get(f"/api/attestations/{att_id}").json()["status"] == "invalid"
    assert "invalid" in client.get(f"/api/attestations/{att_id}/badge.svg").text

    second = client.post(f"/api/sites/{site_id}/attestations", headers=auth_headers).json()["payload"]["id"]
    with client.app.state.sessionmaker() as db:
        db.get(Attestation, second).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert client.get(f"/api/attestations/{second}").json()["status"] == "expired"

    third = client.post(f"/api/sites/{site_id}/attestations", headers=auth_headers).json()["payload"]["id"]
    assert client.post(f"/api/attestations/{third}/revoke", headers=user(client, "x@example.com")).status_code == 404
    assert client.post(f"/api/attestations/{third}/revoke", headers=auth_headers).json()["status"] == "revoked"


def test_only_a_verified_patched_site_can_be_attested(client, auth_headers, world):
    unverified = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["id"]
    r = client.post(f"/api/sites/{unverified}/attestations", headers=auth_headers)
    assert r.status_code == 403 and r.json()["error"] == "verification_required"

    exposed = client.post("/api/sites", json={"domain": demo("php84-unpatched")}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{exposed}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(client.app.state.watchdog.run_version_checks())
    verify_site(client, auth_headers, world, exposed)
    r = client.post(f"/api/sites/{exposed}/attestations", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "not_attestable"


# --- migration quotes ----------------------------------------------------------------

def test_a_migration_gets_an_instant_fixed_price_quote(client, auth_headers):
    mig = plan(client, auth_headers, add_wp74(client, auth_headers))
    q = client.get(f"/api/migrations/{mig['id']}/quote", headers=auth_headers).json()
    assert q["rate"] == 95 and q["currency"] == "USD" and q["hours"] >= 4 and q["hours"] * 2 == int(q["hours"] * 2)
    assert q["total"] == -(-q["hours"] * 95 // 1)  # rounded up to a whole unit
    assert sum(line["hours"] for line in q["lines"]) <= q["hours"]
    assert "Statement of work" in q["statement_of_work"] and f"{q['total']} USD" in q["statement_of_work"]
    assert client.get(f"/api/migrations/{mig['id']}/quote", headers=auth_headers).json()["created_at"] == q["created_at"]

    accepted = client.post(f"/api/migrations/{mig['id']}/quote/accept", headers=auth_headers).json()
    assert accepted["accepted_at"]
    again = client.post(f"/api/migrations/{mig['id']}/quote/accept", headers=auth_headers)
    assert again.status_code == 409 and again.json()["error"] == "already_accepted"
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    rows = client.get("/api/admin/billing", params={"month": month}, headers=_admin(client)).json()["rows"]
    assert [(r["item"], r["amount"]) for r in rows] == [("migration_quote", q["total"])]


def test_a_team_rate_is_used_and_viewers_cannot_accept(client, auth_headers):
    viewer = user(client, "client@example.com")
    org = team(client, auth_headers, {"client@example.com": "viewer"})
    client.patch(f"/api/orgs/{org}", json={"hourly_rate": 120}, headers=auth_headers)
    site_id = add_wp74(client, auth_headers)
    share(client, auth_headers, site_id, org)
    mig = plan(client, auth_headers, site_id)
    assert client.get(f"/api/migrations/{mig['id']}/quote", headers=viewer).json()["rate"] == 120
    r = client.post(f"/api/migrations/{mig['id']}/quote/accept", headers=viewer)
    assert r.status_code == 403 and r.json()["error"] == "approve_not_allowed"


def test_no_alert_or_audit_detail_leaks_between_teams(client, auth_headers, world):
    other = user(client, "other@example.com")
    org = team(client, auth_headers)
    site_id = add_site(client, auth_headers, "shop84")
    share(client, auth_headers, site_id, org)
    with client.app.state.sessionmaker() as db:
        db.add(Alert(site_id=site_id, cve_id="X-1", severity="high", message="m"))
        db.commit()
    assert client.get("/api/alerts", headers=other).json()["alerts"] == []
    assert client.get(f"/api/orgs/{org}", headers=other).status_code == 404
    with client.app.state.sessionmaker() as db:
        assert db.query(AuditLog).filter_by(action="site.team_set").count() == 1
        assert db.query(User).count() == 2
    assert json.dumps(client.get(f"/api/orgs/{org}", headers=auth_headers).json())


def test_a_platform_admin_can_look_but_never_approve(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    job = dry_run(client, auth_headers, site_id)
    admin = _admin(client)
    assert client.get(f"/api/sites/{site_id}", headers=admin).status_code == 200
    r = client.post(f"/api/patches/{job['id']}/approve", headers=admin)
    assert r.status_code == 403 and r.json()["error"] == "approve_not_allowed"
    assert client.post("/api/patches", json={"site_id": site_id}, headers=admin).status_code == 403
    assert world.get(demo("shop84")).mutations == []


def test_the_billing_export_skips_cancelled_and_defuses_spreadsheet_formulas(client, auth_headers):
    org = client.post("/api/orgs", json={"name": "=HYPERLINK(\"http://x\")"}, headers=auth_headers).json()["id"]
    site_id = add_site(client, auth_headers, "shop84")
    share(client, auth_headers, site_id, org)
    approve(client, auth_headers, dry_run(client, auth_headers, site_id)["id"])
    stopped = add_site(client, auth_headers, "fragile84")
    client.post(f"/api/sites/{stopped}/monitoring", json={"enabled": True}, headers=auth_headers)
    client.post(f"/api/sites/{stopped}/monitoring", json={"enabled": False}, headers=auth_headers)
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    admin = _admin(client)
    rows = client.get("/api/admin/billing", params={"month": month}, headers=admin).json()["rows"]
    assert [r["item"] for r in rows] == ["patch_fee"]  # the cancelled subscription is not billed
    csv = client.get("/api/admin/billing", params={"month": month, "format": "csv"}, headers=admin).text
    assert "'=HYPERLINK" in csv and ',=HYPERLINK' not in csv and '"=HYPERLINK' not in csv


def test_a_safe_site_has_no_exposure_days(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(client.app.state.watchdog.run_version_checks())
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    report = client.get(f"/api/sites/{site_id}/monthly-report", params={"month": month}, headers=auth_headers).json()
    assert report["outcomes"]["exposure_days"] == 0 and "exposed" not in report["summary"]
