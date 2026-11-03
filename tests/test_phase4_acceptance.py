"""Phase 4 acceptance tests, one per bullet in SPEC.md section 7."""

from __future__ import annotations

from patchwarden.models import Migration

from .conftest import demo
from .test_phase2_acceptance import add_site, approve, dry_run

PHP80_REMOVED = {"create_function", "each", "get_magic_quotes_gpc", "get_magic_quotes_runtime", "money_format"}


def add_wp74(client, auth) -> int:
    r = client.post("/api/sites", json={"domain": demo("wp74"), "platform": "wordpress", "form_path": "/checkout"},
                    headers=auth)
    assert r.status_code == 201, r.text
    site_id = r.json()["id"]
    assert client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "wp74-demo-token"},
                       headers=auth).status_code == 201
    return site_id


def plan(client, auth, site_id: int, **extra) -> dict:
    r = client.post("/api/migrations", json={"site_id": site_id, **extra}, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()


def staging(client, auth, mig_id: int) -> dict:
    r = client.post(f"/api/migrations/{mig_id}/staging", headers=auth)
    assert r.status_code == 202, r.text
    return client.get(f"/api/migrations/{mig_id}", headers=auth).json()


def developer_fixes_staging(world) -> None:
    """What a developer does on the staging site for the two manual fixes in the plan."""
    host = world.get("staging." + demo("wp74"))
    path = "wp-content/plugins/bakery-orders/bakery-orders.php"
    host.files[path] = (host.files[path]
                        .replace("    reset($items);\n    while (list($sku, $qty) = each($items)) {",
                                 "    foreach ($items as $sku => $qty) {")
                        .replace("create_function('$a,$b', 'return $a[\"total\"] - $b[\"total\"];')",
                                 "function ($a, $b) { return $a['total'] - $b['total']; }"))


def test_php74_wordpress_site_gets_a_breakage_list_with_real_removed_functions(client, auth_headers, world):
    site_id = add_wp74(client, auth_headers)
    mig = plan(client, auth_headers, site_id)

    assert (mig["from_version"], mig["to_version"], mig["state"]) == ("7.4.33", "8.4.27", "planned")
    hits = mig["breakage"]["hits"]
    removed = [h for h in hits if h["found"] in PHP80_REMOVED]
    assert removed, hits
    where = {(h["found"], h["file"], h["line"]) for h in removed}
    assert ("each", "wp-content/plugins/bakery-orders/bakery-orders.php", 6) in where
    assert ("create_function", "wp-content/plugins/bakery-orders/bakery-orders.php", 13) in where
    assert ("get_magic_quotes_gpc", "wp-content/themes/bakery/functions.php", 4) in where
    for h in removed:  # the site's own code, not WordPress core
        assert h["severity"] == "error" and h["since"] == "8.0"
        assert h["file"].startswith("wp-content/") and h["component"] in {"plugin bakery-orders", "theme bakery"}
    assert mig["breakage"]["skipped_wordpress_core"] == 1
    assert "while (list($sku, $qty) = each($items)) {" in {h["code"] for h in hits}

    # The plan: ordered fixes, effort bucket, target.
    p = mig["plan"]
    assert p["target_version"] == "8.4.27" and p["effort"] in {"small", "medium", "large"}
    assert [f["severity"] for f in p["fixes"]] == sorted((f["severity"] for f in p["fixes"]),
                                                          key=lambda s: s != "error")
    assert {f["rule"]: f["automatic"] for f in p["fixes"]}["each"] is False
    # Planning is read-only: production was not touched.
    assert world.get(demo("wp74")).mutations == []


def test_promotion_without_signoff_is_refused(client, auth_headers, world):
    site_id = add_wp74(client, auth_headers)
    mig = plan(client, auth_headers, site_id)

    r = client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers)
    assert r.status_code == 403
    assert r.json() == {"error": "signoff_required",
                        "message": "Promotion to production needs the owner's or IT's sign-off in the dashboard first."}

    # Still refused once staging has passed, until someone signs off.
    assert staging(client, auth_headers, mig["id"])["state"] == "staging_failed"  # manual fixes still missing
    developer_fixes_staging(world)
    assert staging(client, auth_headers, mig["id"])["state"] == "staging_passed"
    r = client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers)
    assert r.status_code == 403 and r.json()["error"] == "signoff_required"

    prod = world.get(demo("wp74"))
    assert prod.php_version == "7.4.33" and not any(m.startswith(("set_php", "write_files")) for m in prod.mutations)
    with client.app.state.sessionmaker() as db:
        assert db.get(Migration, mig["id"]).patch_job_id is None


def test_promoted_migration_produces_the_same_before_after_report_as_phase2(client, auth_headers, world):
    # A plain Phase 2 patch, for comparison.
    phase2 = approve(client, auth_headers, dry_run(client, auth_headers, add_site(client, auth_headers, "shop84"))["id"])
    assert phase2["state"] == "succeeded"

    site_id = add_wp74(client, auth_headers)
    mig = plan(client, auth_headers, site_id)
    staging(client, auth_headers, mig["id"])
    developer_fixes_staging(world)
    passed = staging(client, auth_headers, mig["id"])
    assert passed["state"] == "staging_passed", passed["staging_report"]
    signed = client.post(f"/api/migrations/{mig['id']}/signoff", headers=auth_headers).json()
    assert signed["state"] == "signed_off" and signed["signed_off_by"] is not None

    r = client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers)
    assert r.status_code == 202
    done = client.get(f"/api/migrations/{mig['id']}", headers=auth_headers).json()
    assert done["state"] == "promoted", done["promotion"]

    job = client.get(f"/api/patches/{done['patch_job_id']}", headers=auth_headers).json()
    assert job["state"] == "succeeded"
    assert set(job) == set(phase2)
    assert set(job["report"]) - {"kind", "migration_id"} == set(phase2["report"])
    assert [s["step"] for s in job["report"]["steps"]] == ["backup", "before_checks", "deploy", "switch", "restart",
                                                           "after_checks"]
    assert job["report"]["before"]["php_version"] == "7.4.33" and job["report"]["after"]["php_version"] == "8.4.27"
    assert all(c["ok"] for c in job["report"]["after"]["checks"])
    assert job["backup"]["verified"] is True
    assert job["approved_by"] == signed["signed_off_by"]  # the sign-off is the approval record

    prod = world.get(demo("wp74"))
    assert prod.php_version == "8.4.27" and prod.serve("/").status_code == 200
    assert "each(" not in prod.files["wp-content/plugins/bakery-orders/bakery-orders.php"]
    assert "'DB_NAME', 'bakery'" in prod.files["wp-config.php"]  # production config was not overwritten by staging's

    # The same printable report page as Phase 2.
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    page = client.get(f"/dashboard/patches/{done['patch_job_id']}")
    assert page.status_code == 200 and "Done: site updated" in page.text and "deploy" in page.text
    assert "PHP 7.4.33" in page.text and "PHP 8.4.27" in page.text
