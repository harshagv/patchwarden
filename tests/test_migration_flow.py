"""Migration agent safety and flow details beyond the acceptance tests."""

from __future__ import annotations

import io
import logging
import re
import uuid
import zipfile

from patchwarden.models import AuditLog, Migration

from .conftest import demo
from .test_patch_safety import _other_user
from .test_phase2_acceptance import add_site
from .test_phase4_acceptance import add_wp74, developer_fixes_staging, plan, staging


def _signed_off_wp74(client, auth, world) -> dict:
    mig = plan(client, auth, add_wp74(client, auth))
    staging(client, auth, mig["id"])
    developer_fixes_staging(world)
    assert staging(client, auth, mig["id"])["state"] == "staging_passed"
    return client.post(f"/api/migrations/{mig['id']}/signoff", headers=auth).json()


def test_custom_php81_site_passes_staging_first_time(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "legacy81")
    mig = plan(client, auth_headers, site_id)
    assert (mig["from_version"], mig["to_version"]) == ("8.1.31", "8.4.27")
    assert mig["breakage"]["errors"] == 0 and mig["plan"]["effort"] == "small"
    result = staging(client, auth_headers, mig["id"])
    report = result["staging_report"]
    assert result["state"] == "staging_passed", report
    assert {a["rule"] for a in report["auto_fixes"]} == {"dollar_brace_interp", "implicit_nullable"}
    remaining = {h["rule"] for h in report["remaining"]["hits"]}
    # A deprecation to review, not a blocker. FILTER_SANITIZE_STRING is not listed: it was
    # deprecated in 8.1, which this site already runs, so it is not new in this move.
    assert remaining == {"utf8_encode"}
    staging_host = world.get("staging." + demo("legacy81"))
    assert "?string $query = null" in staging_host.files["src/Report.php"]
    assert "?string" not in world.get(demo("legacy81")).files["src/Report.php"]  # production untouched


def test_staging_failure_explains_what_is_left(client, auth_headers, world):
    mig = plan(client, auth_headers, add_wp74(client, auth_headers))
    failed = staging(client, auth_headers, mig["id"])
    report = failed["staging_report"]
    assert failed["state"] == "staging_failed" and report["passed"] is False
    assert {h["found"] for h in report["remaining"]["hits"] if h["severity"] == "error"} == {"each", "create_function"}
    assert all(c["status"] == 500 for c in report["checks"])  # the copy really breaks on 8.4 without the fixes
    assert world.get(demo("wp74")).mutations == ["create_staging"]  # only a copy was made


def test_breaking_code_fails_staging_even_when_pages_load(client, auth_headers, world):
    world.get(demo("wp74")).run_code = False  # the broken plugin is not loaded by the checked pages
    mig = plan(client, auth_headers, add_wp74(client, auth_headers))
    done = staging(client, auth_headers, mig["id"])
    assert all(c["ok"] for c in done["staging_report"]["checks"])
    assert done["state"] == "staging_failed"  # the re-scan still finds each() and create_function()
    assert done["staging_report"]["remaining"]["errors"] == 2


def test_code_changed_after_signoff_blocks_promotion(client, auth_headers, world):
    mig = _signed_off_wp74(client, auth_headers, world)
    world.get("staging." + demo("wp74")).files["wp-content/themes/bakery/extra.php"] = "<?php echo 'untested';"
    assert client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers).status_code == 202
    done = client.get(f"/api/migrations/{mig['id']}", headers=auth_headers).json()
    assert done["state"] == "staging_failed" and done["signed_off_by"] is None
    assert "changed after it was tested" in done["promotion"]["message"]
    prod = world.get(demo("wp74"))
    assert prod.php_version == "7.4.33" and "write_files" not in " ".join(prod.mutations)


def test_rerunning_staging_clears_the_signoff(client, auth_headers, world):
    mig = _signed_off_wp74(client, auth_headers, world)
    rerun = staging(client, auth_headers, mig["id"])
    assert rerun["state"] == "staging_passed" and rerun["signed_off_by"] is None
    assert client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers).status_code == 403


def test_production_failure_rolls_back_code_and_version(client, auth_headers, world):
    prod = world.get(demo("wp74"))
    files_before = dict(prod.files)
    mig = _signed_off_wp74(client, auth_headers, world)
    prod.broken_on = {"8.4.27": {"/checkout"}}  # production differs from staging (a server module, say)
    client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers)
    done = client.get(f"/api/migrations/{mig['id']}", headers=auth_headers).json()
    assert done["state"] == "promotion_failed"
    job = client.get(f"/api/patches/{done['patch_job_id']}", headers=auth_headers).json()
    assert job["state"] == "rolled_back" and job["report"]["rollback"]["trigger"] == "automatic"
    assert prod.php_version == "7.4.33" and prod.files == files_before


def test_signoff_needs_a_passed_staging_and_the_owner(client, auth_headers, world):
    mig = plan(client, auth_headers, add_wp74(client, auth_headers))
    r = client.post(f"/api/migrations/{mig['id']}/signoff", headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "staging_not_passed"
    stranger = _other_user(client)
    for path in ("", "/staging", "/signoff", "/promote"):
        method = "GET" if not path else "POST"
        assert client.request(method, f"/api/migrations/{mig['id']}{path}", headers=stranger).status_code == 404


def test_supported_lines_go_to_the_patch_agent(client, auth_headers):
    site_id = add_site(client, auth_headers, "shop84")
    r = client.post("/api/migrations", json={"site_id": site_id}, headers=auth_headers)
    assert r.status_code == 409 and r.json()["error"] == "patch_not_migrate"
    wp = add_wp74(client, auth_headers)
    for target, code in (("8.2.35", "invalid_target"), ("8.4.13", "invalid_target"), ("8.4.30", "target_unavailable")):
        r = client.post("/api/migrations", json={"site_id": wp, "to_version": target}, headers=auth_headers)
        assert r.status_code == 422 and r.json()["error"] == code
    assert plan(client, auth_headers, wp, to_version="8.3.36")["to_version"] == "8.3.36"


def _zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in entries.items():
            z.writestr(name, text)
    return buf.getvalue()


def test_uploaded_codebase_is_scanned_safely(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": "legacy.example"}, headers=auth_headers).json()["id"]
    data = _zip({
        "mysite/index.php": "<?php\necho money_format('%i', $total);\n",
        "mysite/lib/old.inc": "<?php $x = $name{0};",
        "mysite/../../etc/evil.php": "<?php each($a);",
        "mysite/logo.png": "not code",
    })
    r = client.post("/api/migrations", data={"site_id": str(site_id)},
                    files={"file": ("site.zip", data, "application/zip")}, headers=auth_headers)
    assert r.status_code == 422 and r.json()["error"] == "from_version_needed"
    r = client.post("/api/migrations", data={"site_id": str(site_id), "from_version": "7.4.33"},
                    files={"file": ("site.zip", data, "application/zip")}, headers=auth_headers)
    assert r.status_code == 201, r.text
    mig = r.json()
    assert mig["source"] == "upload"
    assert {(h["file"], h["found"]) for h in mig["breakage"]["hits"]} == {("index.php", "money_format"),
                                                                          ("lib/old.inc", "${…} offset")}
    # Staging needs access to the host: the plan alone is still useful.
    done = staging(client, auth_headers, mig["id"])
    assert done["state"] == "staging_failed" and "API token" in done["staging_report"]["message"]

    r = client.post("/api/migrations", data={"site_id": str(site_id), "from_version": "7.4.33"},
                    files={"file": ("x.zip", b"not a zip", "application/zip")}, headers=auth_headers)
    assert r.status_code == 400 and r.json()["error"] == "invalid_zip"


def test_dashboard_flow_needs_a_confirmed_signoff(client, auth_headers, world):
    site_id = add_wp74(client, auth_headers)
    client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/dashboard/sites").text).group(1)
    r = client.post(f"/dashboard/sites/{site_id}/migration", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    url = r.headers["location"]
    page = client.get(url)
    assert "What breaks" in page.text and "bakery-orders.php" in page.text and "Run staging tests" in page.text
    client.post(f"{url}/staging", data={"csrf": csrf})
    developer_fixes_staging(world)
    client.post(f"{url}/staging", data={"csrf": csrf})
    assert "Sign off" in client.get(url).text
    r = client.post(f"{url}/signoff", data={"csrf": csrf})
    assert r.status_code == 422 and "Tick the box" in r.text
    client.post(f"{url}/signoff", data={"csrf": csrf, "confirm": "yes"})
    assert "Promote to production" in client.get(url).text
    client.post(f"{url}/promote", data={"csrf": csrf})
    page = client.get(url)
    assert "Done: production migrated" in page.text and "Before / after report for production" in page.text


def test_no_credential_or_code_literal_leaks(client, auth_headers, world, caplog):
    token, literal = f"CANARY-TOKEN-{uuid.uuid4().hex}", f"CANARY-LITERAL-{uuid.uuid4().hex}"
    host = world.get(demo("wp74"))
    host.files["wp-config.php"] = host.files["wp-config.php"].replace("demo-only-db-password", literal)
    host.files["wp-content/themes/bakery/functions.php"] += f"\ndefine('API_SECRET', '{literal}', true);\n"
    seen = []
    with caplog.at_level(logging.DEBUG):
        site_id = client.post("/api/sites", json={"domain": demo("wp74"), "platform": "wordpress"},
                              headers=auth_headers).json()["id"]
        client.post(f"/api/sites/{site_id}/credentials", json={"kind": "plesk_token", "value": token}, headers=auth_headers)
        mig = plan(client, auth_headers, site_id)
        seen.append(str(mig))
        staging(client, auth_headers, mig["id"])
        developer_fixes_staging(world)
        seen.append(str(staging(client, auth_headers, mig["id"])))
        seen.append(str(client.post(f"/api/migrations/{mig['id']}/signoff", headers=auth_headers).json()))
        client.post(f"/api/migrations/{mig['id']}/promote", headers=auth_headers)
        done = client.get(f"/api/migrations/{mig['id']}", headers=auth_headers).json()
        seen.append(str(done))
        seen.append(str(client.get(f"/api/patches/{done['patch_job_id']}", headers=auth_headers).json()))
        client.post("/dashboard/login", data={"email": "owner@example.com", "password": "correct horse battery"})
        seen += [client.get(f"/dashboard/migrations/{mig['id']}").text,
                 client.get(f"/dashboard/patches/{done['patch_job_id']}").text]
    assert done["state"] == "promoted"
    assert any(h["rule"] == "define_ci" for h in mig["breakage"]["hits"])  # the line with the literal was reported...
    blob = "\n".join(seen) + caplog.text + "\n".join(str(r.__dict__) for r in caplog.records)
    with client.app.state.sessionmaker() as db:
        blob += "\n".join(str((m.breakage, m.plan, m.staging_report, m.promotion)) for m in db.query(Migration))
        blob += "\n".join(str(a.detail) for a in db.query(AuditLog))
    assert token not in blob
    assert literal not in blob  # ...but its string contents never are
