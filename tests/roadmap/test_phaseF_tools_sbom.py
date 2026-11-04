"""Phase F: real PHP tooling in a sandbox for migrations, and a per-site CycloneDX SBOM."""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import replace

import pytest

from patchwarden.config import ConfigError, load_settings
from patchwarden.migration import sandbox as sbx
from patchwarden.models import Advisory, Alert, Scan

from ..conftest import demo, verify_site
from ..spec.test_phase4_acceptance import plan


def run(coro):
    return asyncio.run(coro)


RECTOR_OUT = """{
    "totals": {"changed_files": 1, "errors": 0},
    "file_diffs": [{"file": "/app/src/Report.php",
                    "diff": "--- Original\\n+++ New\\n-        return utf8_encode($name);\\n+        return mb_convert_encoding($name, 'UTF-8', 'ISO-8859-1');",
                    "applied_rectors": ["Rector\\\\Php82\\\\Rector\\\\FuncCall\\\\Utf8DecodeEncodeToMbConvertEncodingRector"]}],
    "changed_files": ["src/Report.php"]
}"""

PHPSTAN_OUT = """Note: Using configuration file /app/.patchwarden-phpstan.neon.
{"totals":{"errors":0,"file_errors":2},
 "files":{"/app/src/Report.php":{"errors":2,"messages":[
   {"message":"Function utf8_encode not found.","line":8,"ignorable":true,"identifier":"function.notFound"},
   {"message":"Constant FILTER_SANITIZE_STRING not found.","line":4,"ignorable":true,"identifier":"constant.notFound"}]}},
 "errors":[]}"""


class FakeSandbox:
    """Answers like the real tools would, without running anything."""

    name = "fake"

    def __init__(self):
        self.calls: list[tuple[str, list[str], set[str]]] = []

    def available(self, tool: str) -> bool:
        return True

    async def run(self, tool, args, files):
        self.calls.append((tool, args, set(files)))
        if tool == "rector":
            return sbx.RunResult(2, RECTOR_OUT, "")
        if tool == "phpstan":
            return sbx.RunResult(1, PHPSTAN_OUT, "")
        return sbx.RunResult(0, "No syntax errors detected in /app/index.php\n", "")


# --- the sandbox itself ------------------------------------------------------------------

@pytest.mark.parametrize("path", ["../etc/passwd", "/etc/passwd", "src/../../x.php", "-rf", "src/--config.php", ""])
def test_unsafe_code_paths_are_refused(path):
    with pytest.raises(ValueError):
        sbx.safe_relpath(path)


def test_safe_paths_stay_inside_the_work_folder(tmp_path):
    sbx.write_tree(tmp_path, {"src/a.php": "<?php", "index.php": "<?php"})
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*.php")) == ["index.php", "src/a.php"]


def test_the_docker_sandbox_isolates_the_tools(settings):
    cmd = sbx.DockerSandbox(settings).command("/tmp/work", "phpstan", ["analyse", "--error-format=json"])
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--user 65534:65534", "--pids-limit 256", "--memory 1g", "-v /tmp/work:/app:ro"):
        assert flag in joined
    assert cmd[0] == "docker" and cmd[-2:] == ["analyse", "--error-format=json"]
    assert settings.sandbox_image in cmd and not any(";" in c or "&&" in c for c in cmd)


def test_the_local_sandbox_is_refused_in_production(settings):
    with pytest.raises(ConfigError):
        sbx.LocalSandbox(replace(settings, app_env="production"))
    assert sbx.make_sandbox(replace(settings, migration_tools="off")) is None
    assert isinstance(sbx.make_sandbox(replace(settings, migration_tools="docker")), sbx.DockerSandbox)


def test_an_unknown_tools_mode_is_a_config_error(monkeypatch):
    monkeypatch.setenv("MIGRATION_TOOLS", "bare-metal")
    with pytest.raises(ConfigError):
        load_settings(load_dotenv_file=False)


def test_tool_configs_target_the_new_php_version():
    assert "->withPhpSets(php84: true)" in sbx.rector_config("8.4.27")
    assert "phpVersion: 80300" in sbx.phpstan_config("8.3.36")


def test_rector_and_phpstan_output_is_read():
    r = sbx.parse_rector(RECTOR_OUT)
    assert r["changed_files"] == 1 and r["changes"][0]["file"] == "src/Report.php"
    assert r["changes"][0]["rectors"] == ["Utf8DecodeEncodeToMbConvertEncodingRector"]
    s = sbx.parse_phpstan(PHPSTAN_OUT)  # a note line before the JSON is tolerated
    assert [(e["file"], e["line"]) for e in s["errors"]] == [("src/Report.php", 4), ("src/Report.php", 8)]


def test_lint_output_is_read_once_per_error():
    out = ('PHP Parse error:  syntax error, unexpected token ";" in /app/b.php on line 3\n'
           'Parse error: syntax error, unexpected token ";" in /app/b.php on line 3\n')
    assert sbx.parse_lint(out) == [{"file": "b.php", "line": 3, "message": 'syntax error, unexpected token ";"'}]


@pytest.mark.skipif(shutil.which("php") is None, reason="php is not installed")
def test_the_local_sandbox_really_runs_php_lint(settings):
    box = sbx.LocalSandbox(replace(settings, migration_tools="local"))
    files = {"ok.php": "<?php echo 1;\n", "src/broken.php": "<?php\nfunction f() {\n  return (;\n}\n",
             "README.md": "not code"}
    result = run(sbx.tool_scan(box, files, "8.4.27"))
    assert result["tools"]["lint"]["status"] == "ok"
    assert [(e["file"], e["line"]) for e in result["tools"]["lint"]["errors"]] == [("src/broken.php", 3)]
    for tool in ("rector", "phpstan"):
        if not box.available(tool):
            assert result["tools"][tool] == {"status": "unavailable"}


@pytest.mark.skipif(not (shutil.which("rector") and shutil.which("phpstan")), reason="rector/phpstan not installed")
def test_real_rector_and_phpstan_find_the_php8_breakage(settings):
    from patchwarden.fakes import _LEGACY81_FILES

    box = sbx.LocalSandbox(replace(settings, migration_tools="local"))
    result = run(sbx.tool_scan(box, dict(_LEGACY81_FILES), "8.4.27"))
    assert result["tools"]["rector"]["status"] == "ok" and result["tools"]["rector"]["changes"]
    assert any("utf8_encode" in e["message"] for e in result["tools"]["phpstan"]["errors"])


# --- in the migration plan -----------------------------------------------------------------

def test_tool_findings_join_the_migration_plan_and_the_quote(client, auth_headers):
    fake = FakeSandbox()
    client.app.state.sandbox = fake
    site_id = client.post("/api/sites", json={"domain": demo("legacy81")}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "legacy-demo-token"},
                headers=auth_headers)
    mig = plan(client, auth_headers, site_id)
    tools = mig["breakage"]["tools"]
    assert tools["sandbox"] == "fake" and tools["tools"]["phpstan"]["errors"][0]["line"] == 4
    rules = [f["rule"] for f in mig["plan"]["fixes"]]
    assert "tool:phpstan" in rules and "tool:rector" in rules and "tool:php-lint" not in rules
    steps = [f["step"] for f in mig["plan"]["fixes"]]
    assert steps == list(range(1, len(steps) + 1))
    # The tools got only code and their own config, never composer.lock or other files.
    for tool, _, files in fake.calls:
        assert all(f.endswith(".php") or f.startswith(".patchwarden-") for f in files), (tool, files)
        assert "composer.lock" not in files
    q = client.get(f"/api/migrations/{mig['id']}/quote", headers=auth_headers).json()
    assert any("PHPStan" in line["what"] and line["hours"] == 1.0 for line in q["lines"])


def test_without_a_sandbox_the_plan_is_rule_based_only(client, auth_headers):
    assert client.app.state.sandbox is None  # MIGRATION_TOOLS defaults to off
    site_id = client.post("/api/sites", json={"domain": demo("legacy81")}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "legacy-demo-token"},
                headers=auth_headers)
    mig = plan(client, auth_headers, site_id)
    assert "tools" not in mig["breakage"] and not any(f["rule"].startswith("tool:") for f in mig["plan"]["fixes"])


# --- SBOM --------------------------------------------------------------------------------

def legacy_site(client, auth, world) -> int:
    site_id = client.post("/api/sites", json={"domain": demo("legacy81")}, headers=auth).json()["id"]
    client.post(f"/api/sites/{site_id}/credentials", json={"kind": "cpanel_token", "value": "legacy-demo-token"},
                headers=auth)
    return site_id


def test_the_sbom_is_for_verified_sites_only(client, auth_headers, world):
    site_id = legacy_site(client, auth_headers, world)
    r = client.get(f"/api/sites/{site_id}/sbom", headers=auth_headers)
    assert r.status_code == 403 and r.json()["error"] == "verification_required"
    other = client.post("/api/auth/register", json={"email": "o@example.com", "password": "a long test password"})
    assert other.status_code in (200, 201)
    token = client.post("/api/auth/login", json={"email": "o@example.com", "password": "a long test password"}).json()
    assert client.get(f"/api/sites/{site_id}/sbom",
                      headers={"Authorization": f"Bearer {token['access_token']}"}).status_code == 404


def test_the_sbom_lists_php_composer_wordpress_and_known_flaws(client, auth_headers, world):
    site_id = legacy_site(client, auth_headers, world)
    verify_site(client, auth_headers, world, site_id)
    with client.app.state.sessionmaker() as db:
        db.add(Scan(site_id=site_id, detected_version="8.1.31", risk="must_migrate", raw_headers={},
                    scanned_url=f"https://{demo('legacy81')}/", findings={"wordpress": {
                        "detected": True, "core_version": "6.4.2", "components": [
                            {"type": "plugin", "slug": "demo-contact-form", "version": "2.3.0", "vulnerabilities": [
                                {"id": "WPV-1", "cve": "CVE-2026-1111", "title": "Stored XSS", "severity": "medium",
                                 "fixed_in": "2.3.1", "status": "affected"}]}]}}))
        db.add(Advisory(id="CVE-2026-999301", source="nvd", severity="critical", score=9.2, summary="RCE",
                        affected=[], fixed_in="8.1.32", url="https://nvd.nist.gov/vuln/detail/CVE-2026-999301",
                        kev=True, epss=0.93))
        db.add(Alert(site_id=site_id, cve_id="CVE-2026-999301", severity="critical", message="m"))
        db.add(Alert(site_id=site_id, cve_id="risk:must_migrate:1", severity="high", message="m"))
        db.commit()

    r = client.get(f"/api/sites/{site_id}/sbom", headers=auth_headers)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    bom = r.json()
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5" and bom["serialNumber"].startswith("urn:uuid:")
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    assert by_ref["php"]["cpe"] == "cpe:2.3:a:php:php:8.1.31:*:*:*:*:*:*:*"
    assert by_ref["wordpress"]["version"] == "6.4.2"
    assert by_ref["wordpress-plugin:demo-contact-form"]["purl"] == "pkg:generic/wordpress-plugin/demo-contact-form@2.3.0"
    assert by_ref["composer:guzzlehttp/guzzle"]["purl"] == "pkg:composer/guzzlehttp/guzzle@7.4.5"
    assert by_ref["composer:phpunit/phpunit"]["scope"] == "optional"
    assert set(bom["dependencies"][0]["dependsOn"]) == set(by_ref)

    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    assert set(vulns) == {"CVE-2026-999301", "CVE-2026-1111"}  # risk alerts are not advisories
    php_flaw = vulns["CVE-2026-999301"]
    assert php_flaw["affects"] == [{"ref": "php"}] and php_flaw["ratings"][0] == {"severity": "critical", "score": 9.2,
                                                                                    "method": "CVSSv31"}
    assert {"name": "patchwarden:kev", "value": "true"} in php_flaw["properties"]
    assert vulns["CVE-2026-1111"]["affects"] == [{"ref": "wordpress-plugin:demo-contact-form"}]
    refs = {c["bom-ref"] for c in bom["components"]}
    assert all(a["ref"] in refs for v in bom["vulnerabilities"] for a in v["affects"])
    json.dumps(bom)  # serialisable as-is


def test_the_sbom_works_without_host_access(client, auth_headers, world):
    site_id = client.post("/api/sites", json={"domain": demo("php84-fixed")}, headers=auth_headers).json()["id"]
    client.post(f"/api/sites/{site_id}/monitoring", json={"enabled": True}, headers=auth_headers)
    run(client.app.state.watchdog.run_version_checks())
    verify_site(client, auth_headers, world, site_id)
    bom = client.get(f"/api/sites/{site_id}/sbom", headers=auth_headers).json()
    assert [c["bom-ref"] for c in bom["components"]] == ["php"]
    assert {"name": "patchwarden:composer_lock", "value": "not_read"} in bom["metadata"]["properties"]
