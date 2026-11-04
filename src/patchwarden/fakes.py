"""A fake hosting world for tests and `make dev`: demo sites whose PHP version can really change.

A FakeHost is one site on a pretend host. The demo HTTP transport serves its
pages (so the Scanner and the Patch agent's checks see the live state), and
FakeHostingAdapter changes it through the same interface the real cPanel,
Plesk and agent adapters implement. Only hosts under *.demo.patchwarden.test exist here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .patch.adapters import AdapterError, BackupData, HostingAdapter, RestoreCheck

DEMO_SUFFIX = ".demo.patchwarden.test"


class SimulatedCrash(BaseException):
    """Stands in for the process dying (BaseException: no `except Exception` can swallow it)."""


@dataclass
class FakeHost:
    domain: str
    php_version: str  # the version PHP workers run now
    available_versions: list[str]
    pages: dict[str, int] = field(default_factory=lambda: {"/": 200, "/login": 200, "/checkout": 200})
    # version -> paths that return 500 on that version (an incompatible plugin, say)
    broken_on: dict[str, set[str]] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    database: dict[str, list] = field(default_factory=dict)
    configured_version: str | None = None  # set by the panel, live after a restart
    expected_token: str | None = None  # None: any non-empty token is accepted
    hide_version: bool = False  # no X-Powered-By header: only an inside check can read the version
    run_code: bool = True  # False: the checked pages do not load the broken files (so checks pass anyway)
    crash_on: str | None = None  # simulate the Patchwarden server dying during this call (once)
    well_known: dict = field(default_factory=dict)  # "/.well-known/x" -> text, served as plain text
    _calls: dict = field(default_factory=dict, repr=False)
    fail_backup: bool = False
    corrupt_backup: bool = False  # backup written but it does not match its checksum
    fail_restore: bool = False
    mutations: list[str] = field(default_factory=list)  # every state-changing call
    restarts: int = 0

    def crash_check(self, call: str) -> None:
        """crash_on="restart_php" crashes on the first restart; "restart_php#2" on the second."""
        if not self.crash_on:
            return
        name, _, nth = self.crash_on.partition("#")
        if name != call:
            return
        self._calls[call] = self._calls.get(call, 0) + 1
        if self._calls[call] == int(nth or 1):
            self.crash_on = None
            raise SimulatedCrash(f"simulated server crash during {call}")

    def snapshot(self) -> dict:
        return {"php_version": self.php_version, "configured_version": self.configured_version,
                "files": copy.deepcopy(self.files), "database": copy.deepcopy(self.database)}

    def code_fails(self) -> bool:
        """Pretend to run the code: a function removed in the running PHP version is a fatal error."""
        from .migration.scanner import scan_files

        return self.run_code and scan_files(self.files, "5.6.0", self.php_version)["errors"] > 0

    def serve(self, path: str) -> httpx.Response:
        if path in self.well_known:
            return httpx.Response(200, headers={"Content-Type": "text/plain"}, text=self.well_known[path])
        status = self.pages.get(path, 404)
        if path in self.broken_on.get(self.php_version, set()) or (status == 200 and self.code_fails()):
            status = 500
        title = {200: "OK", 404: "Not found", 500: "Server error"}.get(status, str(status))
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if not self.hide_version:
            headers["X-Powered-By"] = f"PHP/{self.php_version}"
        return httpx.Response(status, headers=headers,
                              text=f"<html><body><h1>{self.domain}{path}: {title}</h1></body></html>")


def _shop(domain: str, version: str, **kw) -> FakeHost:
    return FakeHost(
        domain=domain,
        php_version=version,
        available_versions=["8.3.36", "8.4.13", "8.4.27", "8.5.12"],
        files={"index.php": "<?php require 'app.php';", "app.php": "<?php echo 'shop';",
               "wp-config.php": "<?php define('DB_NAME', 'shop');"},
        database={"orders": [{"id": 1, "total": 42}], "customers": [{"id": 1}]},
        **kw,
    )


_WP74_FILES = {
    "wp-config.php": (
        "<?php\ndefine('DB_NAME', 'bakery');\ndefine('DB_USER', 'bakery');\n"
        "define('DB_PASSWORD', 'demo-only-db-password');\n$table_prefix = 'wp_';\n"
        "require_once ABSPATH . 'wp-settings.php';\n"),
    "wp-includes/version.php": "<?php\n$wp_version = '6.6.2';\n",
    "wp-content/themes/bakery/functions.php": (
        "<?php\n"
        "// Bakery theme helpers\n"
        "function bakery_clean($value) {\n"
        "    if (get_magic_quotes_gpc()) {\n"
        "        $value = stripslashes($value);\n"
        "    }\n"
        "    return trim($value);\n"
        "}\n\n"
        "function bakery_initial($title) {\n"
        "    return strtoupper($title{0});\n"
        "}\n\n"
        "function bakery_badge(WP_Post $post = null) {\n"
        "    return $post ? 'New: ' . $post->post_title : '';\n"
        "}\n\n"
        "function bakery_date($ts) {\n"
        "    return strftime('%d %B %Y', $ts);\n"
        "}\n"),
    "wp-content/plugins/bakery-orders/bakery-orders.php": (
        "<?php\n"
        "/* Plugin Name: Bakery Orders */\n"
        "function bakery_order_lines($items) {\n"
        "    $lines = array();\n"
        "    reset($items);\n"
        "    while (list($sku, $qty) = each($items)) {\n"
        "        $lines[] = $sku . ' x ' . $qty;\n"
        "    }\n"
        "    return $lines;\n"
        "}\n\n"
        "function bakery_sort_orders($orders) {\n"
        "    usort($orders, create_function('$a,$b', 'return $a[\"total\"] - $b[\"total\"];'));\n"
        "    return $orders;\n"
        "}\n"),
}

_LEGACY81_FILES = {
    "index.php": "<?php\nrequire __DIR__ . '/src/Report.php';\necho (new Report())->render($_GET['q'] ?? null);\n",
    "src/Report.php": (
        "<?php\n"
        "class Report {\n"
        "    public function render(string $query = null): string {\n"
        "        $q = filter_var($query, FILTER_SANITIZE_STRING);\n"
        "        return \"<h1>Results for ${q}</h1>\";\n"
        "    }\n"
        "    public function legacyName(string $name): string {\n"
        "        return utf8_encode($name);\n"
        "    }\n"
        "}\n"),
    # Composer dependencies, for the per-site SBOM (not code: the migration scan ignores it).
    "composer.lock": json.dumps({"packages": [
        {"name": "monolog/monolog", "version": "2.9.1", "license": ["MIT"]},
        {"name": "guzzlehttp/guzzle", "version": "7.4.5", "license": ["MIT"]},
    ], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.13", "license": ["BSD-3-Clause"]}]}),
}


def _site(domain: str, version: str, files: dict[str, str], available: list[str], **kw) -> FakeHost:
    return FakeHost(domain=domain, php_version=version, available_versions=available, files=dict(files),
                    database={"orders": [{"id": 1, "total": 42}]}, **kw)


class DemoWorld:
    """All fake hosts for one app instance (tests get a fresh one each time)."""

    def __init__(self, hosts: list[FakeHost] | None = None):
        self.hosts: dict[str, FakeHost] = {h.domain: h for h in (hosts or [])}
        self.txt_records: dict[str, list[str]] = {}  # fake DNS: name -> TXT strings
        self.waf_rules: dict[str, list[str]] = {}  # fake edge WAF: domain -> virtual patch rule tags

    @classmethod
    def seeded(cls) -> DemoWorld:
        return cls([
            # Patches cleanly from 8.4.13 to 8.4.27.
            _shop(f"shop84{DEMO_SUFFIX}", "8.4.13"),
            # Its checkout breaks on 8.4.27, so a patch must roll back.
            _shop(f"fragile84{DEMO_SUFFIX}", "8.4.13", broken_on={"8.4.27": {"/checkout"}}),
            _shop(f"shop83{DEMO_SUFFIX}", "8.3.20"),
            # Migration demos: WordPress on 7.4 (has code that breaks on PHP 8), custom code on 8.1.
            _site(f"wp74{DEMO_SUFFIX}", "7.4.33", _WP74_FILES, ["7.4.33", "8.3.36", "8.4.27", "8.5.12"],
                  pages={"/": 200, "/wp-login.php": 200, "/checkout": 200}),
            _site(f"legacy81{DEMO_SUFFIX}", "8.1.31", _LEGACY81_FILES, ["8.1.31", "8.3.36", "8.4.27"]),
            # WordPress Guard demo: a WordPress shop on unpatched 8.4 ("Fix it" -> Phase 2 approval).
            _site(f"wpshop84{DEMO_SUFFIX}", "8.4.13", {"wp-config.php": "<?php define('DB_NAME', 'shop');"},
                  ["8.4.13", "8.4.27"], pages={"/": 200, "/wp-login.php": 200, "/checkout": 200}),
        ])

    def get(self, domain: str) -> FakeHost | None:
        return self.hosts.get(domain)


class FakeHostingAdapter(HostingAdapter):
    def __init__(self, host: FakeHost, display_name: str, token: str, world: DemoWorld | None = None):
        self.host = host
        self.display_name = display_name
        self._token = token
        self.world = world

    def __repr__(self) -> str:
        return f"<FakeHostingAdapter {self.display_name} {self.host.domain}>"

    def _auth(self) -> FakeHost:
        if not self._token or (self.host.expected_token is not None and self._token != self.host.expected_token):
            raise AdapterError("auth_failed",
                               f"{self.display_name} refused the access token. Create a new token and add it again.")
        return self.host

    async def php_version(self) -> str:
        return self._auth().php_version

    async def available_versions(self) -> list[str]:
        return list(self._auth().available_versions)

    async def create_backup(self) -> BackupData:
        host = self._auth()
        if host.fail_backup:
            raise AdapterError("backup_failed", f"{self.display_name} could not create a backup.")
        host.crash_check("create_backup")
        host.mutations.append("create_backup")
        data = json.dumps({"domain": host.domain, "php_version": host.php_version,
                           "files": host.files, "database": host.database}, sort_keys=True).encode()
        checksum = hashlib.sha256(data).hexdigest()
        if host.corrupt_backup:  # the archive arrives damaged: it no longer matches the host's checksum
            data = data[: len(data) // 2]
        return BackupData(archive=data, checksum=checksum)

    async def verify_restore(self, archive: bytes) -> RestoreCheck:
        self._auth()
        try:
            parsed = json.loads(archive)
            files, tables = parsed["files"], parsed["database"]
        except (ValueError, KeyError):
            return RestoreCheck(False, "The backup could not be read back.")
        return RestoreCheck(True, f"Restore dry-run read {len(files)} files and {len(tables)} database tables.")

    async def set_php_version(self, version: str) -> None:
        host = self._auth()
        host.crash_check("set_php_version")
        if version not in host.available_versions:
            raise AdapterError("version_unavailable", f"PHP {version} is not available on this host.")
        host.mutations.append(f"set_php_version:{version}")
        host.configured_version = version

    async def restart_php(self) -> None:
        host = self._auth()
        host.crash_check("restart_php")
        host.mutations.append("restart_php")
        host.restarts += 1
        if host.configured_version:
            host.php_version = host.configured_version
            host.configured_version = None

    async def restore_backup(self, archive: bytes) -> None:
        host = self._auth()
        if host.fail_restore:
            raise AdapterError("restore_failed", f"{self.display_name} could not restore the backup.")
        parsed = json.loads(archive)
        host.mutations.append("restore_backup")
        host.files = parsed["files"]
        host.database = parsed["database"]

    async def read_code(self) -> dict[str, str]:
        return dict(self._auth().files)

    async def create_staging(self) -> tuple[str, HostingAdapter]:
        host = self._auth()
        if self.world is None:
            raise AdapterError("staging_unavailable", "This host cannot create a staging site.")
        host.mutations.append("create_staging")
        domain = f"staging.{host.domain}"
        files = dict(host.files)
        if "wp-config.php" in files:  # staging gets its own database, like a real staging copy
            files["wp-config.php"] = files["wp-config.php"].replace("'DB_NAME', '", "'DB_NAME', 'staging_")
        staging = FakeHost(domain=domain, php_version=host.php_version,
                           available_versions=list(host.available_versions), pages=dict(host.pages),
                           broken_on=copy.deepcopy(host.broken_on), files=files,
                           database=copy.deepcopy(host.database), expected_token=host.expected_token,
                           run_code=host.run_code)
        self.world.hosts[domain] = staging
        return domain, FakeHostingAdapter(staging, self.display_name, self._token, self.world)

    async def open_staging(self) -> tuple[str, HostingAdapter] | None:
        self._auth()
        staging = self.world.get(f"staging.{self.host.domain}") if self.world else None
        if staging is None:
            return None
        return staging.domain, FakeHostingAdapter(staging, self.display_name, self._token, self.world)

    async def write_files(self, files: dict[str, str]) -> None:
        host = self._auth()
        host.crash_check("write_files")
        host.mutations.append("write_files:" + ",".join(sorted(files)))
        host.files.update(files)
