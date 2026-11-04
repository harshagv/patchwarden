"""Helpers for WordPress Guard tests: a live Patchwarden server and a WordPress stand-in running the real plugin."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import uvicorn

from patchwarden.app import create_app
from patchwarden.scanner import demo_sites
from patchwarden.scanner.service import Scanner
from patchwarden.watchdog.feeds import NvdSource

PROJECT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).resolve().parent / "wp_harness" / "harness.php"
PLUGIN_DIR = PROJECT / "wordpress-plugin" / "patchwarden"
PHP = shutil.which("php")

needs_php = pytest.mark.skipif(PHP is None, reason="PHP is not installed (brew install php): the plugin cannot run")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    def __init__(self, settings, world, nvd, notifier, tmp_path: Path):
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        s = replace(settings, public_base_url=self.url, database_url=f"sqlite:///{tmp_path / 'live.db'}")
        scanner = Scanner(s, wporg_transport=demo_sites.demo_wporg_transport(), demo_world=world)
        self.app = create_app(s, scanner=scanner, demo_world=world, notifier=notifier,
                              sources=[NvdSource(transport=httpx.MockTransport(nvd.handler))])
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> LiveServer:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("live server did not start")
            time.sleep(0.05)
        self.http = httpx.Client(base_url=self.url, timeout=10)
        return self

    def __exit__(self, *exc) -> None:
        self.http.close()
        self.server.should_exit = True
        self.thread.join(10)

    def owner(self, email="owner@example.com", password="correct horse battery") -> dict:
        self.http.post("/api/auth/register", json={"email": email, "password": password})
        token = self.http.post("/api/auth/login", json={"email": email, "password": password}).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}


def demo_wordpress_state(home_url: str) -> dict:
    return {
        "home_url": home_url,
        "wp_version": "6.6.2",
        "plugins": {
            "akismet/akismet.php": {"Name": "Akismet Anti-spam", "Version": "5.3.3"},
            "demo-contact-form/demo-contact-form.php": {"Name": "Demo Contact Form", "Version": "2.3.0"},
            "hello.php": {"Name": "Hello Dolly", "Version": "1.7.2"},
            "patchwarden/patchwarden.php": {"Name": "Patchwarden", "Version": "0.1.0"},
        },
        "active_plugins": ["akismet/akismet.php", "demo-contact-form/demo-contact-form.php", "patchwarden/patchwarden.php"],
        "themes": {"demo-storefront": {"Name": "Demo Storefront", "Version": "3.4.0"},
                   "twentytwentyfour": {"Name": "Twenty Twenty-Four", "Version": "1.2"}},
        "stylesheet": "demo-storefront",
        "site_transients": {"update_plugins": {"response": {
            "demo-contact-form/demo-contact-form.php": {"new_version": "2.5.0"}}}},
        "available_updates": {"demo-contact-form/demo-contact-form.php": "2.5.0"},
        # Something WordPress itself stores: must survive the plugin's uninstall.
        "options": {"blogname": "Demo Bakery"},
    }


class WordPress:
    """One WordPress site (a JSON 'database') with the Patchwarden plugin installed from `plugin_dir`."""

    def __init__(self, tmp_path: Path, api_url: str, home_url: str, plugin_dir: Path = PLUGIN_DIR):
        self.state_file = tmp_path / "wordpress.json"
        self.state_file.write_text(json.dumps(demo_wordpress_state(home_url)))
        self.env = {**os.environ, "PATCHWARDEN_HARNESS_STATE": str(self.state_file), "PATCHWARDEN_API_URL": api_url,
                    "PATCHWARDEN_PLUGIN_DIR": str(plugin_dir), "HARNESS_WP_DIR": str(tmp_path / "wp"),
                    "HARNESS_ADMIN": "1"}

    def run(self, *args: str, admin: bool = True) -> dict:
        env = dict(self.env)
        if not admin:
            env.pop("HARNESS_ADMIN")
        r = subprocess.run([PHP, str(HARNESS), *args], env=env, capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Fatal error" not in r.stdout + r.stderr and "Warning:" not in r.stdout + r.stderr, r.stdout + r.stderr
        return self.state

    @property
    def state(self) -> dict:
        return json.loads(self.state_file.read_text())

    def edit(self, **changes) -> None:
        state = self.state
        state.update(changes)
        self.state_file.write_text(json.dumps(state))


def php_version() -> str:
    return subprocess.run([PHP, "-r", "echo PHP_VERSION;"], capture_output=True, text=True).stdout.strip()
