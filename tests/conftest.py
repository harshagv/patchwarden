"""Shared fixtures. Every test runs offline: demo sites and WordPress.org are mocked."""

from __future__ import annotations

import os
from dataclasses import replace

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

# Make sure a developer's real .env can never leak into a test run.
os.environ["APP_ENV"] = "test"

from patchwarden.app import create_app  # noqa: E402
from patchwarden.config import load_settings  # noqa: E402
from patchwarden.fakes import DemoWorld  # noqa: E402
from patchwarden.scanner import demo_sites  # noqa: E402
from patchwarden.scanner.service import Scanner  # noqa: E402
from patchwarden.watchdog.feeds import NvdSource  # noqa: E402
from patchwarden.watchdog.notify import OutboxNotifier  # noqa: E402

TEST_JWT_SECRET = "t" * 64  # test-only value, not a real secret


@pytest.fixture
def settings(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setenv("CREDENTIAL_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DEMO_SITES", "true")
    return replace(load_settings(load_dotenv_file=False), public_base_url="http://testserver",
                   backup_dir=tmp_path / "backups")


@pytest.fixture
def world():
    """Fresh fake hosting panels for each test."""
    return DemoWorld.seeded()


@pytest.fixture
def scanner(settings, world):
    # WordPress.org is replaced with the demo mock: no real network in tests.
    return Scanner(settings, wporg_transport=demo_sites.demo_wporg_transport(), demo_world=world)


class FakeNvd:
    """A mocked NVD CVE API 2.0. Tests append CVE items to `items`; requests are recorded."""

    def __init__(self):
        self.items: list[dict] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={"resultsPerPage": len(self.items), "startIndex": 0,
                                         "totalResults": len(self.items), "vulnerabilities": self.items})


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def notifier():
    return OutboxNotifier(delivered=True)


@pytest.fixture
def client(settings, scanner, world, nvd, notifier):
    sources = [NvdSource(api_key=settings.nvd_api_key, transport=httpx.MockTransport(nvd.handler))]
    app = create_app(settings, scanner=scanner, demo_world=world, notifier=notifier, sources=sources)
    with TestClient(app) as c:
        yield c


def demo(label: str) -> str:
    return f"{label}{demo_sites.DEMO_SUFFIX}"


@pytest.fixture
def auth_headers(client):
    client.post("/api/auth/register", json={"email": "owner@example.com", "password": "correct horse battery"})
    r = client.post("/api/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
