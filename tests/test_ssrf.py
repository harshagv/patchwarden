"""SSRF protection on the server-side fetch of user-supplied URLs."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx
import pytest

from patchwarden.models import Scan
from patchwarden.scanner.fetch import BlockedTarget, FetchError, SafeFetcher, is_public_ip

from .conftest import demo

PUBLIC_IP = "93.184.215.14"  # any global address; the mock transport never connects


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1", "2002:7f00:1::1", "198.51.100.7",
])
def test_internal_addresses_are_not_public(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_public(ip):
    assert is_public_ip(ip)


def _fetcher(settings, *, answers=None, handler=None):
    async def resolver(host, port):
        if answers is None or host not in answers:
            raise OSError("no such host")
        return answers[host]

    transport = httpx.MockTransport(handler or (lambda r: httpx.Response(200, text="ok")))
    return SafeFetcher(settings, transport=transport, resolver=resolver)


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("url,code", [
    ("http://127.0.0.1/", "blocked_private"),
    ("http://10.0.0.5/", "blocked_private"),
    ("http://169.254.169.254/latest/meta-data/", "blocked_private"),
    ("http://[::1]/", "blocked_private"),
    ("http://[::ffff:127.0.0.1]/", "blocked_private"),
    ("http://localhost/", "blocked_private"),
    ("http://printer.local/", "blocked_private"),
    ("http://db.internal/", "blocked_private"),
    ("file:///etc/passwd", "blocked_scheme"),
    ("gopher://example.com/", "blocked_scheme"),
    ("http://user:pw@example.com/", "blocked_credentials"),
    ("http://example.com:22/", "blocked_port"),
    ("http://example.com:6379/", "blocked_port"),
])
def test_blocked_targets(settings, url, code):
    f = _fetcher(settings, answers={"example.com": [PUBLIC_IP]})
    with pytest.raises(BlockedTarget) as exc:
        _run(f.fetch(url))
    assert exc.value.code == code


def test_hostname_resolving_to_private_address_is_blocked(settings):
    f = _fetcher(settings, answers={"evil.example": ["10.0.0.7"]})
    with pytest.raises(BlockedTarget):
        _run(f.fetch("https://evil.example/"))


def test_mixed_public_and_private_answers_are_blocked(settings):
    f = _fetcher(settings, answers={"rebind.example": [PUBLIC_IP, "127.0.0.1"]})
    with pytest.raises(BlockedTarget):
        _run(f.fetch("https://rebind.example/"))


def test_connection_is_pinned_to_the_checked_address(settings):
    seen = {}

    def handler(request: httpx.Request):
        seen["host"] = request.url.host
        seen["host_header"] = request.headers["host"]
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.27"}, text="hi")

    f = _fetcher(settings, answers={"shop.example": [PUBLIC_IP]}, handler=handler)
    result = _run(f.fetch("https://shop.example/"))
    assert result.status_code == 200
    assert seen == {"host": PUBLIC_IP, "host_header": "shop.example", "sni": "shop.example"}


def test_every_redirect_hop_is_checked(settings):
    def handler(request: httpx.Request):
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:80/admin"})

    f = _fetcher(settings, answers={"shop.example": [PUBLIC_IP]}, handler=handler)
    with pytest.raises(BlockedTarget) as exc:
        _run(f.fetch("https://shop.example/"))
    assert exc.value.after_redirect


def test_redirects_are_capped(settings):
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url)
        return httpx.Response(301, headers={"Location": "/again"})

    f = _fetcher(settings, answers={"loop.example": [PUBLIC_IP]}, handler=handler)
    with pytest.raises(FetchError) as exc:
        _run(f.fetch("https://loop.example/"))
    assert exc.value.code == "too_many_redirects"
    assert len(calls) == settings.scan_max_redirects + 1


def test_slow_site_times_out(settings):
    async def slow(request: httpx.Request):
        await asyncio.sleep(5)
        return httpx.Response(200)

    fast = replace(settings, scan_timeout_seconds=0.2)
    f = SafeFetcher(fast, transport=httpx.MockTransport(slow), resolver=_ok_resolver)
    with pytest.raises(FetchError) as exc:
        _run(f.fetch("https://slow.example/"))
    assert exc.value.code == "timeout"


def test_body_is_capped(settings):
    small = replace(settings, scan_max_body_bytes=1000)
    f = SafeFetcher(small, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 50_000)),
                    resolver=_ok_resolver)
    assert len(_run(f.fetch("https://big.example/")).text) == 1000


def test_proxy_environment_is_ignored(settings, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    f = _fetcher(settings, answers={"shop.example": [PUBLIC_IP]})
    assert _run(f.fetch("https://shop.example/")).status_code == 200


async def _ok_resolver(host, port):
    return [PUBLIC_IP]


# --- through the API ---------------------------------------------------------

def test_api_refuses_internal_target_and_stores_nothing(client):
    r = client.post("/api/scans", json={"domain": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400
    assert r.json() == {"error": "blocked_private", "message": "Private or internal addresses cannot be scanned."}
    with client.app.state.sessionmaker() as db:
        assert db.query(Scan).count() == 0


def test_bulk_reports_rejected_rows_and_scans_the_rest(client):
    r = client.post("/api/scans", json={"domains": [demo("php84-fixed"), "http://127.0.0.1/", "ftp://x.example"]})
    assert r.status_code == 201
    body = r.json()
    assert body["count"] == 1
    assert [x["error"] for x in body["rejected"]] == ["blocked_private", "blocked_scheme"]


def test_site_redirecting_to_metadata_service_is_not_followed(client):
    r = client.post("/api/scans", json={"domain": demo("redirect-internal")})
    assert r.status_code == 201
    scan = r.json()["scans"][0]
    assert scan["risk"] == "unknown"
    assert scan["findings"]["error"]["code"] == "blocked_private"


def test_demo_redirect_to_public_demo_site_is_followed(client):
    scan = client.post("/api/scans", json={"domain": demo("redirect")}).json()["scans"][0]
    assert scan["risk"] == "safe"
    assert scan["findings"]["redirects"] == [f"https://{demo('redirect')}"]


def test_demo_hosts_are_not_special_when_demo_mode_is_off(settings):
    off = replace(settings, demo_sites=False)
    f = SafeFetcher(off, transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                    resolver=lambda h, p: _raise_dns(), demo_transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(FetchError) as exc:
        _run(f.fetch(f"https://{demo('php84-fixed')}/"))
    assert exc.value.code == "dns_failed"


async def _raise_dns():
    raise OSError("nxdomain")
