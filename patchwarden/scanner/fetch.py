"""Server-side fetch of a user-supplied URL, with SSRF protection.

Every hop (the first request and each redirect) is checked:
- http/https only, no user:password@ in the URL, allowed ports only;
- the host name must resolve to public addresses only (private, loopback,
  link-local, multicast, reserved and cloud-metadata ranges are refused);
- the connection goes to the address we checked (pinned), so a DNS answer
  that changes between check and connect cannot redirect us inside;
- redirects are capped, there is an overall time limit, and the body is
  read only up to a size cap. Proxy environment variables are ignored.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx

from ..config import Settings

Resolver = Callable[[str, int], Awaitable[list[str]]]

USER_AGENT = "Patchwarden-Scanner/0.1 (+external version check; no login attempted)"
BLOCKED_NAMES = ("localhost", "localhost.localdomain")
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


class FetchError(Exception):
    """A fetch that did not produce a response. `message` is safe to show the owner."""

    def __init__(self, code: str, message: str):
        super().__init__(code)
        self.code = code
        self.message = message
        self.after_redirect = False  # True when the site itself sent us there


class BlockedTarget(FetchError):
    pass


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: httpx.Headers
    text: str
    redirects: list[str] = field(default_factory=list)


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def is_public_ip(raw: str) -> bool:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return is_public_ip(str(mapped))
        if ip.teredo:
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def normalise_target(raw: str) -> str:
    """Turn 'example.com' or 'https://example.com/x' into a URL to fetch."""
    raw = raw.strip()
    if not raw:
        raise FetchError("invalid_url", "Please enter a website address.")
    if "://" not in raw:
        raw = "https://" + raw
    return raw


class SafeFetcher:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
        demo_transport: httpx.AsyncBaseTransport | None = None,
        demo_suffix: str = ".demo.patchwarden.test",
    ):
        self.settings = settings
        self.resolver = resolver or system_resolver
        self.demo_suffix = demo_suffix
        timeout = httpx.Timeout(settings.scan_timeout_seconds, connect=min(5.0, settings.scan_timeout_seconds))
        common = dict(timeout=timeout, follow_redirects=False, trust_env=False,
                      headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
        self._client = httpx.AsyncClient(transport=transport, **common)
        self._demo_client = httpx.AsyncClient(transport=demo_transport, **common) if demo_transport else None

    async def aclose(self) -> None:
        await self._client.aclose()
        if self._demo_client:
            await self._demo_client.aclose()

    async def __aenter__(self) -> SafeFetcher:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()

    async def fetch(self, url: str) -> FetchResult:
        try:
            async with asyncio.timeout(self.settings.scan_timeout_seconds):
                return await self._fetch(url)
        except TimeoutError:
            raise FetchError("timeout", "The site took too long to answer.") from None

    async def _fetch(self, url: str) -> FetchResult:
        current = self._parse(url)
        redirects: list[str] = []
        try:
            return await self._follow(current, redirects)
        except FetchError as exc:
            exc.after_redirect = bool(redirects)
            raise

    async def _follow(self, current: httpx.URL, redirects: list[str]) -> FetchResult:
        while True:
            response = await self._send(current)
            try:
                location = response.headers.get("location")
                if response.is_redirect and location:
                    if len(redirects) >= self.settings.scan_max_redirects:
                        raise FetchError("too_many_redirects", "The site redirected too many times.")
                    redirects.append(str(current))
                    current = self._parse(str(current.join(location)))
                    continue
                body = await self._read_capped(response)
            finally:
                await response.aclose()
            encoding = response.charset_encoding or "utf-8"
            return FetchResult(
                url=str(current),
                status_code=response.status_code,
                headers=response.headers,
                text=body.decode(encoding, errors="replace"),
                redirects=redirects,
            )

    def _parse(self, url: str) -> httpx.URL:
        try:
            parsed = httpx.URL(url)
        except (httpx.InvalidURL, ValueError):
            raise FetchError("invalid_url", "That does not look like a website address.") from None
        if parsed.scheme not in {"http", "https"}:
            raise BlockedTarget("blocked_scheme", "Only http and https addresses can be scanned.")
        if parsed.userinfo:
            raise BlockedTarget("blocked_credentials", "Addresses with a username or password in them are not scanned.")
        host = parsed.host.rstrip(".").lower()
        if not host:
            raise FetchError("invalid_url", "That does not look like a website address.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.settings.scan_allowed_ports:
            raise BlockedTarget("blocked_port", "Only standard web ports can be scanned.")
        return parsed

    def _is_demo(self, host: str) -> bool:
        return self._demo_client is not None and self.settings.demo_sites and host.endswith(self.demo_suffix)

    async def _resolve_public(self, host: str, port: int) -> str:
        if host in BLOCKED_NAMES or host.endswith(BLOCKED_SUFFIXES):
            raise BlockedTarget("blocked_private", "Private or internal addresses cannot be scanned.")
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            try:
                addresses = await self.resolver(host, port)
            except (OSError, UnicodeError):
                raise FetchError("dns_failed", "We could not find that website. Check the address.") from None
        if not addresses:
            raise FetchError("dns_failed", "We could not find that website. Check the address.")
        # Refuse if ANY answer is internal: a mixed answer is a rebinding trick.
        if not all(is_public_ip(a) for a in addresses):
            raise BlockedTarget("blocked_private", "Private or internal addresses cannot be scanned.")
        return addresses[0]

    async def _send(self, url: httpx.URL) -> httpx.Response:
        host = url.host.rstrip(".").lower()
        try:
            if self._is_demo(host):
                assert self._demo_client is not None
                return await self._demo_client.send(self._demo_client.build_request("GET", url), stream=True)

            port = url.port or (443 if url.scheme == "https" else 80)
            ip = await self._resolve_public(host, port)
            pinned = url.copy_with(host=ip)
            host_header = host if url.port is None else f"{host}:{url.port}"
            extensions = {"sni_hostname": host} if url.scheme == "https" else {}
            request = self._client.build_request("GET", pinned, headers={"Host": host_header}, extensions=extensions)
            return await self._client.send(request, stream=True)
        except FetchError:
            raise
        except httpx.TimeoutException:
            raise FetchError("timeout", "The site took too long to answer.") from None
        except httpx.HTTPError:
            raise FetchError("unreachable", "We could not connect to the site.") from None

    async def _read_capped(self, response: httpx.Response) -> bytes:
        cap = self.settings.scan_max_body_bytes
        chunks: list[bytes] = []
        size = 0
        try:
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= cap:
                    break
        except httpx.HTTPError:
            raise FetchError("unreachable", "The connection to the site broke while reading the page.") from None
        return b"".join(chunks)[:cap]
