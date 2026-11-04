"""WordPress plugin/theme check: WordPress.org lookup + a WPScan-style vulnerability feed.

The feed is a local JSON file (WP_VULN_FEED_PATH). The one shipped in
src/patchwarden/data/ is demo data with made-up IDs; swap in a real export when
you have one. The real WPScan API needs a paid token and is not used.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

import httpx

from .detect import WpComponent

log = logging.getLogger(__name__)

WPORG_BASE = "https://api.wordpress.org"


def _vtuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4])


@dataclass(frozen=True)
class FeedEntry:
    id: str
    kind: str
    slug: str
    title: str
    fixed_in: str | None
    severity: str
    cve: str | None = None


class VulnFeed:
    def __init__(self, name: str, entries: list[FeedEntry]):
        self.name = name
        self._by_key: dict[tuple[str, str], list[FeedEntry]] = {}
        for e in entries:
            self._by_key.setdefault((e.kind, e.slug), []).append(e)

    @classmethod
    def load(cls, path: Path) -> VulnFeed:
        data = json.loads(path.read_text())
        entries = [
            FeedEntry(
                id=item["id"],
                kind=item["type"],
                slug=item["slug"].lower(),
                title=item["title"],
                fixed_in=item.get("fixed_in"),
                severity=item.get("severity", "unknown"),
                cve=item.get("cve"),
            )
            for item in data.get("vulnerabilities", [])
        ]
        return cls(data.get("name", path.name), entries)

    def match(self, comp: WpComponent) -> list[dict]:
        hits = []
        for e in self._by_key.get((comp.kind, comp.slug), []):
            if comp.version_hint and e.fixed_in:
                if _vtuple(comp.version_hint) >= _vtuple(e.fixed_in):
                    continue
                status = "affected"
            else:
                # We cannot see the installed version: flag it, do not claim it.
                status = "check_needed"
            hits.append({
                "id": e.id, "cve": e.cve, "title": e.title, "severity": e.severity,
                "fixed_in": e.fixed_in, "status": status,
            })
        return hits


class WordPressOrgClient:
    """Looks up public plugin/theme info. The host is fixed, never user-supplied."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 8.0):
        self._client = httpx.AsyncClient(base_url=WPORG_BASE, transport=transport, timeout=timeout, trust_env=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def info(self, kind: str, slug: str) -> dict | None:
        path = "/plugins/info/1.2/" if kind == "plugin" else "/themes/info/1.2/"
        action = "plugin_information" if kind == "plugin" else "theme_information"
        try:
            r = await self._client.get(path, params={"action": action, "request[slug]": slug})
        except httpx.HTTPError:
            log.info("WordPress.org lookup failed for %s %s", kind, slug)
            return {"lookup": "failed"}
        if r.status_code == 404:
            return None
        try:
            data = r.json()
        except ValueError:
            return {"lookup": "failed"}
        if not isinstance(data, dict) or data.get("error"):
            return None
        return {"lookup": "ok", "name": data.get("name"), "latest_version": data.get("version")}


async def check_components(
    components: list[WpComponent], feed: VulnFeed, wporg: WordPressOrgClient | None
) -> list[dict]:
    results = []
    for comp in components:
        entry: dict = {"type": comp.kind, "slug": comp.slug, "version_hint": comp.version_hint}
        if wporg is not None:
            info = await wporg.info(comp.kind, comp.slug)
            entry["wordpress_org"] = info if info is not None else {"lookup": "not_listed"}
        entry["vulnerabilities"] = feed.match(comp)
        results.append(entry)
    return results
