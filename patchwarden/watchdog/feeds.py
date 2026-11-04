"""CVE and release feeds for the Watchdog, normalised to Advisory records with PHP version ranges.

- NvdSource: the NVD CVE API 2.0, filtered to the PHP product CPE. The API key is
  optional (a higher rate limit) and goes in a header, never the URL.
- PhpReleaseSource: php.net's release JSON. A new release tagged "security" becomes
  an advisory affecting older releases on the same PHP line.
- FixtureSource: a local JSON file in the same shapes, for tests and `make dev`.
  Edit it to "add a fake CVE to the feed".
"""

from __future__ import annotations

import json
import logging
import operator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

import httpx

from ..scanner.versions import FIXED_VERSIONS, parse_version

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PHP_CPE = "cpe:2.3:a:php:php"
PHP_RELEASES_URL = "https://www.php.net/releases/index.php"
WATCHED_BRANCHES = tuple(f"{a}.{b}" for a, b in sorted(FIXED_VERSIONS))


class FeedError(Exception):
    """A feed could not be read. The message is safe to log (no key, no URL with a key)."""


@dataclass
class Advisory:
    id: str
    source: str
    severity: str
    summary: str
    affected: list[dict]  # [{"start_incl": "8.4.0", "end_excl": "8.4.27"}, {"exact": "8.3.1"}, ...]
    score: float | None = None
    fixed_in: str | None = None
    url: str | None = None


class AdvisorySource(Protocol):
    name: str

    async def fetch(self, since: datetime, until: datetime) -> list[Advisory]: ...


# --- version ranges -----------------------------------------------------------

def _core(version: str) -> tuple[int, ...] | None:
    v = parse_version(version)
    if v is None:
        return None
    return (v.major, v.minor, v.patch if v.patch is not None else 0)


_RANGE_OPS = {"start_incl": operator.ge, "start_excl": operator.gt, "end_incl": operator.le, "end_excl": operator.lt}


def version_affected(version: str, ranges: list[dict]) -> bool:
    """True if `version` falls in any range. A version without a patch number never matches: no guessing."""
    v = parse_version(version)
    if v is None or v.patch is None:
        return False
    t = (v.major, v.minor, v.patch)
    for r in ranges:
        if "exact" in r:
            if _core(r["exact"]) == t:
                return True
            continue
        bounds = {key: _core(r[key]) for key in _RANGE_OPS if r.get(key)}
        if not bounds or None in bounds.values():
            continue
        if all(_RANGE_OPS[key](t, b) for key, b in bounds.items()):
            return True
    return False


def fixed_in(ranges: list[dict]) -> str | None:
    ends = [r["end_excl"] for r in ranges if r.get("end_excl")]
    return min(ends, key=_core) if ends else None


# --- NVD ----------------------------------------------------------------------

def _nvd_ranges(cve: dict) -> list[dict]:
    ranges = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if not match.get("vulnerable") or not criteria.startswith(PHP_CPE + ":"):
                    continue
                r = {k_out: match[k_in] for k_in, k_out in (
                    ("versionStartIncluding", "start_incl"), ("versionStartExcluding", "start_excl"),
                    ("versionEndIncluding", "end_incl"), ("versionEndExcluding", "end_excl")) if match.get(k_in)}
                if not r:
                    exact = criteria.split(":")[5] if len(criteria.split(":")) > 5 else "*"
                    if exact in {"*", "-"}:
                        continue  # "every version" is too vague to alert on
                    r = {"exact": exact}
                ranges.append(r)
    return ranges


def _nvd_severity(cve: dict) -> tuple[str, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            if severity:
                return severity.lower(), data.get("baseScore")
    return "unknown", None


def parse_nvd(payload: dict, source: str = "nvd") -> list[Advisory]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        ranges = _nvd_ranges(cve)
        if not cve_id or not ranges:
            continue
        summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        severity, score = _nvd_severity(cve)
        out.append(Advisory(id=cve_id, source=source, severity=severity, score=score, summary=summary[:2000],
                            affected=ranges, fixed_in=fixed_in(ranges),
                            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))
    return out


class NvdSource:
    name = "nvd"

    def __init__(self, api_key: str = "", transport: httpx.AsyncBaseTransport | None = None):
        headers = {"User-Agent": "Patchwarden-Watchdog/0.1"}
        if api_key:
            headers["apiKey"] = api_key  # header only: never in a URL that might be logged
        self._client = httpx.AsyncClient(transport=transport, headers=headers, timeout=30, trust_env=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, since: datetime, until: datetime) -> list[Advisory]:
        # NVD allows at most 120 days per query.
        since = max(since, until - timedelta(days=119))
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        params = {"virtualMatchString": PHP_CPE, "lastModStartDate": since.strftime(fmt),
                  "lastModEndDate": until.strftime(fmt), "resultsPerPage": 200, "startIndex": 0}
        advisories: list[Advisory] = []
        while True:
            try:
                r = await self._client.get(NVD_URL, params=params)
            except httpx.HTTPError as exc:
                raise FeedError(f"NVD request failed ({type(exc).__name__})") from None
            if r.status_code != 200:
                raise FeedError(f"NVD answered HTTP {r.status_code}")
            try:
                payload = r.json()
            except ValueError:
                raise FeedError("NVD sent something that is not JSON") from None
            advisories += parse_nvd(payload)
            total = int(payload.get("totalResults", 0))
            params["startIndex"] += int(payload.get("resultsPerPage", 0) or 200)
            if params["startIndex"] >= total:
                return advisories


# --- php.net releases ---------------------------------------------------------

def release_advisory(release: dict) -> Advisory | None:
    version = release.get("version", "")
    v = parse_version(version)
    tags = release.get("tags") or []
    if v is None or v.patch is None or "security" not in tags:
        return None
    branch = f"{v.major}.{v.minor}"
    return Advisory(
        id=f"PHP-{version}",
        source="php_release",
        severity="high",
        summary=(f"PHP {version} is a security release for PHP {branch} (released {release.get('date', 'recently')}). "
                 f"Older {branch} releases miss its fixes."),
        affected=[{"start_incl": f"{branch}.0", "end_excl": version}],
        fixed_in=version,
        url=f"https://www.php.net/ChangeLog-{v.major}.php#{version}",
    )


class PhpReleaseSource:
    name = "php_release"

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, branches=WATCHED_BRANCHES):
        self._client = httpx.AsyncClient(transport=transport, timeout=20, trust_env=False,
                                         headers={"User-Agent": "Patchwarden-Watchdog/0.1"})
        self.branches = branches

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, since: datetime, until: datetime) -> list[Advisory]:
        out = []
        for branch in self.branches:
            try:
                r = await self._client.get(PHP_RELEASES_URL, params={"json": "", "version": branch})
                release = r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError):
                raise FeedError(f"php.net release feed failed for {branch}") from None
            adv = release_advisory(release) if isinstance(release, dict) else None
            if adv:
                out.append(adv)
        return out


# --- local fixture ------------------------------------------------------------

class FixtureSource:
    name = "fixture"

    def __init__(self, path: Path):
        self.path = path

    async def aclose(self) -> None:
        return None

    async def fetch(self, since: datetime, until: datetime) -> list[Advisory]:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            raise FeedError(f"could not read the fixture feed {self.path.name}") from None
        out = parse_nvd({"vulnerabilities": data.get("nvd", [])}, source="fixture")
        out += [a for a in (release_advisory(r) for r in data.get("php_releases", [])) if a]
        return out


# --- exploitation signals: CISA KEV and FIRST EPSS -------------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class KevFeed:
    """CISA's Known Exploited Vulnerabilities catalog: CVE id -> date added."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, fixture: Path | None = None):
        self.fixture = fixture
        self._client = httpx.AsyncClient(transport=transport, timeout=30, trust_env=False,
                                         headers={"User-Agent": "Patchwarden-Watchdog/0.1"})

    async def aclose(self) -> None:
        await self._client.aclose()

    async def exploited(self) -> dict[str, str]:
        if self.fixture is not None:
            try:
                data = json.loads(self.fixture.read_text()).get("kev", [])
            except (OSError, ValueError):
                raise FeedError("could not read the fixture KEV list") from None
            return {str(k["cveID"]).upper(): str(k.get("dateAdded", "")) for k in data if k.get("cveID")}
        try:
            r = await self._client.get(KEV_URL)
            payload = r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            raise FeedError("CISA KEV feed failed") from None
        if not isinstance(payload, dict):
            raise FeedError(f"CISA KEV feed answered HTTP {r.status_code}")
        return {str(v["cveID"]).upper(): str(v.get("dateAdded", ""))
                for v in payload.get("vulnerabilities", []) if isinstance(v, dict) and v.get("cveID")}


class EpssClient:
    """FIRST's Exploit Prediction Scoring System: CVE id -> probability of exploitation in the next 30 days."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, fixture: Path | None = None):
        self.fixture = fixture
        self._client = httpx.AsyncClient(transport=transport, timeout=30, trust_env=False,
                                         headers={"User-Agent": "Patchwarden-Watchdog/0.1"})

    async def aclose(self) -> None:
        await self._client.aclose()

    async def scores(self, cve_ids: list[str]) -> dict[str, float]:
        ids = [c for c in dict.fromkeys(cve_ids) if c.upper().startswith("CVE-")]
        if not ids:
            return {}
        if self.fixture is not None:
            try:
                data = json.loads(self.fixture.read_text()).get("epss", {})
            except (OSError, ValueError):
                raise FeedError("could not read the fixture EPSS scores") from None
            return {c: float(data[c]) for c in ids if c in data}
        out: dict[str, float] = {}
        for i in range(0, len(ids), 100):  # the API takes a comma-separated list
            try:
                r = await self._client.get(EPSS_URL, params={"cve": ",".join(ids[i:i + 100])})
                payload = r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError):
                raise FeedError("FIRST EPSS request failed") from None
            for row in payload.get("data", []) if isinstance(payload, dict) else []:
                try:
                    out[str(row["cve"]).upper()] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return out
