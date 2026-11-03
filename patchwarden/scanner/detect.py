"""Read PHP and WordPress signals from a public homepage response. No guessing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from .versions import PhpVersion, parse_version

# Headers that can name the PHP version, in the order we trust them.
VERSION_HEADERS = ("x-powered-by", "server", "x-php-version")

_PHP_TOKEN = re.compile(r"\bPHP/(\S+)", re.IGNORECASE)
_PHP_SESSION_COOKIE = re.compile(r"(?:^|[;,]\s*)PHPSESSID=", re.IGNORECASE)

_WP_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)', re.IGNORECASE)
_WP_MARKERS = re.compile(r"/wp-(?:content|includes)/", re.IGNORECASE)
_WP_ASSET = re.compile(
    r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_-]{0,99})/[^\"'\s<>]*?(?:\?ver=([0-9][0-9a-z.\-]{0,31}))?[\"'\s>]",
    re.IGNORECASE,
)


@dataclass
class VersionEvidence:
    version: PhpVersion | None
    source: str | None  # header the version came from
    php_detected: bool  # PHP seen even if the version is hidden
    php_hint: str | None = None


@dataclass
class WpComponent:
    kind: str  # "plugin" or "theme"
    slug: str
    version_hint: str | None = None  # from ?ver= on an asset URL; not proof


@dataclass
class WordPressEvidence:
    is_wordpress: bool
    core_version: str | None = None
    components: list[WpComponent] = field(default_factory=list)


def safe_headers(headers: httpx.Headers) -> dict[str, str]:
    """Headers to store. Cookie values are dropped: we keep only cookie names."""
    out: dict[str, str] = {}
    for name in {k.lower() for k in headers.keys()}:
        values = headers.get_list(name)
        if name == "set-cookie":
            out[name] = ", ".join(v.split("=", 1)[0].strip() + "=<redacted>" for v in values)
        else:
            out[name] = ", ".join(values)
    return dict(sorted(out.items()))


def detect_php_version(headers: httpx.Headers) -> VersionEvidence:
    for name in VERSION_HEADERS:
        for value in headers.get_list(name):
            if name == "x-php-version":
                v = parse_version(value)
                if v:
                    return VersionEvidence(v, name, True)
                continue
            m = _PHP_TOKEN.search(value)
            if m:
                v = parse_version(m.group(1))
                if v:
                    return VersionEvidence(v, name, True)

    for value in headers.get_list("x-powered-by"):
        if re.search(r"\bPHP\b", value, re.IGNORECASE):
            return VersionEvidence(None, None, True, "X-Powered-By says PHP but hides the version")
    for value in headers.get_list("set-cookie"):
        if _PHP_SESSION_COOKIE.search(value):
            return VersionEvidence(None, None, True, "A PHP session cookie is set, but the version is hidden")
    return VersionEvidence(None, None, False)


def detect_wordpress(headers: httpx.Headers, html: str) -> WordPressEvidence:
    link = " ".join(headers.get_list("link"))
    gen = _WP_GENERATOR.search(html)
    is_wp = bool(gen) or "api.w.org" in link or bool(_WP_MARKERS.search(html))
    if not is_wp:
        return WordPressEvidence(False)

    found: dict[tuple[str, str], WpComponent] = {}
    for kind_dir, slug, ver in _WP_ASSET.findall(html):
        kind = "plugin" if kind_dir.lower() == "plugins" else "theme"
        key = (kind, slug.lower())
        comp = found.setdefault(key, WpComponent(kind, slug.lower()))
        if ver and comp.version_hint is None:
            comp.version_hint = ver
    components = sorted(found.values(), key=lambda c: (c.kind, c.slug))
    return WordPressEvidence(True, (gen.group(1) or None) if gen else None, components)
