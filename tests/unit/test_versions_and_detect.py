"""Version parsing, header detection and the risk score."""

from __future__ import annotations

from datetime import date

import httpx
import pytest

from patchwarden.models import Risk
from patchwarden.scanner.detect import detect_php_version, detect_wordpress, safe_headers
from patchwarden.scanner.versions import assess, parse_version

BEFORE_8_2_WINDOW = date(2026, 9, 1)  # more than 90 days before 8.2 EOL
INSIDE_8_2_WINDOW = date(2026, 11, 2)
AFTER_8_2_EOL = date(2027, 1, 5)


@pytest.mark.parametrize("version,risk", [
    ("8.5.11", Risk.patch_now), ("8.5.12", Risk.safe), ("8.5.20", Risk.safe),
    ("8.4.26", Risk.patch_now), ("8.4.27", Risk.safe),
    ("8.3.35", Risk.patch_now), ("8.3.36", Risk.safe),
    ("8.1.33", Risk.must_migrate), ("8.0.30", Risk.must_migrate), ("7.4.33", Risk.must_migrate),
    ("5.6.40", Risk.must_migrate),
    ("8.4", Risk.unknown),  # branch only: we cannot tell if it is patched
    ("9.0.1", Risk.unknown),  # not in our table: no guess
])
def test_risk_table(version, risk):
    assert assess(parse_version(version), today=BEFORE_8_2_WINDOW).risk == risk


def test_php82_before_the_migration_window_is_scored_like_any_branch():
    assert assess(parse_version("8.2.34"), today=BEFORE_8_2_WINDOW).risk == Risk.patch_now
    assert assess(parse_version("8.2.35"), today=BEFORE_8_2_WINDOW).risk == Risk.safe


@pytest.mark.parametrize("today", [INSIDE_8_2_WINDOW, AFTER_8_2_EOL])
def test_php82_close_to_or_after_eol_must_migrate_even_when_patched(today):
    patched = assess(parse_version("8.2.35"), today=today)
    unpatched = assess(parse_version("8.2.20"), today=today)
    assert patched.risk == unpatched.risk == Risk.must_migrate
    assert "carries the fix" in patched.summary
    assert "8.2.35" in unpatched.next_step


def test_hidden_version_is_unknown():
    assert assess(None).risk == Risk.unknown


def test_distro_build_gets_a_backport_note():
    a = assess(parse_version("8.4.13-1+deb12u1"), today=BEFORE_8_2_WINDOW)
    assert a.risk == Risk.patch_now
    assert any("backported" in n for n in a.notes)


@pytest.mark.parametrize("headers,expected,source", [
    ({"X-Powered-By": "PHP/8.4.13"}, "8.4.13", "x-powered-by"),
    ({"X-Powered-By": "PHP/8.3.36, PleskLin"}, "8.3.36", "x-powered-by"),
    ({"Server": "Apache/2.4.58 (Ubuntu) PHP/8.1.2-1ubuntu2.14 OpenSSL/3.0.2"}, "8.1.2-1ubuntu2.14", "server"),
    ({"X-PHP-Version": "8.5.12"}, "8.5.12", "x-php-version"),
    ({"Server": "Apache/2.4.58 (Ubuntu)"}, None, None),
    ({"X-Powered-By": "PHP"}, None, None),
    ({"X-Powered-By": "Express"}, None, None),
])
def test_header_detection(headers, expected, source):
    ev = detect_php_version(httpx.Headers(headers))
    assert (str(ev.version) if ev.version else None) == expected
    assert ev.source == source


def test_apache_version_is_not_mistaken_for_php():
    ev = detect_php_version(httpx.Headers({"Server": "Apache/2.4.58"}))
    assert ev.version is None and not ev.php_detected


def test_php_session_cookie_means_php_but_hidden_version():
    ev = detect_php_version(httpx.Headers({"Set-Cookie": "PHPSESSID=abc123; path=/"}))
    assert ev.version is None and ev.php_detected


def test_stored_headers_drop_cookie_values():
    h = safe_headers(httpx.Headers([("Set-Cookie", "PHPSESSID=secretvalue; path=/"), ("Server", "nginx")]))
    assert h == {"server": "nginx", "set-cookie": "PHPSESSID=<redacted>"}


def test_wordpress_detection_lists_slugs():
    html = """<meta name="generator" content="WordPress 6.6.2" />
    <script src="/wp-content/plugins/akismet/a.js?ver=5.3"></script>
    <link href='/wp-content/themes/twentytwentyfour/style.css' rel='stylesheet'>"""
    wp = detect_wordpress(httpx.Headers(), html)
    assert wp.is_wordpress and wp.core_version == "6.6.2"
    assert [(c.kind, c.slug, c.version_hint) for c in wp.components] == [
        ("plugin", "akismet", "5.3"), ("theme", "twentytwentyfour", None),
    ]


def test_non_wordpress_page():
    assert not detect_wordpress(httpx.Headers(), "<html><body>hello</body></html>").is_wordpress
