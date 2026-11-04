"""What a virtual patch blocks: generic PHP code-injection request patterns.

These are not PHP2Shell's exact exploit (no public details are assumed here). They are the shapes that
PHP remote-code-execution attacks have used for years: ini overrides passed to php-cgi
(allow_url_include, auto_prepend_file), PHP stream wrappers that smuggle code (php://input,
php://filter, data://), PHP open tags in a query string, and direct requests to php-cgi.

The list is meant to be replaced: when a vendor or CERT publishes a precise signature, put it here and
every provider's rule is built from it. A virtual patch buys time; it does not replace the PHP update.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit


@dataclass(frozen=True)
class Signature:
    id: str
    field: str  # "query" or "path"
    contains: str  # matched after URL-decoding and lower-casing
    why: str


SIGNATURES: tuple[Signature, ...] = (
    Signature("ini-allow-url-include", "query", "allow_url_include", "PHP setting overridden from the URL"),
    Signature("ini-auto-prepend", "query", "auto_prepend_file", "PHP setting overridden from the URL"),
    Signature("wrapper-php-input", "query", "php://input", "PHP stream wrapper used to run posted code"),
    Signature("wrapper-php-filter", "query", "php://filter", "PHP stream wrapper used to read source code"),
    Signature("wrapper-data", "query", "data://", "Inline code passed as a data:// URL"),
    Signature("php-open-tag", "query", "<?php", "PHP code in the query string"),
    Signature("php-cgi-direct", "path", "php-cgi", "Direct request to the php-cgi binary"),
)

RULE_TAG = "patchwarden-vp"


def blocks(url: str, signatures: tuple[Signature, ...] = SIGNATURES) -> Signature | None:
    """The signature a request URL matches, if any (used by the demo WAF and the tests)."""
    parts = urlsplit(url)
    fields = {"query": unquote_plus(parts.query).lower(), "path": unquote_plus(parts.path).lower()}
    return next((s for s in signatures if s.contains in fields[s.field]), None)


def cloudflare_expression(signatures: tuple[Signature, ...] = SIGNATURES) -> str:
    """Cloudflare Rules language: one OR expression over the decoded, lower-cased query and path."""
    field = {"query": "lower(url_decode(http.request.uri.query))", "path": "lower(url_decode(http.request.uri.path))"}
    return " or ".join(f'({field[s.field]} contains "{s.contains}")' for s in signatures)
