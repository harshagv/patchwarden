"""In-process demo sites under *.demo.patchwarden.test (.test never resolves publicly).

Used by the acceptance tests and by `make dev` so you can try the scanner
without touching a real third-party site. Off in production (config refuses it).
"""

from __future__ import annotations

import httpx

from ..fakes import DEMO_SUFFIX, DemoWorld

_PLAIN_HTML = "<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>"

_WP_HTML = """<!doctype html><html><head>
<title>Demo Bakery</title>
<meta name="generator" content="WordPress 6.6.2" />
<link rel="stylesheet" href="https://wordpress.demo.patchwarden.test/wp-content/themes/demo-storefront/style.css" />
<link rel="stylesheet" href="https://wordpress.demo.patchwarden.test/wp-content/plugins/demo-gallery/css/gallery.css?ver=1.9.2" />
<script src="https://wordpress.demo.patchwarden.test/wp-content/plugins/demo-contact-form/js/form.js?ver=2.3.0"></script>
<script src="https://wordpress.demo.patchwarden.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body><h1>Demo Bakery</h1></body></html>"""

# host label -> (headers, html)
_SITES: dict[str, tuple[dict[str, str], str]] = {
    "php84-unpatched": ({"X-Powered-By": "PHP/8.4.13", "Server": "nginx"}, _PLAIN_HTML.format(title="Shop on PHP 8.4.13")),
    "php84-fixed": ({"X-Powered-By": "PHP/8.4.27", "Server": "nginx"}, _PLAIN_HTML.format(title="Shop on PHP 8.4.27")),
    "php85-fixed": ({"X-Powered-By": "PHP/8.5.12"}, _PLAIN_HTML.format(title="Blog on PHP 8.5.12")),
    "php83-unpatched": ({"X-Powered-By": "PHP/8.3.20"}, _PLAIN_HTML.format(title="Agency on PHP 8.3.20")),
    "php82-fixed": ({"X-Powered-By": "PHP/8.2.35"}, _PLAIN_HTML.format(title="Club on PHP 8.2.35")),
    "php81": ({"Server": "Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.14"}, _PLAIN_HTML.format(title="Clinic on PHP 8.1")),
    "php74": ({"X-Powered-By": "PHP/7.4.33"}, _PLAIN_HTML.format(title="Legacy store on PHP 7.4")),
    "hidden": (
        {"Server": "nginx", "Set-Cookie": "PHPSESSID=demo-session-value; path=/; HttpOnly"},
        _PLAIN_HTML.format(title="Site that hides its PHP version"),
    ),
    "branch-only": ({"X-Powered-By": "PHP/8.4"}, _PLAIN_HTML.format(title="Shows only the PHP branch")),
    "static": ({"Server": "nginx"}, _PLAIN_HTML.format(title="Static site, no PHP signals")),
    "wordpress": (
        {"X-Powered-By": "PHP/8.3.20", "Link": '<https://wordpress.demo.patchwarden.test/wp-json/>; rel="https://api.w.org/"'},
        _WP_HTML,
    ),
}

# bulk-01 .. bulk-10 rotate through versions so a bulk CSV gives a mix of results.
_BULK_VERSIONS = ["8.4.13", "8.4.27", "8.1.31", "8.3.36", "8.5.3", None, "8.2.20", "8.3.12", "7.4.33", "8.5.12"]
for _i, _v in enumerate(_BULK_VERSIONS, start=1):
    _SITES[f"bulk-{_i:02d}"] = (
        {"X-Powered-By": f"PHP/{_v}"} if _v else {"Server": "nginx"},
        _PLAIN_HTML.format(title=f"Bulk demo site {_i}"),
    )

_REDIRECTS = {
    "redirect": "https://php84-fixed.demo.patchwarden.test/",
    # Points at the cloud metadata address: the fetcher must refuse to follow.
    "redirect-internal": "http://169.254.169.254/latest/meta-data/",
    "redirect-loop": "https://redirect-loop.demo.patchwarden.test/",
}


def demo_site_handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if not host.endswith(DEMO_SUFFIX):
        return httpx.Response(502, text="not a demo host")
    label = host[: -len(DEMO_SUFFIX)]
    if label in _REDIRECTS:
        return httpx.Response(302, headers={"Location": _REDIRECTS[label]})
    if label not in _SITES:
        return httpx.Response(404, text="no such demo site")
    headers, html = _SITES[label]
    return httpx.Response(200, headers={"Content-Type": "text/html; charset=utf-8", **headers}, text=html)


_DEMO_WPORG = {
    ("plugin", "demo-contact-form"): {"name": "Demo Contact Form", "version": "2.5.0"},
    ("plugin", "demo-gallery"): {"name": "Demo Gallery", "version": "1.9.2"},
    ("theme", "demo-storefront"): {"name": "Demo Storefront", "version": "3.4.0"},
}


def demo_wporg_handler(request: httpx.Request) -> httpx.Response:
    kind = "plugin" if request.url.path.startswith("/plugins/") else "theme"
    slug = request.url.params.get("request[slug]", "")
    info = _DEMO_WPORG.get((kind, slug))
    if info is None:
        return httpx.Response(404, json={"error": f"{kind.title()} not found."})
    return httpx.Response(200, json={"slug": slug, **info})


def demo_transport(world: DemoWorld | None = None) -> httpx.AsyncBaseTransport:
    """Static demo sites, plus the live fake hosts the Patch agent can change."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = world.get(request.url.host) if world else None
        if host is not None:
            return host.serve(request.url.path or "/")
        return demo_site_handler(request)

    return httpx.MockTransport(handler)


def demo_wporg_transport() -> httpx.AsyncBaseTransport:
    return httpx.MockTransport(demo_wporg_handler)
