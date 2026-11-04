"""Build the generated parts of the website in site/: the docs page and the example screens.

    make site

- site/docs/index.html     docs/TECHNICAL.md rendered to HTML
- site/examples/*.html     real pages produced by the app from the built-in demo sites
                           (tokens, CSRF values and local paths scrubbed; buttons disabled)

The landing page (site/index.html) and its assets are written by hand. The build fails if
any output still contains a local path, a share token or a secret.
"""

from __future__ import annotations

import html
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
BACKUP_PLACEHOLDER = "/var/lib/patchwarden/backups"


# --- docs -----------------------------------------------------------------------

def page(title: str, description: str, body: str, *, depth: int = 1) -> str:
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<meta name="theme-color" content="#eeebe4" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1a1917" media="(prefers-color-scheme: dark)">
<link rel="canonical" href="https://patchwarden.harshagv.me/docs/">
<link rel="icon" href="{up}assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{up}assets/style.css">
</head>
<body class="docs-page">
<a class="skip" href="#main">Skip to content</a>
<header class="nav">
  <a class="brand" href="{up}"><img src="{up}assets/favicon.svg" alt="" width="26" height="26"> Patchwarden</a>
  <nav class="nav__links">
    <a href="{up}#how">How it works</a>
    <a href="{up}#agents">Agents</a>
    <a href="{up}#edge">Edge</a>
    <a href="{up}#screens">Screens</a>
    <a href="{up}#run">Run it</a>
    <a href="{up}docs/" aria-current="page">Docs</a>
    <a href="https://github.com/harshagv/patchwarden" rel="noopener">GitHub</a>
  </nav>
  <a class="button button--small" href="https://www.linkedin.com/in/harshagv/" rel="noopener">Request access</a>
  <details class="nav__menu">
    <summary aria-label="Menu">Menu</summary>
    <nav aria-label="Sections (menu)">
      <a href="{up}">Overview</a><a href="{up}#how">How it works</a><a href="{up}#agents">Agents</a>
      <a href="{up}#edge">Edge</a><a href="{up}#run">Run it</a><a href="{up}#faq">FAQ</a>
      <a href="https://github.com/harshagv/patchwarden" rel="noopener">GitHub</a>
      <a class="nav__menu-cta" href="https://www.linkedin.com/in/harshagv/" rel="noopener">Request access</a>
    </nav>
  </details>
</header>
<main class="docs" id="main">
{body}
</main>
<footer class="footer footer--slim">
  <p>Patchwarden · <a href="{up}">Overview</a> · <a href="{up}#status">What is ready today</a> ·
  <a href="https://github.com/harshagv/patchwarden" rel="noopener">Source on GitHub</a> (MIT) ·
  Patchwarden is not affiliated with The PHP Group. PHP is a trademark of The PHP Group.</p>
</footer>
<script src="{up}assets/site.js" defer></script>
</body>
</html>
"""


def build_docs() -> None:
    src = (ROOT / "docs" / "TECHNICAL.md").read_text()
    # Links that point into the private repository have no page on the site.
    src = src.replace("[README](../README.md)", "[overview](../)")
    src = src.replace("](../SPEC.md)", "](https://github.com/harshagv/patchwarden/blob/main/SPEC.md)")
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                           extension_configs={"toc": {"toc_depth": "2-2", "permalink": False}})
    body_html = md.convert(src)
    toc = md.toc  # type: ignore[attr-defined]
    # A <details> so the long contents list can fold away on phones (site.js opens it on wide screens).
    body = (f'<details class="docs__toc" open><summary><p class="eyebrow">On this page</p></summary>{toc}</details>'
            f'<article class="docs__body">{body_html}</article>')
    out = SITE / "docs" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page("Patchwarden technical guide",
                        "Every Patchwarden flow, endpoint, safety rule and setting.", body))


# --- example screens --------------------------------------------------------------

EXAMPLE_BANNER = (
    '<div class="pw-example">Example output from the Patchwarden demo sites · buttons are disabled · '
    '<a href="../#screens" target="_top">back to the overview</a></div>'
)
EXAMPLE_STYLE = (
    "<style>.pw-example{position:sticky;top:0;z-index:9;background:#1d1c1a;color:#f0ede7;font:13px/1.4 system-ui,sans-serif;"
    "padding:8px 14px;text-align:center}.pw-example a{color:#dfa592;pointer-events:auto}"
    "form,button,input,select,main a,nav a{pointer-events:none}</style>"
)


def scrub(page_html: str, backup_dir: str) -> str:
    out = page_html.replace(backup_dir, BACKUP_PLACEHOLDER)
    out = re.sub(r'name="csrf" value="[0-9a-f]+"', 'name="csrf" value="example"', out)
    out = re.sub(r"\?token=[^\"'&<\s]+", "", out)
    out = re.sub(r'<meta http-equiv="refresh"[^>]*>', "", out)
    out = re.sub(r'href="/(?!/)[^"]*"', 'href="#"', out)
    out = out.replace("<head>", '<head>\n<meta name="robots" content="noindex">', 1)
    out = re.sub(r"(<body[^>]*>)", r"\1" + EXAMPLE_BANNER, out, count=1)
    return out.replace("</head>", EXAMPLE_STYLE + "</head>", 1)


def build_examples() -> dict[str, str]:
    backup_dir = tempfile.mkdtemp(prefix="pw-site-")
    os.environ.update(APP_ENV="test", DATABASE_URL="sqlite://", JWT_SECRET=secrets.token_hex(32),
                      DEMO_SITES="true", CVE_FEED="fixture", BACKUP_DIR=backup_dir,
                      PUBLIC_BASE_URL="https://app.patchwarden.example", WATCHDOG_SCHEDULER="false")
    os.environ.pop("CREDENTIAL_KEY", None)
    sys.path.insert(0, str(ROOT / "src"))
    from fastapi.testclient import TestClient

    from patchwarden.app import create_app
    from patchwarden.config import load_settings
    from patchwarden.watchdog.notify import OutboxNotifier

    settings = load_settings(load_dotenv_file=False)
    app = create_app(settings, notifier=OutboxNotifier())
    pages: dict[str, str] = {}
    with TestClient(app) as c:
        pw = "a long demo password"
        c.post("/api/auth/register", json={"email": "owner@example.com", "password": pw})
        auth = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"email": "owner@example.com",
                                                                             "password": pw}).json()["access_token"]}
        c.post("/dashboard/login", data={"email": "owner@example.com", "password": pw})
        html_get = lambda url: c.get(url, headers={"Accept": "text/html"}).text  # noqa: E731

        def site(domain: str, *, platform="custom", token=True, form="/checkout", login="/login") -> int:
            body = {"domain": domain, "platform": platform, "form_path": form}
            if platform != "wordpress":
                body["login_path"] = login
            sid = c.post("/api/sites", json=body, headers=auth).json()["id"]
            if token:
                c.post(f"/api/sites/{sid}/credentials", json={"kind": "cpanel_token", "value": "demo-panel-token"},
                       headers=auth)
            return sid

        # 1. The free one-page report.
        scan = c.post("/api/scans", json={"domain": "php84-unpatched.demo.patchwarden.test"}).json()["scans"][0]
        pages["report"] = html_get(scan["share_url"].replace(settings.public_base_url, ""))

        # 2. A patch that succeeded, and 3. one that rolled itself back.
        for name, label in (("patch", "shop84"), ("rollback", "fragile84")):
            sid = site(f"{label}.demo.patchwarden.test")
            job = c.post("/api/patches", json={"site_id": sid}, headers=auth).json()
            c.post(f"/api/patches/{job['id']}/approve", headers=auth)
            pages[name] = html_get(f"/dashboard/patches/{job['id']}")

        # 4. A migration plan with a breakage report (WordPress on PHP 7.4).
        sid = site("wp74.demo.patchwarden.test", platform="wordpress")
        mig = c.post("/api/migrations", json={"site_id": sid}, headers=auth).json()
        pages["migration"] = html_get(f"/dashboard/migrations/{mig['id']}")

        # 5. WordPress Guard: score, fix list and the one Fix it button.
        sid = site("wpshop84.demo.patchwarden.test", platform="wordpress")
        c.post("/api/scans", json={"domain": "wpshop84.demo.patchwarden.test"}, headers=auth)
        c.post(f"/api/sites/{sid}/wp-guard", json={"enabled": True}, headers=auth)
        pages["wp-guard"] = html_get(f"/dashboard/wp-guard/{sid}")

        # 6. Alerts from the watchdog.
        sid = site("php83-unpatched.demo.patchwarden.test", token=False)
        c.post(f"/api/sites/{sid}/monitoring", json={"enabled": True}, headers=auth)
        c.post("/api/watchdog/run", headers=auth)
        pages["alerts"] = html_get("/dashboard/alerts")

    out_dir = SITE / "examples"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, raw in pages.items():
        (out_dir / f"{name}.html").write_text(scrub(raw, backup_dir))
    return pages


def check_outputs() -> None:
    # A real share token is a long JWT; the docs only mention "?token=" in prose.
    bad = re.compile(r"/Users/|/private/tmp|/var/folders|harsha\.gv|\?token=[A-Za-z0-9_.-]{20,}|eyJhbGciOi|pw_[A-Za-z0-9_-]{20}")
    problems = []
    for f in SITE.rglob("*.html"):
        for m in bad.finditer(f.read_text()):
            problems.append(f"{f.relative_to(ROOT)}: {m.group(0)}")
    if problems:
        sys.exit("Refusing to publish, found private data:\n" + "\n".join(problems))


if __name__ == "__main__":
    build_docs()
    built = build_examples()
    check_outputs()
    print(f"site/docs/index.html and {len(built)} example pages built")
