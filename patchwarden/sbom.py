"""Per-site software inventory (SBOM) in CycloneDX 1.5 JSON, with the vulnerabilities we know about.

What goes in, from the best evidence Patchwarden already holds:
- the PHP runtime (latest check), with its CPE so other scanners can match it;
- WordPress core, plugins and themes (latest plugin report, else the outside scan);
- Composer packages from composer.lock, read from the host (read-only) when access is set up;
- vulnerabilities: PHP advisories matched by the Watchdog (with CISA KEV and EPSS where known), and
  WordPress component flaws from the vulnerability feed.

Package URLs: pkg:composer/... is the standard purl type. PHP, WordPress core and WordPress plugins
and themes have no purl type of their own, so they use pkg:generic with a clear namespace.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__
from .models import Advisory, Alert, Scan, Site

SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}


def _latest_scan(db: Session, site: Site) -> Scan | None:
    from .wpguard.service import latest_scan

    return latest_scan(db, site)


def composer_components(lock_text: str) -> list[dict]:
    try:
        lock = json.loads(lock_text)
    except ValueError:
        return []
    out = []
    for scope, key in (("required", "packages"), ("optional", "packages-dev")):
        for pkg in lock.get(key) or []:
            name, version = str(pkg.get("name", "")), str(pkg.get("version", "")).removeprefix("v")
            if "/" not in name or not version:
                continue
            vendor, short = name.split("/", 1)
            comp = {"type": "library", "bom-ref": f"composer:{name}", "group": vendor, "name": short,
                    "version": version, "purl": f"pkg:composer/{name}@{version}", "scope": scope}
            if pkg.get("license"):
                comp["licenses"] = [{"license": {"id": lic}} for lic in pkg["license"] if isinstance(lic, str)][:5]
            out.append(comp)
    return out


def _severity(value: str | None) -> str:
    v = (value or "unknown").lower()
    return v if v in SEVERITIES else "unknown"


def build(db: Session, site: Site, *, composer_lock: str | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    scan = _latest_scan(db, site)
    components: list[dict] = []
    vulns: list[dict] = []

    php_version = next((s.detected_version for s in db.scalars(
        select(Scan).where(Scan.site_id == site.id, Scan.detected_version.is_not(None))
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1))), None)
    if php_version:
        components.append({"type": "platform", "bom-ref": "php", "name": "php", "version": php_version,
                           "purl": f"pkg:generic/php@{php_version}",
                           "cpe": f"cpe:2.3:a:php:php:{php_version}:*:*:*:*:*:*:*"})
        for alert in db.scalars(select(Alert).where(Alert.site_id == site.id).order_by(Alert.id)):
            adv = db.get(Advisory, alert.cve_id)
            if adv is None:
                continue  # risk-change alerts are not advisories
            v = {"bom-ref": f"vuln:{adv.id}", "id": adv.id,
                 "source": {"name": "NVD" if adv.id.startswith("CVE-") else adv.source, "url": adv.url or ""},
                 "ratings": [{"severity": _severity(adv.severity), **({"score": adv.score, "method": "CVSSv31"}
                                                                      if adv.score is not None else {})}],
                 "description": (adv.summary or "")[:1000], "affects": [{"ref": "php"}],
                 "properties": [{"name": "patchwarden:kev", "value": str(bool(adv.kev)).lower()}]}
            if adv.fixed_in:
                v["recommendation"] = f"Update PHP to {adv.fixed_in} or newer."
            if adv.epss is not None:
                v["properties"].append({"name": "patchwarden:epss", "value": f"{adv.epss:.4f}"})
            vulns.append(v)

    wp = ((scan.findings or {}).get("wordpress") if scan else None) or {}
    if wp.get("detected"):
        if wp.get("core_version"):
            components.append({"type": "application", "bom-ref": "wordpress", "name": "wordpress",
                               "version": wp["core_version"], "purl": f"pkg:generic/wordpress@{wp['core_version']}"})
        for c in wp.get("components", []):
            kind, slug = c.get("type", "plugin"), c.get("slug")
            version = c.get("version") or c.get("version_hint")
            if not slug:
                continue
            ref = f"wordpress-{kind}:{slug}"
            comp = {"type": "library", "bom-ref": ref, "group": f"wordpress-{kind}", "name": slug,
                    "purl": f"pkg:generic/wordpress-{kind}/{slug}" + (f"@{version}" if version else "")}
            if version:
                comp["version"] = version
            components.append(comp)
            for hit in c.get("vulnerabilities", []):
                vid = hit.get("cve") or hit.get("id")
                vulns.append({"bom-ref": f"vuln:{vid}:{ref}", "id": vid, "source": {"name": "Patchwarden WordPress feed"},
                              "ratings": [{"severity": _severity(hit.get("severity"))}],
                              "description": hit.get("title", ""), "affects": [{"ref": ref}],
                              **({"recommendation": f"Update {slug} to {hit['fixed_in']} or newer."}
                                 if hit.get("fixed_in") else {}),
                              "properties": [{"name": "patchwarden:status", "value": hit.get("status", "affected")}]})

    if composer_lock:
        components += composer_components(composer_lock)

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": now.isoformat(),
            "tools": {"components": [{"type": "application", "name": "Patchwarden", "version": __version__}]},
            "component": {"type": "application", "bom-ref": "site", "name": site.domain},
            "properties": [{"name": "patchwarden:evidence", "value": scan.scanned_url if scan else "none"},
                           {"name": "patchwarden:composer_lock", "value": "read" if composer_lock else "not_read"}],
        },
        "components": components,
        "dependencies": [{"ref": "site", "dependsOn": [c["bom-ref"] for c in components]}],
        "vulnerabilities": vulns,
    }
