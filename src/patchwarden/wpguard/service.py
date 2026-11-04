"""WordPress Guard: the plugin connection, the site's safety score, and "Fix it".

- The plugin authenticates with an API key that the dashboard generates and
  shows once. Only its SHA-256 hash is stored.
- The plugin only calls out: it reports the PHP version and inventory, and it
  pulls actions that an owner has already approved. Patchwarden never connects
  into the WordPress site.
- "Fix it" never changes anything. It creates a Phase 2 patch job waiting for
  the owner's approval. Plugin/theme updates are queued for the plugin only
  after that approval.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..errors import AppError
from ..models import (
    AccessMethod,
    AuditLog,
    PatchJob,
    PatchState,
    Platform,
    PluginAction,
    PluginKey,
    Product,
    Risk,
    Scan,
    Site,
    Subscription,
    SubscriptionStatus,
    User,
    WatchCheck,
)
from ..scanner.detect import WpComponent
from ..scanner.versions import assess, parse_version
from ..scanner.wordpress import VulnFeed
from ..watchdog import service as wd

KEY_PREFIX = "pw_"
PANEL_METHODS = (AccessMethod.cpanel, AccessMethod.plesk)
REPORT_FRESH = timedelta(hours=48)
SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 4}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# --- keys -----------------------------------------------------------------------

def generate_key(db: Session, site: Site, user: User) -> str:
    """A new key for the site; any older key stops working. The caller shows it once."""
    for old in db.scalars(select(PluginKey).where(PluginKey.site_id == site.id, PluginKey.revoked_at.is_(None))):
        old.revoked_at = utcnow()
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    db.add(PluginKey(site_id=site.id, key_hash=_hash(key), key_hint=key[:7] + "…"))
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="plugin_key.created", detail={"hint": key[:7] + "…"}))
    db.commit()
    return key


def key_from_request(db: Session, presented: str | None) -> PluginKey:
    if not presented or not presented.startswith(KEY_PREFIX) or len(presented) > 100:
        raise AppError(401, "invalid_plugin_key", "The plugin's API key is missing or not valid. Paste a new key from the dashboard.")
    digest = _hash(presented)
    row = db.scalar(select(PluginKey).where(PluginKey.key_hash == digest))
    if row is None or row.revoked_at is not None or not hmac.compare_digest(row.key_hash, digest):
        raise AppError(401, "invalid_plugin_key", "The plugin's API key is missing or not valid. Paste a new key from the dashboard.")
    return row


def active_key(db: Session, site: Site) -> PluginKey | None:
    return db.scalar(select(PluginKey).where(PluginKey.site_id == site.id, PluginKey.revoked_at.is_(None))
                     .order_by(PluginKey.id.desc()).limit(1))


def disconnect(db: Session, key: PluginKey) -> None:
    key.revoked_at = utcnow()
    db.add(AuditLog(user_id=None, site_id=key.site_id, action="plugin_key.revoked",
                    detail={"hint": key.key_hint, "by": "plugin uninstall"}))
    db.commit()


# --- reports from the plugin ----------------------------------------------------

def _clean(value: Any, limit: int = 200) -> str:
    return str(value or "")[:limit]


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


async def ingest_report(db: Session, key: PluginKey, report: dict, feed: VulnFeed,
                        watchdog: wd.Watchdog | None, now: datetime | None = None) -> Scan:
    now = now or utcnow()
    site = key.site
    if _host(_clean(report.get("site_url"), 500)) != site.domain.removeprefix("www."):
        raise AppError(409, "site_mismatch", "This key belongs to a different site. Paste the key for this site.")
    # The plugin runs on this domain with this site's key: that proves control of the site.
    from ..security.verification import mark_verified
    mark_verified(db, site, "plugin", None)
    php_version = _clean(report.get("php_version"), 64)
    parsed = parse_version(php_version)
    if parsed is None:
        raise AppError(422, "invalid_report", "The plugin's report did not include a PHP version.")

    components, inventory = [], {"plugins": [], "themes": []}
    for kind, items in (("plugin", report.get("plugins")), ("theme", report.get("themes"))):
        for item in (items or [])[:500]:
            if not isinstance(item, dict) or not item.get("slug"):
                continue
            entry = {"slug": _clean(item["slug"], 100).lower(), "name": _clean(item.get("name")),
                     "version": _clean(item.get("version"), 32) or None, "active": bool(item.get("active")),
                     "update_available": _clean(item.get("update_available"), 32) or None}
            if kind == "plugin":
                entry["file"] = _clean(item.get("file"), 200)
            inventory[f"{kind}s"].append(entry)
            comp = WpComponent(kind, entry["slug"], entry["version"])
            components.append({"type": kind, "slug": comp.slug, "name": entry["name"], "version": entry["version"],
                               "active": entry["active"], "update_available": entry["update_available"],
                               "file": entry.get("file"), "vulnerabilities": feed.match(comp)})

    a = assess(parsed)
    findings = {
        "source": "plugin", "version_source": "plugin", "php_detected": True, "summary": a.summary,
        "next_step": a.next_step, "fixed_version": a.fixed_version, "notes": list(a.notes),
        "wordpress": {"detected": True, "core_version": _clean(report.get("wp_version"), 32) or None,
                      "components": components, "feed": feed.name,
                      "issues": sum(len(c["vulnerabilities"]) for c in components)},
    }
    scan = Scan(site_id=site.id, detected_version=str(parsed), risk=a.risk, raw_headers={},
                scanned_url=f"plugin://{site.domain}", findings=findings, created_at=now)
    db.add(scan)
    site.platform = Platform.wordpress
    key.last_seen_at = now
    key.inventory = {"plugin_version": _clean(report.get("plugin_version"), 32), "received_at": now.isoformat(),
                     "php_version": str(parsed), "wp_version": findings["wordpress"]["core_version"], **inventory}
    db.flush()
    if watchdog is not None and wd.is_monitored(db, site):
        last = wd.Watchdog.last_version_check(db, site)
        check = WatchCheck(site_id=site.id, kind="version", scan_id=scan.id, detected_version=scan.detected_version,
                           risk=scan.risk, detail={"version_source": "plugin"}, created_at=now)
        db.add(check)
        db.flush()
        await watchdog._risk_alert(db, site, scan, last, check, now)
        await watchdog._match_site(db, site, scan.detected_version, now)
    db.commit()
    return scan


# --- the owner's view -----------------------------------------------------------

def latest_scan(db: Session, site: Site) -> Scan | None:
    """The best evidence we have: a fresh plugin report beats an outside scan."""
    plugin = db.scalar(select(Scan).where(Scan.site_id == site.id, Scan.scanned_url.like("plugin://%"))
                       .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1))
    if plugin is not None and utcnow() - plugin.created_at < REPORT_FRESH:
        return plugin
    return db.scalar(select(Scan).where(Scan.site_id == site.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1))


def wp_guard_subscription(db: Session, site: Site) -> Subscription | None:
    return db.scalar(select(Subscription).where(Subscription.site_id == site.id,
                                                Subscription.product == Product.wp_guard))


def set_wp_guard(db: Session, site: Site, user: User, enabled: bool) -> None:
    sub = wp_guard_subscription(db, site)
    if enabled:
        if sub is None:
            db.add(Subscription(site_id=site.id, product=Product.wp_guard, status=SubscriptionStatus.active))
        elif sub.status == SubscriptionStatus.cancelled:
            wd.change_status(db, sub, SubscriptionStatus.active, actor_id=user.id)
        site.platform = Platform.wordpress
    elif sub is not None and sub.status != SubscriptionStatus.cancelled:
        wd.change_status(db, sub, SubscriptionStatus.cancelled, actor_id=user.id)
    db.add(AuditLog(user_id=user.id, site_id=site.id, action="wp_guard.on" if enabled else "wp_guard.off", detail={}))
    db.commit()


def fixable_components(scan: Scan | None) -> list[dict]:
    comps = ((scan.findings or {}).get("wordpress") or {}).get("components", []) if scan else []
    return [c for c in comps if any(v["status"] == "affected" for v in c.get("vulnerabilities", []))]


def safety(db: Session, site: Site) -> dict:
    """A 0-100 score and a plain-language fix list. No jargon on purpose."""
    scan = latest_scan(db, site)
    key = active_key(db, site)
    monitored = wd.is_monitored(db, site)
    score, fixes = 100, []
    risk = scan.risk if scan else Risk.unknown
    version = scan.detected_version if scan else None
    if risk == Risk.patch_now:
        score -= 40
        fixes.append({"what": f"Your PHP ({version}) has the serious flaw that lets attackers take over websites.",
                      "fix": f"Update PHP to {scan.findings.get('fixed_version')}. Press Fix it: you approve before anything changes.",
                      "fixable": True})
    elif risk == Risk.must_migrate:
        score -= 50
        fixes.append({"what": f"Your PHP ({version}) is too old to get security fixes.",
                      "fix": "Your site needs to move to a newer PHP. Press Fix it to plan the move.", "fixable": True})
    elif risk == Risk.unknown:
        score -= 15
        fixes.append({"what": "We cannot see which PHP version your site runs.",
                      "fix": "Install the Patchwarden plugin and paste your key, so we can check from the inside.",
                      "fixable": False})
    comps = ((scan.findings or {}).get("wordpress") or {}).get("components", []) if scan else []
    for c in comps:
        for v in c.get("vulnerabilities", []):
            name = c.get("name") or c["slug"]
            if v["status"] == "affected":
                score -= SEVERITY_POINTS.get(v["severity"], 8)
                fixes.append({"what": f"The {c['type']} \"{name}\" has a known security problem.",
                              "fix": f"Update it to {v['fixed_in'] or 'the latest version'} or newer. Fix it can do this through the plugin, after you approve.",
                              "fixable": True})
            else:
                score -= 3
                fixes.append({"what": f"The {c['type']} \"{name}\" may have a known security problem.",
                              "fix": "Install the Patchwarden plugin so we can see its version.", "fixable": False})
    if not monitored:
        score -= 10
        fixes.append({"what": "Nobody is watching this site for new risks.",
                      "fix": "Turn on WordPress Guard: we check every day and tell you the day a new risk appears.",
                      "fixable": False})
    if key is None or key.last_seen_at is None:
        fixes.append({"what": "The Patchwarden plugin is not connected yet.",
                      "fix": "Download the plugin, upload it in WordPress (Plugins > Add New > Upload), and paste your key.",
                      "fixable": False})
    score = max(0, min(100, score))
    return {
        "score": score,
        "grade": "Good" if score >= 85 else "Needs attention" if score >= 60 else "At risk",
        "php_version": version, "risk": risk.value,
        "checked_at": scan.created_at.isoformat() if scan else None,
        "evidence": "plugin" if scan and scan.scanned_url.startswith("plugin://") else ("outside scan" if scan else None),
        "fixes": fixes,
        "fixable": any(i["fixable"] for i in fixes),
        "monitored": monitored,
        "plugin": ({"connected": key.last_seen_at is not None, "hint": key.key_hint,
                    "last_seen_at": key.last_seen_at.isoformat() if key.last_seen_at else None,
                    "inventory": key.inventory} if key else {"connected": False}),
    }


# --- Fix it ---------------------------------------------------------------------

async def fix_it(db: Session, site: Site, user: User, *, vault, world) -> dict:
    """Route into the approval flow. Returns where to send the owner; never changes the site."""
    from ..migration import service as migrations
    from ..patch import service as patches

    scan = latest_scan(db, site)
    risk = scan.risk if scan else Risk.unknown
    if risk == Risk.must_migrate:
        if site.access_method not in PANEL_METHODS:
            raise AppError(409, "panel_token_needed",
                           "Moving PHP needs access to your hosting panel. Add your cPanel or Plesk API token first.")
        mig = await migrations.create_migration(db, site=site, user=user, to_version=None, vault=vault, world=world)
        return {"kind": "migration", "id": mig.id, "url": f"/dashboard/migrations/{mig.id}"}

    components = fixable_components(scan)
    key = active_key(db, site)
    updates = [{"type": c["type"], "slug": c["slug"], "file": c.get("file"), "from_version": c.get("version"),
                "fixed_in": next(v["fixed_in"] for v in c["vulnerabilities"] if v["status"] == "affected")}
               for c in components] if key is not None and key.last_seen_at is not None else []

    if risk == Risk.patch_now:
        if site.access_method not in PANEL_METHODS:
            raise AppError(409, "panel_token_needed",
                           "Updating PHP needs access to your hosting panel (the WordPress plugin cannot change PHP). "
                           "Add your cPanel or Plesk API token first.")
        job = await patches.create_dry_run(db, site=site, user=user, to_version=None, vault=vault, world=world,
                                           state=PatchState.awaiting_approval, components=updates, origin="fix_it")
    elif updates:
        job = PatchJob(site_id=site.id, from_version=scan.detected_version or "", to_version=scan.detected_version or "",
                       state=PatchState.awaiting_approval, requested_by=user.id,
                       report={"origin": "fix_it", "dry_run_at": utcnow().isoformat(), "steps": [],
                               "plan": {"access": "Patchwarden plugin", "from_version": scan.detected_version,
                                        "to_version": scan.detected_version, "checks": [], "components": updates,
                                        "steps": [f"Ask the Patchwarden plugin to update the {u['type']} {u['slug']} "
                                                  f"to {u['fixed_in']} or newer." for u in updates],
                                        "changes_made": "None yet. Nothing changes until you approve."}})
        db.add(job)
        db.flush()
        db.add(AuditLog(user_id=user.id, site_id=site.id, action="patch.dry_run",
                        detail={"patch_job_id": job.id, "origin": "fix_it", "components": [u["slug"] for u in updates]}))
        db.commit()
    elif components:
        raise AppError(409, "plugin_needed", "Connect the Patchwarden plugin first, so it can update the affected plugins for you.")
    else:
        raise AppError(409, "nothing_to_fix", "There is nothing to fix right now. We will tell you if that changes.")
    return {"kind": "patch", "id": job.id, "url": f"/dashboard/patches/{job.id}"}


def queue_component_updates(db: Session, job: PatchJob) -> list[PluginAction]:
    """After approval: hand the plan's plugin/theme updates to the plugin."""
    actions = []
    for u in (job.report.get("plan") or {}).get("components", []):
        action = PluginAction(site_id=job.site_id, patch_job_id=job.id, kind="update_component", payload=u,
                              approved_by=job.approved_by)
        db.add(action)
        actions.append(action)
    db.flush()
    if actions:
        db.add(AuditLog(user_id=job.approved_by, site_id=job.site_id, action="plugin_actions.queued",
                        detail={"patch_job_id": job.id, "actions": [a.id for a in actions]}))
    return actions


def pull_actions(db: Session, key: PluginKey) -> list[dict]:
    actions = db.scalars(select(PluginAction).where(PluginAction.site_id == key.site_id,
                                                    PluginAction.state == "queued").order_by(PluginAction.id)).all()
    out = []
    for a in actions:
        a.state, a.sent_at = "sent", utcnow()
        out.append({"id": a.id, "kind": a.kind, "payload": a.payload})
    key.last_seen_at = utcnow()
    db.commit()
    return out


def action_result(db: Session, key: PluginKey, action_id: int, ok: bool, detail: str, version: str | None) -> PluginAction:
    a = db.get(PluginAction, action_id)
    if a is None or a.site_id != key.site_id or a.state not in {"sent", "queued"}:
        raise AppError(404, "action_not_found", "That action is not waiting for a result.")
    a.state, a.finished_at = ("done" if ok else "failed"), utcnow()
    a.result = {"ok": ok, "detail": _clean(detail, 500), "version": _clean(version, 32) or None}
    db.add(AuditLog(user_id=None, site_id=a.site_id, action=f"plugin_action.{a.state}",
                    detail={"action_id": a.id, "kind": a.kind, "slug": a.payload.get("slug"), **a.result}))
    if a.patch_job_id:
        _settle_job(db, db.get(PatchJob, a.patch_job_id))
    db.commit()
    return a


def _settle_job(db: Session, job: PatchJob) -> None:
    actions = db.scalars(select(PluginAction).where(PluginAction.patch_job_id == job.id)).all()
    report = dict(job.report)
    report["components"] = [{"id": a.id, "slug": a.payload.get("slug"), "type": a.payload.get("type"),
                             "state": a.state, "result": a.result} for a in actions]
    if all(a.state in {"done", "failed"} for a in actions) and job.state == PatchState.running:
        failed = [a.payload.get("slug") for a in actions if a.state == "failed"]
        job.state = PatchState.failed if failed else PatchState.succeeded
        report.update(outcome=job.state.value, finished_at=utcnow().isoformat(),
                      message=("The plugin could not update: " + ", ".join(failed) + ". Update them in WordPress."
                               if failed else "The plugin updated: " + ", ".join(a.payload.get("slug") for a in actions) + "."))
        db.add(AuditLog(user_id=None, site_id=job.site_id, action=f"patch.{job.state.value}",
                        detail={"patch_job_id": job.id, "message": report["message"]}))
    job.report = report
