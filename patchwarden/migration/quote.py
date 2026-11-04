"""Instant fixed-price quote for a migration, from the breakage scan: hours, rate, statement of work.

The estimate is deliberately simple and explainable: every line says where its hours come from, so a
customer (or the agency selling it) can check it. Mechanical fixes cost almost nothing because
Patchwarden applies them; the hours are in the manual fixes and the staging/promotion work.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Migration, Organization

BASE_HOURS = 4.0  # staging copy, test run, sign-off walkthrough, promotion
PER_MANUAL_ERROR = 1.5
PER_MANUAL_WARNING = 0.5
PER_FILE = 0.5  # reading and re-testing each file a developer has to touch
PER_AUTO_FIX = 0.1  # review of a mechanical fix
VALID_DAYS = 30


def _half(hours: float) -> float:
    return math.ceil(hours * 2) / 2


def build(db: Session, settings: Settings, mig: Migration, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    hits = (mig.breakage or {}).get("hits", [])
    manual = [h for h in hits if not h["auto_fix"]]
    errors = sum(1 for h in manual if h["severity"] == "error")
    warnings = len(manual) - errors
    files = len({h["file"] for h in manual})
    auto = len(hits) - len(manual)
    org = db.get(Organization, mig.site.org_id) if mig.site.org_id else None
    rate = (org.hourly_rate if org and org.hourly_rate else settings.migration_hourly_rate)
    lines = [
        {"what": "Staging copy, test run on the new PHP, sign-off walkthrough and promotion", "hours": BASE_HOURS},
        {"what": f"{errors} manual fix(es) for things that stop working", "hours": errors * PER_MANUAL_ERROR},
        {"what": f"{warnings} manual fix(es) for deprecations", "hours": warnings * PER_MANUAL_WARNING},
        {"what": f"Re-testing {files} file(s) changed by hand", "hours": files * PER_FILE},
        {"what": f"Review of {auto} automatic fix(es)", "hours": round(auto * PER_AUTO_FIX, 2)},
    ]
    tools = (mig.breakage or {}).get("tools", {}).get("tools", {})  # Rector / PHPStan / php -l, when run
    lint, stan = len(tools.get("lint", {}).get("errors", [])), len(tools.get("phpstan", {}).get("errors", []))
    rector = len(tools.get("rector", {}).get("changes", []))
    lines += [
        {"what": f"{lint} file(s) that do not parse", "hours": lint * PER_MANUAL_ERROR},
        {"what": f"{stan} error(s) PHPStan reports for the new version", "hours": stan * PER_MANUAL_WARNING},
        {"what": f"Review of Rector's changes to {rector} file(s)", "hours": rector * PER_FILE},
    ]
    hours = _half(sum(line["hours"] for line in lines))
    total = math.ceil(hours * rate)
    plan = mig.plan or {}
    return {
        "migration_id": mig.id, "site": mig.site.domain,
        "from_version": mig.from_version, "to_version": mig.to_version,
        "hours": hours, "rate": rate, "currency": settings.currency, "total": total,
        "lines": [line for line in lines if line["hours"]],
        "effort": plan.get("effort"),
        "valid_until": (now + timedelta(days=VALID_DAYS)).isoformat(),
        "created_at": now.isoformat(),
        "statement_of_work": statement_of_work(mig, hours, rate, total, settings.currency),
    }


def statement_of_work(mig: Migration, hours: float, rate: int, total: int, currency: str) -> str:
    plan = mig.plan or {}
    fixes = plan.get("fixes", [])
    scope = "\n".join(f"  {f['step']}. {f['title']} ({f['count']} place(s); "
                      f"{'automatic' if f['automatic'] else 'by a developer'})" for f in fixes) or "  (no code changes found)"
    return (
        f"Statement of work: move {mig.site.domain} from PHP {mig.from_version} to PHP {mig.to_version}\n\n"
        f"Scope\n{scope}\n\n"
        "How it is done\n" + "\n".join(f"  - {s}" for s in plan.get("steps", [])) + "\n\n"
        "Not included\n"
        "  - Changes to features, design or content.\n"
        "  - Code that was not part of the scanned files (for example, code added after the scan).\n"
        "  - Third-party services the site calls.\n\n"
        "Done when\n"
        f"  - The staging site passes its checks on PHP {mig.to_version}, the owner or IT signs off, and the\n"
        "    production switch passes the same checks (or is rolled back automatically).\n\n"
        f"Price\n  {hours} hours at {rate} {currency}/hour = {total} {currency}, fixed. "
        f"Valid for {VALID_DAYS} days.\n"
    )
