"""Entitlements and the billing export. No payment is taken here: this records what is owed, for the
payment system (or an accountant) to collect.

The leak this closes: before Phase D every patch run was free and nothing recorded what was delivered.

- A patch on a site with an active Watchdog or WordPress Guard subscription is included.
- Otherwise it is a one-time patch fee (PRICE_PATCH).
- The decision is made when the change is approved (that is when the work is delivered) and stored on
  the patch job, so a later price change never rewrites history.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from calendar import monthrange

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .models import Migration, Organization, PatchJob, Product, Site, Subscription, SubscriptionStatus

PRICES = {Product.watchdog: "price_watchdog", Product.wp_guard: "price_wp_guard"}


def active_subscription(db: Session, site: Site) -> Subscription | None:
    return db.scalar(select(Subscription).where(Subscription.site_id == site.id,
                                                Subscription.status == SubscriptionStatus.active)
                     .order_by(Subscription.id).limit(1))


def patch_entitlement(db: Session, settings: Settings, site: Site) -> dict:
    sub = active_subscription(db, site)
    if sub is not None:
        return {"item": "included", "covered_by": sub.product.value, "subscription_id": sub.id,
                "amount": 0, "currency": settings.currency}
    return {"item": "patch_fee", "amount": settings.price_patch, "currency": settings.currency}


def _month(year: int, month: int) -> tuple[datetime, datetime]:
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    return start, start + timedelta(days=monthrange(year, month)[1])


def export(db: Session, settings: Settings, year: int, month: int) -> list[dict]:
    """Every billable (and included) item in the month, one row each."""
    start, end = _month(year, month)
    orgs = {o.id: o.name for o in db.scalars(select(Organization))}
    rows: list[dict] = []

    def row(site: Site, item: str, amount: int, ref: str, when: datetime, note: str = "") -> None:
        rows.append({"date": when.date().isoformat(), "site_id": site.id, "domain": site.domain,
                     "team": orgs.get(site.org_id, ""), "item": item, "amount": amount,
                     "currency": settings.currency, "ref": ref, "note": note})

    # Subscriptions that ran during the month (a cancelled one still owes the month it was used in).
    for sub in db.scalars(select(Subscription).where(Subscription.created_at < end).order_by(Subscription.id)):
        if sub.status == SubscriptionStatus.cancelled:
            continue
        site = db.get(Site, sub.site_id)
        row(site, f"subscription:{sub.product.value}", getattr(settings, PRICES[sub.product]),
            f"subscription:{sub.id}", max(sub.created_at, start), sub.status.value)

    for job in db.scalars(select(PatchJob).where(PatchJob.approved_at >= start, PatchJob.approved_at < end)
                          .order_by(PatchJob.id)):
        b = job.billing or {}
        if not b:
            continue
        row(job.site, b["item"], b.get("amount", 0), f"patch_job:{job.id}", job.approved_at,
            f"PHP {job.from_version} -> {job.to_version}" + (f", covered by {b['covered_by']}" if b.get("covered_by") else ""))

    for mig in db.scalars(select(Migration).where(Migration.quote_accepted_at >= start,
                                                  Migration.quote_accepted_at < end).order_by(Migration.id)):
        q = mig.quote or {}
        row(mig.site, "migration_quote", q.get("total", 0), f"migration:{mig.id}", mig.quote_accepted_at,
            f"{q.get('hours', 0)} h at {q.get('rate', 0)}")

    from .virtual_patch.service import billing_rows  # Phase E: virtual patches active in the month
    for site, amount, ref, when, note in billing_rows(db, settings, start, end):
        row(site, "virtual_patch", amount, ref, when, note)

    rows.sort(key=lambda r: (r["date"], r["site_id"], r["ref"]))
    return rows


def to_csv(rows: list[dict]) -> str:
    out = io.StringIO()
    fields = ["date", "site_id", "domain", "team", "item", "amount", "currency", "ref", "note"]
    w = csv.DictWriter(out, fieldnames=fields)
    w.writeheader()
    for r in rows:
        # Spreadsheet formula injection: a cell starting with = + - @ is treated as text.
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()})
    return out.getvalue()
