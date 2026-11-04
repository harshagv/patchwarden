"""Tamper-evident audit log: every entry carries the SHA-256 of the entry before it.

entry_hash = SHA-256(prev_hash + "\\n" + canonical JSON of {user_id, site_id, action, detail, created_at})

The hash is computed as part of every flush (a SQLAlchemy before_flush hook), so no code path can
write an entry without it. Changing, deleting or reordering any entry breaks every hash after it,
and verify() reports the first broken entry. On PostgreSQL a transaction-level advisory lock
serialises writers, so two processes cannot fork the chain.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import event, inspect, select, text
from sqlalchemy.orm import Session

from ..models import AuditLog

GENESIS = "0" * 64
_ADVISORY_LOCK_ID = 7_140_331  # any constant; identifies the audit-chain lock


def canonical(entry: AuditLog) -> str:
    created = entry.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return json.dumps({
        "user_id": entry.user_id, "site_id": entry.site_id, "action": entry.action,
        "detail": entry.detail or {}, "created_at": created.astimezone(timezone.utc).isoformat(),
    }, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, entry: AuditLog) -> str:
    return hashlib.sha256((prev_hash + "\n" + canonical(entry)).encode()).hexdigest()


def _insert_order(obj) -> int:
    return getattr(inspect(obj), "insert_order", 0) or 0


@event.listens_for(Session, "before_flush")
def _chain_new_entries(session: Session, flush_context, instances) -> None:
    new = sorted((o for o in session.new if isinstance(o, AuditLog)), key=_insert_order)
    if not new:
        return
    with session.no_autoflush:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _ADVISORY_LOCK_ID})
        prev = session.execute(select(AuditLog.entry_hash).where(AuditLog.entry_hash.is_not(None))
                               .order_by(AuditLog.id.desc()).limit(1)).scalar() or GENESIS
    for entry in new:
        if entry.created_at is None:
            entry.created_at = datetime.now(timezone.utc)
        if entry.detail is None:
            entry.detail = {}
        entry.prev_hash = prev
        entry.entry_hash = compute_hash(prev, entry)
        prev = entry.entry_hash


def verify(db: Session) -> dict:
    """Walk the whole chain. Entries written before the chain existed are allowed only at the start."""
    prev, checked, legacy, first_bad, seen_chain = GENESIS, 0, 0, None, False
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.id)).yield_per(500):
        if entry.entry_hash is None and not seen_chain:
            legacy += 1
            continue
        seen_chain = True
        checked += 1
        if entry.prev_hash != prev or entry.entry_hash != compute_hash(prev, entry):
            first_bad = entry.id
            break
        prev = entry.entry_hash
    return {"ok": first_bad is None, "checked": checked, "unchained_legacy_entries": legacy,
            "first_broken_entry": first_bad, "head": prev if first_bad is None else None}


def export_lines(db: Session) -> Iterator[str]:
    """JSON lines, one per entry, for copying to write-once (WORM) storage."""
    for e in db.scalars(select(AuditLog).order_by(AuditLog.id)).yield_per(500):
        yield json.dumps({"id": e.id, "user_id": e.user_id, "site_id": e.site_id, "action": e.action,
                          "detail": e.detail, "created_at": e.created_at.isoformat(),
                          "prev_hash": e.prev_hash, "entry_hash": e.entry_hash}, sort_keys=True)
