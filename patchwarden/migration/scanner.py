"""Breakage scan, auto-fixes and the migration plan."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ..scanner.versions import parse_version
from .lexer import lex
from .rules import RULES, RULES_BY_ID, Rule

CODE_EXTENSIONS = (".php", ".inc", ".phtml", ".module")
# Never edited by an auto-fix and never copied from staging to production:
# each environment keeps its own database and secrets.
CONFIG_FILES = {"wp-config.php", ".env", "config.php", "configuration.php", "settings.php", "local.xml"}
_WP_CORE = re.compile(r"^(?:wp-admin/|wp-includes/|wp-[\w-]+\.php$|index\.php$|xmlrpc\.php$)")
_DEFINED = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(", re.IGNORECASE)


def is_code(path: str) -> bool:
    return path.lower().endswith(CODE_EXTENSIONS)


def is_config(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower() in CONFIG_FILES


def looks_like_wordpress(files) -> bool:
    return any(p.startswith(("wp-includes/", "wp-content/")) or p == "wp-config.php" for p in files)


def is_wordpress_core(path: str, wordpress: bool = True) -> bool:
    return wordpress and bool(_WP_CORE.match(path)) and not is_config(path)


def component(path: str) -> str:
    parts = path.split("/")
    if len(parts) > 2 and parts[0] == "wp-content" and parts[1] in {"plugins", "themes", "mu-plugins"}:
        kind = {"plugins": "plugin", "themes": "theme", "mu-plugins": "must-use plugin"}[parts[1]]
        return f"{kind} {parts[2]}"
    return "site code"


def line_of(v: str) -> tuple[int, int]:
    p = parse_version(v)
    if p is None:
        raise ValueError(f"not a PHP version: {v}")
    return p.branch


def rules_between(from_version: str, to_version: str) -> list[Rule]:
    lo, hi = line_of(from_version), line_of(to_version)
    return [r for r in RULES if lo < r.since <= hi]


def scan_files(files: dict[str, str], from_version: str, to_version: str) -> dict:
    """Breakage list with file + line references for a move from one PHP version to another."""
    rules = rules_between(from_version, to_version)
    wp = looks_like_wordpress(files)
    code = {p: t for p, t in files.items() if is_code(p) and not is_wordpress_core(p, wp)}
    sources = {p: lex(p, t) for p, t in sorted(code.items())}
    defined = {m.group(1).lower() for s in sources.values() for m in _DEFINED.finditer(s.masked)}

    hits: list[dict] = []
    for path, src in sources.items():
        for rule in rules:
            for h in rule.find(src):
                if getattr(rule.find, "is_call", False) and h.name in defined:
                    continue  # the site ships its own polyfill for this function
                line, col = src.position(h.start)
                hits.append({
                    "rule": rule.id, "severity": rule.severity, "kind": rule.kind, "since": rule.since_label,
                    "title": rule.title, "fix": rule.fix, "file": path, "line": line, "column": col,
                    "component": component(path), "found": h.name, "code": src.snippet(line),
                    "auto_fix": h.edit is not None and not is_config(path),
                })
    hits.sort(key=lambda h: (h["severity"] != "error", h["file"], h["line"], h["column"]))
    return {
        "from_version": from_version,
        "to_version": to_version,
        "files_scanned": len(sources),
        "skipped_wordpress_core": sum(1 for p in files if is_code(p) and is_wordpress_core(p, wp)),
        "rules_checked": [r.id for r in rules],
        "hits": hits,
        "errors": sum(1 for h in hits if h["severity"] == "error"),
        "warnings": sum(1 for h in hits if h["severity"] == "warning"),
    }


def apply_auto_fixes(files: dict[str, str], from_version: str, to_version: str) -> tuple[dict[str, str], list[dict]]:
    """Exact mechanical fixes only. Returns the changed files and what was changed where."""
    rules = rules_between(from_version, to_version)
    wp = looks_like_wordpress(files)
    changed: dict[str, str] = {}
    applied: list[dict] = []
    for path, text in sorted(files.items()):
        if not is_code(path) or is_config(path) or is_wordpress_core(path, wp):
            continue
        src = lex(path, text)
        edits = []
        for rule in rules:
            for h in rule.find(src):
                if h.edit is not None:
                    edits.append((h.edit, rule, src.position(h.start)[0]))
        if not edits:
            continue
        new, last_start = text, len(text) + 1
        for (start, end, repl), rule, line in sorted(edits, key=lambda e: e[0][0], reverse=True):
            if end > last_start:
                continue  # overlapping edits: keep the later one, the next run picks up the rest
            new = new[:start] + repl + new[end:]
            last_start = start
            applied.append({"file": path, "line": line, "rule": rule.id, "title": rule.title})
        if new != text:
            changed[path] = new
    applied.sort(key=lambda a: (a["file"], a["line"]))
    return changed, applied


def effort(breakage: dict) -> str:
    manual_errors = sum(1 for h in breakage["hits"] if h["severity"] == "error" and not h["auto_fix"])
    manual_warnings = sum(1 for h in breakage["hits"] if h["severity"] == "warning" and not h["auto_fix"])
    files = len({h["file"] for h in breakage["hits"] if not h["auto_fix"]})
    if manual_errors <= 3 and manual_warnings <= 10 and files <= 3:
        return "small"
    if manual_errors <= 15 and files <= 15:
        return "medium"
    return "large"


def build_plan(breakage: dict) -> dict:
    """Ordered fix list: what breaks first, then deprecations; mechanical fixes are marked as automatic."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for h in breakage["hits"]:
        groups[h["rule"]].append(h)
    order = sorted(groups, key=lambda rid: (RULES_BY_ID[rid].severity != "error", RULES_BY_ID[rid].since, rid))
    fixes = []
    for n, rid in enumerate(order, start=1):
        rule, hits = RULES_BY_ID[rid], groups[rid]
        auto = all(h["auto_fix"] for h in hits)
        fixes.append({
            "step": n, "rule": rid, "severity": rule.severity, "since": rule.since_label, "title": rule.title,
            "fix": rule.fix, "automatic": auto, "count": len(hits),
            "where": [f"{h['file']}:{h['line']}" for h in hits],
            "who": "Patchwarden applies this on staging" if auto else "A developer fixes this on staging",
        })
    level = effort(breakage)
    return {
        "target_version": breakage["to_version"],
        "from_version": breakage["from_version"],
        "effort": level,
        "effort_note": {"small": "A few hours of developer time.", "medium": "One to a few days of developer time.",
                        "large": "More than a few days; plan it as a project."}[level],
        "fixes": fixes,
        "steps": [
            "Copy the site to a staging site. Production is not touched.",
            "Apply the automatic fixes on staging; a developer makes the manual fixes on staging.",
            f"Switch staging to PHP {breakage['to_version']} and run the site checks there.",
            "The owner or IT signs off in the dashboard after checking staging.",
            "Promote: back up production, copy the tested code (not the database or config) to production, "
            f"switch production to PHP {breakage['to_version']}, re-check, and roll back automatically if anything fails.",
        ],
    }


def code_hash(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in files if is_code(p) and not is_config(p)):
        h.update(path.encode() + b"\0" + files[path].encode() + b"\0")
    return h.hexdigest()
