"""PHP release facts for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and the risk score."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from ..models import Risk

PHP2SHELL_CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXES_RELEASED = date(2026, 10, 21)

# First fixed release per supported branch.
FIXED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

# End of security support. 8.1 and older have no official patch.
SECURITY_EOL: dict[tuple[int, int], date] = {
    (8, 2): date(2026, 12, 31),
}
LAST_DEAD_BRANCH = (8, 1)

# A branch this close to its end of security support is scored must_migrate
# even when it carries the PHP2Shell fix.
MIGRATE_WINDOW_DAYS = 90

_VERSION_RE = re.compile(r"(?<![\d.])(\d+)\.(\d+)(?:\.(\d+))?([^\s,;()]*)")


@dataclass(frozen=True)
class PhpVersion:
    major: int
    minor: int
    patch: int | None  # None when only "8.4" is exposed
    suffix: str = ""  # distro build tag, e.g. "-1ubuntu2.14"

    @property
    def branch(self) -> tuple[int, int]:
        return (self.major, self.minor)

    def __str__(self) -> str:
        core = f"{self.major}.{self.minor}" + (f".{self.patch}" if self.patch is not None else "")
        return core + self.suffix


def parse_version(text: str) -> PhpVersion | None:
    m = _VERSION_RE.search(text)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else None
    return PhpVersion(major, minor, patch, m.group(4) or "")


def fmt(v: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in v)


@dataclass(frozen=True)
class Assessment:
    risk: Risk
    summary: str  # one plain-language line: "Your risk"
    next_step: str  # "What to do next"
    fixed_version: str | None = None
    notes: tuple[str, ...] = ()


def assess(version: PhpVersion | None, *, today: date | None = None) -> Assessment:
    today = today or date.today()
    if version is None:
        return Assessment(
            Risk.unknown,
            "We could not see which PHP version this site runs. That is not proof it is safe.",
            "Install the Patchwarden plugin or server agent so we can read the version from the inside.",
        )

    branch = version.branch
    if branch <= LAST_DEAD_BRANCH:
        return Assessment(
            Risk.must_migrate,
            f"PHP {fmt(branch)} no longer gets official security fixes, so there is no official patch for this flaw.",
            "Move the site to a supported PHP version (8.3 or newer). Our Migration agent can plan it.",
        )

    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        return Assessment(
            Risk.unknown,
            f"PHP {version} is not in our release table, so we cannot score it yet.",
            "Install the Patchwarden plugin or server agent for an inside check.",
        )

    if version.patch is None:
        return Assessment(
            Risk.unknown,
            f"The site shows PHP {fmt(branch)} but hides the exact release, so we cannot tell if it is patched.",
            "Install the Patchwarden plugin or server agent for an exact version check.",
            fixed_version=fmt(fixed),
        )

    notes: list[str] = []
    if version.suffix.startswith(("-", "+", "~")):
        notes.append(
            "This looks like a Linux distribution build. Your host may have backported the fix "
            "without changing the version number; an inside check can confirm."
        )
    patched = (version.major, version.minor, version.patch) >= fixed

    eol = SECURITY_EOL.get(branch)
    if eol is not None and (eol - today).days <= MIGRATE_WINDOW_DAYS:
        state = "carries the fix" if patched else "is not patched"
        when = "ended" if today > eol else "ends"
        return Assessment(
            Risk.must_migrate,
            f"PHP {version} {state}, and security fixes for PHP {fmt(branch)} {when} on {eol:%B} {eol.day}, {eol.year}.",
            "Plan a move to PHP 8.3 or newer before that date. Our Migration agent can plan it."
            + ("" if patched else f" Until then, update to {fmt(fixed)} now."),
            fixed_version=fmt(fixed),
            notes=tuple(notes),
        )

    if patched:
        return Assessment(
            Risk.safe,
            f"PHP {version} includes the fix for this flaw.",
            "Nothing to do today. Keep watching for the next release.",
            fixed_version=fmt(fixed),
            notes=tuple(notes),
        )
    return Assessment(
        Risk.patch_now,
        f"PHP {version} has the flaw that lets attackers take over a site without logging in.",
        f"Update PHP to {fmt(fixed)} or newer as soon as possible. Our Patch agent can do it with your approval.",
        fixed_version=fmt(fixed),
        notes=tuple(notes),
    )
