"""Real PHP tooling for the migration scan, run in a sandbox: Rector, PHPStan and `php -l`.

The built-in breakage scan (scanner.py) is fast, explainable and always available. When a sandbox is
set up (MIGRATION_TOOLS), these tools add what a rule list cannot:
- Rector (dry run): the upgrade changes it would make for the target PHP version, as diffs;
- PHPStan (with phpVersion set to the target): type and call errors the new version would raise;
- php -l: files that do not even parse.

The site's code is untrusted input, so the tools never run next to the app:
- DockerSandbox (production): `docker run` with no network, a read-only root, the code mounted
  read-only, all capabilities dropped, no-new-privileges, an unprivileged user, and memory, CPU, PID and
  time limits. Commands are argument lists, never a shell string.
- LocalSandbox (development only, refused when APP_ENV=production): runs locally installed binaries in
  a temporary folder with a clean environment, CPU and file-size limits and a timeout. It has no
  network isolation, which is why it is refused in production.

The image (docker/php-tools/Dockerfile) holds PHP, Composer, Rector and PHPStan. Build it yourself;
nothing is pulled at run time.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from ..config import ConfigError, Settings

MAX_FILES = 5000
MAX_BYTES = 50 * 1024 * 1024


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class Sandbox(Protocol):
    name: str

    def available(self, tool: str) -> bool: ...

    async def run(self, tool: str, args: list[str], files: dict[str, str]) -> RunResult: ...


def safe_relpath(path: str) -> str:
    """A code path from the host or an upload, as a safe relative path inside the work folder."""
    p = PurePosixPath(path.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts or any(part.startswith("-") for part in p.parts):
        raise ValueError(f"unsafe path {path!r}")
    return str(p)


def write_tree(root: Path, files: dict[str, str]) -> None:
    if len(files) > MAX_FILES or sum(len(t) for t in files.values()) > MAX_BYTES:
        raise ValueError("too much code for one sandbox run")
    for rel, text in files.items():
        target = root / safe_relpath(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


async def _exec(cmd: list[str], *, cwd: str, timeout: int, env: dict[str, str] | None = None,
                preexec=None) -> RunResult:
    proc = await asyncio.create_subprocess_exec(*cmd, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE, preexec_fn=preexec)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return RunResult(-1, "", "timed out", timed_out=True)
    cap = 5 * 1024 * 1024
    return RunResult(proc.returncode or 0, out[:cap].decode("utf-8", "replace"), err[:cap].decode("utf-8", "replace"))


TOOL_COMMANDS = {
    "rector": ["/tools/vendor/bin/rector"],
    "phpstan": ["/tools/vendor/bin/phpstan"],
    "php": ["php"],
}


class DockerSandbox:
    name = "docker"

    def __init__(self, settings: Settings, docker: str = "docker"):
        self.image, self.timeout, self.docker = settings.sandbox_image, settings.sandbox_timeout, docker

    def available(self, tool: str) -> bool:
        return shutil.which(self.docker) is not None

    def command(self, workdir: str, tool: str, args: list[str]) -> list[str]:
        return [self.docker, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "65534:65534", "--pids-limit", "256",
                "--memory", "1g", "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
                "--env", "HOME=/tmp", "-v", f"{workdir}:/app:ro", "-w", "/app", self.image,
                *TOOL_COMMANDS[tool], *args]

    async def run(self, tool: str, args: list[str], files: dict[str, str]) -> RunResult:
        with tempfile.TemporaryDirectory(prefix="pw-sbx-") as tmp:
            write_tree(Path(tmp), files)
            return await _exec(self.command(tmp, tool, args), cwd=tmp, timeout=self.timeout)


class LocalSandbox:
    """Development only: locally installed tools, no network isolation."""

    name = "local"

    def __init__(self, settings: Settings):
        if settings.is_production:
            raise ConfigError("MIGRATION_TOOLS=local is for development only. Use docker in production.")
        self.timeout = settings.sandbox_timeout
        self.bins = {"rector": shutil.which("rector"), "phpstan": shutil.which("phpstan"), "php": shutil.which("php")}

    def available(self, tool: str) -> bool:
        return self.bins.get(tool) is not None

    @staticmethod
    def _limits() -> None:  # runs in the child before exec
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))

    async def run(self, tool: str, args: list[str], files: dict[str, str]) -> RunResult:
        if not self.available(tool):
            return RunResult(127, "", f"{tool} is not installed")
        with tempfile.TemporaryDirectory(prefix="pw-sbx-") as tmp:
            # The tools' own config files name /app (the container path); here the code is in tmp.
            write_tree(Path(tmp), {p: t.replace("/app", tmp) if p.startswith(".patchwarden-") else t
                                   for p, t in files.items()})
            args = [a.replace("/app", tmp) for a in args]
            env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": tmp, "LANG": "C.UTF-8"}
            r = await _exec([self.bins[tool], *args], cwd=tmp, timeout=self.timeout, env=env, preexec=self._limits)
            for real in (str(Path(tmp).resolve()), tmp):  # report paths as the container would: /app/...
                r.stdout, r.stderr = r.stdout.replace(real, "/app"), r.stderr.replace(real, "/app")
            return r


def make_sandbox(settings: Settings) -> Sandbox | None:
    if settings.migration_tools == "docker":
        return DockerSandbox(settings)
    if settings.migration_tools == "local":
        return LocalSandbox(settings)
    return None


# --- the tools ---------------------------------------------------------------------------

def _php_id(version: str) -> tuple[int, int]:
    m = re.match(r"^(\d+)\.(\d+)", version or "")
    if not m:
        raise ValueError("bad version")
    return int(m.group(1)), int(m.group(2))


def rector_config(to_version: str) -> str:
    major, minor = _php_id(to_version)
    return ("<?php\nuse Rector\\Config\\RectorConfig;\n"
            "return RectorConfig::configure()\n"
            "    ->withPaths([__DIR__])\n"
            "    ->withSkip([__DIR__ . '/vendor', __DIR__ . '/wp-admin', __DIR__ . '/wp-includes'])\n"
            f"    ->withPhpSets(php{major}{minor}: true);\n")


def phpstan_config(to_version: str) -> str:
    major, minor = _php_id(to_version)
    return ("parameters:\n"
            "    level: 0\n"
            f"    phpVersion: {major * 10000 + minor * 100}\n"
            "    paths:\n        - /app\n"
            "    excludePaths:\n        - /app/vendor\n        - /app/wp-admin\n        - /app/wp-includes\n"
            "    tmpDir: /tmp/phpstan\n")


def parse_rector(stdout: str, root: str = "/app") -> dict:
    data = json.loads(stdout[stdout.find("{"):])
    changes = [{"file": _rel(d.get("file", ""), root), "rectors": [r.rsplit("\\", 1)[-1] for r in d.get("applied_rectors", [])],
                "diff": d.get("diff", "")[:20000]} for d in data.get("file_diffs", [])]
    return {"changed_files": data.get("totals", {}).get("changed_files", len(changes)), "changes": changes,
            "errors": [e.get("message", str(e)) if isinstance(e, dict) else str(e) for e in data.get("errors", [])][:200]}


def parse_phpstan(stdout: str, root: str = "/app") -> dict:
    data = json.loads(stdout[stdout.find("{"):])
    errors = []
    for path, info in (data.get("files") or {}).items():
        for m in info.get("messages", []):
            errors.append({"file": _rel(path, root), "line": m.get("line"), "message": m.get("message", ""),
                           "identifier": m.get("identifier")})
    errors.sort(key=lambda e: (e["file"], e["line"] or 0))
    return {"file_errors": data.get("totals", {}).get("file_errors", len(errors)), "errors": errors[:1000],
            "general": [str(e) for e in data.get("errors", [])][:50]}


_LINT = re.compile(r"(?:PHP )?(?:Parse|Fatal) error:\s*(?P<msg>.+?) in (?P<file>\S+) on line (?P<line>\d+)")


def parse_lint(output: str, root: str = "/app") -> list[dict]:
    seen, out = set(), []
    for m in _LINT.finditer(output):  # php prints each error on stdout and on stderr: keep one
        e = (_rel(m.group("file"), root), int(m.group("line")), m.group("msg").strip())
        if e not in seen:
            seen.add(e)
            out.append({"file": e[0], "line": e[1], "message": e[2]})
    return out


def _rel(path: str, root: str) -> str:
    for prefix in (root.rstrip("/") + "/", "/app/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path.lstrip("./")


async def tool_scan(sandbox: Sandbox, files: dict[str, str], to_version: str) -> dict:
    """Run every available tool. A tool that is missing or fails is reported, never fatal."""
    code = {p: t for p, t in files.items() if p.endswith((".php", ".inc", ".phtml"))}
    out: dict = {"sandbox": sandbox.name, "target_version": to_version, "tools": {}}

    def failed(r: RunResult, what: str) -> dict:
        return {"status": "timed_out" if r.timed_out else "failed", "message": f"{what} did not finish",
                "detail": (r.stderr or r.stdout)[-500:]}

    if sandbox.available("php"):
        lint_errors, paths = [], sorted(code)[:2000]
        for i in range(0, len(paths), 200):  # php -l takes many files at once (PHP 8.3+)
            chunk = paths[i:i + 200]
            r = await sandbox.run("php", ["-l", *[f"/app/{safe_relpath(p)}" for p in chunk]], {p: code[p] for p in chunk})
            if r.timed_out:
                lint_errors.append({"file": chunk[0], "line": None, "message": "php -l timed out"})
            lint_errors += parse_lint(r.stdout + r.stderr)
        out["tools"]["lint"] = {"status": "ok", "errors": lint_errors}
    else:
        out["tools"]["lint"] = {"status": "unavailable"}

    if sandbox.available("rector"):
        r = await sandbox.run("rector", ["process", "--dry-run", "--output-format=json", "--no-progress-bar",
                                         "--config", "/app/.patchwarden-rector.php"],
                              {**code, ".patchwarden-rector.php": rector_config(to_version)})
        try:
            out["tools"]["rector"] = {"status": "ok", **parse_rector(r.stdout)}
        except (ValueError, KeyError, AttributeError):
            out["tools"]["rector"] = failed(r, "Rector")
    else:
        out["tools"]["rector"] = {"status": "unavailable"}

    if sandbox.available("phpstan"):
        r = await sandbox.run("phpstan", ["analyse", "--error-format=json", "--no-progress", "--no-interaction",
                                          "-c", "/app/.patchwarden-phpstan.neon"],
                              {**code, ".patchwarden-phpstan.neon": phpstan_config(to_version)})
        try:
            out["tools"]["phpstan"] = {"status": "ok", **parse_phpstan(r.stdout)}
        except (ValueError, KeyError, AttributeError):
            out["tools"]["phpstan"] = failed(r, "PHPStan")
    else:
        out["tools"]["phpstan"] = {"status": "unavailable"}
    return out


def plan_additions(tools: dict) -> list[dict]:
    """Extra plan steps from the tools, in the same shape as the rule-based fixes."""
    t = tools.get("tools", {})
    steps = []
    if t.get("lint", {}).get("errors"):
        e = t["lint"]["errors"]
        steps.append({"rule": "tool:php-lint", "severity": "error", "title": "Files that do not parse",
                      "fix": "Fix the syntax errors first; nothing else can be checked in these files.",
                      "automatic": False, "count": len(e), "where": [f"{x['file']}:{x['line']}" for x in e],
                      "who": "A developer fixes this on staging"})
    if t.get("phpstan", {}).get("errors"):
        e = t["phpstan"]["errors"]
        steps.append({"rule": "tool:phpstan", "severity": "error",
                      "title": f"Errors PHPStan finds for PHP {tools.get('target_version')}",
                      "fix": "Fix each reported call or type error.", "automatic": False, "count": len(e),
                      "where": [f"{x['file']}:{x['line']}" for x in e][:200], "who": "A developer fixes this on staging"})
    if t.get("rector", {}).get("changes"):
        c = t["rector"]["changes"]
        steps.append({"rule": "tool:rector", "severity": "warning", "title": "Upgrade changes Rector proposes",
                      "fix": "Review Rector's diffs; apply them on staging.", "automatic": False, "count": len(c),
                      "where": [x["file"] for x in c][:200], "who": "A developer reviews and applies this on staging"})
    return steps


def available_tools(sandbox: Sandbox | None) -> dict[str, bool]:
    return {t: bool(sandbox and sandbox.available(t)) for t in ("php", "rector", "phpstan")}

