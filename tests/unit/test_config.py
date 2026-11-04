"""Production refuses to start without its required secrets, and names the missing one."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from patchwarden.config import ConfigError, load_settings

PROJECT = Path(__file__).resolve().parents[2]
GOOD_JWT = "j" * 64  # test-only value


def _prod_env(monkeypatch, **overrides):
    values = {
        "APP_ENV": "production",
        "DATABASE_URL": "postgresql://patchwarden@db:5432/patchwarden",
        "JWT_SECRET": GOOD_JWT,
        "CREDENTIAL_KEY": Fernet.generate_key().decode(),
        "DEMO_SITES": "false",
    }
    values.update(overrides)
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    return values


@pytest.mark.parametrize("missing", ["DATABASE_URL", "JWT_SECRET", "CREDENTIAL_KEY"])
def test_production_names_the_missing_secret(monkeypatch, missing):
    values = _prod_env(monkeypatch, **{missing: ""})
    with pytest.raises(ConfigError) as exc:
        load_settings(load_dotenv_file=False)
    message = str(exc.value)
    assert missing in message
    # The message never contains the secrets that ARE set.
    for name in ("JWT_SECRET", "CREDENTIAL_KEY"):
        if name != missing:
            assert values[name] not in message


def test_production_with_all_secrets_starts(monkeypatch):
    _prod_env(monkeypatch)
    s = load_settings(load_dotenv_file=False)
    assert s.is_production and not s.demo_sites
    assert s.database_url.startswith("postgresql+psycopg://")
    assert GOOD_JWT not in repr(s)


def test_production_refuses_demo_sites(monkeypatch):
    _prod_env(monkeypatch, DEMO_SITES="true")
    with pytest.raises(ConfigError, match="DEMO_SITES"):
        load_settings(load_dotenv_file=False)


def test_bad_secrets_are_refused(monkeypatch):
    _prod_env(monkeypatch, JWT_SECRET="short")
    with pytest.raises(ConfigError, match="JWT_SECRET is too short"):
        load_settings(load_dotenv_file=False)
    _prod_env(monkeypatch, CREDENTIAL_KEY="not-a-fernet-key")
    with pytest.raises(ConfigError, match="CREDENTIAL_KEY is not a valid Fernet key"):
        load_settings(load_dotenv_file=False)


def test_development_runs_with_no_secrets(monkeypatch):
    for name in ("DATABASE_URL", "JWT_SECRET", "CREDENTIAL_KEY", "DEMO_SITES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    s = load_settings(load_dotenv_file=False)
    assert s.database_url.startswith("sqlite:///") and s.demo_sites
    assert len(s.jwt_secret) >= 32


def test_cli_exits_and_names_missing_secret():
    env = {k: v for k, v in os.environ.items() if k not in {"DATABASE_URL", "JWT_SECRET", "CREDENTIAL_KEY"}}
    # JWT_SECRET is set but empty: a developer's .env cannot fill it (real env wins over .env).
    env.update(APP_ENV="production", DATABASE_URL="postgresql://patchwarden@db/patchwarden", JWT_SECRET="",
               CREDENTIAL_KEY=Fernet.generate_key().decode(), DEMO_SITES="false")
    r = subprocess.run([sys.executable, "-m", "patchwarden", "--check-config"], cwd=PROJECT, env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2
    assert "missing required secret JWT_SECRET" in r.stderr
    assert env["CREDENTIAL_KEY"] not in r.stderr + r.stdout
    assert "Traceback" not in r.stderr
