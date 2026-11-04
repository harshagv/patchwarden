"""Entry point.

    python -m patchwarden [--check-config] [--host H] [--port P] [--reload]   run the server
    python -m patchwarden verify-audit             check the audit log hash chain (exit 1 if broken)
    python -m patchwarden export-audit --out F     write the audit log as JSON lines (for WORM storage)
    python -m patchwarden rotate-credentials       re-encrypt stored tokens with the first CREDENTIAL_KEY
    python -m patchwarden purge-backups            delete backups past BACKUP_RETENTION_DAYS

Settings are checked before anything runs, so production with a missing secret exits with code 2
and names the secret, without a stack trace.
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import ConfigError, Settings, load_settings

COMMANDS = ("serve", "verify-audit", "export-audit", "rotate-credentials", "purge-backups")


def _session(settings: Settings):
    from .db import create_schema, make_engine, make_sessionmaker
    from .security import audit_chain  # noqa: F401  (registers the hash-chain hook)

    engine = make_engine(settings.database_url)
    create_schema(engine)
    return make_sessionmaker(engine)()


def verify_audit(settings: Settings) -> int:
    from .security.audit_chain import verify

    with _session(settings) as db:
        result = verify(db)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def export_audit(settings: Settings, out: str) -> int:
    from .security.audit_chain import export_lines

    with _session(settings) as db, open(out, "w", encoding="utf-8") as fh:
        n = 0
        for line in export_lines(db):
            fh.write(line + "\n")
            n += 1
    print(f"Wrote {n} audit entries to {out}.")
    return 0


def rotate_credentials(settings: Settings) -> int:
    from .models import AuditLog, Credential, User
    from .security.crypto import CredentialVault

    vault = CredentialVault(settings)
    with _session(settings) as db:
        creds = db.query(Credential).all()
        for c in creds:
            c.encrypted_value = vault.rotate(c.encrypted_value)
        mfa = [u for u in db.query(User).filter(User.mfa_secret.is_not(None))]
        for u in mfa:
            u.mfa_secret = vault.rotate(u.mfa_secret)
        db.add(AuditLog(user_id=None, action="credentials.rotated",
                        detail={"credentials": len(creds), "mfa_secrets": len(mfa)}))
        db.commit()
    print(f"Re-encrypted {len(creds)} credential(s) and {len(mfa)} two-step secret(s) with the first key. "
          "You can now remove the old key from CREDENTIAL_KEY.")
    return 0


def purge_backups(settings: Settings) -> int:
    from .patch.backups import BackupStore, purge_expired

    with _session(settings) as db:
        n = purge_expired(db, BackupStore(settings))
    print(f"Deleted {n} expired backup(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchwarden")
    parser.add_argument("command", nargs="?", default="serve", choices=COMMANDS)
    parser.add_argument("--check-config", action="store_true", help="validate settings and exit")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--out", default="audit-log.jsonl", help="export-audit: output file")
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Patchwarden: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print(f"Patchwarden: configuration OK ({settings.app_env}).")
        return 0
    if args.command == "verify-audit":
        return verify_audit(settings)
    if args.command == "export-audit":
        return export_audit(settings, args.out)
    if args.command == "rotate-credentials":
        return rotate_credentials(settings)
    if args.command == "purge-backups":
        return purge_backups(settings)

    import uvicorn

    uvicorn.run("patchwarden.app:create_app", factory=True, host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
