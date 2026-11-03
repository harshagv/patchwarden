"""Entry point: `python -m patchwarden [--check-config] [--host H] [--port P] [--reload]`.

Settings are checked before the server starts, so production with a missing
secret exits with code 2 and names the secret, without a stack trace.
"""

from __future__ import annotations

import argparse
import sys

from .config import ConfigError, load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchwarden")
    parser.add_argument("--check-config", action="store_true", help="validate settings and exit")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Patchwarden: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print(f"Patchwarden: configuration OK ({settings.app_env}).")
        return 0

    import uvicorn

    uvicorn.run("patchwarden.app:create_app", factory=True, host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
