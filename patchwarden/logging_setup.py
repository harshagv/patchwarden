"""Logging with a redaction filter (defence in depth: the code also never logs secrets)."""

from __future__ import annotations

import logging
import re

from .config import Settings

_PATTERNS = [
    # Share-link tokens in access-log query strings.
    (re.compile(r"([?&]token=)[^&\s\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)(\"?password\"?\s*[:=]\s*)\"?[^\s\",}]+"), r"\1<redacted>"),
]


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: list[str]):
        super().__init__()
        self._secrets = [s for s in secrets if s and len(s) >= 8]

    def _clean(self, text: str) -> str:
        for pattern, repl in _PATTERNS:
            text = pattern.sub(repl, text)
        for secret in self._secrets:
            text = text.replace(secret, "<redacted>")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        # Clean the template and each argument separately: formatters such as
        # uvicorn's access formatter read record.args, so they must stay a tuple.
        if isinstance(record.msg, str):
            record.msg = self._clean(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self._clean(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: self._clean(v) if isinstance(v, str) else v for k, v in record.args.items()}
        return True


def configure_logging(settings: Settings) -> None:
    redactor = RedactingFilter([settings.jwt_secret, settings.credential_key,
                                settings.nvd_api_key, settings.smtp_password])
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error"):
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(redactor)
    # httpx logs every request URL at INFO; keep it quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
