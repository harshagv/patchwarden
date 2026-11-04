"""Email for alerts and monthly reports. SMTP when configured; otherwise kept on the dashboard only."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from ..config import Settings

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    body: str


class Notifier(Protocol):
    async def send(self, email: Email) -> bool:
        """True only if the email was handed to a mail server."""


class SmtpNotifier:
    def __init__(self, settings: Settings):
        self.host, self.port = settings.smtp_host, settings.smtp_port
        self.user, self._password = settings.smtp_user, settings.smtp_password
        self.sender = settings.alert_from_email

    def __repr__(self) -> str:
        return f"<SmtpNotifier {self.host}:{self.port}>"

    def _send_sync(self, email: Email) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, email.to, email.subject
        msg.set_content(email.body)
        with smtplib.SMTP(self.host, self.port, timeout=20) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if self.user:
                smtp.login(self.user, self._password)
            smtp.send_message(msg)

    async def send(self, email: Email) -> bool:
        try:
            await asyncio.to_thread(self._send_sync, email)
            return True
        except (smtplib.SMTPException, OSError) as exc:
            # The exception text can quote the server's reply; log the type only.
            log.warning("Alert email not sent: %s", type(exc).__name__)
            return False


class OutboxNotifier:
    """No SMTP configured: keep emails in memory (tests read them) and report them as not sent."""

    def __init__(self, delivered: bool = False):
        self.delivered = delivered
        self.sent: list[Email] = []

    async def send(self, email: Email) -> bool:
        self.sent.append(email)
        if not self.delivered:
            log.info("SMTP not configured: alert kept on the dashboard only")
        return self.delivered


def make_notifier(settings: Settings) -> Notifier:
    return SmtpNotifier(settings) if settings.smtp_host else OutboxNotifier()
