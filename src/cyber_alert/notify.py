"""Send alerts to Slack, Discord, email or any webhook.

Delivery runs on a background thread so a slow or unreachable channel never
delays detection. Alert text includes attacker-controlled usernames, so each
channel escapes it for its own markup.
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlsplit

from . import __version__
from .alerts import Alert, Severity
from .text import printable

log = logging.getLogger(__name__)

HTTP_TIMEOUT = 10  # seconds
MAX_USERNAMES = 5


class DeliveryError(Exception):
    def __init__(self, message: str, *, retryable: bool, retry_after: float | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class Channel(ABC):
    kind: str

    def __init__(self, *, min_severity: Severity = Severity.HIGH):
        self.min_severity = min_severity

    def wants(self, alert: Alert) -> bool:
        return alert.severity >= self.min_severity

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver one alert, raising DeliveryError on failure."""

    @abstractmethod
    def describe(self) -> str:
        """A label for logs. Must not include secrets such as webhook tokens."""


# --- Webhook channels ---------------------------------------------------------


class SlackChannel(Channel):
    kind = "slack"

    def __init__(self, webhook_url: str, **kwargs):
        super().__init__(**kwargs)
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> None:
        post_json(self.webhook_url, slack_payload(alert))

    def describe(self) -> str:
        return f"slack ({urlsplit(self.webhook_url).hostname})"


class DiscordChannel(Channel):
    kind = "discord"

    def __init__(self, webhook_url: str, **kwargs):
        super().__init__(**kwargs)
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> None:
        post_json(self.webhook_url, discord_payload(alert))

    def describe(self) -> str:
        return f"discord ({urlsplit(self.webhook_url).hostname})"


class WebhookChannel(Channel):
    """POSTs the alert as JSON, for chat tools, SIEMs or custom automation."""

    kind = "webhook"

    def __init__(self, url: str, headers: Mapping[str, str] | None = None, **kwargs):
        super().__init__(**kwargs)
        self.url = url
        self.headers = dict(headers or {})

    def send(self, alert: Alert) -> None:
        post_json(self.url, {"source": "cyber-alert", "alert": alert.to_dict()}, self.headers)

    def describe(self) -> str:
        return f"webhook ({urlsplit(self.url).hostname})"


def post_json(url: str, payload: object, headers: Mapping[str, str] | None = None) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"cyber-alert/{__version__}",
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        # 429 (rate limited) and 5xx are worth retrying; other 4xx mean bad config.
        raise DeliveryError(
            f"HTTP {exc.code}",
            retryable=exc.code == 429 or exc.code >= 500,
            retry_after=_seconds(exc.headers.get("Retry-After")),
        ) from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"connection failed: {reason}", retryable=True) from None


def _seconds(value: str | None) -> float | None:
    try:
        return max(0.0, float(value)) if value else None
    except ValueError:
        return None  # an HTTP date; fall back to normal backoff


# --- Email ------------------------------------------------------------------------


class EmailChannel(Channel):
    kind = "email"

    def __init__(
        self,
        *,
        smtp_host: str,
        sender: str,
        recipients: Iterable[str],
        smtp_port: int | None = None,
        security: str = "starttls",
        username: str | None = None,
        password: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if security not in ("starttls", "ssl", "none"):
            raise ValueError(f"unknown security mode {security!r}")
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port or {"starttls": 587, "ssl": 465, "none": 25}[security]
        self.security = security
        self.username = username
        self.password = password
        self.sender = sender
        self.recipients = list(recipients)

    def send(self, alert: Alert) -> None:
        message = email_message(alert, sender=self.sender, recipients=self.recipients)
        context = ssl.create_default_context()
        try:
            if self.security == "ssl":
                smtp = smtplib.SMTP_SSL(
                    self.smtp_host, self.smtp_port, timeout=HTTP_TIMEOUT, context=context
                )
            else:
                smtp = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=HTTP_TIMEOUT)
            with smtp:
                if self.security == "starttls":
                    smtp.starttls(context=context)
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(message)
        except (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused) as exc:
            raise DeliveryError(f"rejected by server: {exc}", retryable=False) from None
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"SMTP error: {exc}", retryable=True) from None

    def describe(self) -> str:
        return f"email ({self.smtp_host})"


# --- Message formatting -------------------------------------------------------


def _usernames(alert: Alert) -> str:
    shown = ", ".join(printable(u) for u in alert.usernames[:MAX_USERNAMES])
    extra = len(alert.usernames) - MAX_USERNAMES
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _details(alert: Alert) -> list[tuple[str, str]]:
    return [
        ("Severity", alert.severity.name.lower()),
        ("Technique", f"{alert.technique.id} {alert.technique.name}"),
        ("Source IP", alert.source_ip),
        ("Usernames", _usernames(alert)),
        ("Events", str(alert.event_count)),
        ("First seen", alert.first_seen.isoformat()),
        ("Last seen", alert.last_seen.isoformat()),
    ]


def slack_escape(text: str) -> str:
    # Slack reads <...> as links and mentions such as <!channel>; these three
    # escapes are all that's needed to keep attacker text inert.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(alert: Alert) -> dict[str, object]:
    lines = [
        f"*[{alert.severity.name}] {slack_escape(printable(alert.title))}*",
        slack_escape(printable(alert.description)),
        "",
        *(f"*{label}:* {slack_escape(value)}" for label, value in _details(alert)),
        f"<{alert.technique.url}|MITRE ATT&amp;CK {alert.technique.id}>",
    ]
    return {"text": "\n".join(lines), "unfurl_links": False, "unfurl_media": False}


_DISCORD_MARKDOWN = str.maketrans({ch: f"\\{ch}" for ch in "\\*_~`|>#-[]()<:@"})
DISCORD_MAX_LENGTH = 2000


def discord_escape(text: str) -> str:
    return text.translate(_DISCORD_MARKDOWN)


def discord_payload(alert: Alert) -> dict[str, object]:
    lines = [
        f"**[{alert.severity.name}] {discord_escape(printable(alert.title))}**",
        discord_escape(printable(alert.description)),
        "",
        *(f"**{label}:** {discord_escape(value)}" for label, value in _details(alert)),
        f"MITRE ATT&CK: <{alert.technique.url}>",
    ]
    content = "\n".join(lines)
    if len(content) > DISCORD_MAX_LENGTH:
        content = content[: DISCORD_MAX_LENGTH - 1] + "…"
    # Belt and braces with the escaping: never let alert text ping anyone.
    return {"content": content, "username": "Cyber Alert", "allowed_mentions": {"parse": []}}


def email_message(alert: Alert, *, sender: str, recipients: list[str]) -> EmailMessage:
    message = EmailMessage()
    # printable() turns CR/LF into "\x0d"/"\x0a", so a username can't add header lines.
    message["Subject"] = f"[{alert.severity.name}] {printable(alert.title)}"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    body = [printable(alert.title), printable(alert.description), ""]
    body += [f"{label}: {value}" for label, value in _details(alert)]
    body += ["", f"MITRE ATT&CK: {alert.technique.url}"]
    message.set_content("\n".join(body))
    return message


# --- Dispatcher -------------------------------------------------------------------


class Notifier:
    """Queues alerts and delivers them to every interested channel in the background.

    Only alerts about recent activity are sent: on a first run over an old log,
    detection still stores every alert, but channels aren't flooded with history.
    """

    _STOP = object()

    def __init__(
        self,
        channels: Iterable[Channel],
        *,
        max_age: timedelta = timedelta(hours=1),
        queue_size: int = 1000,
        attempts: int = 3,
        backoff: float = 1.0,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.channels = list(channels)
        self.max_age = max_age
        self._attempts = attempts
        self._backoff = backoff
        self._clock = clock
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._thread = threading.Thread(target=self._run, name="notifier", daemon=True)
        self._thread.start()

    def submit(self, alert: Alert) -> bool:
        """Queue ``alert`` for delivery; return False if it won't be sent."""
        if self._clock() - alert.last_seen > self.max_age:
            log.info("Not notifying about old activity: %s", printable(alert.title))
            return False
        if not any(channel.wants(alert) for channel in self.channels):
            return False
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            log.warning("Notification queue full; dropping: %s", printable(alert.title))
            return False
        return True

    def close(self, timeout: float = 30.0) -> None:
        """Deliver what's queued, then stop the worker thread."""
        self._queue.put(self._STOP)
        self._thread.join(timeout)

    def _run(self) -> None:
        while (alert := self._queue.get()) is not self._STOP:
            for channel in self.channels:
                if channel.wants(alert):
                    self._deliver(channel, alert)

    def _deliver(self, channel: Channel, alert: Alert) -> None:
        for attempt in range(1, self._attempts + 1):
            try:
                channel.send(alert)
            except DeliveryError as exc:
                if not exc.retryable or attempt == self._attempts:
                    log.error("Couldn't notify %s: %s", channel.describe(), exc)
                    return
                time.sleep(exc.retry_after or self._backoff * 2 ** (attempt - 1))
            except Exception:  # a bug in one channel must not kill the worker
                log.exception("Couldn't notify %s", channel.describe())
                return
            else:
                log.info("Notified %s: %s", channel.describe(), printable(alert.title))
                return
