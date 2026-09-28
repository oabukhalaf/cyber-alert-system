"""Parse OpenSSH authentication events out of syslog-style auth logs.

Understands both the classic syslog timestamp (``Sep 27 10:31:15``) that most
distributions write to ``/var/log/auth.log`` and the RFC 3339 timestamp
(``2026-09-27T10:31:15.123456+00:00``) that newer rsyslog defaults use.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path


class EventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    # A client named an account that doesn't exist. sshd logs this when the connection
    # starts, so it usually precedes an AUTH_FAILURE for the same username.
    INVALID_USER = "invalid_user"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    timestamp: datetime
    host: str
    event_type: EventType
    username: str
    source_ip: str
    port: int | None = None
    method: str | None = None  # "password", "publickey", "keyboard-interactive/pam", ...
    invalid_user: bool = False
    count: int = 1  # >1 when syslog collapsed repeats into "message repeated N times"

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "event_type": self.event_type.value,
            "username": self.username,
            "source_ip": self.source_ip,
            "port": self.port,
            "method": self.method,
            "invalid_user": self.invalid_user,
            "count": self.count,
        }


_PROCESS = r"(?P<process>[^\s\[:]+)(?:\[\d+\])?"
_SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2}) "
    rf"(?P<host>\S+) {_PROCESS}: (?P<message>.*)$"
)
_ISO_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    rf"(?P<host>\S+) {_PROCESS}: (?P<message>.*)$"
)
_REPEATED = re.compile(r"^message repeated (?P<count>\d+) times: \[ ?(?P<message>.*?) ?\]$")

# The username is attacker-controlled and can itself contain "from <ip> port <n>".
# A greedy username group plus the end anchor bind the match to the *last*
# "from ... port ..." on the line, which is the one sshd appended.
_AUTH_RESULT = re.compile(
    r"^(?P<outcome>Failed|Accepted) (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?:: .*)?$"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


def parse_line(line: str, *, now: datetime | None = None) -> AuthEvent | None:
    """Parse one log line, returning ``None`` if it isn't an sshd authentication event.

    Classic syslog timestamps carry no year or time zone, so they're interpreted
    relative to ``now`` (default: the local clock).
    """
    line = line.rstrip("\r\n")
    header = _SYSLOG_LINE.match(line) or _ISO_LINE.match(line)
    # OpenSSH 9.8+ logs from "sshd-session" and "sshd-auth" as well as "sshd".
    if header is None or not header["process"].startswith("sshd"):
        return None

    timestamp = _parse_timestamp(header, now or datetime.now().astimezone())
    if timestamp is None:
        return None

    message, count = header["message"], 1
    if repeated := _REPEATED.match(message):
        message, count = repeated["message"], int(repeated["count"])

    if match := _AUTH_RESULT.match(message):
        return AuthEvent(
            timestamp=timestamp,
            host=header["host"],
            event_type=(
                EventType.AUTH_SUCCESS if match["outcome"] == "Accepted" else EventType.AUTH_FAILURE
            ),
            username=match["user"],
            source_ip=_normalize_ip(match["ip"]),
            port=int(match["port"]),
            method=match["method"],
            invalid_user=match["invalid"] is not None,
            count=count,
        )
    if match := _INVALID_USER.match(message):
        return AuthEvent(
            timestamp=timestamp,
            host=header["host"],
            event_type=EventType.INVALID_USER,
            username=match["user"],
            source_ip=_normalize_ip(match["ip"]),
            port=int(match["port"]) if match["port"] else None,
            invalid_user=True,
            count=count,
        )
    return None


def parse_lines(lines: Iterable[str], *, now: datetime | None = None) -> Iterator[AuthEvent]:
    """Yield the authentication events found in ``lines``, skipping everything else."""
    now = now or datetime.now().astimezone()
    for line in lines:
        if (event := parse_line(line, now=now)) is not None:
            yield event


def parse_file(path: str | Path, *, now: datetime | None = None) -> list[AuthEvent]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f, now=now))


def _parse_timestamp(header: re.Match[str], now: datetime) -> datetime | None:
    fields = header.groupdict()
    if "timestamp" in fields:
        text = fields["timestamp"]
        # datetime.fromisoformat() only accepts a "Z" suffix from Python 3.11 on.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    try:
        month, day = _MONTHS[fields["month"]], int(fields["day"])
        hour, minute, second = (int(part) for part in fields["clock"].split(":"))
        timestamp = datetime(now.year, month, day, hour, minute, second, tzinfo=now.tzinfo)
        # Assume the most recent past occurrence of the date, so a December line
        # read in January is attributed to the previous year.
        if timestamp - now > timedelta(days=1):
            timestamp = timestamp.replace(year=timestamp.year - 1)
    except (KeyError, ValueError):
        return None
    return timestamp


def _normalize_ip(value: str) -> str:
    """Canonicalize IP addresses (e.g. compress IPv6); pass hostnames from UseDNS through."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value
