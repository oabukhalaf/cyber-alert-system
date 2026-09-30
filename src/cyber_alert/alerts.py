"""Alerts raised by detection rules, tagged with MITRE ATT&CK techniques."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class Technique:
    """A MITRE ATT&CK technique, e.g. T1110.003 (Brute Force: Password Spraying)."""

    id: str
    name: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


BRUTE_FORCE = Technique("T1110", "Brute Force")
PASSWORD_GUESSING = Technique("T1110.001", "Brute Force: Password Guessing")
PASSWORD_SPRAYING = Technique("T1110.003", "Brute Force: Password Spraying")


@dataclass(frozen=True, slots=True)
class Alert:
    rule_id: str
    severity: Severity
    technique: Technique
    title: str
    description: str
    source_ip: str
    usernames: tuple[str, ...]
    event_count: int
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name.lower(),
            "technique": {
                "id": self.technique.id,
                "name": self.technique.name,
                "url": self.technique.url,
            },
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "usernames": list(self.usernames),
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


def format_duration(span: timedelta) -> str:
    """Render a duration compactly for alert text: "45s", "2m 30s", "1h 5m"."""
    seconds = round(span.total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    if minutes:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    return f"{seconds}s"
