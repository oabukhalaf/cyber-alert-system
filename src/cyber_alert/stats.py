"""Aggregate parsed auth events into the counts shown by the CLI and dashboard."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from .parser import AuthEvent, EventType


@dataclass
class Summary:
    total_events: int = 0
    failures_by_ip: Counter[str] = field(default_factory=Counter)
    successes_by_ip: Counter[str] = field(default_factory=Counter)
    attempts_by_user: Counter[str] = field(default_factory=Counter)
    invalid_usernames: Counter[str] = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def total_failures(self) -> int:
        return self.failures_by_ip.total()

    @property
    def total_successes(self) -> int:
        return self.successes_by_ip.total()


def summarize(events: Iterable[AuthEvent]) -> Summary:
    summary = Summary()
    for event in events:
        summary.total_events += event.count
        if summary.first_seen is None or event.timestamp < summary.first_seen:
            summary.first_seen = event.timestamp
        if summary.last_seen is None or event.timestamp > summary.last_seen:
            summary.last_seen = event.timestamp

        # INVALID_USER lines are connection notices that sshd usually follows with an
        # AUTH_FAILURE for the same attempt, so counting them too would double-count.
        if event.event_type is EventType.AUTH_FAILURE:
            summary.failures_by_ip[event.source_ip] += event.count
            summary.attempts_by_user[event.username] += event.count
            if event.invalid_user:
                summary.invalid_usernames[event.username] += event.count
        elif event.event_type is EventType.AUTH_SUCCESS:
            summary.successes_by_ip[event.source_ip] += event.count
            summary.attempts_by_user[event.username] += event.count
    return summary
