"""Aggregate parsed auth events into the counts shown by the CLI and dashboard."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .parser import AuthEvent, EventType


@dataclass
class Summary:
    total_events: int = 0
    failures_by_ip: Counter[str] = field(default_factory=Counter)
    successes_by_ip: Counter[str] = field(default_factory=Counter)
    failures_by_user: Counter[str] = field(default_factory=Counter)
    attempts_by_user: Counter[str] = field(default_factory=Counter)
    invalid_usernames: Counter[str] = field(default_factory=Counter)
    source_ips: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def total_failures(self) -> int:
        return self.failures_by_ip.total()

    @property
    def total_successes(self) -> int:
        return self.successes_by_ip.total()

    def add(self, event: AuthEvent) -> None:
        self.total_events += event.count
        self.source_ips.add(event.source_ip)
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

        # INVALID_USER lines are connection notices that sshd usually follows with an
        # AUTH_FAILURE for the same attempt, so counting them too would double-count.
        if event.event_type is EventType.AUTH_FAILURE:
            self.failures_by_ip[event.source_ip] += event.count
            self.failures_by_user[event.username] += event.count
            self.attempts_by_user[event.username] += event.count
            if event.invalid_user:
                self.invalid_usernames[event.username] += event.count
        elif event.event_type is EventType.AUTH_SUCCESS:
            self.successes_by_ip[event.source_ip] += event.count
            self.attempts_by_user[event.username] += event.count


def summarize(events: Iterable[AuthEvent]) -> Summary:
    summary = Summary()
    for event in events:
        summary.add(event)
    return summary


@dataclass(frozen=True, slots=True)
class TimelineBucket:
    start: datetime
    failures: int
    successes: int


class Timeline:
    """Failed and successful logins counted per minute, regrouped into buckets on request.

    Keeping per-minute counts lets one timeline serve any bucket size without
    re-reading events. Buckets are aligned to multiples of their size since the
    Unix epoch, so hourly and daily buckets start on UTC hour and day boundaries.
    """

    BUCKET_SIZES = tuple(
        timedelta(minutes=minutes) for minutes in (1, 5, 15, 30, 60, 180, 360, 720, 1440)
    )
    MAX_BUCKETS = 2000

    def __init__(self) -> None:
        self._minutes: dict[int, list[int]] = {}  # minutes since epoch -> [failures, successes]

    def add(self, event: AuthEvent) -> None:
        if event.event_type is EventType.AUTH_FAILURE:
            column = 0
        elif event.event_type is EventType.AUTH_SUCCESS:
            column = 1
        else:
            return
        minute = int(event.timestamp.timestamp() // 60)
        self._minutes.setdefault(minute, [0, 0])[column] += event.count

    def auto_bucket_size(self, target_buckets: int = 48) -> timedelta:
        """The smallest standard bucket size that spans the data in ``target_buckets`` or fewer."""
        if not self._minutes:
            return self.BUCKET_SIZES[0]
        span = max(self._minutes) - min(self._minutes) + 1
        for size in self.BUCKET_SIZES:
            if span / (size // timedelta(minutes=1)) <= target_buckets:
                return size
        return self.BUCKET_SIZES[-1]

    def buckets(self, size: timedelta) -> list[TimelineBucket]:
        """Contiguous buckets from the first event to the last, including empty ones."""
        if size < timedelta(minutes=1) or size % timedelta(minutes=1):
            raise ValueError("bucket size must be a whole number of minutes")
        if not self._minutes:
            return []

        width = size // timedelta(minutes=1)
        first = min(self._minutes) // width * width
        last = max(self._minutes) // width * width
        if (last - first) // width + 1 > self.MAX_BUCKETS:
            raise ValueError(f"bucket size too small: more than {self.MAX_BUCKETS} buckets")

        totals = {start: [0, 0] for start in range(first, last + 1, width)}
        for minute, (failures, successes) in self._minutes.items():
            bucket = totals[minute // width * width]
            bucket[0] += failures
            bucket[1] += successes
        return [
            TimelineBucket(datetime.fromtimestamp(start * 60, timezone.utc), failures, successes)
            for start, (failures, successes) in totals.items()
        ]
