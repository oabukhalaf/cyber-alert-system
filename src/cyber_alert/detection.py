"""Stateful detection rules evaluated over a stream of auth events.

Rules measure time with the events' own timestamps, never the wall clock. Replaying
a log file therefore raises exactly the alerts that watching it live would have,
which keeps detection deterministic and testable.

Events are assumed to arrive in time order, as they do when read from a log.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Hashable, Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from typing import ClassVar

from .alerts import Alert, Severity, Technique
from .parser import AuthEvent


class Rule(ABC):
    """One detection. Subclasses set the class attributes and implement ``process``."""

    id: ClassVar[str]  # stable identifier used in config files and stored alerts
    severity: ClassVar[Severity]
    technique: ClassVar[Technique]

    @abstractmethod
    def process(self, event: AuthEvent) -> list[Alert]:
        """Consume the next event and return any alerts it triggers (usually none)."""

    def alert(self, *, title: str, description: str, events: Sequence[AuthEvent]) -> Alert:
        """Build an alert from the events that caused it, oldest first."""
        return Alert(
            rule_id=self.id,
            severity=self.severity,
            technique=self.technique,
            title=title,
            description=description,
            source_ip=events[-1].source_ip,
            usernames=tuple(dict.fromkeys(event.username for event in events)),
            event_count=sum(event.count for event in events),
            first_seen=events[0].timestamp,
            last_seen=events[-1].timestamp,
        )


class EventWindow:
    """Recent events grouped by key, covering the last ``duration`` of event time.

    Typical use inside a rule::

        self._window = EventWindow(timedelta(minutes=1))
        ...
        recent = self._window.add(event.source_ip, event)  # this IP's last minute
    """

    _SWEEP_EVERY = 1024  # adds between sweeps for keys that have gone quiet

    def __init__(self, duration: timedelta):
        self.duration = duration
        self._events: dict[Hashable, deque[AuthEvent]] = {}
        self._adds = 0

    def add(self, key: Hashable, event: AuthEvent) -> list[AuthEvent]:
        """Record ``event`` under ``key`` and return the key's events in the window."""
        self._events.setdefault(key, deque()).append(event)
        self._adds += 1
        if self._adds % self._SWEEP_EVERY == 0:
            self._sweep(event.timestamp)
        return self.get(key, event.timestamp)

    def get(self, key: Hashable, now: datetime) -> list[AuthEvent]:
        """Return the key's events from the ``duration`` before ``now``, oldest first."""
        events = self._events.get(key)
        if events is None:
            return []
        cutoff = now - self.duration
        while events and events[0].timestamp < cutoff:
            events.popleft()
        if not events:
            del self._events[key]
            return []
        return list(events)

    def clear(self, key: Hashable) -> None:
        self._events.pop(key, None)

    def __len__(self) -> int:
        return len(self._events)

    def _sweep(self, now: datetime) -> None:
        # Keys are only trimmed when touched, so without this an attacker rotating
        # through many source IPs would grow memory without bound.
        cutoff = now - self.duration
        for key in [key for key, events in self._events.items() if events[-1].timestamp < cutoff]:
            del self._events[key]


class Throttle:
    """Allow at most one alert per key per ``period`` of event time.

    Without it, a rule would re-alert on every event of a sustained attack.
    """

    def __init__(self, period: timedelta):
        self.period = period
        self._last_allowed: dict[Hashable, datetime] = {}

    def allow(self, key: Hashable, now: datetime) -> bool:
        """Return True, and start a new quiet period, if ``key`` may alert at ``now``."""
        last = self._last_allowed.get(key)
        if last is not None and now - last < self.period:
            return False
        self._last_allowed[key] = now
        return True


class Detector:
    """Runs every rule over each event."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def process(self, event: AuthEvent) -> list[Alert]:
        return [alert for rule in self.rules for alert in rule.process(event)]

    def run(self, events: Iterable[AuthEvent]) -> Iterator[Alert]:
        for event in events:
            yield from self.process(event)
