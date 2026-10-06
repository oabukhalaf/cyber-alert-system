"""Live state behind the dashboard: everything the log watcher has seen so far."""

from __future__ import annotations

import threading
from collections import deque
from datetime import timedelta

from .alerts import Alert, Severity
from .detection import Detector
from .parser import AuthEvent
from .stats import Summary, Timeline, TimelineBucket
from .store import AlertStore


class Monitor:
    """Runs each auth event through detection and keeps running statistics.

    The log watcher thread calls ``process``; web request threads read
    snapshots. A lock keeps readers from seeing an event half-applied, and
    keeps the (not thread-safe) detector to one caller at a time.
    """

    def __init__(self, detector: Detector, store: AlertStore, *, recent_limit: int = 500):
        self.store = store
        self._detector = detector
        self._lock = threading.Lock()
        self._summary = Summary()
        self._timeline = Timeline()
        self._recent: deque[AuthEvent] = deque(maxlen=recent_limit)

    def process(self, event: AuthEvent) -> list[Alert]:
        """Record ``event``; return the alerts it raised that weren't already stored."""
        with self._lock:
            self._summary.add(event)
            self._timeline.add(event)
            self._recent.append(event)
            alerts = self._detector.process(event)
        # Database writes happen outside the lock so slow I/O never blocks readers.
        return [alert for alert in alerts if self.store.add(alert)]

    def summary(self, *, top: int = 10) -> dict[str, object]:
        """Headline numbers and top offenders, ready to serialize as JSON."""
        with self._lock:
            summary = self._summary
            data: dict[str, object] = {
                "total_events": summary.total_events,
                "failed_logins": summary.total_failures,
                "successful_logins": summary.total_successes,
                "unique_sources": len(summary.source_ips),
                "first_seen": summary.first_seen.isoformat() if summary.first_seen else None,
                "last_seen": summary.last_seen.isoformat() if summary.last_seen else None,
                "top_failed_sources": [
                    {"source_ip": ip, "count": count}
                    for ip, count in summary.failures_by_ip.most_common(top)
                ],
                "top_failed_usernames": [
                    {"username": username, "count": count}
                    for username, count in summary.failures_by_user.most_common(top)
                ],
            }
        counts = self.store.count_by_severity()
        data["alerts_by_severity"] = {
            severity.name.lower(): counts.get(severity, 0)
            for severity in sorted(Severity, reverse=True)
        }
        return data

    def timeline(self, size: timedelta | None = None) -> tuple[timedelta, list[TimelineBucket]]:
        """Login counts per bucket; ``size`` defaults to one that suits the data's span."""
        with self._lock:
            size = size or self._timeline.auto_bucket_size()
            return size, self._timeline.buckets(size)

    def recent_events(self, limit: int) -> list[AuthEvent]:
        """The most recent events, newest first."""
        with self._lock:
            return list(reversed(self._recent))[:limit]
