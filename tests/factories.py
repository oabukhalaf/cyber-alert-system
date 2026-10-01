"""Builders for AuthEvents in tests, timed in seconds after a fixed start."""

from datetime import datetime, timedelta, timezone

from cyber_alert.parser import AuthEvent, EventType

START = datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc)


def failure(username="root", ip="203.0.113.45", *, at=0, count=1, invalid_user=False):
    return _event(EventType.AUTH_FAILURE, username, ip, at, count, "password", invalid_user)


def success(username="alice", ip="203.0.113.45", *, at=0, method="password"):
    return _event(EventType.AUTH_SUCCESS, username, ip, at, 1, method, False)


def invalid_user(username="admin", ip="203.0.113.45", *, at=0):
    return _event(EventType.INVALID_USER, username, ip, at, 1, None, True)


def _event(event_type, username, ip, at, count, method, invalid):
    return AuthEvent(
        timestamp=START + timedelta(seconds=at),
        host="web-01",
        event_type=event_type,
        username=username,
        source_ip=ip,
        port=40000,
        method=method,
        invalid_user=invalid,
        count=count,
    )
