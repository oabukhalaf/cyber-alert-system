from datetime import datetime, timezone

from cyber_alert.parser import AuthEvent, EventType
from cyber_alert.stats import summarize


def event(event_type, username, ip, *, minute=0, invalid_user=False, count=1):
    return AuthEvent(
        timestamp=datetime(2026, 9, 27, 10, minute, tzinfo=timezone.utc),
        host="web-01",
        event_type=event_type,
        username=username,
        source_ip=ip,
        invalid_user=invalid_user,
        count=count,
    )


def test_empty_input():
    summary = summarize([])

    assert summary.total_events == 0
    assert summary.first_seen is None
    assert summary.total_failures == 0


def test_counts_failures_and_successes_by_ip_and_user():
    summary = summarize(
        [
            event(EventType.AUTH_FAILURE, "root", "203.0.113.45", minute=5, count=5),
            event(EventType.AUTH_FAILURE, "root", "203.0.113.45", minute=6),
            event(EventType.AUTH_SUCCESS, "alice", "10.0.4.21", minute=1),
        ]
    )

    assert summary.total_events == 7
    assert summary.failures_by_ip == {"203.0.113.45": 6}
    assert summary.successes_by_ip == {"10.0.4.21": 1}
    assert summary.attempts_by_user == {"root": 6, "alice": 1}
    assert (summary.total_failures, summary.total_successes) == (6, 1)
    assert summary.first_seen.minute == 1
    assert summary.last_seen.minute == 6


def test_invalid_user_notice_is_not_double_counted():
    # sshd logs "Invalid user x" and then "Failed password for invalid user x" for one attempt.
    summary = summarize(
        [
            event(EventType.INVALID_USER, "oracle", "198.51.100.23", invalid_user=True),
            event(EventType.AUTH_FAILURE, "oracle", "198.51.100.23", invalid_user=True),
        ]
    )

    assert summary.failures_by_ip == {"198.51.100.23": 1}
    assert summary.invalid_usernames == {"oracle": 1}
    assert summary.attempts_by_user == {"oracle": 1}
