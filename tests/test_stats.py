from datetime import datetime, timedelta, timezone

import pytest
from factories import START, failure, invalid_user, success

from cyber_alert.parser import AuthEvent, EventType
from cyber_alert.stats import Timeline, summarize


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


def test_tracks_failures_per_username_and_every_source():
    summary = summarize(
        [
            event(EventType.AUTH_FAILURE, "root", "203.0.113.45", count=3),
            event(EventType.AUTH_SUCCESS, "root", "10.0.4.21"),
            event(EventType.INVALID_USER, "oracle", "198.51.100.23", invalid_user=True),
        ]
    )

    assert summary.failures_by_user == {"root": 3}
    assert summary.source_ips == {"203.0.113.45", "10.0.4.21", "198.51.100.23"}


# --- Timeline -----------------------------------------------------------------


def test_empty_timeline():
    timeline = Timeline()

    assert timeline.buckets(timedelta(minutes=5)) == []
    assert timeline.auto_bucket_size() == timedelta(minutes=1)


def test_timeline_counts_per_bucket_and_fills_gaps():
    timeline = Timeline()
    for e in [failure(at=0), failure(at=30, count=3), success(at=61), failure(at=300)]:
        timeline.add(e)

    buckets = timeline.buckets(timedelta(minutes=1))

    assert [(b.start.minute, b.failures, b.successes) for b in buckets] == [
        (0, 4, 0),
        (1, 0, 1),
        (2, 0, 0),
        (3, 0, 0),
        (4, 0, 0),
        (5, 1, 0),
    ]
    assert buckets[0].start == START


def test_timeline_regroups_into_larger_buckets():
    timeline = Timeline()
    for e in [failure(at=0), success(at=61), failure(at=300)]:
        timeline.add(e)

    assert [(b.start, b.failures, b.successes) for b in timeline.buckets(timedelta(minutes=5))] == [
        (START, 1, 1),
        (START + timedelta(minutes=5), 1, 0),
    ]


def test_timeline_buckets_align_to_their_size():
    timeline = Timeline()
    timeline.add(failure(at=7 * 60))  # 10:07

    [bucket] = timeline.buckets(timedelta(hours=1))

    assert bucket.start == START  # 10:00, not 10:07


def test_timeline_ignores_invalid_user_notices():
    timeline = Timeline()
    timeline.add(invalid_user(at=0))

    assert timeline.buckets(timedelta(minutes=1)) == []


def test_auto_bucket_size_fits_the_span():
    timeline = Timeline()
    timeline.add(failure(at=0))
    timeline.add(failure(at=9 * 3600))  # a 9-hour span

    assert timeline.auto_bucket_size() == timedelta(minutes=15)  # 37 buckets


@pytest.mark.parametrize("size", [timedelta(seconds=30), timedelta(seconds=90)])
def test_bucket_size_must_be_whole_minutes(size):
    with pytest.raises(ValueError, match="whole number of minutes"):
        Timeline().buckets(size)


def test_too_many_buckets_is_rejected():
    timeline = Timeline()
    timeline.add(failure(at=0))
    timeline.add(failure(at=3 * 86400))

    with pytest.raises(ValueError, match="too small"):
        timeline.buckets(timedelta(minutes=1))
