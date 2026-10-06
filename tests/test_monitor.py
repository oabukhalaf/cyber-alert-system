import threading
from datetime import timedelta

from factories import failure, invalid_user, success

from cyber_alert.detection import Detector
from cyber_alert.monitor import Monitor
from cyber_alert.rules import LoginAfterFailuresRule
from cyber_alert.store import AlertStore

BREAK_IN = [failure("deploy", at=0), failure("deploy", at=4), failure("deploy", at=8)]
BREAK_IN.append(success("deploy", at=12))


def make_monitor(tmp_path, **kwargs):
    store = AlertStore(tmp_path / "alerts.db")
    return Monitor(Detector([LoginAfterFailuresRule()]), store, **kwargs)


def test_process_returns_new_alerts(tmp_path):
    monitor = make_monitor(tmp_path)

    alerts = [alert for event in BREAK_IN for alert in monitor.process(event)]

    assert [alert.rule_id for alert in alerts] == ["ssh-login-after-failures"]
    assert len(monitor.store.recent()) == 1


def test_alerts_already_stored_are_not_returned_again(tmp_path):
    first = make_monitor(tmp_path)
    for event in BREAK_IN:
        first.process(event)
    restarted = make_monitor(tmp_path)  # same database, fresh detector state

    assert [alert for event in BREAK_IN for alert in restarted.process(event)] == []


def test_summary(tmp_path):
    monitor = make_monitor(tmp_path)
    for event in [*BREAK_IN, failure("root", ip="198.51.100.7", at=20, count=5)]:
        monitor.process(event)

    summary = monitor.summary(top=1)

    assert summary["total_events"] == 9
    assert summary["failed_logins"] == 8
    assert summary["successful_logins"] == 1
    assert summary["unique_sources"] == 2
    assert summary["top_failed_sources"] == [{"source_ip": "198.51.100.7", "count": 5}]
    assert summary["top_failed_usernames"] == [{"username": "root", "count": 5}]
    assert summary["first_seen"] == BREAK_IN[0].timestamp.isoformat()
    assert summary["alerts_by_severity"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}


def test_summary_before_any_events(tmp_path):
    summary = make_monitor(tmp_path).summary()

    assert summary["total_events"] == 0
    assert summary["first_seen"] is None
    assert summary["top_failed_sources"] == []


def test_timeline_picks_a_bucket_size_when_not_given(tmp_path):
    monitor = make_monitor(tmp_path)
    for event in BREAK_IN:
        monitor.process(event)

    size, buckets = monitor.timeline()

    assert size == timedelta(minutes=1)
    assert [(b.failures, b.successes) for b in buckets] == [(3, 1)]


def test_recent_events_are_newest_first_and_bounded(tmp_path):
    monitor = make_monitor(tmp_path, recent_limit=3)
    for seconds in range(5):
        monitor.process(invalid_user(f"user{seconds}", at=seconds))

    assert [e.username for e in monitor.recent_events(10)] == ["user4", "user3", "user2"]
    assert [e.username for e in monitor.recent_events(1)] == ["user4"]


def test_reads_are_safe_while_events_are_processed(tmp_path):
    monitor = make_monitor(tmp_path)
    errors = []

    def read():
        try:
            for _ in range(200):
                monitor.summary()
                monitor.timeline()
                monitor.recent_events(50)
        except Exception as exc:  # e.g. "dictionary changed size during iteration"
            errors.append(exc)

    reader = threading.Thread(target=read)
    reader.start()
    for i in range(3000):
        monitor.process(failure(f"user{i}", ip=f"198.51.{i // 250}.{i % 250}", at=i))
    reader.join()

    assert errors == []
