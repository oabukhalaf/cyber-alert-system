import threading
from dataclasses import replace
from datetime import timedelta, timezone

from factories import failure, success

from cyber_alert.alerts import Severity
from cyber_alert.rules import LoginAfterFailuresRule, PasswordSprayRule
from cyber_alert.store import AlertStore


def spray_alert(ip="198.51.100.23", start=0):
    events = [failure(f"user{i}", ip=ip, at=start + i) for i in range(5)]
    return PasswordSprayRule().alert(title=f"Spray from {ip}", description="d", events=events)


def compromise_alert(start=0):
    events = [failure("deploy", at=start), success("deploy", at=start + 5)]
    return LoginAfterFailuresRule().alert(title="Login", description="d", events=events)


def test_round_trip(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert = spray_alert()

    assert store.add(alert) is True
    assert store.recent() == [alert]


def test_duplicate_alerts_are_ignored(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")

    assert store.add(spray_alert()) is True
    assert store.add(spray_alert()) is False
    assert len(store.recent()) == 1


def test_data_survives_reopening(tmp_path):
    AlertStore(tmp_path / "alerts.db").add(spray_alert())

    assert len(AlertStore(tmp_path / "alerts.db").recent()) == 1


def test_recent_is_newest_first_and_limited(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    for minute in (5, 1, 9):
        store.add(spray_alert(start=minute * 60))

    assert [a.last_seen.minute for a in store.recent()] == [9, 5, 1]
    assert len(store.recent(limit=2)) == 2


def test_timestamps_are_normalized_to_utc(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    utc_alert = spray_alert()
    eastern = timezone(timedelta(hours=-5))
    alert = replace(
        utc_alert,
        first_seen=utc_alert.first_seen.astimezone(eastern),
        last_seen=utc_alert.last_seen.astimezone(eastern),
    )

    store.add(alert)

    [stored] = store.recent()
    assert stored.first_seen == alert.first_seen  # the same instant...
    assert stored.first_seen.utcoffset() == timedelta(0)  # ...expressed in UTC
    assert store.add(utc_alert) is False  # so it's recognized as the same alert


def test_count_by_severity(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.add(spray_alert("198.51.100.1"))
    store.add(spray_alert("198.51.100.2"))
    store.add(compromise_alert())

    assert store.count_by_severity() == {Severity.MEDIUM: 2, Severity.CRITICAL: 1}


def test_concurrent_writers(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")

    def write(offset):
        for i in range(20):
            store.add(spray_alert(start=offset * 1000 + i * 10))

    threads = [threading.Thread(target=write, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(store.recent(limit=1000)) == 80
