from datetime import timedelta

import pytest
from factories import START, failure, success

from cyber_alert.alerts import PASSWORD_GUESSING, Severity, Technique, format_duration
from cyber_alert.detection import Detector, EventWindow, Rule, Throttle


def test_window_returns_events_for_key_within_duration():
    window = EventWindow(timedelta(seconds=60))

    window.add("a", failure(at=0))
    window.add("b", failure(at=10))
    recent = window.add("a", failure(at=30))

    assert [e.timestamp for e in recent] == [START, START + timedelta(seconds=30)]


def test_window_keeps_events_exactly_one_duration_old_and_drops_older_ones():
    window = EventWindow(timedelta(seconds=60))
    window.add("a", failure(at=0))

    assert len(window.add("a", failure(at=60))) == 2  # first event is exactly 60s old
    assert len(window.add("a", failure(at=61))) == 2  # now it's 61s old and dropped


def test_window_get_and_clear():
    window = EventWindow(timedelta(seconds=60))
    window.add("a", failure(at=0))

    assert len(window.get("a", START + timedelta(seconds=30))) == 1
    assert window.get("a", START + timedelta(seconds=120)) == []
    assert window.get("unknown", START) == []

    window.add("a", failure(at=200))
    window.clear("a")
    assert window.get("a", START + timedelta(seconds=200)) == []


def test_window_sweeps_keys_that_went_quiet():
    window = EventWindow(timedelta(seconds=60))
    window._SWEEP_EVERY = 3
    window.add("quiet-1", failure(at=0))
    window.add("quiet-2", failure(at=1))

    window.add("active", failure(at=500))  # third add triggers a sweep

    assert len(window) == 1


def test_throttle_allows_one_alert_per_period_per_key():
    throttle = Throttle(timedelta(seconds=60))

    assert throttle.allow("a", START)
    assert not throttle.allow("a", START + timedelta(seconds=59))
    assert throttle.allow("b", START + timedelta(seconds=59))
    assert throttle.allow("a", START + timedelta(seconds=60))


class EveryFailure(Rule):
    id = "test-every-failure"
    severity = Severity.LOW
    technique = PASSWORD_GUESSING

    def process(self, event):
        if event.event_type.value != "auth_failure":
            return []
        return [self.alert(title="failure", description="", events=[event])]


def test_rule_alert_summarizes_its_events():
    events = [
        failure("root", at=0, count=5),
        failure("admin", at=10),
        failure("root", at=20),
    ]

    alert = EveryFailure().alert(title="t", description="d", events=events)

    assert alert.rule_id == "test-every-failure"
    assert alert.severity is Severity.LOW
    assert alert.technique is PASSWORD_GUESSING
    assert alert.usernames == ("root", "admin")
    assert alert.event_count == 7
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=20)
    assert alert.source_ip == "203.0.113.45"


def test_detector_runs_every_rule_on_every_event():
    detector = Detector([EveryFailure(), EveryFailure()])

    alerts = list(detector.run([failure(at=0), success(at=1), failure(at=2)]))

    assert len(alerts) == 4


def test_technique_url():
    assert Technique("T1110.003", "x").url == "https://attack.mitre.org/techniques/T1110/003/"
    assert Technique("T1110", "x").url == "https://attack.mitre.org/techniques/T1110/"


def test_alert_to_dict():
    alert = EveryFailure().alert(title="t", description="d", events=[failure(at=0)])

    data = alert.to_dict()

    assert data["severity"] == "low"
    assert data["technique"]["id"] == "T1110.001"
    assert data["usernames"] == ["root"]
    assert data["first_seen"] == "2026-09-27T10:00:00+00:00"


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(0, "0s"), (45, "45s"), (60, "1m"), (150, "2m 30s"), (3600, "1h"), (3900, "1h 5m")],
)
def test_format_duration(seconds, text):
    assert format_duration(timedelta(seconds=seconds)) == text
