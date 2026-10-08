from datetime import timedelta
from pathlib import Path

from factories import START, failure, invalid_user, success

from cyber_alert.alerts import PASSWORD_GUESSING, Severity
from cyber_alert.parser import parse_file
from cyber_alert.rules import ALL_RULES
from cyber_alert.rules.brute_force import BruteForceRule

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "logs" / "sample_auth.log"


def run(rule, events):
    return [alert for event in events for alert in rule.process(event)]


def test_alerts_when_failures_reach_the_threshold():
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=60))

    alerts = run(rule, [failure("root", at=0), failure("root", at=10), failure("root", at=20)])

    [alert] = alerts
    assert alert.rule_id == "ssh-brute-force"
    assert alert.severity is Severity.MEDIUM
    assert alert.technique is PASSWORD_GUESSING
    assert alert.source_ip == "203.0.113.45"
    assert alert.usernames == ("root",)
    assert alert.event_count == 3
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=20)
    assert "203.0.113.45" in alert.title


def test_no_alert_below_the_threshold():
    rule = BruteForceRule(threshold=3)

    assert run(rule, [failure("root", at=0), failure("root", at=10)]) == []


def test_failures_outside_the_window_do_not_count():
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=60))

    # By the third failure, the first one is 61 seconds old.
    assert run(rule, [failure(at=0), failure(at=30), failure(at=61)]) == []


def test_collapsed_repeats_count_toward_the_threshold():
    # One "message repeated 3 times: [ Failed password ... ]" line is three failures.
    rule = BruteForceRule(threshold=3)

    [alert] = run(rule, [failure("root", at=0, count=3)])

    assert alert.event_count == 3


def test_each_username_is_tracked_separately():
    # Many usernames with one attempt each is spraying, a different rule's job.
    rule = BruteForceRule(threshold=3)

    assert run(rule, [failure("root", at=0), failure("admin", at=1), failure("oracle", at=2)]) == []


def test_each_source_is_tracked_separately():
    rule = BruteForceRule(threshold=3)
    events = [failure("root", ip=f"198.51.100.{n}", at=n) for n in range(3)]

    assert run(rule, events) == []


def test_only_failed_logins_count():
    rule = BruteForceRule(threshold=3)
    events = [success("root", at=0), success("root", at=1), success("root", at=2)]
    events += [invalid_user("root", at=3), invalid_user("root", at=4), invalid_user("root", at=5)]

    assert run(rule, events) == []


def test_a_successful_login_resets_the_count():
    # A user who mistypes now and then but always gets in isn't being brute forced.
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=60))
    events = []
    for second in (0, 10, 20, 30):
        events += [failure("bob", at=second), success("bob", at=second + 2)]

    assert run(rule, events) == []


def test_another_users_login_does_not_reset_the_count():
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=60))
    events = [failure("root", at=0), failure("root", at=1), success("alice", at=2)]

    assert len(run(rule, [*events, failure("root", at=3)])) == 1


def test_one_alert_per_window_during_a_sustained_attack():
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=60))
    events = [failure("root", at=seconds) for seconds in range(0, 180, 5)]  # every 5s for 3 min

    alerts = run(rule, events)

    # First alert on the 3rd failure (10s), then no more until a full window has passed.
    assert [alert.last_seen - START for alert in alerts] == [
        timedelta(seconds=10),
        timedelta(seconds=70),
        timedelta(seconds=130),
    ]


def test_detects_the_attack_in_the_sample_log():
    alerts = run(BruteForceRule(), parse_file(SAMPLE_LOG))

    assert [(alert.source_ip, alert.usernames) for alert in alerts] == [
        ("203.0.113.45", ("root",)),
    ]


def test_rule_is_registered():
    assert ALL_RULES.get("ssh-brute-force") is BruteForceRule
