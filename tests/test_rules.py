from datetime import timedelta
from pathlib import Path

from factories import failure, invalid_user, success

from cyber_alert.alerts import Severity
from cyber_alert.detection import Detector
from cyber_alert.parser import parse_file
from cyber_alert.rules import LoginAfterFailuresRule, PasswordSprayRule

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "logs" / "sample_auth.log"


def run(rule, events):
    return [alert for event in events for alert in rule.process(event)]


# --- Password spray ---------------------------------------------------------


def test_spray_alerts_when_enough_distinct_usernames_are_tried():
    rule = PasswordSprayRule(distinct_users=3, window=timedelta(minutes=5))

    alerts = run(rule, [failure("admin", at=0), failure("oracle", at=5), failure("test", at=9)])

    [alert] = alerts
    assert alert.rule_id == "ssh-password-spray"
    assert alert.usernames == ("admin", "oracle", "test")
    assert alert.title == "Password spray from 203.0.113.45"
    assert alert.description == "3 different usernames tried in 9s"


def test_spray_ignores_repeated_attempts_on_one_username():
    rule = PasswordSprayRule(distinct_users=3)

    assert run(rule, [failure("root", at=i) for i in range(10)]) == []


def test_spray_counts_invalid_user_notices():
    rule = PasswordSprayRule(distinct_users=3)

    alerts = run(rule, [invalid_user("a", at=0), invalid_user("b", at=1), invalid_user("c", at=2)])

    assert len(alerts) == 1


def test_spray_ignores_usernames_outside_the_window():
    rule = PasswordSprayRule(distinct_users=3, window=timedelta(minutes=5))

    alerts = run(rule, [failure("a", at=0), failure("b", at=10), failure("c", at=311)])

    assert alerts == []


def test_spray_tracks_each_source_separately():
    rule = PasswordSprayRule(distinct_users=3)

    alerts = run(
        rule,
        [
            failure("a", ip="198.51.100.1", at=0),
            failure("b", ip="198.51.100.2", at=1),
            failure("c", ip="198.51.100.3", at=2),
        ],
    )

    assert alerts == []


def test_spray_alerts_once_per_window_during_a_sustained_attack():
    rule = PasswordSprayRule(distinct_users=3, window=timedelta(minutes=5))
    events = [failure(f"user{i}", at=i * 10) for i in range(40)]  # 400s of spraying

    alerts = run(rule, events)

    assert [a.last_seen.minute for a in alerts] == [0, 5]


# --- Login after failures -----------------------------------------------------


def test_login_after_failures_alerts_on_success():
    rule = LoginAfterFailuresRule(min_failures=3, window=timedelta(minutes=10))

    alerts = run(
        rule,
        [
            failure("deploy", at=0),
            failure("deploy", at=4),
            failure("deploy", at=8),
            success("deploy", at=15),
        ],
    )

    [alert] = alerts
    assert alert.severity is Severity.CRITICAL
    assert alert.title == "Login as deploy from 203.0.113.45 after repeated failures"
    assert alert.description.startswith("Accepted password login followed 3 failed logins in 15s")
    assert alert.event_count == 4


def test_login_after_a_typo_is_not_suspicious():
    rule = LoginAfterFailuresRule(min_failures=3)

    assert run(rule, [failure("bob", at=0), success("bob", at=5)]) == []


def test_login_after_failures_counts_collapsed_repeats():
    rule = LoginAfterFailuresRule(min_failures=3)

    assert len(run(rule, [failure(at=0, count=3), success(at=5)])) == 1


def test_login_after_failures_ignores_old_failures():
    rule = LoginAfterFailuresRule(min_failures=3, window=timedelta(minutes=10))
    failures = [failure(at=i) for i in range(3)]

    assert run(rule, [*failures, success(at=10 * 60 + 5)]) == []


def test_login_after_failures_ignores_failures_from_other_sources():
    rule = LoginAfterFailuresRule(min_failures=3)
    failures = [failure(ip="198.51.100.9", at=i) for i in range(5)]

    assert run(rule, [*failures, success(ip="10.0.4.21", at=10)]) == []


def test_occasional_typos_followed_by_logins_are_not_suspicious():
    # One mistyped password before each of three logins within ten minutes.
    rule = LoginAfterFailuresRule(min_failures=3, window=timedelta(minutes=10))
    events = []
    for minute in (0, 3, 6):
        events += [failure("bob", at=minute * 60), success("bob", at=minute * 60 + 5)]

    assert run(rule, events) == []


def test_login_after_failures_does_not_realert_on_the_same_failures():
    rule = LoginAfterFailuresRule(min_failures=3)
    failures = [failure(at=i) for i in range(3)]

    alerts = run(rule, [*failures, success(at=5), success(at=6)])

    assert len(alerts) == 1


# --- Sample log ---------------------------------------------------------------


def test_sample_log_raises_the_expected_alerts():
    detector = Detector([PasswordSprayRule(), LoginAfterFailuresRule()])

    alerts = list(detector.run(parse_file(SAMPLE_LOG)))

    assert [(a.rule_id, a.source_ip) for a in alerts] == [
        ("ssh-password-spray", "198.51.100.23"),
        ("ssh-login-after-failures", "192.0.2.77"),
    ]
