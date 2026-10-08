import itertools
import random
from datetime import datetime, timedelta

import pytest

from cyber_alert import cli
from cyber_alert.config import load_rules
from cyber_alert.detection import Detector
from cyber_alert.parser import parse_line
from cyber_alert.simulate import Simulator, Step, format_line, run

BASE = datetime(2026, 10, 8, 9, 0)
NOW = datetime(2026, 10, 8, 23, 0).astimezone()
STAFF = {"alice", "bob", "j.smith"}


def simulated_lines(seed=1, steps=600):
    """Simulated log lines, timestamped by each step's delay rather than the wall clock."""
    when = BASE
    for step in itertools.islice(Simulator(random.Random(seed)).steps(), steps):
        when += timedelta(seconds=step.delay)
        yield format_line(when, "web-01", step)


def test_line_format_matches_syslog():
    line = format_line(datetime(2026, 10, 8, 9, 5, 3), "web-01", Step(0, 123, "hello"))

    assert line == "Oct  8 09:05:03 web-01 sshd[123]: hello"


def test_month_names_ignore_the_locale():
    months = [format_line(datetime(2026, m, 10), "h", Step(0, 1, "x"))[:3] for m in range(1, 13)]

    assert months == [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]


def test_every_line_is_valid_and_sshd_auth_lines_parse():
    lines = list(simulated_lines())

    events = [event for line in lines if (event := parse_line(line, now=NOW))]
    noise = [line for line in lines if "pam_unix(" in line]
    assert len(events) + len(noise) == len(lines)


def test_simulated_attacks_raise_every_alert_type_and_staff_raise_none():
    events = [event for line in simulated_lines() if (event := parse_line(line, now=NOW))]

    alerts = list(Detector(load_rules()).run(events))

    assert {alert.rule_id for alert in alerts} == {
        "ssh-brute-force",
        "ssh-password-spray",
        "ssh-login-after-failures",
    }
    assert not [alert for alert in alerts if STAFF & set(alert.usernames)]


def test_same_seed_same_traffic():
    first = list(itertools.islice(Simulator(random.Random(5)).steps(), 50))
    second = list(itertools.islice(Simulator(random.Random(5)).steps(), 50))

    assert first == second


def test_run_writes_lines_paced_by_speed(tmp_path):
    log = tmp_path / "auth.log"
    sleeps = []

    written = run(log, speed=4, duration=120, seed=3, clock=lambda: BASE, sleep=sleeps.append)

    lines = log.read_text(encoding="utf-8").splitlines()
    assert written == len(lines) > 0
    assert all(line.startswith("Oct  8 09:00:00 web-01 ") for line in lines)
    assert sum(sleeps) * 4 <= 120  # simulated time stays within the duration


def test_run_appends_to_an_existing_log(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("existing line\n", encoding="utf-8")

    run(log, duration=30, seed=3, sleep=lambda _: None)

    assert log.read_text(encoding="utf-8").startswith("existing line\n")


def test_simulate_command(tmp_path, capsys):
    log = tmp_path / "auth.log"

    assert cli.main(["simulate", str(log), "--speed", "100000", "--duration", "60"]) == 0

    assert log.exists()
    assert "Wrote" in capsys.readouterr().err


@pytest.mark.parametrize("speed", ["0", "-1", "fast"])
def test_simulate_rejects_bad_speeds(tmp_path, speed):
    with pytest.raises(SystemExit) as error:
        cli.main(["simulate", str(tmp_path / "auth.log"), "--speed", speed])

    assert error.value.code == 2
