from datetime import datetime, timezone
from pathlib import Path

import pytest

from cyber_alert import cli
from cyber_alert.parser import AuthEvent, EventType

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "logs" / "sample_auth.log"
FAILED_LINE = "Sep 27 10:31:15 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1"


def test_summary_of_sample_log(capsys):
    assert cli.main(["summary", str(SAMPLE_LOG)]) == 0

    out = capsys.readouterr().out
    assert "26 failed, 5 successful" in out
    failed_table = out.split("Failed logins by source IP\n")[1].splitlines()
    assert failed_table[0].split() == ["198.51.100.23", "10"]
    # 1 line + "message repeated 5 times" + 3 lines: collapsed repeats are counted.
    assert failed_table[1].split() == ["203.0.113.45", "9"]
    assert "(empty)" in out


def test_summary_top_limits_rows(capsys):
    cli.main(["summary", str(SAMPLE_LOG), "--top", "1"])

    assert "... and 4 more" in capsys.readouterr().out


def test_summary_of_log_without_events(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("nothing to see here\n")

    assert cli.main(["summary", str(log)]) == 0
    assert "No SSH authentication events" in capsys.readouterr().out


def test_summary_of_missing_file(tmp_path, capsys):
    assert cli.main(["summary", str(tmp_path / "missing.log")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_log_file_defaults_to_environment_variable(tmp_path, monkeypatch, capsys):
    log = tmp_path / "auth.log"
    log.write_text(FAILED_LINE + "\n")
    monkeypatch.setenv("CYBER_ALERT_LOG_FILE", str(log))

    assert cli.main(["summary"]) == 0
    assert str(log) in capsys.readouterr().out


def test_watch_prints_parsed_events(monkeypatch, capsys):
    monkeypatch.setattr(cli, "follow", lambda *args, **kwargs: iter([FAILED_LINE, "noise"]))

    assert cli.main(["watch", "auth.log"]) == 0

    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1
    assert "FAILED" in out[0] and "root from 203.0.113.45 via password" in out[0]


def test_format_event_escapes_terminal_control_characters():
    event = AuthEvent(
        timestamp=datetime(2026, 9, 27, 10, 31, 15, tzinfo=timezone.utc),
        host="web-01",
        event_type=EventType.AUTH_FAILURE,
        username="\x1b[2Jroot",
        source_ip="203.0.113.45",
        method="password",
        invalid_user=True,
        count=3,
    )

    text = cli.format_event(event)

    assert "\x1b" not in text
    assert "\\x1b[2Jroot" in text
    assert text.endswith("(nonexistent user) x3")


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("cyber-alert ")
