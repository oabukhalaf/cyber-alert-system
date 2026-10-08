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


def test_detect_on_sample_log(capsys):
    assert cli.main(["detect", str(SAMPLE_LOG)]) == 0

    out = capsys.readouterr().out
    assert "ALERT  MEDIUM    T1110.003  Password spray from 198.51.100.23" in out
    assert "ALERT  CRITICAL  T1110      Login as deploy from 192.0.2.77" in out
    # Totals follow whichever rules are registered.
    total = out.splitlines()[-1]
    assert total.startswith(f"{out.count('  ALERT  ')} alerts: 1 critical, ")


def test_detect_saves_alerts_once(tmp_path, capsys):
    db = tmp_path / "alerts.db"

    cli.main(["detect", str(SAMPLE_LOG), "--db", str(db)])
    first_run = capsys.readouterr().out
    cli.main(["detect", str(SAMPLE_LOG), "--db", str(db)])
    second_run = capsys.readouterr().out

    assert f"Saved {first_run.count('  ALERT  ')} new alert(s)" in first_run
    assert "Saved 0 new alert(s)" in second_run


def test_detect_with_config_file(tmp_path, capsys):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  ssh-password-spray:\n    enabled: false\n", encoding="utf-8")

    cli.main(["detect", str(SAMPLE_LOG), "--config", str(rules)])

    out = capsys.readouterr().out
    assert "Password spray" not in out
    assert "Login as deploy" in out


def test_detect_without_alerts(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(FAILED_LINE + "\n")

    cli.main(["detect", str(log)])

    assert capsys.readouterr().out.strip() == "No alerts."


def test_invalid_config_file_exits_with_status_2(tmp_path, capsys):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  ssh-password-spray:\n    treshold: 3\n", encoding="utf-8")

    assert cli.main(["detect", str(SAMPLE_LOG), "--config", str(rules)]) == 2
    assert "treshold: unknown setting" in capsys.readouterr().err


def test_watch_alerts_only(monkeypatch, capsys):
    lines = SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    monkeypatch.setattr(cli, "follow", lambda *args, **kwargs: iter(lines))

    cli.main(["watch", "auth.log", "--alerts-only"])

    out = capsys.readouterr().out
    assert "FAILED" not in out
    assert "Password spray from 198.51.100.23" in out
    assert "Login as deploy from 192.0.2.77" in out


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


# --- Notifications ------------------------------------------------------------------


def notification_config(tmp_path, url):
    path = tmp_path / "cyber-alert.yaml"
    # The sample log is days old; a long max_age lets its alerts through.
    path.write_text(
        f"notifications:\n  max_age: 3650d\n  channels:\n    - {{type: webhook, url: '{url}'}}\n",
        encoding="utf-8",
    )
    return path


def test_test_notifications_reports_each_channel(tmp_path, webhook_server, capsys):
    config = notification_config(tmp_path, webhook_server.url)

    assert cli.main(["test-notifications", "--config", str(config)]) == 0

    assert capsys.readouterr().out == "OK      webhook (127.0.0.1)\n"
    alert = webhook_server.received[0]["json"]["alert"]
    assert alert["title"] == "Test notification from cyber-alert"


def test_test_notifications_reports_failures(tmp_path, webhook_server, capsys):
    webhook_server.statuses.append(400)
    config = notification_config(tmp_path, webhook_server.url)

    assert cli.main(["test-notifications", "--config", str(config)]) == 1
    assert capsys.readouterr().out == "FAILED  webhook (127.0.0.1): HTTP 400\n"


def test_test_notifications_without_channels(monkeypatch, capsys):
    monkeypatch.delenv("CYBER_ALERT_CONFIG", raising=False)

    assert cli.main(["test-notifications"]) == 1
    assert "No notification channels are configured" in capsys.readouterr().err


def test_watch_notifies_once_per_new_alert(tmp_path, webhook_server, monkeypatch):
    lines = SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    monkeypatch.setattr(cli, "follow", lambda *args, **kwargs: iter(lines))
    config = notification_config(tmp_path, webhook_server.url)
    args = ["watch", "auth.log", "--alerts-only", "--config", str(config)]
    args += ["--db", str(tmp_path / "alerts.db")]

    cli.main(args)
    cli.main(args)  # a restart over the same log: its alerts are already stored

    # Only the critical alert clears the default "high" threshold, and only once.
    rule_ids = [request["json"]["alert"]["rule_id"] for request in webhook_server.received]
    assert rule_ids == ["ssh-login-after-failures"]
