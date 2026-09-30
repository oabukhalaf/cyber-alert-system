import time

import pytest
from factories import failure, success

from cyber_alert.config import ConfigError
from cyber_alert.rules import LoginAfterFailuresRule
from cyber_alert.tailer import LogTailer
from cyber_alert.web import create_app, publish_new_events, start_log_watcher

PREFIX = "Sep 27 10:31:15 web-01 sshd[2412]: "
BREAK_IN = [
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Accepted password for deploy from 192.0.2.77 port 58001 ssh2\n",
]


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        f"{PREFIX}Failed password for root from 203.0.113.45 port 40112 ssh2\n"
        f"{PREFIX}Accepted password for bob from 10.0.4.35 port 49811 ssh2\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def make_app(tmp_path):
    def make(log, **kwargs):
        return create_app(log, db_path=tmp_path / "alerts.db", **kwargs)

    return make


def append(path, lines):
    with path.open("a", encoding="utf-8") as f:
        f.writelines(lines)


def received_until(client, predicate, timeout=5.0):
    """Collect Socket.IO messages until ``predicate(messages)`` holds or time runs out."""
    messages = []
    deadline = time.monotonic() + timeout
    while not predicate(messages) and time.monotonic() < deadline:
        messages += client.get_received()
        time.sleep(0.01)
    return messages


def test_summary_page_shows_counts(make_app, log_file):
    response = make_app(log_file).test_client().get("/")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "1 failed, 1 successful" in page
    assert "203.0.113.45" in page
    assert "No alerts raised." in page


def test_summary_page_escapes_usernames(make_app, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        f"{PREFIX}Failed password for invalid user <script>alert(1)</script> "
        "from 203.0.113.9 port 4000 ssh2\n",
        encoding="utf-8",
    )

    page = make_app(log).test_client().get("/").get_data(as_text=True)

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_summary_page_reports_missing_log(make_app, tmp_path):
    response = make_app(tmp_path / "missing.log").test_client().get("/")

    assert response.status_code == 503
    assert "Could not read the log file" in response.get_data(as_text=True)


def test_live_page_loads_socketio_client(make_app, log_file):
    response = make_app(log_file).test_client().get("/live")

    assert response.status_code == 200
    assert "socket.io.min.js" in response.get_data(as_text=True)


def test_alerts_page_without_alerts(make_app, log_file):
    page = make_app(log_file).test_client().get("/alerts").get_data(as_text=True)

    assert "No alerts yet." in page


def test_alerts_page_lists_stored_alerts_safely(make_app, log_file):
    app = make_app(log_file)
    alert = LoginAfterFailuresRule().alert(
        title="Login as <b>x</b>",
        description="d",
        events=[failure("deploy", at=0), success("deploy", at=5)],
    )
    app.extensions["alert_store"].add(alert)
    client = app.test_client()

    alerts_page = client.get("/alerts").get_data(as_text=True)
    summary_page = client.get("/").get_data(as_text=True)

    assert "Login as &lt;b&gt;x&lt;/b&gt;" in alerts_page
    assert "https://attack.mitre.org/techniques/T1110/" in alerts_page
    assert "1 critical" in summary_page


def test_new_lines_are_published_as_events_and_alerts(make_app, log_file):
    app = make_app(log_file)
    client = app.extensions["socketio"].test_client(app)
    tailer = LogTailer(log_file)  # only new lines

    append(log_file, [*BREAK_IN, f"{PREFIX}Connection closed by 192.0.2.77 port 1 [preauth]\n"])

    assert publish_new_events(app, tailer) == 4
    messages = client.get_received()
    assert [m["name"] for m in messages] == ["auth_event"] * 4 + ["alert"]
    assert messages[-1]["args"][0]["rule_id"] == "ssh-login-after-failures"
    assert len(app.extensions["alert_store"].recent()) == 1


def test_known_alerts_are_not_announced_again(make_app, log_file):
    append(log_file, BREAK_IN)
    app = make_app(log_file)
    publish_new_events(app, LogTailer(log_file, from_start=True))

    restarted = make_app(log_file)  # same database, fresh detector state
    client = restarted.extensions["socketio"].test_client(restarted)
    publish_new_events(restarted, LogTailer(log_file, from_start=True))

    assert "alert" not in [m["name"] for m in client.get_received()]
    assert len(restarted.extensions["alert_store"].recent()) == 1


def test_background_watcher_processes_existing_and_new_lines(make_app, log_file):
    app = make_app(log_file)
    client = app.extensions["socketio"].test_client(app)
    stop = start_log_watcher(app, poll_interval=0.01)
    try:
        append(log_file, BREAK_IN)
        messages = received_until(client, lambda ms: any(m["name"] == "alert" for m in ms))
    finally:
        stop.set()

    events = [m["args"][0]["username"] for m in messages if m["name"] == "auth_event"]
    assert events == ["root", "bob", "deploy", "deploy", "deploy", "deploy"]
    assert [m["name"] for m in messages].count("alert") == 1


def test_invalid_rules_file_fails_at_startup(make_app, log_file, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  ssh-nope: {}\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        make_app(log_file, rules_file=rules)
