import mimetypes
import re
import time

import pytest
from conftest import PREFIX

from cyber_alert.config import ConfigError
from cyber_alert.tailer import LogTailer
from cyber_alert.web import publish_new_events, start_log_watcher

BREAK_IN = [
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Failed password for deploy from 192.0.2.77 port 58001 ssh2\n",
    f"{PREFIX}Accepted password for deploy from 192.0.2.77 port 58001 ssh2\n",
]


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


def test_dashboard_page(make_app, log_file):
    response = make_app(log_file).test_client().get("/")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert str(log_file) in page
    assert "<option>ssh-brute-force</option>" in page  # rule filter choices
    assert "/static/dashboard.js" in page


def test_dashboard_has_no_inline_scripts_or_styles(make_app, log_file):
    page = make_app(log_file).test_client().get("/").get_data(as_text=True)

    # The Content-Security-Policy forbids inline code, so none may exist.
    assert all("src=" in tag for tag in re.findall(r"<script[^>]*>", page))
    assert "<style" not in page
    assert " style=" not in page


def test_security_headers(make_app, log_file):
    headers = make_app(log_file).test_client().get("/").headers

    policy = headers["Content-Security-Policy"]
    assert "script-src 'self' https://cdn.socket.io" in policy
    assert "style-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "frame-ancestors 'none'" in policy
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize(
    ("path", "mimetype"),
    [
        ("/static/dashboard.js", "text/javascript"),
        ("/static/dashboard.css", "text/css"),
        ("/static/favicon.svg", "image/svg+xml"),
    ],
)
def test_static_files_are_served(make_app, log_file, path, mimetype):
    response = make_app(log_file).test_client().get(path)

    assert response.status_code == 200
    assert response.mimetype == mimetype


def test_script_type_does_not_depend_on_the_system_mime_table(make_app, log_file):
    # Simulate a Windows registry that maps .js to text/plain, as some machines' do.
    mimetypes.add_type("text/plain", ".js")
    try:
        response = make_app(log_file).test_client().get("/static/dashboard.js")
    finally:
        mimetypes.add_type("text/javascript", ".js")

    assert response.mimetype == "text/javascript"


def test_new_lines_are_published_and_counted(make_app, log_file):
    app = make_app(log_file)
    client = app.extensions["socketio"].test_client(app)
    tailer = LogTailer(log_file)  # only new lines

    append(log_file, [*BREAK_IN, f"{PREFIX}Connection closed by 192.0.2.77 port 1 [preauth]\n"])

    assert publish_new_events(app, tailer) == 4
    messages = client.get_received()
    assert [m["name"] for m in messages] == ["auth_event"] * 4 + ["alert"]
    assert messages[-1]["args"][0]["rule_id"] == "ssh-login-after-failures"
    summary = app.extensions["monitor"].summary()
    assert (summary["failed_logins"], summary["successful_logins"]) == (3, 1)


def test_known_alerts_are_not_announced_again(make_app, log_file):
    append(log_file, BREAK_IN)
    app = make_app(log_file)
    publish_new_events(app, LogTailer(log_file, from_start=True))

    restarted = make_app(log_file)  # same database, fresh detector state
    client = restarted.extensions["socketio"].test_client(restarted)
    publish_new_events(restarted, LogTailer(log_file, from_start=True))

    assert "alert" not in [m["name"] for m in client.get_received()]
    assert len(restarted.extensions["monitor"].store.recent()) == 1


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
