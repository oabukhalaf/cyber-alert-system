import time

import pytest

from cyber_alert.tailer import LogTailer
from cyber_alert.web import create_app, publish_new_events, start_log_watcher

PREFIX = "Sep 27 10:31:15 web-01 sshd[2412]: "


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        f"{PREFIX}Failed password for root from 203.0.113.45 port 40112 ssh2\n"
        f"{PREFIX}Accepted password for bob from 10.0.4.35 port 49811 ssh2\n",
        encoding="utf-8",
    )
    return path


def test_summary_page_shows_counts(log_file):
    response = create_app(log_file).test_client().get("/")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "1 failed, 1 successful" in page
    assert "203.0.113.45" in page


def test_summary_page_escapes_usernames(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        f"{PREFIX}Failed password for invalid user <script>alert(1)</script> "
        "from 203.0.113.9 port 4000 ssh2\n",
        encoding="utf-8",
    )

    page = create_app(log).test_client().get("/").get_data(as_text=True)

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_summary_page_reports_missing_log(tmp_path):
    response = create_app(tmp_path / "missing.log").test_client().get("/")

    assert response.status_code == 503
    assert "Could not read the log file" in response.get_data(as_text=True)


def test_live_page_loads_socketio_client(log_file):
    response = create_app(log_file).test_client().get("/live")

    assert response.status_code == 200
    assert "socket.io.min.js" in response.get_data(as_text=True)


def test_new_log_lines_are_pushed_to_connected_clients(log_file):
    app = create_app(log_file)
    socketio = app.extensions["socketio"]
    client = socketio.test_client(app)
    tailer = LogTailer(log_file)  # starts at the end, like the real watcher

    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"{PREFIX}Failed password for invalid user oracle from 198.51.100.23 port 1 ssh2\n")
        f.write(f"{PREFIX}Connection closed by 198.51.100.23 port 1 [preauth]\n")

    assert publish_new_events(socketio, tailer) == 1
    [message] = client.get_received()
    assert message["name"] == "auth_event"
    assert message["args"][0]["username"] == "oracle"
    assert message["args"][0]["source_ip"] == "198.51.100.23"


def test_background_watcher_streams_appended_lines(log_file):
    app = create_app(log_file)
    client = app.extensions["socketio"].test_client(app)
    stop = start_log_watcher(app, poll_interval=0.01)
    try:
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"{PREFIX}Accepted publickey for alice from 10.0.4.21 port 51022 ssh2\n")

        received = []
        deadline = time.monotonic() + 5
        while not received and time.monotonic() < deadline:
            received = client.get_received()
            time.sleep(0.01)
    finally:
        stop.set()

    assert [m["args"][0]["username"] for m in received] == ["alice"]
