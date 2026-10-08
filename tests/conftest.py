import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from cyber_alert.web import create_app

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


@pytest.fixture
def make_app(tmp_path):
    """Build a dashboard app whose alert database lives in the test's temp directory."""

    def make(log, **kwargs):
        return create_app(log, db_path=tmp_path / "alerts.db", **kwargs)

    return make


@pytest.fixture
def webhook_server():
    """A local HTTP server that records POSTed JSON and answers with queued statuses.

    Append status codes to ``.statuses`` to make the next requests fail; once
    they run out, requests succeed with 204.
    """
    received, statuses = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(
                {"path": self.path, "headers": dict(self.headers), "json": json.loads(body)}
            )
            status = statuses.pop(0) if statuses else 204
            self.send_response(status)
            if status == 429:
                self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    yield SimpleNamespace(
        url=f"http://127.0.0.1:{server.server_port}/hook", received=received, statuses=statuses
    )
    server.shutdown()
    server.server_close()
