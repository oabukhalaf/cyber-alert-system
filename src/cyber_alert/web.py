"""Flask + Socket.IO dashboard and JSON API."""

from __future__ import annotations

import logging
import mimetypes
import threading
from pathlib import Path

from flask import Flask, Response, render_template
from flask_socketio import SocketIO

from .api import api
from .config import load_rules
from .detection import Detector
from .monitor import Monitor
from .parser import parse_lines
from .rules import ALL_RULES
from .store import AlertStore
from .tailer import LogTailer

log = logging.getLogger(__name__)

# All scripts and styles are served as files, so the policy can forbid inline code:
# even if an attacker-controlled username slipped past escaping, it couldn't run.
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' https://cdn.socket.io",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)

# Python takes MIME types from the Windows registry, where installed software can map
# .js to text/plain. Browsers refuse to run a script served that way (all the more
# with nosniff), which would leave the dashboard blank, so pin the types we serve.
STATIC_MIME_TYPES = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}


def create_app(
    log_file: str | Path, *, db_path: str | Path, rules_file: str | Path | None = None
) -> Flask:
    for extension, mimetype in STATIC_MIME_TYPES.items():
        mimetypes.add_type(mimetype, extension)

    app = Flask(__name__)
    app.config["LOG_FILE"] = str(log_file)
    SocketIO(app, async_mode="threading")  # registers itself as app.extensions["socketio"]
    # Load rules now so a bad config file fails at startup, not in the watcher thread.
    app.extensions["monitor"] = Monitor(Detector(load_rules(rules_file)), AlertStore(db_path))
    app.register_blueprint(api)

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/")
    def dashboard():
        return render_template(
            "dashboard.html", log_file=app.config["LOG_FILE"], rule_ids=list(ALL_RULES)
        )

    return app


def start_log_watcher(app: Flask, *, poll_interval: float = 1.0) -> threading.Event:
    """Run detection on the app's log file and push events and alerts to browsers.

    The whole existing file is processed first, so the dashboard's statistics
    cover it and alerts for activity that happened while the dashboard was down
    are still raised. Alerts already in the store aren't announced twice.

    Returns an event that stops the watcher when set.
    """
    socketio: SocketIO = app.extensions["socketio"]
    tailer = LogTailer(app.config["LOG_FILE"], from_start=True)
    stop = threading.Event()

    def watch() -> None:
        log.info("Watching %s", tailer.path)
        while not stop.is_set():
            try:
                publish_new_events(app, tailer)
            except Exception:  # e.g. permissions changed; keep watching rather than die silently
                log.exception("Failed to process %s", tailer.path)
            stop.wait(poll_interval)

    socketio.start_background_task(watch)
    return stop


def publish_new_events(app: Flask, tailer: LogTailer) -> int:
    """Process newly logged lines; return how many auth events they contained."""
    socketio: SocketIO = app.extensions["socketio"]
    monitor: Monitor = app.extensions["monitor"]

    count = 0
    for event in parse_lines(tailer.poll()):
        count += 1
        socketio.emit("auth_event", event.to_dict())
        for alert in monitor.process(event):
            log.warning("%s: %s", alert.severity.name, alert.title)
            socketio.emit("alert", alert.to_dict())
    return count
