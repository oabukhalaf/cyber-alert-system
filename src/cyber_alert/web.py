"""Flask + Socket.IO dashboard: login summary, alert history and a live feed."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

from .alerts import Severity
from .config import load_rules
from .detection import Detector
from .parser import parse_file, parse_lines
from .stats import summarize
from .store import AlertStore
from .tailer import LogTailer

log = logging.getLogger(__name__)


def create_app(
    log_file: str | Path, *, db_path: str | Path, rules_file: str | Path | None = None
) -> Flask:
    app = Flask(__name__)
    app.config["LOG_FILE"] = str(log_file)
    SocketIO(app, async_mode="threading")  # registers itself as app.extensions["socketio"]
    app.extensions["alert_store"] = store = AlertStore(db_path)
    # Load rules now so a bad config file fails at startup, not in the watcher thread.
    app.extensions["detector"] = Detector(load_rules(rules_file))

    @app.context_processor
    def template_helpers():
        return {"Severity": Severity}

    @app.get("/")
    def summary_page():
        log_file = app.config["LOG_FILE"]
        alert_counts = store.count_by_severity()
        try:
            summary = summarize(parse_file(log_file))
        except OSError as exc:
            return render_template(
                "summary.html", log_file=log_file, alert_counts=alert_counts, error=exc.strerror
            ), 503
        return render_template(
            "summary.html", log_file=log_file, alert_counts=alert_counts, summary=summary
        )

    @app.get("/alerts")
    def alerts_page():
        return render_template("alerts.html", alerts=store.recent(limit=200))

    @app.get("/live")
    def live_page():
        return render_template("live.html", log_file=app.config["LOG_FILE"])

    return app


def start_log_watcher(app: Flask, *, poll_interval: float = 1.0) -> threading.Event:
    """Run detection on the app's log file and push events and alerts to browsers.

    The whole existing file is processed first, so alerts for activity that
    happened while the dashboard was down are still raised. Alerts already in
    the store are recognized and not announced twice.

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
    detector: Detector = app.extensions["detector"]
    store: AlertStore = app.extensions["alert_store"]

    count = 0
    for event in parse_lines(tailer.poll()):
        count += 1
        socketio.emit("auth_event", event.to_dict())
        for alert in detector.process(event):
            if store.add(alert):
                log.warning("%s: %s", alert.severity.name, alert.title)
                socketio.emit("alert", alert.to_dict())
    return count
