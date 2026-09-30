"""Flask + Socket.IO dashboard: a summary page and a live event feed."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

from .parser import parse_file, parse_lines
from .stats import summarize
from .tailer import LogTailer

log = logging.getLogger(__name__)


def create_app(log_file: str | Path) -> Flask:
    app = Flask(__name__)
    app.config["LOG_FILE"] = str(log_file)
    SocketIO(app, async_mode="threading")  # registers itself as app.extensions["socketio"]

    @app.get("/")
    def summary_page():
        log_file = app.config["LOG_FILE"]
        try:
            summary = summarize(parse_file(log_file))
        except OSError as exc:
            return render_template("summary.html", log_file=log_file, error=exc.strerror), 503
        return render_template("summary.html", log_file=log_file, summary=summary)

    @app.get("/live")
    def live_page():
        return render_template("live.html", log_file=app.config["LOG_FILE"])

    return app


def start_log_watcher(app: Flask, *, poll_interval: float = 1.0) -> threading.Event:
    """Push new auth events from the app's log file to connected browsers.

    Returns an event that stops the watcher when set.
    """
    socketio: SocketIO = app.extensions["socketio"]
    tailer = LogTailer(app.config["LOG_FILE"])
    stop = threading.Event()

    def watch() -> None:
        log.info("Watching %s", tailer.path)
        while not stop.is_set():
            try:
                publish_new_events(socketio, tailer)
            except Exception:  # e.g. permissions changed; keep watching rather than die silently
                log.exception("Failed to read %s", tailer.path)
            stop.wait(poll_interval)

    socketio.start_background_task(watch)
    return stop


def publish_new_events(socketio: SocketIO, tailer: LogTailer) -> int:
    """Emit an ``auth_event`` message for each new event; return how many were sent."""
    sent = 0
    for event in parse_lines(tailer.poll()):
        socketio.emit("auth_event", event.to_dict())
        sent += 1
    return sent
