"""Command-line interface: ``cyber-alert summary | detect | watch | serve``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from collections.abc import Sequence

from . import __version__
from .alerts import Alert
from .config import ConfigError, load_rules
from .detection import Detector
from .parser import AuthEvent, EventType, parse_file, parse_line
from .stats import Summary, summarize
from .store import AlertStore
from .tailer import follow

FALLBACK_LOG_FILE = "logs/sample_auth.log"
DEFAULT_DB_FILE = "cyber-alert.db"

_EVENT_LABELS = {
    EventType.AUTH_FAILURE: "FAILED",
    EventType.AUTH_SUCCESS: "ACCEPTED",
    EventType.INVALID_USER: "INVALID",
}


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber-alert", description="Monitor SSH authentication logs for suspicious activity."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    default_log = os.environ.get("CYBER_ALERT_LOG_FILE", FALLBACK_LOG_FILE)
    log_file_args = {
        "nargs": "?",
        "default": default_log,
        "help": f"auth log to read (default: $CYBER_ALERT_LOG_FILE or {FALLBACK_LOG_FILE})",
    }

    summary = commands.add_parser("summary", help="print login statistics for a log file")
    summary.add_argument("log_file", **log_file_args)
    summary.add_argument("--top", type=int, default=10, help="rows per table (default: 10)")
    summary.set_defaults(handler=_run_summary)

    rules_args = {
        "metavar": "FILE",
        "help": "YAML rule settings, e.g. config/rules.yaml (default: built-in settings)",
    }

    detect = commands.add_parser("detect", help="run detection rules over a log file")
    detect.add_argument("log_file", **log_file_args)
    detect.add_argument("--rules", **rules_args)
    detect.add_argument("--db", metavar="FILE", help="also save alerts to this SQLite database")
    detect.set_defaults(handler=_run_detect)

    watch = commands.add_parser("watch", help="print events and alerts as they're logged")
    watch.add_argument("log_file", **log_file_args)
    watch.add_argument(
        "--from-start", action="store_true", help="replay existing lines before following"
    )
    watch.add_argument(
        "--interval", type=float, default=1.0, help="seconds between polls (default: 1.0)"
    )
    watch.add_argument("--alerts-only", action="store_true", help="print alerts but not events")
    watch.add_argument("--rules", **rules_args)
    watch.add_argument("--db", metavar="FILE", help="also save alerts to this SQLite database")
    watch.set_defaults(handler=_run_watch)

    serve = commands.add_parser("serve", help="run the web dashboard")
    serve.add_argument("log_file", **log_file_args)
    serve.add_argument("--rules", **rules_args)
    serve.add_argument(
        "--db",
        metavar="FILE",
        default=DEFAULT_DB_FILE,
        help=f"SQLite database for alert history (default: {DEFAULT_DB_FILE})",
    )
    serve.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=5000, help="port to bind (default: 5000)")
    serve.add_argument(
        "--debug",
        action="store_true",
        help="enable Flask's debugger, which allows code execution; local use only",
    )
    serve.set_defaults(handler=_run_serve)

    return parser


def _run_summary(args: argparse.Namespace) -> int:
    try:
        events = parse_file(args.log_file)
    except OSError as exc:
        print(f"error: cannot read {args.log_file}: {exc.strerror}", file=sys.stderr)
        return 1
    print(format_summary(summarize(events), source=args.log_file, top=args.top))
    return 0


def _run_detect(args: argparse.Namespace) -> int:
    detector = Detector(load_rules(args.rules))
    try:
        events = parse_file(args.log_file)
    except OSError as exc:
        print(f"error: cannot read {args.log_file}: {exc.strerror}", file=sys.stderr)
        return 1

    alerts = list(detector.run(events))
    for alert in alerts:
        print(format_alert(alert))
    if alerts:
        print()
    print(format_alert_totals(alerts))
    if args.db:
        store = AlertStore(args.db)
        saved = sum(store.add(alert) for alert in alerts)
        print(f"Saved {saved} new alert(s) to {args.db}")
    return 0


def _run_watch(args: argparse.Namespace) -> int:
    detector = Detector(load_rules(args.rules))
    store = AlertStore(args.db) if args.db else None
    print(f"Watching {args.log_file} (Ctrl+C to stop)", file=sys.stderr)
    try:
        lines = follow(args.log_file, from_start=args.from_start, poll_interval=args.interval)
        for line in lines:
            if (event := parse_line(line)) is None:
                continue
            if not args.alerts_only:
                print(format_event(event), flush=True)
            for alert in detector.process(event):
                if store is not None:
                    store.add(alert)
                print(format_alert(alert), flush=True)
    except KeyboardInterrupt:
        pass
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    from .web import create_app, start_log_watcher  # Flask is only needed for this command.

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app(args.log_file, db_path=args.db, rules_file=args.rules)
    start_log_watcher(app)
    # The development server is fine for a single-user dashboard bound to localhost.
    app.extensions["socketio"].run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
    return 0


def format_summary(summary: Summary, *, source: str, top: int = 10) -> str:
    if summary.total_events == 0:
        return f"No SSH authentication events found in {source}."

    lines = [
        f"Summary of {source}",
        f"  {summary.total_events} auth events from {summary.first_seen:%Y-%m-%d %H:%M:%S} "
        f"to {summary.last_seen:%Y-%m-%d %H:%M:%S}",
        f"  {summary.total_failures} failed, {summary.total_successes} successful",
    ]
    tables: list[tuple[str, Counter[str]]] = [
        ("Failed logins by source IP", summary.failures_by_ip),
        ("Successful logins by source IP", summary.successes_by_ip),
        ("Login attempts by username", summary.attempts_by_user),
        ("Nonexistent usernames tried", summary.invalid_usernames),
    ]
    for title, counter in tables:
        if not counter:
            continue
        rows = [(_display(key), count) for key, count in counter.most_common(top)]
        width = max(len(label) for label, _ in rows)
        lines += ["", title]
        lines += [f"  {label:<{width}}  {count:>6}" for label, count in rows]
        if len(counter) > top:
            lines.append(f"  ... and {len(counter) - top} more")
    return "\n".join(lines)


def format_event(event: AuthEvent) -> str:
    text = (
        f"{event.timestamp:%Y-%m-%d %H:%M:%S}  {_EVENT_LABELS[event.event_type]:<8}  "
        f"{_display(event.username)} from {event.source_ip}"
    )
    if event.method:
        text += f" via {event.method}"
    if event.invalid_user and event.event_type is not EventType.INVALID_USER:
        text += " (nonexistent user)"
    if event.count > 1:
        text += f" x{event.count}"
    return text


def format_alert(alert: Alert) -> str:
    return (
        f"{alert.last_seen:%Y-%m-%d %H:%M:%S}  ALERT  {alert.severity.name:<8}  "
        f"{alert.technique.id:<9}  {_display(alert.title)}\n"
        f"{'':21}{_display(alert.description)}"
    )


def format_alert_totals(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return "No alerts."
    counts = Counter(alert.severity for alert in alerts)
    breakdown = ", ".join(
        f"{counts[severity]} {severity.name.lower()}" for severity in sorted(counts, reverse=True)
    )
    return f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}: {breakdown}"


def _display(value: str) -> str:
    """Render attacker-controlled log text safely for a terminal.

    Escaping control characters stops a crafted username from injecting ANSI
    escape sequences that could rewrite or hide earlier terminal output.
    """
    if not value:
        return "(empty)"
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
