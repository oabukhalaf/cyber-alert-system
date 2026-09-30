"""Command-line interface: ``cyber-alert summary | watch | serve``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from collections.abc import Sequence

from . import __version__
from .parser import AuthEvent, EventType, parse_file, parse_line
from .stats import Summary, summarize
from .tailer import follow

FALLBACK_LOG_FILE = "logs/sample_auth.log"

_EVENT_LABELS = {
    EventType.AUTH_FAILURE: "FAILED",
    EventType.AUTH_SUCCESS: "ACCEPTED",
    EventType.INVALID_USER: "INVALID",
}


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.handler(args)


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

    watch = commands.add_parser("watch", help="print authentication events as they're logged")
    watch.add_argument("log_file", **log_file_args)
    watch.add_argument(
        "--from-start", action="store_true", help="replay existing lines before following"
    )
    watch.add_argument(
        "--interval", type=float, default=1.0, help="seconds between polls (default: 1.0)"
    )
    watch.set_defaults(handler=_run_watch)

    serve = commands.add_parser("serve", help="run the web dashboard")
    serve.add_argument("log_file", **log_file_args)
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


def _run_watch(args: argparse.Namespace) -> int:
    print(f"Watching {args.log_file} (Ctrl+C to stop)", file=sys.stderr)
    try:
        lines = follow(args.log_file, from_start=args.from_start, poll_interval=args.interval)
        for line in lines:
            if (event := parse_line(line)) is not None:
                print(format_event(event), flush=True)
    except KeyboardInterrupt:
        pass
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    from .web import create_app, start_log_watcher  # Flask is only needed for this command.

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app(args.log_file)
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


def _display(value: str) -> str:
    """Render attacker-controlled log text safely for a terminal.

    Escaping control characters stops a crafted username from injecting ANSI
    escape sequences that could rewrite or hide earlier terminal output.
    """
    if not value:
        return "(empty)"
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
