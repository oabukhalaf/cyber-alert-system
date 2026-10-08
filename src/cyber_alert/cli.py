"""Command-line interface for ``cyber-alert`` and its subcommands."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone

from . import __version__
from .alerts import BRUTE_FORCE, Alert, Severity
from .config import ConfigError, load_config
from .detection import Detector
from .notify import DeliveryError, Notifier
from .parser import AuthEvent, EventType, parse_file, parse_line
from .simulate import run as run_simulation
from .stats import Summary, summarize
from .store import AlertStore
from .tailer import follow
from .text import printable

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

    config_args = {
        "metavar": "FILE",
        "default": os.environ.get("CYBER_ALERT_CONFIG"),
        "help": "YAML settings, e.g. config/cyber-alert.yaml "
        "(default: $CYBER_ALERT_CONFIG or built-in settings)",
    }

    detect = commands.add_parser("detect", help="run detection rules over a log file")
    detect.add_argument("log_file", **log_file_args)
    detect.add_argument("--config", **config_args)
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
    watch.add_argument("--config", **config_args)
    watch.add_argument("--db", metavar="FILE", help="also save alerts to this SQLite database")
    watch.set_defaults(handler=_run_watch)

    serve = commands.add_parser("serve", help="run the web dashboard")
    serve.add_argument("log_file", **log_file_args)
    serve.add_argument("--config", **config_args)
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

    test = commands.add_parser(
        "test-notifications", help="send a test alert to every configured notification channel"
    )
    test.add_argument("--config", **config_args)
    test.set_defaults(handler=_run_test_notifications)

    simulate = commands.add_parser(
        "simulate", help="write simulated SSH traffic, attacks included, to a log file"
    )
    simulate.add_argument("log_file", help="log file to append to (created if missing)")
    simulate.add_argument(
        "--speed",
        type=_positive_float,
        default=1.0,
        help="time multiplier, e.g. 5 to run five times faster (default: 1)",
    )
    simulate.add_argument(
        "--duration",
        type=_positive_float,
        metavar="SECONDS",
        help="stop after this many simulated seconds (default: run until stopped)",
    )
    simulate.add_argument("--seed", type=int, help="random seed, for repeatable traffic")
    simulate.set_defaults(handler=_run_simulate)

    return parser


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = 0
    if not value > 0:
        raise argparse.ArgumentTypeError(f"expected a positive number, got {text!r}")
    return value


def _run_summary(args: argparse.Namespace) -> int:
    try:
        events = parse_file(args.log_file)
    except OSError as exc:
        print(f"error: cannot read {args.log_file}: {exc.strerror}", file=sys.stderr)
        return 1
    print(format_summary(summarize(events), source=args.log_file, top=args.top))
    return 0


def _run_detect(args: argparse.Namespace) -> int:
    detector = Detector(load_config(args.config).rules)
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
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    config = load_config(args.config)
    detector = Detector(config.rules)
    store = AlertStore(args.db) if args.db else None
    notifier = Notifier(config.channels, max_age=config.notify_max_age) if config.channels else None
    print(f"Watching {args.log_file} (Ctrl+C to stop)", file=sys.stderr)
    try:
        lines = follow(args.log_file, from_start=args.from_start, poll_interval=args.interval)
        for line in lines:
            if (event := parse_line(line)) is None:
                continue
            if not args.alerts_only:
                print(format_event(event), flush=True)
            for alert in detector.process(event):
                print(format_alert(alert), flush=True)
                # With a database, only alerts it hasn't seen are new (e.g. after a restart).
                is_new = store.add(alert) if store is not None else True
                if is_new and notifier is not None:
                    notifier.submit(alert)
    except KeyboardInterrupt:
        pass
    finally:
        if notifier is not None:
            notifier.close(timeout=10)
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    from .web import create_app, start_log_watcher  # Flask is only needed for this command.

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app(args.log_file, db_path=args.db, config_file=args.config)
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


def _run_test_notifications(args: argparse.Namespace) -> int:
    channels = load_config(args.config).channels
    if not channels:
        print(
            "No notification channels are configured. Add them under "
            "notifications: channels: in the config file.",
            file=sys.stderr,
        )
        return 1

    now = datetime.now(timezone.utc)
    alert = Alert(
        rule_id="test",
        severity=Severity.CRITICAL,
        technique=BRUTE_FORCE,
        title="Test notification from cyber-alert",
        description="If you can read this, alerts will reach this channel.",
        source_ip="192.0.2.1",
        usernames=("example",),
        event_count=1,
        first_seen=now,
        last_seen=now,
    )
    failed = 0
    for channel in channels:  # every channel, whatever its min_severity
        try:
            channel.send(alert)
        except DeliveryError as exc:
            failed += 1
            print(f"FAILED  {channel.describe()}: {exc}")
        else:
            print(f"OK      {channel.describe()}")
    return 1 if failed else 0


def _run_simulate(args: argparse.Namespace) -> int:
    print(f"Writing simulated SSH traffic to {args.log_file} (Ctrl+C to stop)", file=sys.stderr)
    try:
        written = run_simulation(
            args.log_file, speed=args.speed, duration=args.duration, seed=args.seed
        )
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"error: cannot write {args.log_file}: {exc.strerror}", file=sys.stderr)
        return 1
    print(f"Wrote {written} lines", file=sys.stderr)
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
        rows = [(printable(key), count) for key, count in counter.most_common(top)]
        width = max(len(label) for label, _ in rows)
        lines += ["", title]
        lines += [f"  {label:<{width}}  {count:>6}" for label, count in rows]
        if len(counter) > top:
            lines.append(f"  ... and {len(counter) - top} more")
    return "\n".join(lines)


def format_event(event: AuthEvent) -> str:
    text = (
        f"{event.timestamp:%Y-%m-%d %H:%M:%S}  {_EVENT_LABELS[event.event_type]:<8}  "
        f"{printable(event.username)} from {event.source_ip}"
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
        f"{alert.technique.id:<9}  {printable(alert.title)}\n"
        f"{'':21}{printable(alert.description)}"
    )


def format_alert_totals(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return "No alerts."
    counts = Counter(alert.severity for alert in alerts)
    breakdown = ", ".join(
        f"{counts[severity]} {severity.name.lower()}" for severity in sorted(counts, reverse=True)
    )
    return f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}: {breakdown}"
