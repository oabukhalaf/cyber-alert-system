"""Persist alerts in SQLite so they outlive restarts and log rotation."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .alerts import Alert, Severity, Technique

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    rule_id         TEXT    NOT NULL,
    severity        INTEGER NOT NULL,
    technique_id    TEXT    NOT NULL,
    technique_name  TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    usernames       TEXT    NOT NULL,  -- JSON array
    event_count     INTEGER NOT NULL,
    first_seen      TEXT    NOT NULL,  -- ISO 8601 in UTC, so text order is time order
    last_seen       TEXT    NOT NULL,
    -- Rules are deterministic, so re-reading a log recreates identical alerts.
    UNIQUE (rule_id, source_ip, first_seen)
);
CREATE INDEX IF NOT EXISTS alerts_by_last_seen ON alerts (last_seen);
"""


class AlertStore:
    """SQLite-backed alert history.

    Each call opens its own connection, so one store can be shared by the log
    watcher thread and web request threads (sqlite3 connections can't be).
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode = WAL")  # readers don't block the writer
            db.executescript(_SCHEMA)

    def add(self, alert: Alert) -> bool:
        """Save ``alert``; return False if it was already stored."""
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    rule_id, severity, technique_id, technique_name, title, description,
                    source_ip, usernames, event_count, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.rule_id,
                    int(alert.severity),
                    alert.technique.id,
                    alert.technique.name,
                    alert.title,
                    alert.description,
                    alert.source_ip,
                    json.dumps(alert.usernames),
                    alert.event_count,
                    _to_utc_text(alert.first_seen),
                    _to_utc_text(alert.last_seen),
                ),
            )
            return cursor.rowcount == 1

    def recent(self, limit: int = 100) -> list[Alert]:
        """The most recent alerts, newest first."""
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM alerts ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_from_row(row) for row in rows]

    def count_by_severity(self) -> dict[Severity, int]:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
        return {Severity(severity): count for severity, count in rows}

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db


def _to_utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _from_row(row: sqlite3.Row) -> Alert:
    return Alert(
        rule_id=row["rule_id"],
        severity=Severity(row["severity"]),
        technique=Technique(row["technique_id"], row["technique_name"]),
        title=row["title"],
        description=row["description"],
        source_ip=row["source_ip"],
        usernames=tuple(json.loads(row["usernames"])),
        event_count=row["event_count"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
    )
