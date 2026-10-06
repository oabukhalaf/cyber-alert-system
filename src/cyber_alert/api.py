"""Read-only JSON API under /api, used by the dashboard and available to scripts."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .alerts import Severity
from .config import ConfigError, parse_duration
from .monitor import Monitor

api = Blueprint("api", __name__, url_prefix="/api")

MAX_LIMIT = 500


class InvalidParameter(ValueError):
    pass


@api.errorhandler(InvalidParameter)
def _invalid_parameter(exc: InvalidParameter):
    return jsonify(error=str(exc)), 400


@api.get("/summary")
def summary():
    data = _monitor().summary(top=_limit_arg("top", default=10))
    data["log_file"] = current_app.config["LOG_FILE"]
    return jsonify(data)


@api.get("/timeline")
def timeline():
    requested = request.args.get("bucket", "auto")
    try:
        size = None if requested == "auto" else parse_duration(requested)
        size, buckets = _monitor().timeline(size)
    except (ConfigError, ValueError) as exc:
        raise InvalidParameter(f"bucket: {exc}") from None
    return jsonify(
        bucket_seconds=int(size.total_seconds()),
        buckets=[
            {
                "start": bucket.start.isoformat(),
                "failures": bucket.failures,
                "successes": bucket.successes,
            }
            for bucket in buckets
        ],
    )


@api.get("/alerts")
def alerts():
    severity = request.args.get("severity")
    if severity is not None and severity.upper() not in Severity.__members__:
        choices = ", ".join(s.name.lower() for s in Severity)
        raise InvalidParameter(f"severity: expected one of {choices}")
    found = _monitor().store.recent(
        _limit_arg("limit", default=100),
        min_severity=Severity[severity.upper()] if severity else None,
        rule_id=request.args.get("rule") or None,
        source_ip=request.args.get("source_ip") or None,
    )
    return jsonify(alerts=[alert.to_dict() for alert in found])


@api.get("/events")
def events():
    recent = _monitor().recent_events(_limit_arg("limit", default=100))
    return jsonify(events=[event.to_dict() for event in recent])


def _monitor() -> Monitor:
    return current_app.extensions["monitor"]


def _limit_arg(name: str, *, default: int) -> int:
    raw = request.args.get(name)
    if raw is None:
        return default
    # isascii() too: str.isdigit() accepts characters like "²" that int() rejects.
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= MAX_LIMIT:
        raise InvalidParameter(f"{name}: expected a whole number from 1 to {MAX_LIMIT}")
    return int(raw)
