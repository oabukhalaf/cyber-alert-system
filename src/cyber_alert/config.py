"""Load detection rule settings from a YAML file.

Example::

    rules:
      ssh-password-spray:
        distinct_users: 8
        window: 10m
      ssh-login-after-failures:
        enabled: false

Rules left out of the file run with their defaults. Settings are validated
against each rule's constructor, so a misspelled setting is an error rather
than silently ignored.
"""

from __future__ import annotations

import inspect
import re
import typing
from datetime import timedelta
from pathlib import Path

import yaml

from .detection import Rule
from .rules import ALL_RULES


class ConfigError(ValueError):
    pass


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Build the enabled rules, configured from ``path`` if given."""
    settings = _read_rule_settings(path) if path is not None else {}
    rules = []
    for rule_id, rule_class in ALL_RULES.items():
        params = dict(settings.get(rule_id) or {})
        enabled = params.pop("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{rule_id}.enabled: expected true or false, got {enabled!r}")
        if enabled:
            rules.append(_build_rule(rule_class, params))
    return rules


def default_settings(rule_class: type[Rule]) -> dict[str, object]:
    """A rule's constructor defaults, i.e. its settings when not configured."""
    return {
        name: parameter.default
        for name, parameter in inspect.signature(rule_class.__init__).parameters.items()
        if parameter.default is not inspect.Parameter.empty
    }


def parse_duration(value: object) -> timedelta:
    """Parse ``30``, ``"30s"``, ``"5m"``, ``"2h"`` or ``"1d"``; bare numbers are seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
    elif isinstance(value, str) and (match := _DURATION.fullmatch(value.strip())):
        seconds = float(match["amount"]) * _UNIT_SECONDS[match["unit"] or "s"]
    else:
        raise ConfigError(f"expected a duration like 30s, 5m or 1h, got {value!r}")
    if seconds <= 0:
        raise ConfigError(f"duration must be positive, got {value!r}")
    return timedelta(seconds=seconds)


_DURATION = re.compile(r"(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>[smhd]?)")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _read_rule_settings(path: str | Path) -> dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            document = yaml.safe_load(f)  # never yaml.load(): it can construct arbitrary objects
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: expected a top-level 'rules:' mapping")
    for rule_id, params in rules.items():
        if rule_id not in ALL_RULES:
            raise ConfigError(f"unknown rule {rule_id!r} (known rules: {', '.join(ALL_RULES)})")
        if params is not None and not isinstance(params, dict):
            raise ConfigError(f"{rule_id}: expected a mapping of settings")
    return rules


def _build_rule(rule_class: type[Rule], params: dict[str, object]) -> Rule:
    types = typing.get_type_hints(rule_class.__init__)
    known = default_settings(rule_class)
    kwargs = {}
    for name, value in params.items():
        where = f"{rule_class.id}.{name}"
        if name not in known:
            options = ", ".join(["enabled", *known])
            raise ConfigError(f"{where}: unknown setting (expected one of: {options})")
        try:
            kwargs[name] = _coerce(value, types[name])
        except ConfigError as exc:
            raise ConfigError(f"{where}: {exc}") from None
    return rule_class(**kwargs)


def _coerce(value: object, expected: type) -> object:
    if expected is timedelta:
        return parse_duration(value)
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigError(f"expected a positive whole number, got {value!r}")
        return value
    return value
