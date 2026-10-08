"""Load settings from a YAML config file.

Example::

    rules:
      ssh-password-spray:
        distinct_users: 8
        window: 10m
      ssh-login-after-failures:
        enabled: false

    notifications:
      min_severity: high
      channels:
        - type: slack
          webhook_url: ${SLACK_WEBHOOK_URL}

Both sections are optional. Rules left out run with their defaults. Settings
are validated against each rule's constructor and each channel's schema, so a
misspelled setting is an error rather than silently ignored. Secrets belong in
environment variables, referenced as ``${NAME}`` in notification settings.
"""

from __future__ import annotations

import inspect
import os
import re
import typing
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .alerts import Severity
from .detection import Rule
from .notify import Channel, DiscordChannel, EmailChannel, SlackChannel, WebhookChannel
from .rules import ALL_RULES


class ConfigError(ValueError):
    pass


DEFAULT_NOTIFY_MAX_AGE = timedelta(hours=1)


@dataclass
class Config:
    rules: list[Rule]
    channels: list[Channel] = field(default_factory=list)
    notify_max_age: timedelta = DEFAULT_NOTIFY_MAX_AGE


def load_config(path: str | Path | None = None) -> Config:
    """Build the enabled rules and notification channels, configured from ``path`` if given."""
    document = _read_document(path) if path is not None else {}
    unknown = set(document) - {"rules", "notifications"}
    if unknown:
        raise ConfigError(
            f"unknown section {sorted(unknown)[0]!r} (expected 'rules' and/or 'notifications')"
        )
    channels, max_age = _build_notifications(document.get("notifications"))
    return Config(_build_rules(document.get("rules")), channels, max_age)


def load_rules(path: str | Path | None = None) -> list[Rule]:
    return load_config(path).rules


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


def _read_document(path: str | Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            document = yaml.safe_load(f)  # never yaml.load(): it can construct arbitrary objects
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ConfigError(f"{path}: expected 'rules' and/or 'notifications' sections")
    return document


# --- Rules --------------------------------------------------------------------------


def _build_rules(settings: object) -> list[Rule]:
    if settings is None:
        settings = {}
    if not isinstance(settings, dict):
        raise ConfigError("rules: expected a mapping of rule settings")
    for rule_id, params in settings.items():
        if rule_id not in ALL_RULES:
            raise ConfigError(f"unknown rule {rule_id!r} (known rules: {', '.join(ALL_RULES)})")
        if params is not None and not isinstance(params, dict):
            raise ConfigError(f"{rule_id}: expected a mapping of settings")

    rules = []
    for rule_id, rule_class in ALL_RULES.items():
        params = dict(settings.get(rule_id) or {})
        enabled = params.pop("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{rule_id}.enabled: expected true or false, got {enabled!r}")
        if enabled:
            rules.append(_build_rule(rule_class, params))
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


# --- Notifications ----------------------------------------------------------------

# Per channel type: the class, then each setting's type and whether it's required.
_CHANNELS: dict[str, tuple[type[Channel], dict[str, tuple[type, bool]]]] = {
    "slack": (SlackChannel, {"webhook_url": (str, True)}),
    "discord": (DiscordChannel, {"webhook_url": (str, True)}),
    "webhook": (WebhookChannel, {"url": (str, True), "headers": (dict, False)}),
    "email": (
        EmailChannel,
        {
            "smtp_host": (str, True),
            "smtp_port": (int, False),
            "security": (str, False),
            "username": (str, False),
            "password": (str, False),
            "from": (str, True),
            "to": (list, True),
        },
    ),
}
_ARGUMENT_NAMES = {"from": "sender", "to": "recipients"}
_URL_SETTINGS = {"webhook_url", "url"}
_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _build_notifications(section: object) -> tuple[list[Channel], timedelta]:
    if section is None:
        return [], DEFAULT_NOTIFY_MAX_AGE
    if not isinstance(section, dict):
        raise ConfigError("notifications: expected a mapping")
    unknown = set(section) - {"min_severity", "max_age", "channels"}
    if unknown:
        raise ConfigError(
            f"notifications.{sorted(unknown)[0]}: unknown setting "
            "(expected one of: min_severity, max_age, channels)"
        )

    default_severity = _severity(
        section.get("min_severity", "high"), where="notifications.min_severity"
    )
    try:
        max_age = parse_duration(section.get("max_age", "1h"))
    except ConfigError as exc:
        raise ConfigError(f"notifications.max_age: {exc}") from None

    specs = section.get("channels") or []
    if not isinstance(specs, list):
        raise ConfigError("notifications.channels: expected a list of channels")
    channels = [
        _build_channel(spec, default_severity, where=f"notifications.channels[{index}]")
        for index, spec in enumerate(specs)
    ]
    return channels, max_age


def _build_channel(spec: object, default_severity: Severity, *, where: str) -> Channel:
    # Error messages never echo setting values: they may be secrets.
    if not isinstance(spec, dict):
        raise ConfigError(f"{where}: expected a mapping of channel settings")
    spec = _expand_env(spec, where)
    kind = spec.get("type")
    if kind not in _CHANNELS:
        raise ConfigError(f"{where}.type: expected one of {', '.join(_CHANNELS)}")
    channel_class, schema = _CHANNELS[kind]

    for name in spec:
        if name not in ("type", "min_severity", *schema):
            options = ", ".join(["min_severity", *schema])
            raise ConfigError(
                f"{where}.{name}: unknown {kind} setting (expected one of: {options})"
            )
    for name, (_, required) in schema.items():
        if required and name not in spec:
            raise ConfigError(f"{where}: missing required setting '{name}'")

    kwargs: dict[str, object] = {
        "min_severity": _severity(spec["min_severity"], where=f"{where}.min_severity")
        if "min_severity" in spec
        else default_severity
    }
    for name, (expected, _) in schema.items():
        if name in spec:
            value = _check_type(spec[name], expected, where=f"{where}.{name}")
            if name in _URL_SETTINGS:
                _check_url(value, where=f"{where}.{name}")
            kwargs[_ARGUMENT_NAMES.get(name, name)] = value
    try:
        return channel_class(**kwargs)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def _expand_env(value: object, where: str) -> object:
    """Replace ``${NAME}`` in strings with environment variables, failing if one is unset."""
    if isinstance(value, str):

        def substitute(match: re.Match[str]) -> str:
            name = match[1]
            if name not in os.environ:
                raise ConfigError(f"{where}: environment variable {name} is not set")
            return os.environ[name]

        return _ENV_REFERENCE.sub(substitute, value)
    if isinstance(value, list):
        return [_expand_env(item, where) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item, where) for key, item in value.items()}
    return value


def _check_type(value: object, expected: type, *, where: str) -> object:
    if expected is list and isinstance(value, str):
        value = [value]  # a single email address
    if expected is str:
        valid = isinstance(value, str) and bool(value)
    elif expected is int:
        valid = isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535
    elif expected is list:
        valid = isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)
    else:
        valid = isinstance(value, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        )
    if valid:
        return value
    description = {
        str: "non-empty text",
        int: "a port number",
        list: "an address or list of addresses",
        dict: "a mapping of header names to values",
    }[expected]
    raise ConfigError(f"{where}: expected {description}")


def _check_url(url: str, *, where: str) -> None:
    try:
        parts = urlsplit(url)
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    except ValueError:  # e.g. an unclosed "[" in an IPv6 host
        raise ConfigError(f"{where}: expected an https:// URL") from None
    # Webhook URLs contain tokens, so plain http is only allowed to this machine.
    if not parts.hostname or not (parts.scheme == "https" or (parts.scheme == "http" and local)):
        raise ConfigError(f"{where}: expected an https:// URL")


def _severity(value: object, *, where: str) -> Severity:
    if isinstance(value, str) and value.upper() in Severity.__members__:
        return Severity[value.upper()]
    choices = ", ".join(severity.name.lower() for severity in Severity)
    raise ConfigError(f"{where}: expected one of {choices}")
