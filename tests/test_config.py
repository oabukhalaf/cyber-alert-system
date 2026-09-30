from datetime import timedelta
from pathlib import Path

import pytest

from cyber_alert.config import ConfigError, default_settings, load_rules, parse_duration
from cyber_alert.rules import ALL_RULES, PasswordSprayRule

SHIPPED_CONFIG = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"


def write_config(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_without_a_file_every_rule_runs_with_defaults():
    rules = load_rules()

    assert [rule.id for rule in rules] == list(ALL_RULES)


def test_settings_override_defaults(tmp_path):
    config = write_config(
        tmp_path,
        "rules:\n  ssh-password-spray:\n    distinct_users: 8\n    window: 10m\n",
    )

    [spray] = [rule for rule in load_rules(config) if isinstance(rule, PasswordSprayRule)]

    assert spray.distinct_users == 8
    assert spray._attempts.duration == timedelta(minutes=10)


def test_rules_can_be_disabled(tmp_path):
    config = write_config(tmp_path, "rules:\n  ssh-password-spray:\n    enabled: false\n")

    assert "ssh-password-spray" not in [rule.id for rule in load_rules(config)]


def test_rule_listed_without_settings_uses_defaults(tmp_path):
    config = write_config(tmp_path, "rules:\n  ssh-password-spray:\n")

    assert "ssh-password-spray" in [rule.id for rule in load_rules(config)]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("rules:\n  ssh-nope: {}\n", "unknown rule 'ssh-nope'"),
        ("rules:\n  ssh-password-spray:\n    treshold: 3\n", "treshold: unknown setting"),
        ("rules:\n  ssh-password-spray:\n    window: soon\n", "window: expected a duration"),
        ("rules:\n  ssh-password-spray:\n    distinct_users: 0\n", "expected a positive whole"),
        ("rules:\n  ssh-password-spray:\n    distinct_users: 2.5\n", "expected a positive whole"),
        ("rules:\n  ssh-password-spray:\n    enabled: maybe\n", "expected true or false"),
        ("rules:\n  ssh-password-spray: 5\n", "expected a mapping of settings"),
        ("rules: []\n", "expected a top-level 'rules:' mapping"),
        ("", "expected a top-level 'rules:' mapping"),
        ("rules: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_config_is_rejected_with_a_clear_message(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_rules(write_config(tmp_path, text))


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_rules(tmp_path / "missing.yaml")


@pytest.mark.parametrize(
    ("value", "seconds"),
    [(30, 30), (1.5, 1.5), ("45", 45), ("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)],
)
def test_parse_duration(value, seconds):
    assert parse_duration(value) == timedelta(seconds=seconds)


@pytest.mark.parametrize("value", [0, -5, "0m", "5 minutes", True, None])
def test_parse_duration_rejects_invalid_values(value):
    with pytest.raises(ConfigError):
        parse_duration(value)


def test_shipped_config_lists_every_rule_with_its_defaults():
    import yaml

    shipped = yaml.safe_load(SHIPPED_CONFIG.read_text(encoding="utf-8"))["rules"]

    assert list(shipped) == list(ALL_RULES), "config/rules.yaml should list every rule"
    for rule_id, rule_class in ALL_RULES.items():
        settings = dict(shipped[rule_id])
        assert settings.pop("enabled") is True
        expected = default_settings(rule_class)
        actual = {
            name: parse_duration(value) if isinstance(expected[name], timedelta) else value
            for name, value in settings.items()
        }
        assert actual == expected, f"config/rules.yaml doesn't match {rule_id}'s defaults"
