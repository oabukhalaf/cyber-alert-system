from datetime import timedelta
from pathlib import Path

import pytest

from cyber_alert.alerts import Severity
from cyber_alert.config import (
    ConfigError,
    default_settings,
    load_config,
    load_rules,
    parse_duration,
)
from cyber_alert.notify import DiscordChannel, EmailChannel, SlackChannel, WebhookChannel
from cyber_alert.rules import ALL_RULES, PasswordSprayRule

SHIPPED_CONFIG = Path(__file__).resolve().parents[1] / "config" / "cyber-alert.yaml"
SLACK_URL = "https://hooks.slack.com/services/T000/B000/secret-token"


def write_config(tmp_path, text):
    path = tmp_path / "cyber-alert.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def channels(tmp_path, text):
    return load_config(write_config(tmp_path, text)).channels


# --- Rules ------------------------------------------------------------------------


def test_without_a_file_every_rule_runs_with_defaults():
    rules = load_rules()

    assert [rule.id for rule in rules] == list(ALL_RULES)


def test_empty_file_means_defaults(tmp_path):
    config = load_config(write_config(tmp_path, ""))

    assert [rule.id for rule in config.rules] == list(ALL_RULES)
    assert config.channels == []


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
        ("rules: []\n", "rules: expected a mapping of rule settings"),
        ("- rules\n", "expected 'rules' and/or 'notifications' sections"),
        ("ruels: {}\n", "unknown section 'ruels'"),
        ("rules: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_config_is_rejected_with_a_clear_message(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, text))


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")


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

    assert set(shipped) == set(ALL_RULES), "config/cyber-alert.yaml should list every rule"
    for rule_id, rule_class in ALL_RULES.items():
        settings = dict(shipped[rule_id])
        assert settings.pop("enabled") is True
        expected = default_settings(rule_class)
        actual = {
            name: parse_duration(value) if isinstance(expected[name], timedelta) else value
            for name, value in settings.items()
        }
        assert actual == expected, f"config/cyber-alert.yaml doesn't match {rule_id}'s defaults"


def test_shipped_config_loads():
    config = load_config(SHIPPED_CONFIG)

    assert config.channels == []
    assert config.notify_max_age == timedelta(hours=1)


# --- Notifications --------------------------------------------------------------


def test_no_notifications_by_default():
    config = load_config()

    assert config.channels == []
    assert config.notify_max_age == timedelta(hours=1)


def test_every_channel_type(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
    monkeypatch.setenv("SMTP_PASSWORD", "hunter2")
    built = channels(
        tmp_path,
        """
notifications:
  channels:
    - type: slack
      webhook_url: ${SLACK_WEBHOOK_URL}
    - type: discord
      webhook_url: https://discord.com/api/webhooks/1/abc
    - type: webhook
      url: https://siem.example.com/hooks/ssh
      headers:
        Authorization: Bearer xyz
    - type: email
      smtp_host: smtp.example.com
      username: alerts
      password: ${SMTP_PASSWORD}
      from: alerts@example.com
      to: oncall@example.com
""",
    )

    slack, discord, webhook, email = built
    assert isinstance(slack, SlackChannel) and slack.webhook_url == SLACK_URL
    assert isinstance(discord, DiscordChannel)
    assert isinstance(webhook, WebhookChannel) and webhook.headers == {
        "Authorization": "Bearer xyz"
    }
    assert isinstance(email, EmailChannel)
    assert (email.smtp_port, email.security, email.password) == (587, "starttls", "hunter2")
    assert email.recipients == ["oncall@example.com"]


def test_email_port_follows_security_mode(tmp_path):
    [email] = channels(
        tmp_path,
        "notifications:\n  channels:\n    - {type: email, smtp_host: mail.example.com, "
        "security: ssl, from: a@example.com, to: [b@example.com, c@example.com]}\n",
    )

    assert (email.smtp_port, email.recipients) == (465, ["b@example.com", "c@example.com"])


def test_min_severity_defaults_overrides_and_max_age(tmp_path):
    config = load_config(
        write_config(
            tmp_path,
            "notifications:\n  min_severity: medium\n  max_age: 30m\n  channels:\n"
            f"    - {{type: slack, webhook_url: '{SLACK_URL}'}}\n"
            f"    - {{type: slack, webhook_url: '{SLACK_URL}', min_severity: critical}}\n",
        )
    )

    assert [c.min_severity for c in config.channels] == [Severity.MEDIUM, Severity.CRITICAL]
    assert config.notify_max_age == timedelta(minutes=30)


def test_channels_default_to_high_severity(tmp_path):
    [slack] = channels(
        tmp_path,
        f"notifications:\n  channels:\n    - {{type: slack, webhook_url: '{SLACK_URL}'}}\n",
    )

    assert slack.min_severity is Severity.HIGH


def test_http_is_allowed_only_to_this_machine(tmp_path):
    [webhook] = channels(
        tmp_path,
        "notifications:\n  channels:\n    - {type: webhook, url: 'http://127.0.0.1:9000/hook'}\n",
    )

    assert webhook.url == "http://127.0.0.1:9000/hook"


def test_missing_environment_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    with pytest.raises(ConfigError, match=r"channels\[0\]: environment variable SLACK_WEBHOOK_URL"):
        channels(
            tmp_path,
            "notifications:\n  channels:\n"
            "    - {type: slack, webhook_url: '${SLACK_WEBHOOK_URL}'}\n",
        )


@pytest.mark.parametrize(
    ("channel", "message"),
    [
        ("{type: pager}", r"\.type: expected one of slack, discord, webhook, email"),
        ("{type: slack}", "missing required setting 'webhook_url'"),
        (
            "{type: slack, webhook_url: 'https://x.example', channel: '#ops'}",
            "channel: unknown slack setting",
        ),
        ("{type: slack, webhook_url: 'http://hooks.slack.com/x'}", "expected an https:// URL"),
        ("{type: slack, webhook_url: 'not a url'}", "expected an https:// URL"),
        ("{type: webhook, url: 'http://[::1'}", "expected an https:// URL"),
        ("{type: webhook, url: 'https://x.example', headers: [a]}", "expected a mapping of header"),
        (
            "{type: slack, webhook_url: 'https://x.example', min_severity: urgent}",
            "expected one of",
        ),
        (
            "{type: email, smtp_host: h, from: a@x.com, to: b@x.com, smtp_port: 99999}",
            "smtp_port: expected a port number",
        ),
        (
            "{type: email, smtp_host: h, from: a@x.com, to: b@x.com, security: tls}",
            "unknown security mode 'tls'",
        ),
        ("{type: email, smtp_host: h, from: a@x.com, to: []}", "to: expected an address"),
        ("slack", "expected a mapping of channel settings"),
    ],
)
def test_invalid_channels_are_rejected(tmp_path, channel, message):
    with pytest.raises(ConfigError, match=message):
        channels(tmp_path, f"notifications:\n  channels:\n    - {channel}\n")


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ("[]", "notifications: expected a mapping"),
        ("{channels: {type: slack}}", "channels: expected a list"),
        ("{min_severity: urgent}", "notifications.min_severity: expected one of"),
        ("{max_age: soon}", "notifications.max_age: expected a duration"),
        ("{retries: 3}", "notifications.retries: unknown setting"),
    ],
)
def test_invalid_notification_settings(tmp_path, section, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, f"notifications: {section}\n"))


def test_errors_never_echo_secret_values(tmp_path):
    secret = "http://hooks.slack.com/services/T000/B000/secret-token"

    with pytest.raises(ConfigError) as error:
        channels(
            tmp_path,
            f"notifications:\n  channels:\n    - {{type: slack, webhook_url: '{secret}'}}\n",
        )

    assert "secret-token" not in str(error.value)
