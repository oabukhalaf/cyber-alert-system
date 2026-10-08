import smtplib
import socket
import threading
from dataclasses import replace
from datetime import timedelta

import pytest
from factories import START, failure, success

from cyber_alert.alerts import Severity
from cyber_alert.notify import (
    DISCORD_MAX_LENGTH,
    Channel,
    DeliveryError,
    DiscordChannel,
    EmailChannel,
    Notifier,
    SlackChannel,
    WebhookChannel,
    discord_payload,
    email_message,
    slack_payload,
)
from cyber_alert.rules import LoginAfterFailuresRule

NOW = START + timedelta(minutes=5)


def make_alert(title="Login as deploy from 192.0.2.77 after repeated failures", **changes):
    events = [failure("deploy", ip="192.0.2.77", at=0), success("deploy", ip="192.0.2.77", at=5)]
    alert = LoginAfterFailuresRule().alert(title=title, description="d", events=events)
    return replace(alert, **changes)


class RecordingChannel(Channel):
    kind = "recording"

    def __init__(self, *, fail_with=None, **kwargs):
        super().__init__(**kwargs)
        self.sent = []
        self.fail_with = fail_with

    def send(self, alert):
        if self.fail_with:
            raise self.fail_with
        self.sent.append(alert)

    def describe(self):
        return "recording"


def make_notifier(channels, **kwargs):
    return Notifier(channels, clock=lambda: NOW, backoff=0, **kwargs)


# --- Formatting: attacker text stays inert ----------------------------------------


def test_slack_escapes_mentions_and_links():
    alert = make_alert(title="spray by <!channel> & <https://evil.example|click here>")

    text = slack_payload(alert)["text"]

    assert "<!channel>" not in text
    assert "&lt;!channel&gt; &amp; &lt;https://evil.example|click here&gt;" in text
    assert "<https://attack.mitre.org/techniques/T1110/|MITRE ATT&amp;CK T1110>" in text


def test_slack_escapes_control_characters():
    alert = make_alert(usernames=("\x1b[31mroot",))

    assert "\x1b" not in slack_payload(alert)["text"]


def test_discord_escapes_markdown_and_blocks_mentions():
    alert = make_alert(title="@everyone [click](https://evil.example) **now**")

    payload = discord_payload(alert)

    assert payload["allowed_mentions"] == {"parse": []}
    assert (
        "\\@everyone \\[click\\]\\(https\\://evil.example\\) \\*\\*now\\*\\*" in payload["content"]
    )


def test_discord_content_fits_the_limit():
    alert = make_alert(title="x" * 5000)

    assert len(discord_payload(alert)["content"]) == DISCORD_MAX_LENGTH


def test_email_subject_cannot_gain_header_lines():
    alert = make_alert(title="Login as x\r\nBcc: victim@example.com")

    message = email_message(alert, sender="alerts@example.com", recipients=["oncall@example.com"])

    assert message["Bcc"] is None
    assert "\n" not in message["Subject"]
    assert message["Subject"] == "[CRITICAL] Login as x\\x0d\\x0aBcc: victim@example.com"
    assert "MITRE ATT&CK: https://attack.mitre.org/techniques/T1110/" in message.get_content()


def test_long_username_lists_are_shortened():
    alert = make_alert(usernames=tuple(f"user{i}" for i in range(8)))

    assert "user0, user1, user2, user3, user4 (+3 more)" in slack_payload(alert)["text"]


# --- HTTP delivery -------------------------------------------------------------------


def test_slack_and_discord_post_json(webhook_server):
    SlackChannel(webhook_server.url).send(make_alert())
    DiscordChannel(webhook_server.url).send(make_alert())

    slack, discord = webhook_server.received
    assert "*[CRITICAL] Login as deploy" in slack["json"]["text"]
    assert discord["json"]["username"] == "Cyber Alert"
    assert slack["headers"]["User-Agent"].startswith("cyber-alert/")


def test_webhook_sends_the_alert_with_custom_headers(webhook_server):
    WebhookChannel(webhook_server.url, headers={"Authorization": "Bearer t0ken"}).send(make_alert())

    [request] = webhook_server.received
    assert request["headers"]["Authorization"] == "Bearer t0ken"
    assert request["json"]["source"] == "cyber-alert"
    assert request["json"]["alert"]["rule_id"] == "ssh-login-after-failures"


@pytest.mark.parametrize(
    ("status", "retryable"), [(500, True), (503, True), (429, True), (400, False), (404, False)]
)
def test_http_errors(webhook_server, status, retryable):
    webhook_server.statuses.append(status)

    with pytest.raises(DeliveryError) as error:
        WebhookChannel(webhook_server.url).send(make_alert())

    assert str(error.value) == f"HTTP {status}"
    assert error.value.retryable is retryable


def test_rate_limit_passes_on_retry_after(webhook_server):
    webhook_server.statuses.append(429)

    with pytest.raises(DeliveryError) as error:
        WebhookChannel(webhook_server.url).send(make_alert())

    assert error.value.retry_after == 0


def test_unreachable_endpoint_is_retryable():
    with socket.socket() as sock:  # find a port with nothing listening on it
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    with pytest.raises(DeliveryError, match="connection failed") as error:
        WebhookChannel(f"http://127.0.0.1:{port}/hook").send(make_alert())

    assert error.value.retryable


def test_describe_never_includes_the_secret_path():
    channel = SlackChannel("https://hooks.slack.com/services/T000/B000/secret-token")

    assert channel.describe() == "slack (hooks.slack.com)"


# --- Email ----------------------------------------------------------------------------


class FakeSMTP:
    instances = []
    fail_with = None

    def __init__(self, host, port, timeout):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context):
        self.calls.append("starttls")

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def send_message(self, message):
        if FakeSMTP.fail_with:
            raise FakeSMTP.fail_with
        self.calls.append(("send", message["To"], message["Subject"]))


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances, FakeSMTP.fail_with = [], None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def make_email_channel(**kwargs):
    return EmailChannel(
        smtp_host="smtp.example.com",
        sender="alerts@example.com",
        recipients=["a@example.com", "b@example.com"],
        **kwargs,
    )


def test_email_uses_starttls_and_logs_in(fake_smtp):
    make_email_channel(username="alerts", password="hunter2").send(make_alert())

    [smtp] = fake_smtp.instances
    assert (smtp.host, smtp.port) == ("smtp.example.com", 587)
    assert smtp.calls[0] == "starttls"
    assert smtp.calls[1] == ("login", "alerts", "hunter2")
    assert smtp.calls[2][1] == "a@example.com, b@example.com"


def test_email_rejected_credentials_are_not_retried(fake_smtp):
    fake_smtp.fail_with = smtplib.SMTPAuthenticationError(535, b"bad credentials")

    with pytest.raises(DeliveryError) as error:
        make_email_channel().send(make_alert())

    assert not error.value.retryable


def test_email_server_trouble_is_retried(fake_smtp):
    fake_smtp.fail_with = smtplib.SMTPServerDisconnected("gone")

    with pytest.raises(DeliveryError) as error:
        make_email_channel().send(make_alert())

    assert error.value.retryable


# --- Notifier ---------------------------------------------------------------------------


def test_notifier_delivers_to_channels_that_want_the_alert():
    everything = RecordingChannel(min_severity=Severity.LOW)
    critical_only = RecordingChannel(min_severity=Severity.CRITICAL)
    notifier = make_notifier([everything, critical_only])

    assert notifier.submit(make_alert(severity=Severity.MEDIUM))
    assert notifier.submit(make_alert(severity=Severity.CRITICAL))
    notifier.close()

    assert [a.severity for a in everything.sent] == [Severity.MEDIUM, Severity.CRITICAL]
    assert [a.severity for a in critical_only.sent] == [Severity.CRITICAL]


def test_notifier_skips_alerts_no_channel_wants():
    channel = RecordingChannel(min_severity=Severity.CRITICAL)
    notifier = make_notifier([channel])

    assert not notifier.submit(make_alert(severity=Severity.MEDIUM))
    notifier.close()

    assert channel.sent == []


def test_notifier_skips_old_activity():
    channel = RecordingChannel()
    notifier = make_notifier([channel], max_age=timedelta(minutes=1))

    assert not notifier.submit(make_alert())  # last seen 5 minutes before NOW
    notifier.close()

    assert channel.sent == []


def test_notifier_retries_transient_failures(webhook_server):
    webhook_server.statuses.extend([500, 503])
    notifier = make_notifier([WebhookChannel(webhook_server.url)])

    notifier.submit(make_alert())
    notifier.close()

    assert len(webhook_server.received) == 3


def test_notifier_gives_up_after_its_attempts(webhook_server, caplog):
    webhook_server.statuses.extend([500, 500, 500, 500])
    notifier = make_notifier([WebhookChannel(webhook_server.url)], attempts=3)

    notifier.submit(make_alert())
    notifier.close()

    assert len(webhook_server.received) == 3
    assert "Couldn't notify webhook (127.0.0.1): HTTP 500" in caplog.text


def test_notifier_does_not_retry_bad_requests(webhook_server):
    webhook_server.statuses.append(400)
    notifier = make_notifier([WebhookChannel(webhook_server.url)])

    notifier.submit(make_alert())
    notifier.close()

    assert len(webhook_server.received) == 1


def test_a_broken_channel_does_not_stop_the_others():
    broken = RecordingChannel(fail_with=RuntimeError("bug"))
    working = RecordingChannel()
    notifier = make_notifier([broken, working])

    notifier.submit(make_alert())
    notifier.submit(make_alert(title="second"))
    notifier.close()

    assert [a.title for a in working.sent][-1] == "second"
    assert len(working.sent) == 2


def test_full_queue_drops_instead_of_blocking():
    release = threading.Event()

    class SlowChannel(RecordingChannel):
        def send(self, alert):
            release.wait(5)
            super().send(alert)

    channel = SlowChannel()
    notifier = make_notifier([channel], queue_size=1)
    submitted = [notifier.submit(make_alert(title=f"alert {i}")) for i in range(5)]
    release.set()
    notifier.close()

    assert submitted[0] is True
    assert False in submitted  # detection never waits on a slow channel
    assert len(channel.sent) == submitted.count(True)
