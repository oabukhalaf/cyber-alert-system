import json
from datetime import datetime, timedelta, timezone

import pytest

from cyber_alert.parser import AuthEvent, EventType, parse_file, parse_line, parse_lines

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
PREFIX = "Sep 27 10:31:15 web-01 sshd[2412]: "


def parse(message: str, prefix: str = PREFIX) -> AuthEvent | None:
    return parse_line(prefix + message, now=NOW)


def test_failed_password():
    event = parse("Failed password for root from 203.0.113.45 port 40112 ssh2")

    assert event == AuthEvent(
        timestamp=datetime(2026, 9, 27, 10, 31, 15, tzinfo=timezone.utc),
        host="web-01",
        event_type=EventType.AUTH_FAILURE,
        username="root",
        source_ip="203.0.113.45",
        port=40112,
        method="password",
        invalid_user=False,
    )


def test_failed_password_for_invalid_user():
    event = parse("Failed password for invalid user admin from 198.51.100.23 port 52210 ssh2")

    assert event.event_type is EventType.AUTH_FAILURE
    assert event.username == "admin"
    assert event.invalid_user is True


def test_accepted_publickey_with_key_fingerprint():
    event = parse(
        "Accepted publickey for alice from 10.0.4.21 port 51022 ssh2: "
        "ED25519 SHA256:q8V2hX0mYk1yJf3u6RrZ0bT9Lw4sPq7dNc5aKe2GhUo"
    )

    assert event.event_type is EventType.AUTH_SUCCESS
    assert (event.username, event.source_ip, event.method) == ("alice", "10.0.4.21", "publickey")


def test_keyboard_interactive_method():
    event = parse("Failed keyboard-interactive/pam for root from 203.0.113.45 port 40112 ssh2")

    assert event.method == "keyboard-interactive/pam"


@pytest.mark.parametrize("username", ["j.smith", "svc-backup", "user_01", "Administrator"])
def test_usernames_with_punctuation(username):
    event = parse(f"Accepted password for {username} from 10.0.4.52 port 50344 ssh2")

    assert event.username == username


def test_empty_username():
    event = parse("Failed password for invalid user  from 198.51.100.23 port 52300 ssh2")

    assert event.username == ""
    assert event.invalid_user is True


def test_ipv6_source_is_normalized():
    event = parse("Failed password for root from 2001:DB8:0:0::1F port 60122 ssh2")

    assert event.source_ip == "2001:db8::1f"


def test_username_cannot_spoof_the_source_ip():
    # An attacker picks a username that looks like the rest of the log message.
    event = parse(
        "Failed password for invalid user x from 6.6.6.6 port 22 ssh2 "
        "from 203.0.113.45 port 40112 ssh2"
    )

    assert event.source_ip == "203.0.113.45"
    assert event.username == "x from 6.6.6.6 port 22 ssh2"


def test_invalid_user_line():
    event = parse("Invalid user oracle from 198.51.100.23 port 52224")

    assert event.event_type is EventType.INVALID_USER
    assert (event.username, event.source_ip, event.port) == ("oracle", "198.51.100.23", 52224)
    assert event.method is None


def test_invalid_user_line_without_port():
    # Older OpenSSH releases omit the port.
    event = parse("Invalid user oracle from 198.51.100.23")

    assert event.port is None


def test_repeated_message_carries_count():
    event = parse(
        "message repeated 5 times: [ Failed password for root from 203.0.113.45 port 40112 ssh2]"
    )

    assert event.event_type is EventType.AUTH_FAILURE
    assert event.count == 5


def test_sshd_session_process_name():
    event = parse(
        "Failed password for root from 203.0.113.45 port 40112 ssh2",
        prefix="Sep 27 10:31:15 web-01 sshd-session[3301]: ",
    )

    assert event is not None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a log line",
        "Sep 27 10:31:15 web-01 sshd[2412]: Connection closed by 203.0.113.45 port 40112 [preauth]",
        "Sep 27 10:31:15 web-01 sshd[2412]: pam_unix(sshd:session): session opened for user alice",
        "Sep 27 10:17:01 web-01 CRON[2140]: pam_unix(cron:session): session opened for user root",
        # Right message, wrong process: only sshd is trusted to report SSH logins.
        "Sep 27 10:31:15 web-01 sudo[99]: Failed password for root from 203.0.113.45 port 1 ssh2",
    ],
)
def test_ignores_lines_that_are_not_sshd_auth_events(line):
    assert parse_line(line, now=NOW) is None


def test_iso_timestamp_keeps_its_offset():
    event = parse(
        "Failed password for root from 203.0.113.45 port 40112 ssh2",
        prefix="2026-09-27T10:31:15.123456+02:00 web-01 sshd[2412]: ",
    )

    assert event.timestamp == datetime(
        2026, 9, 27, 10, 31, 15, 123456, tzinfo=timezone(timedelta(hours=2))
    )


def test_iso_timestamp_with_z_suffix():
    event = parse(
        "Failed password for root from 203.0.113.45 port 40112 ssh2",
        prefix="2026-09-27T10:31:15Z web-01 sshd[2412]: ",
    )

    assert event.timestamp == datetime(2026, 9, 27, 10, 31, 15, tzinfo=timezone.utc)


def test_syslog_date_later_than_now_belongs_to_previous_year():
    line = "Dec 31 23:59:59 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    new_year = datetime(2027, 1, 2, 9, 0, tzinfo=timezone.utc)

    assert parse_line(line, now=new_year).timestamp.year == 2026


def test_space_padded_day():
    line = "Sep  7 10:00:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"

    assert parse_line(line, now=NOW).timestamp.day == 7


def test_impossible_date_is_skipped():
    line = "Feb 30 10:00:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"

    assert parse_line(line, now=NOW) is None


def test_crlf_line_ending():
    event = parse("Failed password for root from 203.0.113.45 port 40112 ssh2\r\n")

    assert event.port == 40112


def test_parse_lines_skips_noise():
    lines = [
        PREFIX + "Failed password for root from 203.0.113.45 port 40112 ssh2",
        PREFIX + "Connection closed by 203.0.113.45 port 40112 [preauth]",
        PREFIX + "Accepted password for bob from 10.0.4.35 port 49811 ssh2",
    ]

    events = list(parse_lines(lines, now=NOW))

    assert [e.event_type for e in events] == [EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS]


def test_parse_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        f"{PREFIX}Failed password for root from 203.0.113.45 port 40112 ssh2\n"
        f"{PREFIX}Accepted password for bob from 10.0.4.35 port 49811 ssh2\n",
        encoding="utf-8",
    )

    assert len(parse_file(log, now=NOW)) == 2


def test_to_dict_is_json_serializable():
    event = parse("Failed password for root from 203.0.113.45 port 40112 ssh2")

    payload = json.loads(json.dumps(event.to_dict()))

    assert payload["event_type"] == "auth_failure"
    assert payload["timestamp"] == "2026-09-27T10:31:15+00:00"
