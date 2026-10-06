import pytest
from factories import START, failure, invalid_user, success

PREFIX = "Sep 27 10:31:15 web-01 sshd[2412]: "


@pytest.fixture
def app(make_app, log_file):
    """A dashboard app that has processed a brute force, a break-in and a normal login."""
    app = make_app(log_file)
    monitor = app.extensions["monitor"]
    events = [failure("root", ip="203.0.113.45", at=i) for i in range(6)]
    events += [failure("deploy", ip="192.0.2.77", at=100 + i) for i in range(3)]
    events += [success("deploy", ip="192.0.2.77", at=110)]
    events += [invalid_user("oracle", ip="198.51.100.23", at=150)]
    events += [success("alice", ip="10.0.4.21", at=3600)]  # an hour later
    for event in events:
        monitor.process(event)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def get_json(client, url, status=200):
    response = client.get(url)
    assert response.status_code == status, response.get_data(as_text=True)
    assert response.mimetype == "application/json"
    return response.get_json()


def test_summary(client, log_file):
    data = get_json(client, "/api/summary")

    assert data["log_file"] == str(log_file)
    assert data["total_events"] == 12
    assert data["failed_logins"] == 9
    assert data["successful_logins"] == 2
    assert data["unique_sources"] == 4
    assert data["top_failed_sources"][0] == {"source_ip": "203.0.113.45", "count": 6}
    assert data["alerts_by_severity"]["critical"] == 1


def test_summary_top(client):
    data = get_json(client, "/api/summary?top=1")

    assert len(data["top_failed_sources"]) == 1


@pytest.mark.parametrize("value", ["0", "501", "ten", "-1", "²"])
def test_invalid_limits_are_rejected(client, value):
    data = get_json(client, f"/api/summary?top={value}", status=400)

    assert data["error"] == "top: expected a whole number from 1 to 500"


def test_timeline_auto(client):
    data = get_json(client, "/api/timeline")

    assert data["bucket_seconds"] == 300  # a 1-hour span in 5-minute buckets
    assert data["buckets"][0] == {"start": START.isoformat(), "failures": 9, "successes": 1}
    assert data["buckets"][-1]["successes"] == 1
    assert len(data["buckets"]) == 13


def test_timeline_with_explicit_bucket(client):
    data = get_json(client, "/api/timeline?bucket=1h")

    assert data["bucket_seconds"] == 3600
    assert [(b["failures"], b["successes"]) for b in data["buckets"]] == [(9, 1), (0, 1)]


@pytest.mark.parametrize(
    ("bucket", "message"),
    [("30s", "whole number of minutes"), ("soon", "expected a duration"), ("0m", "positive")],
)
def test_timeline_rejects_bad_buckets(client, bucket, message):
    data = get_json(client, f"/api/timeline?bucket={bucket}", status=400)

    assert data["error"].startswith("bucket: ")
    assert message in data["error"]


def test_timeline_without_events(make_app, log_file):
    data = get_json(make_app(log_file).test_client(), "/api/timeline")

    assert data["buckets"] == []


def test_alerts(client):
    data = get_json(client, "/api/alerts")

    assert [alert["rule_id"] for alert in data["alerts"]] == [
        "ssh-login-after-failures",
        "ssh-brute-force",
    ]
    assert data["alerts"][0]["technique"]["url"] == "https://attack.mitre.org/techniques/T1110/"


@pytest.mark.parametrize(
    ("query", "rule_ids"),
    [
        ("severity=critical", ["ssh-login-after-failures"]),
        ("severity=MEDIUM", ["ssh-login-after-failures", "ssh-brute-force"]),
        ("rule=ssh-brute-force", ["ssh-brute-force"]),
        ("source_ip=203.0.113.45", ["ssh-brute-force"]),
        ("source_ip=10.9.9.9", []),
        ("limit=1", ["ssh-login-after-failures"]),
    ],
)
def test_alert_filters(client, query, rule_ids):
    data = get_json(client, f"/api/alerts?{query}")

    assert [alert["rule_id"] for alert in data["alerts"]] == rule_ids


def test_alerts_reject_unknown_severity(client):
    data = get_json(client, "/api/alerts?severity=urgent", status=400)

    assert data["error"] == "severity: expected one of low, medium, high, critical"


def test_events_are_newest_first(client):
    data = get_json(client, "/api/events?limit=2")

    assert [(e["event_type"], e["username"]) for e in data["events"]] == [
        ("auth_success", "alice"),
        ("invalid_user", "oracle"),
    ]


def test_api_responses_carry_security_headers(client):
    response = client.get("/api/summary")

    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
