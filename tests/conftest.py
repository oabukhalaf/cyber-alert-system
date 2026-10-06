import pytest

from cyber_alert.web import create_app

PREFIX = "Sep 27 10:31:15 web-01 sshd[2412]: "


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        f"{PREFIX}Failed password for root from 203.0.113.45 port 40112 ssh2\n"
        f"{PREFIX}Accepted password for bob from 10.0.4.35 port 49811 ssh2\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def make_app(tmp_path):
    """Build a dashboard app whose alert database lives in the test's temp directory."""

    def make(log, **kwargs):
        return create_app(log, db_path=tmp_path / "alerts.db", **kwargs)

    return make
