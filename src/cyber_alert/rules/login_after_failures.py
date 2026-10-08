from __future__ import annotations

from datetime import timedelta

from ..alerts import BRUTE_FORCE, Alert, Severity, format_duration
from ..detection import EventWindow, Rule
from ..parser import AuthEvent, EventType


class LoginAfterFailuresRule(Rule):
    """A successful login from a source that was just failing repeatedly.

    Failed logins alone are background noise on any internet-facing server; a
    success right after them suggests the guessing worked. This is the alert
    worth waking someone up for, hence CRITICAL.
    """

    id = "ssh-login-after-failures"
    severity = Severity.CRITICAL
    technique = BRUTE_FORCE

    def __init__(self, min_failures: int = 3, window: timedelta = timedelta(minutes=10)):
        self.min_failures = min_failures
        self._failures = EventWindow(window)

    def process(self, event: AuthEvent) -> list[Alert]:
        if event.event_type is EventType.AUTH_FAILURE:
            self._failures.add(event.source_ip, event)
            return []
        if event.event_type is not EventType.AUTH_SUCCESS:
            return []

        failures = self._failures.get(event.source_ip, event.timestamp)
        # A successful login ends the run of failures whether or not it alerts: a user
        # who mistypes once and then gets in, several times an hour, isn't an attack,
        # and a second login shouldn't re-alert on failures already reported.
        self._failures.clear(event.source_ip)
        failure_count = sum(e.count for e in failures)
        if failure_count < self.min_failures:
            return []

        span = format_duration(event.timestamp - failures[0].timestamp)
        return [
            self.alert(
                title=f"Login as {event.username} from {event.source_ip} after repeated failures",
                description=(
                    f"Accepted {event.method} login followed {failure_count} failed logins "
                    f"in {span}; the account's credentials may be compromised"
                ),
                events=[*failures, event],
            )
        ]
