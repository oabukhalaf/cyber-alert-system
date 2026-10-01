from __future__ import annotations

from datetime import timedelta

from ..alerts import PASSWORD_SPRAYING, Alert, Severity, format_duration
from ..detection import EventWindow, Rule, Throttle
from ..parser import AuthEvent, EventType


class PasswordSprayRule(Rule):
    """One source trying many different usernames in a short time.

    Spraying tries a few common passwords across many accounts to stay under
    per-account lockout thresholds, so it's invisible to a rule that only counts
    failures per username.
    """

    id = "ssh-password-spray"
    severity = Severity.MEDIUM
    technique = PASSWORD_SPRAYING

    def __init__(self, distinct_users: int = 5, window: timedelta = timedelta(minutes=5)):
        self.distinct_users = distinct_users
        self._attempts = EventWindow(window)
        self._throttle = Throttle(window)

    def process(self, event: AuthEvent) -> list[Alert]:
        # "Invalid user" notices count as attempts: on servers that only accept keys,
        # they may be the only trace a probe leaves.
        if event.event_type not in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            return []

        recent = self._attempts.add(event.source_ip, event)
        usernames = {e.username for e in recent}
        if len(usernames) < self.distinct_users:
            return []
        if not self._throttle.allow(event.source_ip, event.timestamp):
            return []

        span = format_duration(recent[-1].timestamp - recent[0].timestamp)
        return [
            self.alert(
                title=f"Password spray from {event.source_ip}",
                description=f"{len(usernames)} different usernames tried in {span}",
                events=recent,
            )
        ]
