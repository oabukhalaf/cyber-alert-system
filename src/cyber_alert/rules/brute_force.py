from __future__ import annotations

from datetime import timedelta

from ..alerts import PASSWORD_GUESSING, Alert, Severity, format_duration
from ..detection import EventWindow, Rule, Throttle
from ..parser import AuthEvent, EventType


class BruteForceRule(Rule):
    """Many failed logins for one account from one source in a short time.

    This is classic password guessing (MITRE ATT&CK T1110.001): an attacker
    hammering a single account, usually root, with a list of passwords.

    Fires when one source IP has at least ``threshold`` failed logins for the
    same username within ``window``, and raises at most one alert per
    (source IP, username) per window.
    """

    id = "ssh-brute-force"
    severity = Severity.MEDIUM
    technique = PASSWORD_GUESSING

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=1)):
        self.threshold = threshold
        self._failures = EventWindow(window)
        self._throttle = Throttle(window)

    def process(self, event: AuthEvent) -> list[Alert]:
        # Group by source *and* username: one IP cycling through many usernames
        # is spraying, which PasswordSprayRule covers.
        key = (event.source_ip, event.username)
        if event.event_type is EventType.AUTH_SUCCESS:
            # Getting in shows the user knows the password, so the failures before
            # were typos. (Guessing that succeeds is LoginAfterFailuresRule's job.)
            self._failures.clear(key)
            return []
        if event.event_type is not EventType.AUTH_FAILURE:
            return []

        recent = self._failures.add(key, event)
        # One "message repeated N times" line stands for N failures.
        failure_count = sum(e.count for e in recent)
        if failure_count < self.threshold:
            return []
        if not self._throttle.allow(key, event.timestamp):
            return []

        span = format_duration(recent[-1].timestamp - recent[0].timestamp)
        return [
            self.alert(
                title=f"SSH brute force from {event.source_ip}",
                description=f"{failure_count} failed logins for {event.username} in {span}",
                events=recent,
            )
        ]
