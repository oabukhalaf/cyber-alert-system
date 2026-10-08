"""Write realistic SSH auth log traffic, attacks included, for demos and testing.

Normal activity (key logins, the odd mistyped password) runs continuously, and
every so often an attack campaign plays out: a brute force against root, a
password spray across common usernames, or a guessed password that succeeds.
Attackers use the reserved documentation address ranges (RFC 5737 and RFC 3849).
"""

from __future__ import annotations

import itertools
import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Month names are spelled out rather than using strftime("%b"), which follows the
# locale and would write e.g. "Okt" on a German system.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_STAFF = [("alice", "10.0.4.21"), ("bob", "10.0.4.35"), ("j.smith", "10.0.4.52")]
_SPRAY_USERNAMES = ["admin", "oracle", "postgres", "ubuntu", "test", "git", "ftp", "pi", "guest"]


@dataclass(frozen=True)
class Step:
    delay: float  # seconds to wait before writing this line
    pid: int
    message: str
    process: str = "sshd"


def format_line(when: datetime, host: str, step: Step) -> str:
    """A classic syslog line, as rsyslog writes to /var/log/auth.log."""
    return (
        f"{_MONTHS[when.month - 1]} {when.day:>2} {when:%H:%M:%S} "
        f"{host} {step.process}[{step.pid}]: {step.message}"
    )


class Simulator:
    def __init__(self, rng: random.Random):
        self.rng = rng

    def steps(self) -> Iterator[Step]:
        """An endless stream of log lines: normal traffic punctuated by attacks."""
        attacks = itertools.cycle(
            [self.brute_force, self.password_spray, self.login_after_failures]
        )
        while True:
            for _ in range(self.rng.randint(2, 4)):
                yield from self.normal_activity()
            yield from next(attacks)()

    # --- Normal traffic ---------------------------------------------------------

    def normal_activity(self) -> Iterator[Step]:
        user, ip = self.rng.choice(_STAFF)
        pid, port = self._pid(), self._port()
        delay = self.rng.uniform(2, 5)
        if self.rng.random() < 0.25:  # a mistyped password, then the right one
            yield Step(delay, pid, f"Failed password for {user} from {ip} port {port} ssh2")
            yield Step(
                self.rng.uniform(2, 4),
                pid,
                f"Accepted password for {user} from {ip} port {port} ssh2",
            )
        else:
            yield Step(
                delay,
                pid,
                f"Accepted publickey for {user} from {ip} port {port} ssh2: "
                f"ED25519 SHA256:{self._fingerprint()}",
            )
        yield Step(0, pid, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        if self.rng.random() < 0.3:
            yield Step(
                self.rng.uniform(1, 3),
                self._pid(),
                "pam_unix(cron:session): session opened for user root by (uid=0)",
                process="CRON",
            )

    # --- Attacks ------------------------------------------------------------------

    def brute_force(self) -> Iterator[Step]:
        """Many passwords against root from one address (T1110.001)."""
        ip = f"203.0.113.{self.rng.randint(2, 254)}"
        pid, port = self._pid(), self._port()
        failure = f"Failed password for root from {ip} port {port} ssh2"
        yield Step(self.rng.uniform(2, 4), pid, failure)
        # rsyslog collapses identical consecutive lines into one "repeated" line.
        repeats = self.rng.randint(4, 6)
        yield Step(self.rng.uniform(4, 8), pid, f"message repeated {repeats} times: [ {failure}]")
        for _ in range(self.rng.randint(2, 3)):
            port = self._port()
            yield Step(
                self.rng.uniform(1, 3),
                self._pid(),
                f"Failed password for root from {ip} port {port} ssh2",
            )

    def password_spray(self) -> Iterator[Step]:
        """A few attempts each across many usernames from one address (T1110.003)."""
        ip = f"198.51.100.{self.rng.randint(2, 254)}"
        for user in self.rng.sample(_SPRAY_USERNAMES, self.rng.randint(6, 8)):
            pid, port = self._pid(), self._port()
            yield Step(self.rng.uniform(1, 2.5), pid, f"Invalid user {user} from {ip} port {port}")
            yield Step(
                self.rng.uniform(0.5, 1.5),
                pid,
                f"Failed password for invalid user {user} from {ip} port {port} ssh2",
            )

    def login_after_failures(self) -> Iterator[Step]:
        """Guessing that succeeds: the account is likely compromised (T1110)."""
        ip = self.rng.choice([f"192.0.2.{self.rng.randint(2, 254)}", "2001:db8::bad:1"])
        pid, port = self._pid(), self._port()
        for _ in range(self.rng.randint(3, 4)):
            yield Step(
                self.rng.uniform(2, 4),
                pid,
                f"Failed password for deploy from {ip} port {port} ssh2",
            )
        yield Step(
            self.rng.uniform(2, 4), pid, f"Accepted password for deploy from {ip} port {port} ssh2"
        )

    # --- Helpers ------------------------------------------------------------------

    def _pid(self) -> int:
        return self.rng.randint(1000, 65000)

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def _fingerprint(self) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "".join(self.rng.choice(alphabet) for _ in range(43))


def run(
    path: str | Path,
    *,
    speed: float = 1.0,
    duration: float | None = None,
    seed: int | None = None,
    host: str = "web-01",
    clock: Callable[[], datetime] = datetime.now,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Append simulated traffic to ``path``; return how many lines were written.

    ``speed`` scales time (2 means twice as fast) and ``duration`` stops the
    simulation after that many simulated seconds. Timestamps are the local wall
    clock, matching what syslog writes.
    """
    elapsed = 0.0
    written = 0
    with open(path, "a", encoding="utf-8") as log:
        for step in Simulator(random.Random(seed)).steps():
            elapsed += step.delay
            if duration is not None and elapsed > duration:
                break
            sleep(step.delay / speed)
            log.write(format_line(clock(), host, step) + "\n")
            log.flush()  # make each line visible to the watcher immediately
            written += 1
    return written
