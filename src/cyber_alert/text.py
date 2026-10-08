"""Helpers for showing attacker-controlled log text safely."""

from __future__ import annotations


def printable(value: str) -> str:
    """Escape control characters, and name the empty string.

    Usernames come straight from attackers. Escaping control characters stops a
    crafted one from injecting terminal escape sequences or extra header lines.
    """
    if not value:
        return "(empty)"
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
