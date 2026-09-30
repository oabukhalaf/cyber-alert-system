"""Built-in detection rules, keyed by rule id."""

from __future__ import annotations

from ..detection import Rule
from .login_after_failures import LoginAfterFailuresRule
from .password_spray import PasswordSprayRule

ALL_RULES: dict[str, type[Rule]] = {
    rule.id: rule
    for rule in (
        PasswordSprayRule,
        LoginAfterFailuresRule,
    )
}
