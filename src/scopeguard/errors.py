"""Failures an operator can act on. These are not programming bugs."""

from __future__ import annotations


class ScopeGuardError(Exception):
    """Base class for expected ScopeGuard failures."""


class ConfigError(ScopeGuardError):
    """The assessment file is missing, unsafe, or internally inconsistent."""


class ScopeViolation(ScopeGuardError):
    """A destination failed authorization and was not contacted."""

    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__(message)
        self.target = target


class NetworkError(ScopeGuardError):
    """An authorized destination could not be contacted."""

    def __init__(self, message: str, *, target: str) -> None:
        super().__init__(message)
        self.target = target
