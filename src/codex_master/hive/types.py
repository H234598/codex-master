"""Small immutable Hive domain primitives.

These types intentionally contain no prompts, credentials, filesystem paths,
or provider output.  They are the shared vocabulary for later principal,
repository, authority, dispatch, and admission modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
import time
from typing import Protocol


_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9_-]{0,127}\Z")


class HiveValidationError(ValueError):
    """Raised when a Hive domain value is malformed or unsafe."""


def validate_identifier(value: str, *, field: str = "identifier") -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise HiveValidationError(f"invalid_{field}")
    return value


def validate_utc_datetime(value: datetime, *, field: str = "timestamp") -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HiveValidationError(f"invalid_{field}")
    try:
        normalized = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise HiveValidationError(f"invalid_{field}") from None
    return normalized


class Clock(Protocol):
    """Wall and monotonic time source injectable into state machines."""

    def wall_time_utc(self) -> datetime:
        """Return timezone-aware UTC wall time."""

    def monotonic(self) -> float:
        """Return a monotonic process clock."""


class SystemClock:
    """Production clock with no mutable shared state."""

    def wall_time_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


class DispatchPriority(str, Enum):
    DP0 = "DP0"
    DP1 = "DP1"
    DP2 = "DP2"
    DP3 = "DP3"


class TaskComplexity(str, Enum):
    SIMPLE = "simple"
    COMPLEX = "complex"
    UNKNOWN = "unknown"


__all__ = [
    "Clock",
    "DispatchPriority",
    "HiveValidationError",
    "SystemClock",
    "TaskComplexity",
    "validate_identifier",
    "validate_utc_datetime",
]

