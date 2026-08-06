"""Immutable Selection vocabulary and independently controllable clocks."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import time
from typing import Protocol

from codex_master.hive.types import TaskComplexity


class SelectionValidationError(ValueError):
    """Raised when a Selection value is malformed."""


class SelectionClock(Protocol):
    def wall_time_utc(self) -> datetime:
        """Return timezone-aware UTC wall time."""

    def monotonic(self) -> float:
        """Return a monotonic time value."""


class SystemClock:
    def wall_time_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


class SelectionPriority(str, Enum):
    SP0 = "SP0"
    SP1A = "SP1A"
    SP1B = "SP1B"
    SP2 = "SP2"
    SP3 = "SP3"


def validate_selection_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SelectionValidationError("invalid_selection_time")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise SelectionValidationError("invalid_selection_time") from exc


__all__ = ["SelectionClock", "SelectionPriority", "SelectionValidationError", "SystemClock", "TaskComplexity", "validate_selection_time"]
