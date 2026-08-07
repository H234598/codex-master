from datetime import datetime, timedelta, timezone

import pytest

from codex_master.selection.types import SelectionPriority, SelectionValidationError, SystemClock, validate_selection_time


def test_selection_package_preserves_existing_core_and_adds_typed_priority() -> None:
    from codex_master.selection import SelectionCandidate, SelectionPolicy

    assert SelectionCandidate is not None
    assert SelectionPolicy is not None
    assert [item.value for item in SelectionPriority] == ["SP0", "SP1A", "SP1B", "SP2", "SP3"]


def test_selection_clock_is_wall_and_monotonic_and_rejects_naive_time() -> None:
    clock = SystemClock()
    assert clock.wall_time_utc().tzinfo == timezone.utc
    assert isinstance(clock.monotonic(), float)
    with pytest.raises(SelectionValidationError):
        validate_selection_time(datetime.now())
    assert validate_selection_time(datetime.now(timezone(timedelta(hours=2)))).tzinfo == timezone.utc
