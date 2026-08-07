from datetime import datetime, timedelta, timezone

import pytest

from codex_master.selection.types import SelectionValidationError, SystemClock, validate_selection_time


def test_selection_time_normalizes_offsets_and_rejects_naive_values() -> None:
    normalized = validate_selection_time(datetime(2026, 3, 29, 2, 30, tzinfo=timezone(timedelta(hours=2))))
    assert normalized.tzinfo == timezone.utc
    assert normalized.hour == 0
    with pytest.raises(SelectionValidationError, match="invalid_selection_time"):
        validate_selection_time(datetime(2026, 3, 29, 2, 30))


def test_system_clock_is_utc_and_monotonic_across_short_observation() -> None:
    clock = SystemClock()
    first = clock.monotonic()
    second = clock.monotonic()
    assert clock.wall_time_utc().tzinfo == timezone.utc
    assert second >= first


@pytest.mark.parametrize("skew", [timedelta(days=-1), timedelta(days=1), timedelta(hours=5)])
def test_clock_skew_is_normalized_without_comparing_naive_datetimes(skew: timedelta) -> None:
    base = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
    assert validate_selection_time(base + skew).tzinfo == timezone.utc
