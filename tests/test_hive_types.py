from datetime import datetime, timedelta, timezone

import pytest

from codex_master.hive.types import (
    DispatchPriority,
    HiveValidationError,
    SystemClock,
    TaskComplexity,
    validate_identifier,
    validate_utc_datetime,
)


def test_enum_values_are_explicit_and_stable() -> None:
    assert [item.value for item in DispatchPriority] == ["DP0", "DP1", "DP2", "DP3"]
    assert [item.value for item in TaskComplexity] == ["simple", "complex", "unknown"]


@pytest.mark.parametrize("value", ["", "A1", "bad space", "../escape", "a/child", "a" * 129])
def test_identifier_rejects_ambiguous_or_path_like_values(value: str) -> None:
    with pytest.raises(HiveValidationError, match="invalid_principal"):
        validate_identifier(value, field="principal")


def test_identifier_accepts_bounded_wire_safe_values() -> None:
    assert validate_identifier("queen-codex-master", field="principal") == "queen-codex-master"
    assert validate_identifier("wp_001", field="workpackage") == "wp_001"


def test_utc_validation_normalizes_offsets_without_accepting_naive_time() -> None:
    value = validate_utc_datetime(
        datetime(2026, 8, 6, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    )
    assert value == datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
    with pytest.raises(HiveValidationError, match="invalid_created"):
        validate_utc_datetime(datetime(2026, 8, 6, 12), field="created")


def test_system_clock_returns_aware_utc_and_monotonic_value() -> None:
    clock = SystemClock()
    assert clock.wall_time_utc().tzinfo == timezone.utc
    assert isinstance(clock.monotonic(), float)

