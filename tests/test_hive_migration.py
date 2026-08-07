import pytest

from codex_master.hive.migration import (
    compare_legacy_and_hive_assignment,
    enable_shadow_mode,
    migration_status,
    reconcile_runtime_state,
    rollback_hive_state,
)


def test_migration_status_comparison_and_shadow_mode_are_reversible() -> None:
    assert migration_status() == {
        "mode": "shadow", "legacy": "available", "hive": "shadow_only",
        "mutation_performed": False, "raw_output": "not_returned",
    }
    assert enable_shadow_mode()["mutation_performed"] is False
    assert compare_legacy_and_hive_assignment({})["reason_code"] == "missing_comparison_side"

    equal = compare_legacy_and_hive_assignment({"legacy": {"agent": "a1"}, "hive": {"agent": "a1"}})
    different = compare_legacy_and_hive_assignment({"legacy": {"agent": "a1"}, "hive": {"agent": "a2"}})
    assert equal["comparable"] is True and equal["equal"] is True
    assert different["comparable"] is True and different["equal"] is False
    assert all(str(value).startswith("sha256:") for key, value in equal.items() if key.endswith("digest"))


def test_migration_reconcile_and_rollback_never_mutate_state() -> None:
    assert reconcile_runtime_state() == {
        "reconciled": False, "reason_code": "runtime_context_required",
        "mutation_performed": False, "raw_output": "not_returned",
    }
    dry_run = rollback_hive_state(dry_run=True)
    assert dry_run["rollback_allowed"] is False
    assert dry_run["statefiles_deleted"] is False
    assert dry_run["pool_changed"] is False
    with pytest.raises(ValueError, match="dry_run_required"):
        rollback_hive_state(dry_run="yes")  # type: ignore[arg-type]
