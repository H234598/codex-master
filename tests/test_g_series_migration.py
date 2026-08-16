from __future__ import annotations

from unittest.mock import patch

import pytest

from codex_master.fleet_migration import (
    GMigrationPlanError,
    plan_g_series_migration,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetMigrationSeries,
    FleetMigrationSnapshot,
    LegacyFleetSeriesMember,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)


def account(account_id: str, label: str) -> FleetAccount:
    return FleetAccount(
        account_id,
        label,
        Provider.GEMINI_API,
        AuthKind.API_KEY,
        SecretState.CONFIGURED,
        LimitState.READY,
        True,
        None,
        None,
        None,
    )


def gemini_series(prefix: str, *account_ids: str) -> FleetMigrationSeries:
    return FleetMigrationSeries(
        prefix,
        f"Synthetic {prefix}",
        RunnerKind.GEMINI_CLI,
        Provider.GEMINI_API,
        "synthetic-model",
        True,
        "generic",
        "standard",
        tuple(
            LegacyFleetSeriesMember(
                f"v1:{prefix}:{ordinal}", ordinal, account_id, True,
            )
            for ordinal, account_id in enumerate(account_ids, start=1)
        ),
    )


def snapshot(*series: FleetMigrationSeries) -> FleetMigrationSnapshot:
    account_ids = sorted({member.account_id for item in series for member in item.members})
    return FleetMigrationSnapshot(
        1,
        7,
        tuple(account(item, f"Synthetic {item}") for item in account_ids),
        series,
    )


def test_missing_gemini_binding_fails_closed() -> None:
    source = snapshot(gemini_series("m", "gem-a"))
    with pytest.raises(GMigrationPlanError, match="credential_binding_unknown"):
        plan_g_series_migration(source, credential_bindings={})


def test_free_g_plan_keeps_only_migration_identities_and_never_uses_uuid() -> None:
    source = snapshot(gemini_series("m", "gem-a", "gem-b"))
    bindings = {"gem-a": "opaque-a", "gem-b": "opaque-b"}
    before = source
    with patch("builtins.open", side_effect=AssertionError("no_file_io")):
        first = plan_g_series_migration(source, credential_bindings=bindings)
        second = plan_g_series_migration(source, credential_bindings=dict(bindings))
    assert first == second
    assert source == before
    assert first.target_prefix == "g"
    assert first.g_relocation_target is None
    assert [member.migration_identity for member in first.members] == ["v1:m:1", "v1:m:2"]
    assert [member.target_ordinal for member in first.members] == [1, 2]
    assert all(not hasattr(member, "member_id") for member in first.members)
    assert "opaque-a" not in repr(first)
    assert "opaque-b" not in repr(first)


def test_non_gemini_g_moves_to_first_old_gemini_prefix() -> None:
    displaced_g = FleetMigrationSeries(
        "g",
        "Synthetic local",
        RunnerKind.CODEX_CLI,
        Provider.OLLAMA_LOCAL,
        "local-model",
        True,
        "generic",
        "standard",
        (),
    )
    source = snapshot(displaced_g, gemini_series("m", "gem-a"))
    plan = plan_g_series_migration(source, credential_bindings={"gem-a": "opaque-a"})
    assert plan.target_prefix == "g"
    assert plan.g_relocation_target == "m"
    assert plan.members[0].migration_identity == "v1:m:1"
    assert plan.members[0].target_ordinal == 1


def test_active_duplicate_binding_wins_and_other_member_is_retired() -> None:
    source = snapshot(gemini_series("m", "gem-a"), gemini_series("n", "gem-b"))
    plan = plan_g_series_migration(
        source,
        credential_bindings={"gem-a": "opaque-shared", "gem-b": "opaque-shared"},
        active_migration_identities={"v1:n:1"},
    )
    states = {
        member.migration_identity: (member.disposition, member.target_ordinal)
        for member in plan.members
    }
    assert states == {
        "v1:m:1": ("retired_duplicate_credential", None),
        "v1:n:1": ("g_member", 1),
    }


def test_multiple_active_duplicate_bindings_fail_closed() -> None:
    source = snapshot(gemini_series("m", "gem-a"), gemini_series("n", "gem-b"))
    with pytest.raises(GMigrationPlanError, match="multiple_active_credential_bindings"):
        plan_g_series_migration(
            source,
            credential_bindings={"gem-a": "opaque-shared", "gem-b": "opaque-shared"},
            active_migration_identities={"v1:m:1", "v1:n:1"},
        )


def test_non_g_members_keep_the_smallest_free_ordinals_deterministically() -> None:
    source = snapshot(
        gemini_series("g", "gem-z"),
        gemini_series("m", "gem-b"),
        gemini_series("n", "gem-a"),
    )
    bindings = {"gem-z": "opaque-z", "gem-b": "opaque-b", "gem-a": "opaque-a"}
    plan = plan_g_series_migration(source, credential_bindings=bindings)
    assert [(item.migration_identity, item.target_ordinal) for item in plan.members] == [
        ("v1:g:1", 1),
        ("v1:n:1", 2),
        ("v1:m:1", 3),
    ]


def test_foreign_active_identity_fails_closed() -> None:
    source = snapshot(gemini_series("m", "gem-a"))
    with pytest.raises(GMigrationPlanError, match="invalid_active_migration_identity"):
        plan_g_series_migration(
            source,
            credential_bindings={"gem-a": "opaque-a"},
            active_migration_identities={"v1:x:9"},
        )


def test_snapshot_subclass_fails_closed_at_exact_type_boundary() -> None:
    source = snapshot(gemini_series("m", "gem-a"))

    class SnapshotSubclass(FleetMigrationSnapshot):
        pass

    subclass = SnapshotSubclass(
        source.source_schema_version,
        source.generation,
        source.accounts,
        source.series,
    )
    with pytest.raises(GMigrationPlanError, match="invalid_migration_snapshot"):
        plan_g_series_migration(subclass, credential_bindings={"gem-a": "opaque-a"})


def test_collided_g_ordinals_are_order_independent_and_smallest_free() -> None:
    left = FleetMigrationSeries(
        "g", "Synthetic left", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "synthetic-model", True, "generic", "standard",
        (
            LegacyFleetSeriesMember("v1:g:left:1", 1, "gem-a", True),
            LegacyFleetSeriesMember("v1:g:left:3", 3, "gem-c", True),
        ),
    )
    right = FleetMigrationSeries(
        "g", "Synthetic right", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "synthetic-model", True, "generic", "standard",
        (
            LegacyFleetSeriesMember("v1:g:right:1", 1, "gem-b", True),
            LegacyFleetSeriesMember("v1:g:right:4", 4, "gem-d", True),
        ),
    )
    forward = FleetMigrationSnapshot(
        1,
        7,
        (
            account("gem-a", "Synthetic gem-a"),
            account("gem-b", "Synthetic gem-b"),
            account("gem-c", "Synthetic gem-c"),
            account("gem-d", "Synthetic gem-d"),
        ),
        (left, right),
    )
    left_reversed = FleetMigrationSeries(
        "g", "Synthetic left", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "synthetic-model", True, "generic", "standard", tuple(reversed(left.members)),
    )
    right_reversed = FleetMigrationSeries(
        "g", "Synthetic right", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "synthetic-model", True, "generic", "standard", tuple(reversed(right.members)),
    )
    reversed_source = FleetMigrationSnapshot(
        1,
        7,
        tuple(reversed(forward.accounts)),
        (right_reversed, left_reversed),
    )
    bindings = {
        "gem-a": "opaque-a",
        "gem-b": "opaque-b",
        "gem-c": "opaque-c",
        "gem-d": "opaque-d",
    }

    first = plan_g_series_migration(forward, credential_bindings=bindings)
    second = plan_g_series_migration(reversed_source, credential_bindings=dict(reversed(bindings.items())))

    assert first == second
    assert [
        (member.migration_identity, member.target_ordinal) for member in first.members
    ] == [
        ("v1:g:left:1", 1),
        ("v1:g:right:1", 2),
        ("v1:g:left:3", 3),
        ("v1:g:right:4", 4),
    ]
