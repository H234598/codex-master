from __future__ import annotations

from dataclasses import replace
from uuid import UUID

import pytest

from codex_master.fleet_migration import (
    GSeriesMigrationPlan,
    plan_g_series_migration,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetAccountV2,
    FleetMigrationSeries,
    FleetMigrationSnapshot,
    LegacyFleetSeriesMember,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    fleet_document,
    normalize_fleet_document,
)
from codex_master.fleet_migration_materialization import (
    GMigrationMaterializationError,
    MemberIdAllocation,
    allocate_final_member_ids,
    materialize_g_series_v2,
)


HMAC_A = "hmac-sha256:" + "a" * 64
HMAC_B = "hmac-sha256:" + "b" * 64
UUID_A = UUID("11111111-1111-4111-8111-111111111111")
UUID_B = UUID("22222222-2222-4222-8222-222222222222")
UUID_C = UUID("33333333-3333-4333-8333-333333333333")
UUID_D = UUID("44444444-4444-4444-8444-444444444444")


def account(account_id: str, provider: Provider, *, enabled: bool = True) -> FleetAccount:
    auth_kind = AuthKind.API_KEY if provider is not Provider.OLLAMA_LOCAL else AuthKind.NONE
    secret_state = SecretState.CONFIGURED if auth_kind is AuthKind.API_KEY else SecretState.NOT_REQUIRED
    return FleetAccount(
        account_id,
        f"Synthetic {account_id}",
        provider,
        auth_kind,
        secret_state,
        LimitState.READY,
        enabled,
        None,
        None,
        None,
    )


def member(
    identity: str,
    ordinal: int,
    account_id: str | None,
    *,
    enabled: bool = True,
    model_override: str | None = None,
    skill_profile_override: str | None = None,
    task_profile_override: str | None = None,
) -> LegacyFleetSeriesMember:
    return LegacyFleetSeriesMember(
        identity,
        ordinal,
        account_id,
        enabled,
        model_override,
        skill_profile_override,
        task_profile_override,
    )


def series(
    prefix: str,
    provider: Provider,
    runner: RunnerKind,
    model: str,
    members: tuple[LegacyFleetSeriesMember, ...],
    *,
    enabled: bool = True,
    skill_profile: str = "generic",
    task_profile: str = "standard",
) -> FleetMigrationSeries:
    return FleetMigrationSeries(
        prefix,
        f"Synthetic {prefix}",
        runner,
        provider,
        model,
        enabled,
        skill_profile,
        task_profile,
        members,
    )


def source_snapshot(*, extra_series: tuple[FleetMigrationSeries, ...] = ()) -> FleetMigrationSnapshot:
    accounts = (
        account("codex-account", Provider.OPENAI_API),
        account("gem-a", Provider.GEMINI_API),
        account("gem-b", Provider.GEMINI_API),
    )
    return FleetMigrationSnapshot(
        1,
        7,
        accounts,
        (
            series(
                "c",
                Provider.OPENAI_API,
                RunnerKind.CODEX_CLI,
                "codex-base",
                (member("v1:c:1", 1, "codex-account", model_override="codex-override"),),
                skill_profile="codex-skill",
                task_profile="codex-task",
            ),
            series(
                "g",
                Provider.OLLAMA_LOCAL,
                RunnerKind.CODEX_CLI,
                "local-base",
                (member("v1:g:1", 1, None),),
                skill_profile="local-skill",
                task_profile="local-task",
            ),
            series(
                "m",
                Provider.GEMINI_API,
                RunnerKind.GEMINI_CLI,
                "gem-base",
                (member("v1:m:1", 1, "gem-a"),),
                skill_profile="gem-skill",
                task_profile="gem-task",
            ),
            series(
                "n",
                Provider.GEMINI_API,
                RunnerKind.GEMINI_CLI,
                "gem-alt",
                (
                    member(
                        "v1:n:1",
                        1,
                        "gem-b",
                        model_override="n-model-override",
                        skill_profile_override="n-skill-override",
                        task_profile_override="n-task-override",
                    ),
                ),
                skill_profile="alt-skill",
                task_profile="alt-task",
            ),
            *extra_series,
        ),
    )


def migration_plan(
    source: FleetMigrationSnapshot,
    bindings: dict[str, str],
    *,
    active: set[str] | None = None,
) -> GSeriesMigrationPlan:
    return plan_g_series_migration(
        source,
        credential_bindings=bindings,
        active_migration_identities=() if active is None else active,
    )


def unique_bindings() -> dict[str, str]:
    return {"gem-a": HMAC_A, "gem-b": HMAC_B}


def allocations_for(
    source: FleetMigrationSnapshot,
    plan: GSeriesMigrationPlan,
) -> tuple[MemberIdAllocation, ...]:
    values = iter((UUID_A, UUID_B, UUID_C, UUID_D))
    return allocate_final_member_ids(source, plan, uuid4=lambda: next(values))


def test_allocate_reuses_journalled_ids_and_calls_factory_once_per_remaining_final_member() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    journaled = (MemberIdAllocation("v1:c:1", str(UUID_A)),)
    calls: list[int] = []
    values = iter((UUID_B, UUID_C, UUID_D))

    def uuid4() -> UUID:
        calls.append(1)
        return next(values)

    allocations = allocate_final_member_ids(source, plan, journaled=journaled, uuid4=uuid4)
    assert allocations[0] == journaled[0]
    assert [item.migration_identity for item in allocations] == sorted(
        item.migration_identity for item in allocations
    )
    assert len(calls) == len(allocations) - len(journaled)
    assert len({item.member_id for item in allocations}) == len(allocations)


def test_allocate_excludes_retired_duplicate_from_final_member_ids() -> None:
    source = source_snapshot()
    bindings = {"gem-a": HMAC_A, "gem-b": HMAC_A}
    plan = migration_plan(source, bindings, active={"v1:m:1"})
    allocations = allocations_for(source, plan)
    identities = {item.migration_identity for item in allocations}
    assert identities == {"v1:c:1", "v1:g:1", "v1:m:1"}
    assert "v1:n:1" not in identities


def test_allocate_rejects_foreign_duplicate_unsorted_or_non_v4_journalled_records() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    valid = (
        MemberIdAllocation("v1:c:1", str(UUID_A)),
        MemberIdAllocation("v1:g:1", str(UUID_B)),
    )
    invalid_collections = (
        (MemberIdAllocation("foreign", str(UUID_A)),),
        (valid[0], valid[0]),
        (valid[1], valid[0]),
        (MemberIdAllocation("v1:c:1", "11111111-1111-1111-8111-111111111111"),),
    )
    for journaled in invalid_collections:
        calls: list[int] = []
        with pytest.raises(GMigrationMaterializationError, match="invalid_member_id_allocation"):
            allocate_final_member_ids(source, plan, journaled=journaled, uuid4=lambda: calls.append(1))
        assert calls == []


def test_allocate_rejects_sorted_list_journaled_before_factory() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    valid = allocations_for(source, plan)
    calls: list[int] = []

    with pytest.raises(GMigrationMaterializationError, match="invalid_member_id_allocation"):
        allocate_final_member_ids(
            source,
            plan,
            journaled=[valid[0]],
            uuid4=lambda: calls.append(1),
        )
    assert calls == []


def test_allocate_rejects_mapping_journaled_before_factory() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    valid = allocations_for(source, plan)
    calls: list[int] = []

    with pytest.raises(GMigrationMaterializationError, match="invalid_member_id_allocation"):
        allocate_final_member_ids(
            source,
            plan,
            journaled={valid[0].migration_identity: valid[0].member_id},
            uuid4=lambda: calls.append(1),
        )
    assert calls == []


def test_materialize_rejects_sorted_list_allocations() -> None:
    source = source_snapshot()
    bindings = unique_bindings()
    plan = migration_plan(source, bindings)
    allocations = allocations_for(source, plan)

    with pytest.raises(GMigrationMaterializationError, match="invalid_member_id_allocation"):
        materialize_g_series_v2(
            source,
            plan,
            credential_bindings=bindings,
            allocations=list(allocations),
        )


def test_materialize_rejects_mapping_allocations() -> None:
    source = source_snapshot()
    bindings = unique_bindings()
    plan = migration_plan(source, bindings)
    allocations = allocations_for(source, plan)

    with pytest.raises(GMigrationMaterializationError, match="invalid_member_id_allocation"):
        materialize_g_series_v2(
            source,
            plan,
            credential_bindings=bindings,
            allocations={item.migration_identity: item.member_id for item in allocations},
        )


def test_materialize_preserves_non_gemini_and_relocates_occupied_g() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    allocations = allocations_for(source, plan)
    candidate = materialize_g_series_v2(
        source,
        plan,
        credential_bindings=unique_bindings(),
        allocations=allocations,
    )
    by_prefix = {item.prefix: item for item in candidate.series}
    assert set(by_prefix) == {"c", "g", "m"}
    assert by_prefix["c"].members[0].model_override == "codex-override"
    assert by_prefix["m"].provider is Provider.OLLAMA_LOCAL
    assert by_prefix["m"].members[0].account_id is None
    assert by_prefix["g"].provider is Provider.GEMINI_API


def test_materialize_emits_empty_runtime_principals_and_roundtrips_canonically() -> None:
    source = source_snapshot()
    bindings = unique_bindings()
    plan = migration_plan(source, bindings)
    candidate = materialize_g_series_v2(
        source,
        plan,
        credential_bindings=bindings,
        allocations=allocations_for(source, plan),
    )

    assert candidate.runtime_principals == ()
    document = fleet_document(candidate)
    assert document["runtime_principals"] == []
    assert normalize_fleet_document(document) == candidate


def test_materialize_merges_g_winners_and_preserves_source_profiles_as_overrides() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    candidate = materialize_g_series_v2(
        source,
        plan,
        credential_bindings=unique_bindings(),
        allocations=allocations_for(source, plan),
    )
    g_series = next(item for item in candidate.series if item.prefix == "g")
    assert [item.ordinal for item in g_series.members] == [1, 2]
    second = g_series.members[1]
    assert second.account_id == "gem-b"
    assert second.model_override == "n-model-override"
    assert second.skill_profile_override == "n-skill-override"
    assert second.task_profile_override == "n-task-override"


def test_materialize_retains_exclusive_duplicate_loser_account_disabled() -> None:
    source = source_snapshot()
    bindings = {"gem-a": HMAC_A, "gem-b": HMAC_A}
    plan = migration_plan(source, bindings, active={"v1:m:1"})
    candidate = materialize_g_series_v2(
        source,
        plan,
        credential_bindings=bindings,
        allocations=allocations_for(source, plan),
    )
    gem_b = next(item for item in candidate.accounts if item.account_id == "gem-b")
    assert type(gem_b) is FleetAccountV2
    assert gem_b.enabled is False
    assert all(member.account_id != "gem-b" for item in candidate.series for member in item.members)


def test_materialize_rejects_duplicate_loser_with_foreign_account_reference() -> None:
    foreign_reference = series(
        "x",
        Provider.OPENAI_API,
        RunnerKind.CODEX_CLI,
        "foreign-model",
        (member("v1:x:1", 1, "gem-b"),),
    )
    source = source_snapshot(extra_series=(foreign_reference,))
    bindings = {"gem-a": HMAC_A, "gem-b": HMAC_A}
    plan = migration_plan(source, bindings, active={"v1:m:1"})
    with pytest.raises(GMigrationMaterializationError, match="migration_duplicate_account_conflict"):
        materialize_g_series_v2(
            source,
            plan,
            credential_bindings=bindings,
            allocations=(
                MemberIdAllocation("v1:c:1", str(UUID_A)),
                MemberIdAllocation("v1:g:1", str(UUID_B)),
                MemberIdAllocation("v1:m:1", str(UUID_C)),
                MemberIdAllocation("v1:x:1", str(UUID_D)),
            ),
        )


def test_materialize_rejects_missing_invalid_or_extra_hmac_binding_without_marker_leak() -> None:
    source = source_snapshot()
    plan = migration_plan(source, unique_bindings())
    allocations = allocations_for(source, plan)
    invalid_bindings = (
        {"gem-a": HMAC_A},
        {"gem-a": HMAC_A, "gem-b": "not-a-binding"},
        {"gem-a": HMAC_A, "gem-b": HMAC_B, "unexpected": HMAC_A},
    )
    for bindings in invalid_bindings:
        with pytest.raises(GMigrationMaterializationError) as raised:
            materialize_g_series_v2(source, plan, credential_bindings=bindings, allocations=allocations)
        assert raised.value.code == "credential_binding_unknown"
        assert HMAC_A not in str(raised.value)
        assert HMAC_B not in repr(raised.value)


def test_materialize_rejects_plan_snapshot_mismatch_and_exact_type_lookalikes() -> None:
    source = source_snapshot()
    bindings = unique_bindings()
    plan = migration_plan(source, bindings)
    allocations = allocations_for(source, plan)
    with pytest.raises(GMigrationMaterializationError, match="invalid_migration_plan"):
        materialize_g_series_v2(
            source,
            replace(plan, source_generation=8),
            credential_bindings=bindings,
            allocations=allocations,
        )
    with pytest.raises(GMigrationMaterializationError, match="invalid_migration_plan"):
        materialize_g_series_v2(
            source,
            replace(plan, members=(replace(plan.members[0], migration_identity="foreign"), *plan.members[1:])),
            credential_bindings=bindings,
            allocations=allocations,
        )

    class SnapshotSubclass(FleetMigrationSnapshot):
        pass

    class PlanSubclass(GSeriesMigrationPlan):
        pass

    subclass_snapshot = SnapshotSubclass(source.source_schema_version, source.generation, source.accounts, source.series)
    subclass_plan = PlanSubclass(plan.source_generation, plan.target_prefix, plan.g_relocation_target, plan.members)
    with pytest.raises(GMigrationMaterializationError, match="invalid_migration_materialization"):
        materialize_g_series_v2(
            subclass_snapshot,
            plan,
            credential_bindings=bindings,
            allocations=allocations,
        )
    with pytest.raises(GMigrationMaterializationError, match="invalid_migration_plan"):
        materialize_g_series_v2(
            source,
            subclass_plan,
            credential_bindings=bindings,
            allocations=allocations,
        )


def test_materialize_is_permutation_deterministic_and_input_immutable() -> None:
    source = source_snapshot()
    bindings = unique_bindings()
    plan = migration_plan(source, bindings)
    allocations = allocations_for(source, plan)
    reversed_source = FleetMigrationSnapshot(
        source.source_schema_version,
        source.generation,
        tuple(reversed(source.accounts)),
        tuple(
            replace(item, members=tuple(reversed(item.members)))
            for item in reversed(source.series)
        ),
    )
    reversed_plan = migration_plan(reversed_source, dict(reversed(bindings.items())))
    source_before = source
    reversed_before = reversed_source
    first = materialize_g_series_v2(
        source,
        plan,
        credential_bindings=bindings,
        allocations=allocations,
    )
    second = materialize_g_series_v2(
        reversed_source,
        reversed_plan,
        credential_bindings=dict(reversed(bindings.items())),
        allocations=allocations,
    )
    assert fleet_document(first) == fleet_document(second)
    assert source == source_before
    assert reversed_source == reversed_before
