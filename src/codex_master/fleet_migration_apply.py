from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from uuid import UUID

from .fleet_migration import (
    GMigrationPlanError,
    GSeriesMigrationPlan,
    plan_g_series_migration,
)
from .fleet_migration_materialization import (
    GMigrationMaterializationError,
    MemberIdAllocation,
    allocate_final_member_ids,
    materialize_g_series_v2,
)
from .fleet_registry import (
    AgentDescriptor,
    FleetMigrationSnapshot,
    FleetSeries,
    FleetSnapshot,
    FleetSnapshotV2,
    InventorySnapshot,
    Provider,
    RunnerKind,
    expand_v1_for_migration,
)


_QUEEN_SOURCE_IDS = ("g1", "h1", "i1", "j1", "k1", "l1", "m1", "n1", "o1", "p1")
_QUEEN_SOURCE_DIGEST = "sha256:0576c50268031a46e5fb076f842669344b01285c77de737b5f7bc62329a9b49a"
_EXCLUDED_AGENT_IDS = frozenset({"b1", "c1", "q1", "q2", "q3", "q-inplace", "running", "running1"})


class GMigrationApplyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GMigrationManifest:
    manifest_version: int
    allowed_source_ids: tuple[str, ...]
    expected_registry_generation: int
    source_projection_digest: str


@dataclass(frozen=True, slots=True)
class GMigrationPreflight:
    migration_snapshot: FleetMigrationSnapshot
    source_ids: tuple[str, ...]
    active_migration_identities: tuple[str, ...]
    manifest: GMigrationManifest


@dataclass(frozen=True, slots=True)
class GMigrationPrepared:
    candidate: FleetSnapshotV2
    plan: GSeriesMigrationPlan
    allocations: tuple[MemberIdAllocation, ...]

    def __repr__(self) -> str:
        return "GMigrationPrepared(candidate=<redacted>, plan=<redacted>, allocations=<redacted>)"

    def __str__(self) -> str:
        return repr(self)


QUEEN_G_MANIFEST_V1 = GMigrationManifest(
    manifest_version=1,
    allowed_source_ids=_QUEEN_SOURCE_IDS,
    expected_registry_generation=218,
    source_projection_digest=_QUEEN_SOURCE_DIGEST,
)


def _fail(code: str) -> None:
    raise GMigrationApplyError(code)


def _manifest_is_queen(value: object) -> bool:
    return (
        type(value) is GMigrationManifest
        and type(value.manifest_version) is int
        and value.manifest_version == 1
        and type(value.allowed_source_ids) is tuple
        and value.allowed_source_ids == _QUEEN_SOURCE_IDS
        and type(value.expected_registry_generation) is int
        and value.expected_registry_generation == 218
        and type(value.source_projection_digest) is str
        and value.source_projection_digest == _QUEEN_SOURCE_DIGEST
    )


def _excluded_inventory(inventory: InventorySnapshot) -> bool:
    try:
        for key, descriptor in inventory.agents.items():
            if not isinstance(key, str) or type(descriptor) is not AgentDescriptor:
                continue
            if (
                key in _EXCLUDED_AGENT_IDS
                or descriptor.agent_id in _EXCLUDED_AGENT_IDS
                or descriptor.series_prefix in {"q", "q-inplace", "running"}
                or descriptor.session in {"q-inplace", "running"}
            ):
                return True
    except Exception:
        return False
    return False


def _inventory_shape_is_valid(
    snapshot: FleetSnapshot,
    inventory: InventorySnapshot,
    migration_snapshot: FleetMigrationSnapshot,
) -> tuple[str, ...] | None:
    if type(inventory) is not InventorySnapshot:
        return None
    if (
        type(inventory.agent_ids) is not tuple
        or type(inventory.series_prefixes) is not tuple
        or not isinstance(inventory.agents, Mapping)
        or not isinstance(inventory.by_series, Mapping)
        or not isinstance(inventory.positions, Mapping)
    ):
        return None
    if len(set(inventory.agent_ids)) != len(inventory.agent_ids):
        return None
    if any(type(agent_id) is not str for agent_id in inventory.agent_ids):
        return None
    try:
        agent_items = tuple(inventory.agents.items())
        by_series_items = tuple(inventory.by_series.items())
        position_items = tuple(inventory.positions.items())
    except Exception:
        return None
    if any(type(key) is not str or type(value) is not AgentDescriptor for key, value in agent_items):
        return None
    if {key for key, _value in agent_items} != set(inventory.agent_ids):
        return None
    for key, descriptor in agent_items:
        prefix = key.rstrip("0123456789")
        ordinal_text = key[len(prefix) :]
        if (
            not prefix
            or not ordinal_text.isdigit()
            or descriptor.agent_id != key
            or descriptor.series_prefix != prefix
            or type(descriptor.ordinal) is not int
            or descriptor.ordinal != int(ordinal_text)
        ):
            return None
    if any(
        type(key) is not str
        or type(value) is not tuple
        or any(type(agent_id) is not str for agent_id in value)
        for key, value in by_series_items
    ):
        return None
    if any(type(key) is not str or type(value) is not int for key, value in position_items):
        return None
    if dict(position_items) != {agent_id: index for index, agent_id in enumerate(inventory.agent_ids)}:
        return None

    expected: dict[str, FleetSeries] = {}
    expected_series_keys: set[str] = set()
    for series in snapshot.series:
        if (
            type(series) is not FleetSeries
            or type(series.prefix) is not str
            or type(series.count) is not int
            or isinstance(series.count, bool)
            or series.count < 1
            or series.provider is not Provider.GEMINI_API
            or series.runner is not RunnerKind.GEMINI_CLI
        ):
            return None
        expected_series_keys.add(f"{series.prefix}-series")
        for ordinal in range(1, series.count + 1):
            agent_id = f"{series.prefix}{ordinal}"
            if agent_id in expected:
                return None
            expected[agent_id] = series
    if set(expected) != set(inventory.agent_ids):
        return None
    if {key for key, _values in by_series_items} != expected_series_keys:
        return None
    listed_by_series = tuple(agent_id for _key, values in by_series_items for agent_id in values)
    if len(listed_by_series) != len(set(listed_by_series)) or set(listed_by_series) != set(inventory.agent_ids):
        return None
    for agent_id, descriptor in agent_items:
        series = expected.get(agent_id)
        if series is None:
            return None
        if (
            descriptor.series_prefix != series.prefix
            or descriptor.ordinal < 1
            or descriptor.provider is not series.provider
            or descriptor.runner is not series.runner
            or descriptor.model != series.model
            or descriptor.account_id != series.account_id
        ):
            return None

    source_members = {
        f"{series.prefix}{member.ordinal}": member.migration_identity
        for series in migration_snapshot.series
        for member in series.members
    }
    if set(source_members) != set(expected) or set(source_members) != set(inventory.agent_ids):
        return None
    return tuple(sorted(source_members))


def _preflight_g_migration(
    snapshot: FleetSnapshot,
    inventory: InventorySnapshot,
    manifest: GMigrationManifest,
) -> GMigrationPreflight:
    if type(inventory) is InventorySnapshot and _excluded_inventory(inventory):
        _fail("migration_manifest_excluded")
    if not _manifest_is_queen(manifest) or type(snapshot) is not FleetSnapshot:
        _fail("migration_manifest_invalid")
    if (
        type(snapshot.schema_version) is not int
        or type(snapshot.generation) is not int
        or snapshot.schema_version != 1
        or snapshot.generation != manifest.expected_registry_generation
    ):
        _fail("migration_manifest_invalid")
    try:
        migration_snapshot = expand_v1_for_migration(snapshot)
    except Exception:
        _fail("migration_manifest_invalid")
    if type(migration_snapshot) is not FleetMigrationSnapshot:
        _fail("migration_manifest_invalid")
    source_ids = _inventory_shape_is_valid(snapshot, inventory, migration_snapshot)
    if source_ids is None or source_ids != manifest.allowed_source_ids:
        _fail("migration_manifest_invalid")
    identities_by_source = {
        f"{series.prefix}{member.ordinal}": member.migration_identity
        for series in migration_snapshot.series
        for member in series.members
    }
    active = tuple(
        sorted(
            identities_by_source[agent_id]
            for agent_id in inventory.agent_ids
            if inventory.agents[agent_id].enabled
        )
    )
    return GMigrationPreflight(migration_snapshot, source_ids, active, manifest)


def _materialize_g_migration_locked(
    snapshot: FleetSnapshot,
    bindings: Mapping[str, str],
    preflight: GMigrationPreflight,
    journaled: tuple[MemberIdAllocation, ...],
    uuid4: Callable[[], UUID],
) -> GMigrationPrepared:
    if (
        type(snapshot) is not FleetSnapshot
        or type(preflight) is not GMigrationPreflight
        or type(preflight.migration_snapshot) is not FleetMigrationSnapshot
        or not _manifest_is_queen(preflight.manifest)
        or preflight.migration_snapshot.generation != snapshot.generation
        or preflight.source_ids != _QUEEN_SOURCE_IDS
    ):
        _fail("migration_manifest_invalid")
    try:
        if preflight.migration_snapshot != expand_v1_for_migration(snapshot):
            _fail("migration_manifest_invalid")
        plan = plan_g_series_migration(
            preflight.migration_snapshot,
            credential_bindings=bindings,
            active_migration_identities=preflight.active_migration_identities,
        )
        allocations = allocate_final_member_ids(
            preflight.migration_snapshot,
            plan,
            journaled=journaled,
            uuid4=uuid4,
        )
        candidate = materialize_g_series_v2(
            preflight.migration_snapshot,
            plan,
            credential_bindings=bindings,
            allocations=allocations,
        )
    except GMigrationPlanError as error:
        raise GMigrationApplyError(error.code) from None
    except GMigrationMaterializationError as error:
        raise GMigrationApplyError(error.code) from None
    except Exception:
        raise GMigrationApplyError("migration_manifest_invalid") from None
    if type(candidate) is not FleetSnapshotV2 or type(allocations) is not tuple:
        _fail("migration_manifest_invalid")
    return GMigrationPrepared(candidate, plan, allocations)
