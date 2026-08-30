from __future__ import annotations

import contextlib
import errno
import json
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch
from uuid import UUID

import pytest

from codex_master import server as server_module
from codex_master.fleet_recovery import normalize_g_migration_journal
from codex_master.fleet_migration_materialization import MemberIdAllocation
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    InventorySnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    build_inventory,
    public_fleet_snapshot,
)
from codex_master.fleet_migration_apply import (
    GMigrationApplyError,
    QUEEN_G_MANIFEST_V1,
    _materialize_g_migration_locked,
    _preflight_g_migration,
)


SOURCE_IDS = tuple(f"{prefix}1" for prefix in "ghijklmnop")
HMAC_A = "hmac-sha256:" + "a" * 64
HMAC_B = "hmac-sha256:" + "b" * 64
UUIDS = tuple(UUID(f"{value:08d}-0000-4000-8000-000000000000") for value in range(1, 32))


@pytest.fixture(autouse=True)
def fresh_green_hive_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        server_module,
        "require_fleet_recovery_ready",
        lambda _operation: None,
    )


def _account(account_id: str, *, enabled: bool = True) -> FleetAccount:
    return FleetAccount(
        account_id,
        f"Synthetic {account_id}",
        Provider.GEMINI_API,
        AuthKind.API_KEY,
        SecretState.CONFIGURED,
        LimitState.READY,
        enabled,
        None,
        None,
        None,
    )


def _snapshot(*, disabled: str | None = None, extra: str | None = None) -> FleetSnapshot:
    prefixes = list("ghijklmnop")
    if extra is not None:
        prefixes.append(extra)
    accounts = tuple(_account(f"{prefix}-account", enabled=prefix != disabled) for prefix in prefixes)
    series = tuple(
        FleetSeries(
            prefix,
            f"Synthetic {prefix}",
            1,
            RunnerKind.GEMINI_CLI,
            Provider.GEMINI_API,
            "synthetic-model",
            f"{prefix}-account",
            prefix != disabled,
        )
        for prefix in prefixes
    )
    return FleetSnapshot(1, 218, accounts, series)


def _inventory(snapshot: FleetSnapshot) -> InventorySnapshot:
    return build_inventory(snapshot, Path("/synthetic/not-used"))


def _permuted_inventory(snapshot: FleetSnapshot) -> InventorySnapshot:
    inventory = _inventory(snapshot)
    ids = tuple(reversed(inventory.agent_ids))
    return InventorySnapshot(
        ids,
        MappingProxyType({key: inventory.agents[key] for key in reversed(ids)}),
        inventory.by_series,
        MappingProxyType({key: index for index, key in enumerate(ids)}),
        tuple(reversed(inventory.series_prefixes)),
    )


def _bindings(*, duplicate: bool = False) -> dict[str, str]:
    result = {
        f"{prefix}-account": "hmac-sha256:" + f"{index + 1:x}" + "0" * 63
        for index, prefix in enumerate("ghijklmnop")
    }
    if duplicate:
        result["h-account"] = result["g-account"]
    return result


def _uuid4() -> UUID:
    return UUIDS[_uuid4.calls.pop(0)]


_uuid4.calls: list[int] = []


def _prepared(
    snapshot: FleetSnapshot,
    *,
    inventory: InventorySnapshot | None = None,
    bindings: dict[str, str] | None = None,
) -> object:
    preflight = _preflight_g_migration(snapshot, inventory or _inventory(snapshot), QUEEN_G_MANIFEST_V1)
    _uuid4.calls[:] = list(range(10))
    return _materialize_g_migration_locked(
        snapshot,
        bindings or _bindings(),
        preflight,
        (),
        _uuid4,
    )


@pytest.mark.parametrize(
    ("variant", "code"),
    [
        ("protected_b1", "migration_manifest_excluded"),
        ("q_inplace", "migration_manifest_excluded"),
        ("running", "migration_manifest_excluded"),
        ("foreign", "migration_manifest_invalid"),
        ("digest_drift", "migration_manifest_invalid"),
    ],
)
def test_preflight_fails_before_uuid_journal_or_home(variant: str, code: str) -> None:
    snapshot = _snapshot(extra={
        "protected_b1": "b",
        "q_inplace": "q",
        "running": "running",
        "foreign": "z",
        "digest_drift": None,
    }[variant])
    inventory = _inventory(snapshot)
    manifest = replace(QUEEN_G_MANIFEST_V1, source_projection_digest="sha256:" + "f" * 64) if variant == "digest_drift" else QUEEN_G_MANIFEST_V1
    with pytest.raises(GMigrationApplyError, match=code):
        _preflight_g_migration(snapshot, inventory, manifest)
    assert snapshot.generation == 218
    assert inventory.agent_ids == tuple(inventory.agents)


def test_preflight_excludes_explicit_c1_but_rejects_unknown_z() -> None:
    for extra, expected_agent, code in (
        ("c", "c1", "migration_manifest_excluded"),
        ("z", "z1", "migration_manifest_invalid"),
    ):
        snapshot = _snapshot(extra=extra)
        assert expected_agent in _inventory(snapshot).agent_ids
        with pytest.raises(GMigrationApplyError, match=code):
            _preflight_g_migration(snapshot, _inventory(snapshot), QUEEN_G_MANIFEST_V1)


def test_prepared_repr_and_str_redact_binding_and_member_id_markers() -> None:
    prepared = _prepared(_snapshot())
    rendered = repr(prepared) + str(prepared)

    assert "hmac-sha256:" not in rendered
    assert "member_id" not in rendered
    assert repr(prepared) == str(prepared)


def test_preflight_accepts_permuted_inventory_and_returns_canonical_source() -> None:
    snapshot = _snapshot()
    preflight = _preflight_g_migration(snapshot, _permuted_inventory(snapshot), QUEEN_G_MANIFEST_V1)
    assert preflight.source_ids == SOURCE_IDS
    assert preflight.migration_snapshot.generation == 218


def test_materialization_missing_binding_fails_closed_before_uuid() -> None:
    snapshot = _snapshot()
    preflight = _preflight_g_migration(snapshot, _inventory(snapshot), QUEEN_G_MANIFEST_V1)
    calls: list[int] = []
    with pytest.raises(GMigrationApplyError, match="credential_binding_unknown"):
        _materialize_g_migration_locked(
            snapshot,
            {"g-account": HMAC_A},
            preflight,
            (),
            lambda: calls.append(1),
        )
    assert calls == []


def test_materialization_allows_one_disabled_duplicate_loser() -> None:
    snapshot = _snapshot(disabled="h")
    bindings = _bindings(duplicate=True)
    prepared = _prepared(snapshot, inventory=_inventory(snapshot), bindings=bindings)
    assert prepared.candidate.series[0].prefix == "g"
    assert next(item for item in prepared.candidate.accounts if item.account_id == "h-account").enabled is False


def test_materialization_rejects_two_active_duplicate_accounts_deterministically() -> None:
    snapshot = _snapshot()
    with pytest.raises(GMigrationApplyError, match="multiple_active_credential_bindings"):
        _prepared(snapshot, bindings=_bindings(duplicate=True))


def test_materialization_reuses_journaled_allocations_without_uuid() -> None:
    snapshot = _snapshot()
    preflight = _preflight_g_migration(snapshot, _inventory(snapshot), QUEEN_G_MANIFEST_V1)
    journaled = tuple(
        MemberIdAllocation(f"v1:{prefix}:1", str(UUIDS[index]))
        for index, prefix in enumerate("ghijklmnop")
    )
    calls: list[int] = []
    prepared = _materialize_g_migration_locked(
        snapshot,
        _bindings(),
        preflight,
        journaled,
        lambda: calls.append(1),
    )
    assert prepared.allocations == journaled
    assert calls == []


class SyntheticCrash(RuntimeError):
    pass


class _SyntheticMigrationService:
    def __init__(self, root: Path, snapshot: FleetSnapshot, bindings: dict[str, str]) -> None:
        self._paths = server_module.FleetPaths.from_state_root(root / "state")
        self._io = server_module.build_fleet_private_io(self._paths)
        self.snapshot = snapshot
        self.bindings = bindings

    def load(self) -> FleetSnapshot | object:
        return self.snapshot

    def _with_g_migration_binding_evidence(self, account_ids, *, expected_generation, callback):
        assert expected_generation == self.snapshot.generation
        assert tuple(account_ids) == tuple(account.account_id for account in self.snapshot.accounts)
        return callback(self.snapshot, self.bindings)

    def commit_snapshot(self, snapshot, *, expected_generation):
        assert expected_generation == self.snapshot.generation
        self.snapshot = snapshot
        return snapshot


def _synthetic_migration_state(tmp_path: Path) -> tuple[_SyntheticMigrationService, Path]:
    snapshot = _snapshot()
    pool_root = tmp_path / "pool"
    pool_root.mkdir(parents=True)
    pool_root.chmod(0o700)
    for agent_id in _inventory(snapshot).agent_ids:
        home = pool_root / agent_id
        home.mkdir()
        home.chmod(0o700)
    return _SyntheticMigrationService(tmp_path, snapshot, _bindings()), pool_root


def _use_uuid_free_synthetic_journal_io(service: _SyntheticMigrationService) -> None:
    def replace_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)

    service._io = replace(service._io, replace_text=replace_text)


def test_g_apply_uses_only_task3b_uuid_for_migration_id_and_retry(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)
    _use_uuid_free_synthetic_journal_io(service)
    uuid_calls: list[int] = []
    uuid_values = iter(UUIDS)

    def controlled_uuid4() -> UUID:
        uuid_calls.append(len(uuid_calls))
        return next(uuid_values)

    def crash(point: str) -> None:
        if point == "after_g_journal":
            raise SyntheticCrash(point)

    with _safe_synthetic_runtime(), patch.object(
        server_module.uuid, "uuid4", side_effect=controlled_uuid4
    ), patch.object(server_module, "_g_migration_crash_point", side_effect=crash, create=True):
        with pytest.raises(SyntheticCrash):
            server_module._apply_g_series_migration_for_authorized_caller(
                service=service,
                manifest=QUEEN_G_MANIFEST_V1,
                pool_root=pool_root,
            )

    journal_path = service._paths.root / "g-series-migration.json"
    journal = normalize_g_migration_journal(json.loads(journal_path.read_text()))
    assert len(uuid_calls) == len(SOURCE_IDS)
    assert journal.migration_id == UUID(journal.allocations[0].member_id).hex

    with _safe_synthetic_runtime(), patch.object(
        server_module.uuid, "uuid4", side_effect=AssertionError("retry allocated UUID")
    ), pytest.raises(server_module.AgentError, match="migration_recovery_rolled_back"):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not journal_path.exists()


@pytest.mark.parametrize(
    "allocations",
    [
        (),
        (MemberIdAllocation("v1:g:1", "not-a-canonical-member-id"),),
    ],
)
def test_g_apply_rejects_missing_or_noncanonical_allocation_before_uuid(
    allocations: tuple[MemberIdAllocation, ...],
    tmp_path: Path,
) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)
    _use_uuid_free_synthetic_journal_io(service)
    prepared = _prepared(_snapshot())
    malformed = replace(prepared, allocations=allocations)
    uuid_calls: list[int] = []

    def unexpected_uuid4() -> UUID:
        uuid_calls.append(1)
        return UUIDS[0]

    with _safe_synthetic_runtime(), patch.object(
        server_module, "_materialize_g_migration_locked", return_value=malformed
    ), patch.object(server_module.uuid, "uuid4", side_effect=unexpected_uuid4), pytest.raises(
        server_module.AgentError, match="migration_manifest_invalid"
    ):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert uuid_calls == []
    assert not (service._paths.root / "g-series-migration.json").exists()


@contextlib.contextmanager
def _safe_synthetic_runtime():
    with patch.object(server_module, "agent_lease_status", return_value={"state": "unclaimed"}), patch.object(
        server_module, "pool_home_processes", return_value=[]
    ), patch.object(server_module, "_fleet_tmux_state", return_value="stopped"), patch.object(
        server_module, "publish_agent_inventory"
    ):
        yield


@pytest.mark.parametrize(
    "crash_point",
    [
        "after_g_journal",
        "after_home_stage",
        "after_home_materialize",
        "after_alias_prepare",
        "after_registry_cas",
        "after_inventory_publish",
    ],
)
def test_g_crash_matrix_reuses_journaled_ids_and_redacts(
    crash_point: str,
    tmp_path: Path,
) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)

    def crash(point: str) -> None:
        if point == crash_point:
            raise SyntheticCrash(point)

    with _safe_synthetic_runtime(), patch.object(
        server_module, "_g_migration_crash_point", side_effect=crash, create=True
    ):
        with pytest.raises(SyntheticCrash):
            server_module._apply_g_series_migration_for_authorized_caller(
                service=service,
                manifest=QUEEN_G_MANIFEST_V1,
                pool_root=pool_root,
            )

    journal_path = service._paths.root / "g-series-migration.json"
    journal = normalize_g_migration_journal(json.loads(journal_path.read_text()))
    assert journal.allocations
    journaled_member_ids = {item.member_id for item in journal.allocations}
    rendered = repr(journal) + str(journal)
    assert "marker-binding" not in rendered
    assert "member_id" not in rendered

    if crash_point in {"after_registry_cas", "after_inventory_publish"}:
        with _safe_synthetic_runtime():
            recovered = server_module._apply_g_series_migration_for_authorized_caller(
                service=service,
                manifest=QUEEN_G_MANIFEST_V1,
                pool_root=pool_root,
            )
        assert recovered.generation == 219
        assert public_fleet_snapshot(recovered)["generation"] == 219
        assert {
            member.member_id
            for series in recovered.series
            for member in series.members
        } == journaled_member_ids
    else:
        with _safe_synthetic_runtime():
            recovered = server_module._recover_g_series_migration_for_authorized_caller(
                service=service,
                pool_root=pool_root,
            )
        assert recovered is None
        assert service.snapshot.generation == 218

    assert not journal_path.exists()
    assert not any("marker-secret" in str(value) for value in (service.snapshot, recovered))


def test_g_recovery_reuses_published_alias_view_without_reassignment(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)

    def crash(point: str) -> None:
        if point == "after_inventory_publish":
            raise SyntheticCrash(point)

    real_publish = server_module.publish_agent_inventory
    try:
        with _safe_synthetic_runtime(), patch.object(
            server_module, "publish_agent_inventory", wraps=real_publish
        ), patch.object(
            server_module, "_g_migration_crash_point", side_effect=crash, create=True
        ), pytest.raises(SyntheticCrash):
            server_module._apply_g_series_migration_for_authorized_caller(
                service=service,
                manifest=QUEEN_G_MANIFEST_V1,
                pool_root=pool_root,
            )

        journal_path = service._paths.root / "g-series-migration.json"
        journal = normalize_g_migration_journal(json.loads(journal_path.read_text()))
        assert journal.aliases
        alias = journal.aliases[0]
        with patch.object(server_module, "current_agent_inventory", side_effect=AssertionError("resolver I/O")), patch.object(
            server_module, "g_migration_alias_view", side_effect=AssertionError("second alias parser")
        ):
            assert server_module.canonical_agent_id(alias.old_agent_id) == alias.current_agent_id

        with _safe_synthetic_runtime(), patch.object(
            server_module, "publish_agent_inventory", wraps=real_publish
        ):
            recovered = server_module._recover_g_series_migration_for_authorized_caller(
                service=service,
                pool_root=pool_root,
            )
        assert recovered is not None
        assert recovered.generation == 219
        with patch.object(server_module, "current_agent_inventory", side_effect=AssertionError("resolver I/O")), patch.object(
            server_module, "g_migration_alias_view", side_effect=AssertionError("second alias parser")
        ):
            assert server_module.canonical_agent_id(alias.old_agent_id) == alias.current_agent_id
    finally:
        server_module.swap_agent_inventory(None)


def test_g_adapter_binding_failure_precedes_journal_and_home(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)
    service.bindings = {}
    with _safe_synthetic_runtime(), pytest.raises(
        server_module.AgentError,
        match="credential_binding_unknown",
    ):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not (service._paths.root / "g-series-migration.json").exists()
    assert {path.name for path in pool_root.iterdir()} == set(_inventory(_snapshot()).agent_ids)
    assert service.snapshot.generation == 218


def test_g_adapter_binding_drift_fails_closed_before_journal(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)

    def drift(*_args, **_kwargs):
        raise server_module.FleetSecretError("credential_binding_unavailable")

    service._with_g_migration_binding_evidence = drift
    with _safe_synthetic_runtime(), pytest.raises(
        server_module.AgentError,
        match="credential_binding_unknown",
    ):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not (service._paths.root / "g-series-migration.json").exists()
    assert service.snapshot.generation == 218


def test_g_adapter_collision_cross_device_and_symlink_fail_closed(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)
    (pool_root / "g2").mkdir()
    with _safe_synthetic_runtime(), pytest.raises(server_module.AgentError, match="migration_home_collision"):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not (service._paths.root / "g-series-migration.json").exists()
    (pool_root / "g2").rmdir()

    service, pool_root = _synthetic_migration_state(tmp_path / "cross-device")
    real_rename = server_module.os.rename
    rename_calls = 0

    def fail_cross_device(source, target):
        nonlocal rename_calls
        rename_calls += 1
        if rename_calls == 1:
            raise OSError(errno.EXDEV, "synthetic cross-device")
        return real_rename(source, target)

    with _safe_synthetic_runtime(), patch.object(
        server_module.os,
        "rename",
        side_effect=fail_cross_device,
    ), pytest.raises(server_module.AgentError, match="migration_home_cross_device"):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not (service._paths.root / "g-series-migration.json").exists()
    assert (pool_root / "h1").is_dir()

    service, pool_root = _synthetic_migration_state(tmp_path / "symlink")
    external = tmp_path / "external-home"
    external.mkdir()
    (pool_root / "h1").rmdir()
    (pool_root / "h1").symlink_to(external, target_is_directory=True)
    with _safe_synthetic_runtime(), pytest.raises(server_module.AgentError, match="migration_home_state_unknown"):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert not (service._paths.root / "g-series-migration.json").exists()
    assert not any(external.iterdir())


def test_g_adapter_rejects_hardlinked_private_journal(tmp_path: Path) -> None:
    service, pool_root = _synthetic_migration_state(tmp_path)
    service._paths.root.mkdir(parents=True)
    outside = tmp_path / "journal-copy"
    outside.write_text("synthetic", encoding="utf-8")
    journal_path = service._paths.root / "g-series-migration.json"
    journal_path.hardlink_to(outside)
    with _safe_synthetic_runtime(), pytest.raises(server_module.AgentError, match="migration_journal_invalid"):
        server_module._apply_g_series_migration_for_authorized_caller(
            service=service,
            manifest=QUEEN_G_MANIFEST_V1,
            pool_root=pool_root,
        )
    assert outside.read_text(encoding="utf-8") == "synthetic"
