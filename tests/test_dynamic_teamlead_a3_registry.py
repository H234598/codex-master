from __future__ import annotations

from dataclasses import replace

import pytest

from codex_master.dynamic_teamlead_a3_registry import FleetV2RegistryOperations
from codex_master.fleet_registry import FleetSnapshot, FleetSnapshotV2


class InMemoryStore:
    def __init__(
        self,
        current: object,
        *,
        result: object | None = None,
        load_error: Exception | None = None,
        commit_error: Exception | None = None,
    ) -> None:
        self.current = current
        self.result = result
        self.load_error = load_error
        self.commit_error = commit_error
        self.load_calls = 0
        self.commit_calls: list[tuple[object, int]] = []

    def load(self) -> object:
        self.load_calls += 1
        if self.load_error is not None:
            raise self.load_error
        return self.current

    def commit_snapshot(
        self,
        snapshot: object,
        *,
        expected_generation: int,
    ) -> object:
        self.commit_calls.append((snapshot, expected_generation))
        if self.commit_error is not None:
            raise self.commit_error
        if self.result is None:
            self.current = snapshot
            return snapshot
        return self.result


def snapshot(generation: int = 7, schema_version: int = 2) -> FleetSnapshotV2:
    return FleetSnapshotV2(schema_version, generation, (), (), ())


@pytest.mark.parametrize(
    "captured",
    (FleetSnapshot(1, 7, (), ()), object(), snapshot(schema_version=1), snapshot(0)),
)
def test_rejects_non_v2_or_invalid_captured_snapshot(captured: object) -> None:
    with pytest.raises(ValueError):
        FleetV2RegistryOperations(InMemoryStore(snapshot()), captured)  # type: ignore[arg-type]


def test_commits_exact_captured_v2_source_once() -> None:
    captured = snapshot()
    candidate = snapshot(8)
    store = InMemoryStore(captured)
    operations = FleetV2RegistryOperations(store, captured)

    returned = operations.commit_snapshot(candidate, expected_generation=7)

    assert type(returned) is FleetSnapshotV2
    assert returned == candidate
    assert store.load_calls == 1
    assert store.commit_calls == [(candidate, 7)]


@pytest.mark.parametrize(
    "loaded",
    (FleetSnapshot(1, 7, (), ()), object(), snapshot(schema_version=1)),
)
def test_rejects_v1_or_non_v2_loaded_source_before_commit(loaded: object) -> None:
    captured = snapshot()
    store = InMemoryStore(loaded)
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(snapshot(8), expected_generation=7)

    assert store.commit_calls == []


def test_rejects_source_drift_before_commit() -> None:
    captured = snapshot()
    store = InMemoryStore(replace(captured, generation=8))
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(snapshot(8), expected_generation=7)

    assert store.commit_calls == []


@pytest.mark.parametrize("expected_generation", (6, 8, True, "7"))
def test_rejects_wrong_expected_generation_before_commit(
    expected_generation: object,
) -> None:
    captured = snapshot()
    store = InMemoryStore(captured)
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(  # type: ignore[arg-type]
            snapshot(8),
            expected_generation=expected_generation,
        )

    assert store.commit_calls == []


@pytest.mark.parametrize("candidate", (snapshot(7), snapshot(9), object()))
def test_rejects_non_next_or_non_v2_candidate_before_commit(candidate: object) -> None:
    captured = snapshot()
    store = InMemoryStore(captured)
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(candidate, expected_generation=7)  # type: ignore[arg-type]

    assert store.commit_calls == []


def test_propagates_load_exception_and_rejects_duplicate_attempt() -> None:
    captured = snapshot()
    store = InMemoryStore(captured, load_error=RuntimeError("load failed"))
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(RuntimeError, match="load failed"):
        operations.commit_snapshot(snapshot(8), expected_generation=7)
    with pytest.raises(ValueError, match="already used"):
        operations.commit_snapshot(snapshot(8), expected_generation=7)

    assert store.commit_calls == []
    assert store.load_calls == 1


def test_propagates_store_exception_without_retry() -> None:
    captured = snapshot()
    store = InMemoryStore(captured, commit_error=RuntimeError("commit failed"))
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(RuntimeError, match="commit failed"):
        operations.commit_snapshot(snapshot(8), expected_generation=7)
    with pytest.raises(ValueError, match="already used"):
        operations.commit_snapshot(snapshot(8), expected_generation=7)

    assert store.commit_calls == [(snapshot(8), 7)]
    assert store.load_calls == 1


def test_rejects_wrong_store_return_type_without_retry() -> None:
    captured = snapshot()
    store = InMemoryStore(captured, result=object())
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(snapshot(8), expected_generation=7)
    with pytest.raises(ValueError, match="already used"):
        operations.commit_snapshot(snapshot(8), expected_generation=7)

    assert store.commit_calls == [(snapshot(8), 7)]


def test_rejects_stale_return_generation_without_retry() -> None:
    captured = snapshot()
    candidate = snapshot(8)
    store = InMemoryStore(captured, result=snapshot(7))
    operations = FleetV2RegistryOperations(store, captured)

    with pytest.raises(ValueError):
        operations.commit_snapshot(candidate, expected_generation=7)
    with pytest.raises(ValueError, match="already used"):
        operations.commit_snapshot(candidate, expected_generation=7)

    assert store.commit_calls == [(candidate, 7)]


def test_rejects_duplicate_commit_after_success() -> None:
    captured = snapshot()
    candidate = snapshot(8)
    store = InMemoryStore(captured)
    operations = FleetV2RegistryOperations(store, captured)

    assert operations.commit_snapshot(candidate, expected_generation=7) == candidate
    with pytest.raises(ValueError, match="already used"):
        operations.commit_snapshot(candidate, expected_generation=7)

    assert store.commit_calls == [(candidate, 7)]
