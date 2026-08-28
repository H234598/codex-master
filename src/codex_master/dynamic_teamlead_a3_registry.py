from __future__ import annotations

from typing import Protocol

from codex_master.dynamic_teamlead_coordinator import DynamicTeamleadRegistryOperations
from codex_master.fleet_registry import FleetSnapshotV2


class FleetV2RegistryStore(Protocol):
    def load(self) -> FleetSnapshotV2: ...

    def commit_snapshot(
        self,
        snapshot: FleetSnapshotV2,
        *,
        expected_generation: int,
    ) -> FleetSnapshotV2: ...


class FleetV2RegistryOperations(DynamicTeamleadRegistryOperations):
    __slots__ = ("_store", "_snapshot", "_used")

    def __init__(self, store: FleetV2RegistryStore, snapshot: FleetSnapshotV2):
        if (
            type(snapshot) is not FleetSnapshotV2
            or type(snapshot.schema_version) is not int
            or snapshot.schema_version != 2
            or type(snapshot.generation) is not int
            or snapshot.generation < 1
        ):
            raise ValueError("invalid fleet V2 registry snapshot")
        self._store = store
        self._snapshot = snapshot
        self._used = False

    def commit_snapshot(
        self,
        snapshot: FleetSnapshotV2,
        *,
        expected_generation: int,
    ) -> FleetSnapshotV2:
        if self._used:
            raise ValueError("fleet V2 registry operations already used")
        self._used = True
        current = self._store.load()
        if (
            type(current) is not FleetSnapshotV2
            or type(current.schema_version) is not int
            or current.schema_version != 2
            or current != self._snapshot
            or type(expected_generation) is not int
            or expected_generation != self._snapshot.generation
            or type(snapshot) is not FleetSnapshotV2
            or type(snapshot.schema_version) is not int
            or snapshot.schema_version != 2
            or type(snapshot.generation) is not int
            or snapshot.generation != expected_generation + 1
        ):
            raise ValueError("invalid fleet V2 registry CAS")
        stored = self._store.commit_snapshot(
            snapshot,
            expected_generation=expected_generation,
        )
        if (
            type(stored) is not FleetSnapshotV2
            or type(stored.schema_version) is not int
            or stored.schema_version != 2
            or type(stored.generation) is not int
            or stored.generation != snapshot.generation
            or stored != snapshot
        ):
            raise ValueError("invalid fleet V2 registry CAS result")
        return stored


__all__ = ("FleetV2RegistryOperations", "FleetV2RegistryStore")
