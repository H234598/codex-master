"""Bounded in-process Selection resource state with revision CAS."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock

from codex_master.selection import FairnessLedger


class ResourceStateError(ValueError):
    """Raised for invalid or stale Selection state."""


@dataclass(frozen=True, slots=True)
class ResourceState:
    revision: int
    fairness: FairnessLedger
    selection_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or not 0 <= self.revision <= 10**12:
            raise ResourceStateError("invalid_resource_revision")
        if not isinstance(self.fairness, FairnessLedger):
            raise ResourceStateError("invalid_resource_fairness")
        if not isinstance(self.selection_ids, tuple) or len(self.selection_ids) > 4096:
            raise ResourceStateError("invalid_selection_ids")
        if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in self.selection_ids):
            raise ResourceStateError("invalid_selection_ids")


class ResourceStateStore:
    def __init__(self, state: ResourceState | None = None) -> None:
        self._lock = RLock()
        self._state = state or ResourceState(0, FairnessLedger({}))

    def read(self) -> ResourceState:
        with self._lock:
            return self._state

    def compare_and_replace(self, *, expected_revision: int, state: ResourceState) -> ResourceState:
        if not isinstance(state, ResourceState):
            raise ResourceStateError("invalid_resource_state")
        with self._lock:
            if expected_revision != self._state.revision:
                raise ResourceStateError("stale_resource_revision")
            if state.revision != expected_revision + 1:
                raise ResourceStateError("invalid_resource_revision")
            self._state = state
            return state


def migrate_resource_state(payload: Mapping[str, object]) -> ResourceState:
    if not isinstance(payload, Mapping):
        raise ResourceStateError("invalid_resource_state")
    version = payload.get("schema_version", 1)
    if version not in {0, 1}:
        raise ResourceStateError("unsupported_resource_schema")
    return ResourceState(int(payload.get("revision", 0)), FairnessLedger({}))


__all__ = ["ResourceState", "ResourceStateError", "ResourceStateStore", "migrate_resource_state"]
