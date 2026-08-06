"""Deterministic work scheduling without account or model selection."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from codex_master.hive.dispatch import WorkPackage
from codex_master.hive.types import DispatchPriority, validate_utc_datetime


class QueueError(ValueError):
    """Raised when a work queue request is invalid."""


_PRIORITY_RANK = {DispatchPriority.DP0: 0, DispatchPriority.DP1: 1, DispatchPriority.DP2: 2, DispatchPriority.DP3: 3}
_RUNNABLE = frozenset({"ready", "queued"})
MAX_QUEUE_ITEMS = 4096
MAX_COST_MICRO = 10**18


@dataclass(frozen=True, order=True, slots=True)
class WorkPriorityKey:
    effective_dispatch_priority: int
    explicit_deadline_epoch_ms: int
    queen_deficit_micro: int
    ready_since_epoch_ms: int
    dependency_unblocked_epoch_ms: int
    repo_id: str
    workpackage_id: str


@dataclass(frozen=True, slots=True)
class QueueDecision:
    workpackage: WorkPackage
    priority_key: WorkPriorityKey
    reason_codes: tuple[str, ...]

    def public(self) -> dict[str, object]:
        return {
            "workpackage_id": self.workpackage.workpackage_id,
            "repo_id": self._repo_id(),
            "priority": self.workpackage.resource_profile.get("dispatch_priority", "not_returned"),
            "reason_codes": list(self.reason_codes),
        }

    def _repo_id(self) -> str:
        # WorkPackage intentionally does not duplicate repository identity;
        # the queue only returns the safe metadata supplied by its caller.
        value = self.workpackage.resource_profile.get("repo_id")
        return value if isinstance(value, str) else "not_returned"


class WorkQueue:
    """Pure queue ordering with optional dependency and deficit evidence."""

    def __init__(
        self,
        items: Iterable[WorkPackage],
        *,
        dependency_done: Callable[[str], bool] | None = None,
        queen_deficit: Callable[[WorkPackage], int] | None = None,
    ) -> None:
        values = tuple(items)
        if len(values) > MAX_QUEUE_ITEMS or any(not isinstance(item, WorkPackage) for item in values):
            raise QueueError("invalid_queue_items")
        ids = [item.workpackage_id for item in values]
        if len(set(ids)) != len(ids):
            raise QueueError("duplicate_workpackage")
        self._items = values
        self._dependency_done = dependency_done or (lambda _workpackage_id: False)
        self._queen_deficit = queen_deficit or (lambda _item: 0)
        self._reserved: dict[str, int] = {}
        self._finalized: dict[str, int | None] = {}

    def runnable_items(self, *, now: datetime) -> tuple[WorkPackage, ...]:
        _now(now)
        runnable: list[WorkPackage] = []
        for item in self._items:
            if item.state not in _RUNNABLE:
                continue
            try:
                dependencies_ready = all(self._dependency_done(dependency) for dependency in item.depends_on_workpackage_ids)
            except Exception:
                dependencies_ready = False
            if dependencies_ready:
                runnable.append(item)
        return tuple(sorted(runnable, key=lambda item: self._key(item, now)))

    def preview(self, *, now: datetime, limit: int) -> tuple[QueueDecision, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= MAX_QUEUE_ITEMS:
            raise QueueError("invalid_queue_limit")
        return tuple(
            QueueDecision(item, self._key(item, now), ("dispatch_priority", "deadline", "queen_fairness", "age"))
            for item in self.runnable_items(now=now)[:limit]
        )

    def select_next(self, *, now: datetime) -> QueueDecision:
        decisions = self.preview(now=now, limit=1)
        if not decisions:
            raise QueueError("no_runnable_workpackage")
        return decisions[0]

    def reserve_cost(self, workpackage_id: str, cost_micro: int) -> None:
        if not isinstance(workpackage_id, str) or workpackage_id not in {item.workpackage_id for item in self._items}:
            raise QueueError("unknown_workpackage")
        if isinstance(cost_micro, bool) or not isinstance(cost_micro, int) or not 0 <= cost_micro <= MAX_COST_MICRO:
            raise QueueError("invalid_queue_cost")
        if workpackage_id in self._reserved or workpackage_id in self._finalized:
            raise QueueError("queue_cost_already_recorded")
        self._reserved[workpackage_id] = cost_micro

    def finalize_cost(self, workpackage_id: str, actual_cost_micro: int | None) -> None:
        if workpackage_id not in self._reserved:
            raise QueueError("queue_cost_not_reserved")
        if actual_cost_micro is not None and (
            isinstance(actual_cost_micro, bool) or not isinstance(actual_cost_micro, int) or not 0 <= actual_cost_micro <= MAX_COST_MICRO
        ):
            raise QueueError("invalid_queue_cost")
        self._finalized[workpackage_id] = actual_cost_micro
        del self._reserved[workpackage_id]

    def rollback_cost(self, workpackage_id: str) -> None:
        if workpackage_id not in self._reserved:
            raise QueueError("queue_cost_not_reserved")
        del self._reserved[workpackage_id]

    def _key(self, item: WorkPackage, now: datetime) -> WorkPriorityKey:
        raw_priority = item.resource_profile.get("dispatch_priority", DispatchPriority.DP3.value)
        try:
            priority = raw_priority if isinstance(raw_priority, DispatchPriority) else DispatchPriority(raw_priority)
        except ValueError:
            priority = DispatchPriority.DP3
        deadline = item.resource_profile.get("deadline_epoch_ms", 2**63 - 1)
        ready = item.ready_since_utc or now
        try:
            deadline_ms = int(deadline) if isinstance(deadline, int) and deadline >= 0 else 2**63 - 1
            ready_ms = int(validate_utc_datetime(ready).timestamp() * 1000)
        except (OverflowError, TypeError, ValueError):
            deadline_ms = 2**63 - 1
            ready_ms = 2**63 - 1
        try:
            deficit = int(self._queen_deficit(item))
        except (TypeError, ValueError, OverflowError):
            deficit = 0
        deficit = max(-MAX_COST_MICRO, min(MAX_COST_MICRO, deficit))
        return WorkPriorityKey(_PRIORITY_RANK[priority], deadline_ms, -deficit, ready_ms, ready_ms, str(item.resource_profile.get("repo_id", "")), item.workpackage_id)


def _now(value: datetime) -> datetime:
    try:
        return validate_utc_datetime(value, field="queue_time")
    except ValueError as exc:
        raise QueueError(str(exc)) from exc


__all__ = ["QueueDecision", "QueueError", "WorkPriorityKey", "WorkQueue"]
