"""The sole source-owned dynamic-pool product dispatcher.

This module owns one private, persisted unit of Hive dispatch evidence.  It
does not discover a pool, inspect authority, or perform a runtime action.  A
server composition supplies the authority reader and a narrow bridge to the
existing admission gate; the only effect-facing port is reached exclusively
from the private admission callback below.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Protocol

from the_hive.admission import AdmissionRecord, AdmissionState, MAX_ADMISSION_ID_LENGTH
from the_hive.dynamic_pool import (
    AccountPoolBindingV1,
    DynamicPoolInventoryEntryV1,
    DynamicPoolInventoryV1,
    account_pool_binding_from_payload,
    account_pool_binding_payload,
)
from the_hive.hive.authority import DelegationGrant
from the_hive.hive.control_plane_store import HiveControlPlaneStore
from the_hive.hive.dispatch import (
    AssignmentIntent,
    QueenAssignmentPlan,
    WorkPackage,
    plan_queen_assignment_from_selection,
)
from the_hive.hive.types import DispatchPriority, TaskComplexity
from the_hive.selection import SelectionBand, SelectionResult
from the_hive.selection_service import MAX_EXECUTION_ATTEMPTS
from the_hive.usage_snapshot import UsageEvidenceV2


_RECORD_KIND = "hive_work_dispatcher"
_RECORD_KEYS = frozenset(
    {
        "kind",
        "dispatch_id",
        "generation",
        "state",
        "digest",
        "transitions",
        "workpackage",
        "intent",
        "grant",
        "selection",
        "dynamic_inventory",
        "scope_digest",
        "base_admission_id",
        "bound_account_pool_binding",
        "bound_dynamic_pool_digest",
    }
)
_TRANSITION_KEYS = frozenset({"generation", "state", "digest"})
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ALLOWED_TRANSITIONS = {
    "persisted": frozenset({"bound", "blocked"}),
    "bound": frozenset({"bridge_returned", "blocked"}),
    "bridge_returned": frozenset(),
    "blocked": frozenset(),
}


class HiveWorkDispatcherError(ValueError):
    """Raised when the complete private dispatcher unit cannot be trusted."""


class PoolExecutionPort(Protocol):
    """Resolver-free private effect port reached only after admission."""

    def execute(
        self, admission: AdmissionRecord, fresh_lease: Mapping[str, object]
    ) -> Mapping[str, object]:
        """Perform the already-admitted product action."""


class HiveAssignmentExecutionBridge(Protocol):
    """Narrow server adapter around the one existing Hive admission gate."""

    def scope_digest(
        self, repo_id: str, mode: str, paths: tuple[str, ...]
    ) -> str:
        """Read the existing repository-owned canonical scope digest."""

    def base_admission_id(self) -> str:
        """Read the server-bound base ID used by its admission retry factory."""

    def execute(
        self,
        *,
        plan: QueenAssignmentPlan,
        pool_authority_reader: Callable[[], UsageEvidenceV2],
        hive_assignment_callback: Callable[
            [AdmissionRecord, Mapping[str, object]], Mapping[str, object]
        ],
    ) -> Mapping[str, object]:
        """Invoke the existing admission gate with the bound callback."""


@dataclass(frozen=True, slots=True)
class HiveWorkTransition:
    """One append-only private aggregate transition."""

    generation: int
    state: str
    digest: str

    def __post_init__(self) -> None:
        if type(self.generation) is not int or self.generation < 1:
            raise HiveWorkDispatcherError("invalid_hive_work_generation")
        if self.state not in _ALLOWED_TRANSITIONS:
            raise HiveWorkDispatcherError("invalid_hive_work_state")
        if not isinstance(self.digest, str) or _DIGEST_RE.fullmatch(self.digest) is None:
            raise HiveWorkDispatcherError("invalid_hive_work_digest")


@dataclass(frozen=True, slots=True)
class HiveWorkAggregate:
    """One complete typed dispatcher-owned unit, retained across restart."""

    workpackage: WorkPackage
    intent: AssignmentIntent
    grant: DelegationGrant
    selection: SelectionResult
    dynamic_inventory: DynamicPoolInventoryV1
    scope_digest: str
    base_admission_id: str
    bound_account_pool_binding: AccountPoolBindingV1 | None
    bound_dynamic_pool_digest: str | None
    generation: int
    state: str
    digest: str
    transitions: tuple[HiveWorkTransition, ...]

    def __post_init__(self) -> None:
        _validate_unit(
            self.workpackage,
            self.intent,
            self.grant,
            self.selection,
            self.dynamic_inventory,
            self.scope_digest,
            self.base_admission_id,
            self.state,
            self.bound_account_pool_binding,
            self.bound_dynamic_pool_digest,
        )
        if type(self.generation) is not int or self.generation < 1:
            raise HiveWorkDispatcherError("invalid_hive_work_generation")
        if not isinstance(self.scope_digest, str) or _DIGEST_RE.fullmatch(self.scope_digest) is None:
            raise HiveWorkDispatcherError("invalid_hive_work_scope_digest")
        if not _is_valid_base_admission_id(self.base_admission_id):
            raise HiveWorkDispatcherError("invalid_hive_work_admission_id")
        if self.state not in _ALLOWED_TRANSITIONS:
            raise HiveWorkDispatcherError("invalid_hive_work_state")
        if not isinstance(self.digest, str) or _DIGEST_RE.fullmatch(self.digest) is None:
            raise HiveWorkDispatcherError("invalid_hive_work_digest")
        if not isinstance(self.transitions, tuple) or len(self.transitions) != self.generation:
            raise HiveWorkDispatcherError("invalid_hive_work_transitions")
        for expected_generation, transition in enumerate(self.transitions, start=1):
            if (
                not isinstance(transition, HiveWorkTransition)
                or transition.generation != expected_generation
            ):
                raise HiveWorkDispatcherError("invalid_hive_work_transitions")
        if self.transitions[-1].state != self.state:
            raise HiveWorkDispatcherError("invalid_hive_work_transitions")
        expected_digest = _aggregate_digest(
            self.workpackage,
            self.intent,
            self.grant,
            self.selection,
            self.dynamic_inventory,
            self.scope_digest,
            self.base_admission_id,
            self.bound_account_pool_binding,
            self.bound_dynamic_pool_digest,
            generation=self.generation,
            state=self.state,
        )
        if self.digest != expected_digest:
            raise HiveWorkDispatcherError("hive_work_digest_mismatch")
        for transition in self.transitions:
            transition_binding = (
                None
                if transition.state == "persisted"
                else self.bound_account_pool_binding
            )
            transition_binding_digest = (
                None
                if transition.state == "persisted"
                else self.bound_dynamic_pool_digest
            )
            transition_aggregate_digest = _aggregate_digest(
                self.workpackage,
                self.intent,
                self.grant,
                self.selection,
                self.dynamic_inventory,
                self.scope_digest,
                self.base_admission_id,
                transition_binding,
                transition_binding_digest,
                generation=transition.generation,
                state=transition.state,
            )
            expected_transition_digest = _transition_digest(
                transition.generation,
                transition.state,
                transition_aggregate_digest,
            )
            if transition.digest != expected_transition_digest:
                raise HiveWorkDispatcherError("hive_work_transition_digest_mismatch")

    @property
    def dispatch_id(self) -> str:
        return self.workpackage.dispatch_id


class HiveWorkDispatcher:
    """Persist and execute exactly one D69-bound Hive product unit per dispatch."""

    def __init__(
        self,
        control_plane: HiveControlPlaneStore,
        *,
        execution_port: PoolExecutionPort | None = None,
    ) -> None:
        if not isinstance(control_plane, HiveControlPlaneStore):
            raise HiveWorkDispatcherError("invalid_hive_work_control_plane")
        if execution_port is not None and not callable(getattr(execution_port, "execute", None)):
            raise HiveWorkDispatcherError("invalid_pool_execution_port")
        self._control_plane = control_plane
        self._execution_port = execution_port

    def persist(
        self,
        *,
        workpackage: WorkPackage,
        intent: AssignmentIntent,
        grant: DelegationGrant,
        selection: SelectionResult,
        dynamic_inventory: DynamicPoolInventoryV1,
        scope_digest: str,
        base_admission_id: str,
        now: datetime,
    ) -> HiveWorkAggregate:
        """Write one complete private aggregate through the Task-9 CAS owner."""

        aggregate = _initial_aggregate(
            workpackage,
            intent,
            grant,
            selection,
            dynamic_inventory,
            scope_digest,
            base_admission_id,
        )
        document = self._control_plane.load_task9()
        records = _records(document)
        if any(record["dispatch_id"] == aggregate.dispatch_id for record in records):
            raise HiveWorkDispatcherError("duplicate_hive_work_dispatch")
        updated = dict(document)
        updated["pool_dispatches"] = [*records, _record_from_aggregate(aggregate)]
        self._control_plane.replace_task9(
            updated,
            expected_revision=_revision(document),
            now=now,
        )
        return aggregate

    def rehydrate(self, dispatch_id: str) -> HiveWorkAggregate:
        """Load exactly one strict aggregate record without recreating a binding."""

        if not isinstance(dispatch_id, str) or not dispatch_id:
            raise HiveWorkDispatcherError("invalid_hive_work_dispatch")
        matches = [
            record
            for record in _records(self._control_plane.load_task9())
            if record["dispatch_id"] == dispatch_id
        ]
        if len(matches) != 1:
            raise HiveWorkDispatcherError("hive_work_unavailable")
        return _aggregate_from_record(matches[0])

    def dispatch(
        self,
        *,
        queen_id: str,
        workpackage: WorkPackage,
        intent: AssignmentIntent,
        grant: DelegationGrant,
        selection: SelectionResult,
        dynamic_inventory: DynamicPoolInventoryV1,
        planner_input: Mapping[str, object],
        execution_bridge: HiveAssignmentExecutionBridge,
        pool_authority_reader: Callable[[], UsageEvidenceV2],
        now: datetime,
    ) -> Mapping[str, object]:
        """Bind once, then delegate the one admission execution to the server bridge."""

        if (
            not callable(getattr(execution_bridge, "execute", None))
            or not callable(getattr(execution_bridge, "scope_digest", None))
            or not callable(getattr(execution_bridge, "base_admission_id", None))
        ):
            raise HiveWorkDispatcherError("invalid_hive_execution_bridge")
        if not callable(pool_authority_reader):
            raise HiveWorkDispatcherError("invalid_pool_authority_reader")
        _validate_planner_input(
            planner_input, workpackage, intent, selection
        )
        try:
            base_admission_id = execution_bridge.base_admission_id()
        except Exception as exc:
            raise HiveWorkDispatcherError("hive_work_admission_unavailable") from exc
        if not _is_valid_base_admission_id(base_admission_id):
            raise HiveWorkDispatcherError("invalid_hive_work_admission_id")
        try:
            scope_digest = execution_bridge.scope_digest(
                intent.repo_id, "write", workpackage.write_paths
            )
        except Exception as exc:
            raise HiveWorkDispatcherError("hive_work_scope_unavailable") from exc
        if not isinstance(scope_digest, str) or _DIGEST_RE.fullmatch(scope_digest) is None:
            raise HiveWorkDispatcherError("invalid_hive_work_scope_digest")
        aggregate = self.persist(
            workpackage=workpackage,
            intent=intent,
            grant=grant,
            selection=selection,
            dynamic_inventory=dynamic_inventory,
            scope_digest=scope_digest,
            base_admission_id=base_admission_id,
            now=now,
        )
        plan = plan_queen_assignment_from_selection(
            queen_id=queen_id,
            dispatch_id=aggregate.dispatch_id,
            workpackage=planner_input,
            selection=aggregate.selection,
            dynamic_inventory=aggregate.dynamic_inventory,
        )
        if not isinstance(plan, QueenAssignmentPlan):
            raise HiveWorkDispatcherError("invalid_hive_assignment_plan")
        self._replace(_bind(aggregate, plan.account_pool_binding), now=now)
        result = execution_bridge.execute(
            plan=plan,
            pool_authority_reader=pool_authority_reader,
            hive_assignment_callback=self._hive_assignment_callback,
        )
        if not isinstance(result, Mapping):
            raise HiveWorkDispatcherError("invalid_hive_execution_result")
        self._replace(
            _advance(self.rehydrate(aggregate.dispatch_id), "bridge_returned"),
            now=now,
        )
        return dict(result)

    def _replace(self, aggregate: HiveWorkAggregate, *, now: datetime) -> HiveWorkAggregate:
        document = self._control_plane.load_task9()
        records = _records(document)
        matches = [
            index
            for index, record in enumerate(records)
            if record["dispatch_id"] == aggregate.dispatch_id
        ]
        if len(matches) != 1:
            raise HiveWorkDispatcherError("hive_work_unavailable")
        index = matches[0]
        current = _aggregate_from_record(records[index])
        if current.generation + 1 != aggregate.generation:
            raise HiveWorkDispatcherError("stale_hive_work_generation")
        updated_records = list(records)
        updated_records[index] = _record_from_aggregate(aggregate)
        updated = dict(document)
        updated["pool_dispatches"] = updated_records
        self._control_plane.replace_task9(
            updated,
            expected_revision=_revision(document),
            now=now,
        )
        return aggregate

    def _hive_assignment_callback(
        self, admission: AdmissionRecord, fresh_lease: Mapping[str, object]
    ) -> Mapping[str, object]:
        """Call only the explicitly bound resolver-free product effect port."""

        if not isinstance(admission, AdmissionRecord) or not isinstance(fresh_lease, Mapping):
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        if self._execution_port is None:
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        try:
            aggregate = self.rehydrate(admission.dispatch_id)
        except (HiveWorkDispatcherError, ValueError, TypeError):
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        if not _admission_matches_bound_aggregate(admission, aggregate, fresh_lease):
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        try:
            result = self._execution_port.execute(admission, fresh_lease)
        except Exception:
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        if not isinstance(result, Mapping):
            return {"allowed": False, "reason_code": "pool_execution_unavailable"}
        return dict(result)


def _initial_aggregate(
    workpackage: WorkPackage,
    intent: AssignmentIntent,
    grant: DelegationGrant,
    selection: SelectionResult,
    dynamic_inventory: DynamicPoolInventoryV1,
    scope_digest: str,
    base_admission_id: str,
) -> HiveWorkAggregate:
    _validate_unit(
        workpackage,
        intent,
        grant,
        selection,
        dynamic_inventory,
        scope_digest,
        base_admission_id,
        "persisted",
        None,
        None,
    )
    digest = _aggregate_digest(
        workpackage,
        intent,
        grant,
        selection,
        dynamic_inventory,
        scope_digest,
        base_admission_id,
        None,
        None,
        generation=1,
        state="persisted",
    )
    return HiveWorkAggregate(
        workpackage,
        intent,
        grant,
        selection,
        dynamic_inventory,
        scope_digest,
        base_admission_id,
        None,
        None,
        1,
        "persisted",
        digest,
        (HiveWorkTransition(1, "persisted", _transition_digest(1, "persisted", digest)),),
    )


def _advance(aggregate: HiveWorkAggregate, state: str) -> HiveWorkAggregate:
    if state not in _ALLOWED_TRANSITIONS.get(aggregate.state, frozenset()):
        raise HiveWorkDispatcherError("invalid_hive_work_transition")
    generation = aggregate.generation + 1
    digest = _aggregate_digest(
        aggregate.workpackage,
        aggregate.intent,
        aggregate.grant,
        aggregate.selection,
        aggregate.dynamic_inventory,
        aggregate.scope_digest,
        aggregate.base_admission_id,
        aggregate.bound_account_pool_binding,
        aggregate.bound_dynamic_pool_digest,
        generation=generation,
        state=state,
    )
    transitions = (*aggregate.transitions, HiveWorkTransition(generation, state, _transition_digest(generation, state, digest)))
    return replace(aggregate, generation=generation, state=state, digest=digest, transitions=transitions)


def _bind(
    aggregate: HiveWorkAggregate, binding: AccountPoolBindingV1 | None
) -> HiveWorkAggregate:
    """Persist exactly the one D69 output before entering the admission bridge."""

    if aggregate.state != "persisted" or not isinstance(binding, AccountPoolBindingV1):
        raise HiveWorkDispatcherError("invalid_hive_work_binding")
    expected = _inventory_binding(aggregate.dynamic_inventory, aggregate.selection.agent_id)
    if binding != expected:
        raise HiveWorkDispatcherError("hive_work_binding_mismatch")
    generation = aggregate.generation + 1
    digest = _aggregate_digest(
        aggregate.workpackage,
        aggregate.intent,
        aggregate.grant,
        aggregate.selection,
        aggregate.dynamic_inventory,
        aggregate.scope_digest,
        aggregate.base_admission_id,
        binding,
        _dynamic_pool_binding_digest(aggregate.selection.agent_id, binding),
        generation=generation,
        state="bound",
    )
    transitions = (*aggregate.transitions, HiveWorkTransition(
        generation,
        "bound",
        _transition_digest(generation, "bound", digest),
    ))
    return replace(
        aggregate,
        bound_account_pool_binding=binding,
        bound_dynamic_pool_digest=_dynamic_pool_binding_digest(aggregate.selection.agent_id, binding),
        generation=generation,
        state="bound",
        digest=digest,
        transitions=transitions,
    )


def _validate_unit(
    workpackage: object,
    intent: object,
    grant: object,
    selection: object,
    dynamic_inventory: object,
    scope_digest: object,
    base_admission_id: object,
    state: object,
    bound_account_pool_binding: object,
    bound_dynamic_pool_digest: object,
) -> None:
    if not isinstance(workpackage, WorkPackage):
        raise HiveWorkDispatcherError("invalid_hive_workpackage")
    if not isinstance(intent, AssignmentIntent):
        raise HiveWorkDispatcherError("invalid_hive_assignment_intent")
    if not isinstance(grant, DelegationGrant):
        raise HiveWorkDispatcherError("invalid_hive_delegation_grant")
    if not isinstance(selection, SelectionResult):
        raise HiveWorkDispatcherError("invalid_hive_selection")
    if not isinstance(dynamic_inventory, DynamicPoolInventoryV1):
        raise HiveWorkDispatcherError("invalid_hive_dynamic_inventory")
    if not isinstance(scope_digest, str) or _DIGEST_RE.fullmatch(scope_digest) is None:
        raise HiveWorkDispatcherError("invalid_hive_work_scope_digest")
    if not _is_valid_base_admission_id(base_admission_id):
        raise HiveWorkDispatcherError("invalid_hive_work_admission_id")
    if (
        workpackage.dispatch_id != intent.dispatch_id
        or grant.dispatch_id != workpackage.dispatch_id
        or workpackage.workpackage_id != intent.workpackage_id
        or intent.grant_id != grant.grant_id
        or intent.repo_id != grant.repo_id
        or selection.account_pool_binding is not None
    ):
        raise HiveWorkDispatcherError("hive_work_binding_mismatch")
    try:
        expected_binding = _inventory_binding(dynamic_inventory, selection.agent_id)
    except Exception as exc:
        raise HiveWorkDispatcherError("hive_work_inventory_mismatch") from exc
    if bound_account_pool_binding is None:
        if bound_dynamic_pool_digest is not None or state in {"bound", "bridge_returned"}:
            raise HiveWorkDispatcherError("hive_work_binding_mismatch")
        return
    if (
        state not in {"bound", "bridge_returned", "blocked"}
        or bound_account_pool_binding != expected_binding
        or bound_dynamic_pool_digest
        != _dynamic_pool_binding_digest(selection.agent_id, expected_binding)
    ):
        raise HiveWorkDispatcherError("hive_work_binding_mismatch")


def _validate_planner_input(
    planner_input: Mapping[str, object],
    workpackage: WorkPackage,
    intent: AssignmentIntent,
    selection: SelectionResult,
) -> None:
    if not isinstance(planner_input, Mapping) or "account_pool_binding" in planner_input:
        raise HiveWorkDispatcherError("invalid_hive_planner_input")
    expected = {
        "workpackage_id": workpackage.workpackage_id,
        "repo_id": intent.repo_id,
        "teamlead_principal_id": workpackage.owner_teamlead_principal_id,
        "agent_id": selection.agent_id,
        "model_id": selection.model_id,
        "scope": workpackage.scope,
        "write_paths": workpackage.write_paths,
        "task_complexity": intent.task_complexity.value,
    }
    if any(planner_input.get(key) != value for key, value in expected.items()):
        raise HiveWorkDispatcherError("hive_work_planner_binding_mismatch")


def _records(document: Mapping[str, object]) -> list[dict[str, object]]:
    records = document.get("pool_dispatches")
    if not isinstance(records, list):
        raise HiveWorkDispatcherError("hive_work_store_unavailable")
    parsed: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise HiveWorkDispatcherError("hive_work_store_unavailable")
        parsed.append(record)
    return parsed


def _revision(document: Mapping[str, object]) -> int:
    revision = document.get("revision")
    if type(revision) is not int or revision < 0:
        raise HiveWorkDispatcherError("hive_work_store_unavailable")
    return revision


def _record_from_aggregate(aggregate: HiveWorkAggregate) -> dict[str, object]:
    return {
        "kind": _RECORD_KIND,
        "dispatch_id": aggregate.dispatch_id,
        "generation": aggregate.generation,
        "state": aggregate.state,
        "digest": aggregate.digest,
        "transitions": [
            {
                "generation": transition.generation,
                "state": transition.state,
                "digest": transition.digest,
            }
            for transition in aggregate.transitions
        ],
        "workpackage": _workpackage_payload(aggregate.workpackage),
        "intent": _intent_payload(aggregate.intent),
        "grant": _grant_payload(aggregate.grant),
        "selection": _selection_payload(aggregate.selection),
        "dynamic_inventory": _inventory_payload(aggregate.dynamic_inventory),
        "scope_digest": aggregate.scope_digest,
        "base_admission_id": aggregate.base_admission_id,
        "bound_account_pool_binding": (
            account_pool_binding_payload(aggregate.bound_account_pool_binding)
            if aggregate.bound_account_pool_binding is not None
            else None
        ),
        "bound_dynamic_pool_digest": aggregate.bound_dynamic_pool_digest,
    }


def _aggregate_from_record(record: Mapping[str, object]) -> HiveWorkAggregate:
    if not isinstance(record, Mapping) or set(record) != _RECORD_KEYS or record.get("kind") != _RECORD_KIND:
        raise HiveWorkDispatcherError("invalid_hive_work_record")
    try:
        workpackage = _workpackage_from_payload(record["workpackage"])
        intent = _intent_from_payload(record["intent"])
        grant = _grant_from_payload(record["grant"])
        selection = _selection_from_payload(record["selection"])
        inventory = _inventory_from_payload(record["dynamic_inventory"])
        scope_digest = record["scope_digest"]
        base_admission_id = record["base_admission_id"]
        bound_binding = record["bound_account_pool_binding"]
        if bound_binding is not None:
            bound_binding = account_pool_binding_from_payload(bound_binding)
        bound_digest = record["bound_dynamic_pool_digest"]
        generation = record["generation"]
        state = record["state"]
        digest = record["digest"]
        raw_transitions = record["transitions"]
        if not isinstance(raw_transitions, list):
            raise ValueError
        transitions = tuple(
            HiveWorkTransition(
                raw["generation"], raw["state"], raw["digest"]
            )
            for raw in raw_transitions
            if isinstance(raw, Mapping) and set(raw) == _TRANSITION_KEYS
        )
        if len(transitions) != len(raw_transitions):
            raise ValueError
        aggregate = HiveWorkAggregate(
            workpackage,
            intent,
            grant,
            selection,
            inventory,
            scope_digest,
            base_admission_id,
            bound_binding,
            bound_digest,
            generation,
            state,
            digest,
            transitions,
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, HiveWorkDispatcherError):
            raise
        raise HiveWorkDispatcherError("invalid_hive_work_record") from exc
    if record["dispatch_id"] != aggregate.dispatch_id:
        raise HiveWorkDispatcherError("hive_work_dispatch_mismatch")
    return aggregate


def _workpackage_payload(value: WorkPackage) -> dict[str, object]:
    return {
        "workpackage_id": value.workpackage_id,
        "dispatch_id": value.dispatch_id,
        "owner_teamlead_principal_id": value.owner_teamlead_principal_id,
        "objective": value.objective,
        "scope": list(value.scope),
        "write_paths": list(value.write_paths),
        "success_criteria": list(value.success_criteria),
        "test_requirements": list(value.test_requirements),
        "release_policy": value.release_policy,
        "depends_on_workpackage_ids": list(value.depends_on_workpackage_ids),
        "resource_profile": dict(value.resource_profile),
        "state": value.state,
        "ready_since_utc": value.ready_since_utc.isoformat() if value.ready_since_utc is not None else None,
        "version": value.version,
    }


def _workpackage_from_payload(raw: object) -> WorkPackage:
    expected = {
        "workpackage_id", "dispatch_id", "owner_teamlead_principal_id", "objective", "scope", "write_paths",
        "success_criteria", "test_requirements", "release_policy", "depends_on_workpackage_ids", "resource_profile",
        "state", "ready_since_utc", "version",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_workpackage")
    ready = raw["ready_since_utc"]
    if ready is not None:
        if not isinstance(ready, str):
            raise HiveWorkDispatcherError("invalid_hive_workpackage")
        ready = datetime.fromisoformat(ready)
    return WorkPackage(
        raw["workpackage_id"], raw["dispatch_id"], raw["owner_teamlead_principal_id"], raw["objective"],
        tuple(raw["scope"]), tuple(raw["write_paths"]), tuple(raw["success_criteria"]), tuple(raw["test_requirements"]),
        raw["release_policy"], tuple(raw["depends_on_workpackage_ids"]), raw["resource_profile"], raw["state"], ready, raw["version"],
    )


def _intent_payload(value: AssignmentIntent) -> dict[str, object]:
    return {
        "assignment_intent_id": value.assignment_intent_id,
        "request_id": value.request_id,
        "dispatch_id": value.dispatch_id,
        "workpackage_id": value.workpackage_id,
        "repo_id": value.repo_id,
        "parent_principal_id": value.parent_principal_id,
        "grant_id": value.grant_id,
        "class_id": value.class_id,
        "dispatch_priority": value.dispatch_priority.value,
        "task_complexity": value.task_complexity.value,
        "model_policy_constraints": dict(value.model_policy_constraints),
        "scope_reservation_request": dict(value.scope_reservation_request),
        "expected_usage_bucket": value.expected_usage_bucket,
        "decision_refs": list(value.decision_refs),
        "context_digest": value.context_digest,
    }


def _intent_from_payload(raw: object) -> AssignmentIntent:
    expected = {
        "assignment_intent_id", "request_id", "dispatch_id", "workpackage_id", "repo_id", "parent_principal_id",
        "grant_id", "class_id", "dispatch_priority", "task_complexity", "model_policy_constraints",
        "scope_reservation_request", "expected_usage_bucket", "decision_refs", "context_digest",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_assignment_intent")
    return AssignmentIntent(
        raw["assignment_intent_id"], raw["request_id"], raw["dispatch_id"], raw["workpackage_id"], raw["repo_id"],
        raw["parent_principal_id"], raw["grant_id"], raw["class_id"], DispatchPriority(raw["dispatch_priority"]),
        TaskComplexity(raw["task_complexity"]), raw["model_policy_constraints"], raw["scope_reservation_request"],
        raw["expected_usage_bucket"], tuple(raw["decision_refs"]), raw["context_digest"],
    )


def _grant_payload(value: DelegationGrant) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "grant_id": value.grant_id,
        "issuer_principal_id": value.issuer_principal_id,
        "subject_principal_id": value.subject_principal_id,
        "repo_id": value.repo_id,
        "dispatch_id": value.dispatch_id,
        "capabilities": list(value.capabilities),
        "scope": list(value.scope),
        "write_paths": list(value.write_paths),
        "max_delegation_depth": value.max_delegation_depth,
        "issued_at_utc": value.issued_at_utc.isoformat(),
        "expires_at_utc": value.expires_at_utc.isoformat(),
        "nonce_digest": value.nonce_digest,
        "request_digest": value.request_digest,
        "status": value.status,
        "version": value.version,
    }


def _grant_from_payload(raw: object) -> DelegationGrant:
    expected = {
        "schema_version", "grant_id", "issuer_principal_id", "subject_principal_id", "repo_id", "dispatch_id",
        "capabilities", "scope", "write_paths", "max_delegation_depth", "issued_at_utc", "expires_at_utc",
        "nonce_digest", "request_digest", "status", "version",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_delegation_grant")
    return DelegationGrant(
        raw["schema_version"], raw["grant_id"], raw["issuer_principal_id"], raw["subject_principal_id"], raw["repo_id"],
        raw["dispatch_id"], tuple(raw["capabilities"]), tuple(raw["scope"]), tuple(raw["write_paths"]),
        raw["max_delegation_depth"], datetime.fromisoformat(raw["issued_at_utc"]), datetime.fromisoformat(raw["expires_at_utc"]),
        raw["nonce_digest"], raw["request_digest"], raw["status"], raw["version"],
    )


def _selection_payload(value: SelectionResult) -> dict[str, object]:
    return {
        "agent_id": value.agent_id,
        "model_id": value.model_id,
        "band": value.band.value,
        "fairness_micro": value.fairness_micro,
        "account_pool_binding": account_pool_binding_payload(value.account_pool_binding)
        if value.account_pool_binding is not None
        else None,
    }


def _selection_from_payload(raw: object) -> SelectionResult:
    expected = {"agent_id", "model_id", "band", "fairness_micro", "account_pool_binding"}
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_selection")
    binding = raw["account_pool_binding"]
    return SelectionResult(
        raw["agent_id"], raw["model_id"], SelectionBand(raw["band"]), raw["fairness_micro"],
        account_pool_binding_from_payload(binding) if binding is not None else None,
    )


def _inventory_payload(value: DynamicPoolInventoryV1) -> dict[str, object]:
    return {
        agent_id: {
            "account_id": entry.account_id,
            "pool_id": entry.pool_id,
            "authority_provider": entry.authority_provider,
            "runtime_provider": entry.runtime_provider,
        }
        for agent_id, entry in value.entries_by_agent.items()
    }


def _inventory_from_payload(raw: object) -> DynamicPoolInventoryV1:
    if not isinstance(raw, Mapping):
        raise HiveWorkDispatcherError("invalid_hive_dynamic_inventory")
    entries: dict[str, DynamicPoolInventoryEntryV1] = {}
    expected = {"account_id", "pool_id", "authority_provider", "runtime_provider"}
    for agent_id, entry in raw.items():
        if not isinstance(entry, Mapping) or set(entry) != expected:
            raise HiveWorkDispatcherError("invalid_hive_dynamic_inventory")
        entries[agent_id] = DynamicPoolInventoryEntryV1(
            entry["account_id"], entry["pool_id"], entry["authority_provider"], entry["runtime_provider"]
        )
    return DynamicPoolInventoryV1(entries)


def _aggregate_digest(
    workpackage: WorkPackage,
    intent: AssignmentIntent,
    grant: DelegationGrant,
    selection: SelectionResult,
    dynamic_inventory: DynamicPoolInventoryV1,
    scope_digest: str,
    base_admission_id: str,
    bound_account_pool_binding: AccountPoolBindingV1 | None,
    bound_dynamic_pool_digest: str | None,
    *,
    generation: int,
    state: str,
) -> str:
    payload = {
        "workpackage": _workpackage_payload(workpackage),
        "intent": _intent_payload(intent),
        "grant": _grant_payload(grant),
        "selection": _selection_payload(selection),
        "dynamic_inventory": _inventory_payload(dynamic_inventory),
        "scope_digest": scope_digest,
        "base_admission_id": base_admission_id,
        "bound_account_pool_binding": (
            account_pool_binding_payload(bound_account_pool_binding)
            if bound_account_pool_binding is not None
            else None
        ),
        "bound_dynamic_pool_digest": bound_dynamic_pool_digest,
        "generation": generation,
        "state": state,
    }
    return _digest(payload)


def _inventory_binding(
    inventory: DynamicPoolInventoryV1, agent_id: str
) -> AccountPoolBindingV1:
    entry = inventory.entry_for(agent_id)
    return account_pool_binding_from_payload(
        {
            "account_id": entry.account_id,
            "pool_id": entry.pool_id,
            "authority_provider": entry.authority_provider,
            "runtime_provider": entry.runtime_provider,
        }
    )


def _dynamic_pool_binding_digest(
    agent_id: str, binding: AccountPoolBindingV1
) -> str:
    return _digest(
        {
            "agent_id": agent_id,
            "account_pool_binding": account_pool_binding_payload(binding),
        }
    )


def _fresh_lease_matches_admission(
    admission: AdmissionRecord, fresh_lease: Mapping[str, object]
) -> bool:
    """Keep the callback bound to the private lease facts already in admission."""

    expected = admission.lease_context.expected_state
    if expected in {"available", "unclaimed"}:
        return fresh_lease.get("state") in {"unclaimed", "expired"}
    if expected == "claimed":
        if not (
            fresh_lease.get("state") == "held"
            and fresh_lease.get("held_by_this_server") is True
        ):
            return False
        expected_lease_id = admission.lease_context.lease_id
        return expected_lease_id is None or fresh_lease.get("lease_id") == expected_lease_id
    return fresh_lease.get("state") == expected


def _is_valid_base_admission_id(value: object) -> bool:
    """Match the bounded textual admission-ID boundary before persistence."""

    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_ADMISSION_ID_LENGTH
        and not any(ord(character) < 32 for character in value)
    )


def _admission_id_matches_base(admission_id: object, base_admission_id: object) -> bool:
    """Accept only the server's base ID or one of its bounded retry forms."""

    if not _is_valid_base_admission_id(admission_id) or not _is_valid_base_admission_id(
        base_admission_id
    ):
        return False
    if admission_id == base_admission_id:
        return True
    match = re.fullmatch(r"(?P<prefix>.*)-attempt-(?P<attempt>[1-9][0-9]*)", admission_id)
    if match is None:
        return False
    attempt = int(match.group("attempt"))
    if not 2 <= attempt <= MAX_EXECUTION_ATTEMPTS:
        return False
    suffix = f"-attempt-{attempt}"
    return admission_id == f"{base_admission_id[: MAX_ADMISSION_ID_LENGTH - len(suffix)]}{suffix}"


def _admission_matches_bound_aggregate(
    admission: AdmissionRecord,
    aggregate: HiveWorkAggregate,
    fresh_lease: Mapping[str, object],
) -> bool:
    """Accept only the single admission that exactly belongs to this bound unit."""

    binding = aggregate.bound_account_pool_binding
    return (
        admission.state is AdmissionState.EXECUTING
        and isinstance(admission.admission_id, str)
        and bool(admission.admission_id)
        and _admission_id_matches_base(admission.admission_id, aggregate.base_admission_id)
        and admission.revision >= 4
        and admission.revision % 2 == 0
        and not admission.is_expired(datetime.now(timezone.utc))
        and _fresh_lease_matches_admission(admission, fresh_lease)
        and aggregate.state == "bound"
        and isinstance(binding, AccountPoolBindingV1)
        and aggregate.bound_dynamic_pool_digest
        == _dynamic_pool_binding_digest(aggregate.selection.agent_id, binding)
        and admission.request_id == aggregate.intent.request_id
        and admission.dispatch_id == aggregate.dispatch_id
        and admission.workpackage_id == aggregate.workpackage.workpackage_id
        and admission.assignment_intent_id == aggregate.intent.assignment_intent_id
        and admission.repo_id == aggregate.intent.repo_id == aggregate.grant.repo_id
        and admission.principal_id == aggregate.grant.subject_principal_id
        and admission.parent_principal_id
        == aggregate.intent.parent_principal_id
        == aggregate.grant.issuer_principal_id
        and admission.grant_id == aggregate.grant.grant_id
        and admission.grant_digest == aggregate.grant.binding_digest()
        and admission.work_item_version == aggregate.workpackage.version
        and admission.scope.mode == "write"
        and admission.scope.paths
        == aggregate.workpackage.write_paths
        == aggregate.grant.write_paths
        and admission.scope.canonical_digest == aggregate.scope_digest
        and admission.resource.agent_id == aggregate.selection.agent_id
        and admission.resource.model_id == aggregate.selection.model_id
        and admission.resource.account_pool_binding == binding
    )


def _transition_digest(generation: int, state: str, aggregate_digest: str | None) -> str:
    return _digest(
        {
            "generation": generation,
            "state": state,
            "aggregate_digest": aggregate_digest,
        }
    )


def _digest(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HiveWorkDispatcherError("invalid_hive_work_payload") from exc
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


__all__ = [
    "HiveAssignmentExecutionBridge",
    "HiveWorkAggregate",
    "HiveWorkDispatcher",
    "HiveWorkDispatcherError",
    "HiveWorkTransition",
    "PoolExecutionPort",
]
