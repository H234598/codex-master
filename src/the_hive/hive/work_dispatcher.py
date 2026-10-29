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
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Protocol

from the_hive.admission import AdmissionError, AdmissionRecord, AdmissionState, AdmissionStore, LeaseBinding, MAX_ADMISSION_ID_LENGTH, ResourceBinding
from the_hive.dynamic_pool import (
    AccountPoolBindingV1,
    DynamicPoolInventoryEntryV1,
    DynamicPoolInventoryV1,
    account_pool_binding_from_payload,
    account_pool_binding_payload,
)
from the_hive.hive.authority import AuthorityEngine, AuthorityError, DelegationGrant
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
from the_hive.hive.principals import ExecutionBinding, Principal, PrincipalRegistry
from the_hive.hive.repositories import RepositoryError, RepositoryRegistry


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

    def scope_digest(self, repo_id: str, mode: str, paths: tuple[str, ...]) -> str:
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
        if (
            not isinstance(self.digest, str)
            or _DIGEST_RE.fullmatch(self.digest) is None
        ):
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
        if (
            not isinstance(self.scope_digest, str)
            or _DIGEST_RE.fullmatch(self.scope_digest) is None
        ):
            raise HiveWorkDispatcherError("invalid_hive_work_scope_digest")
        if not _is_valid_base_admission_id(self.base_admission_id):
            raise HiveWorkDispatcherError("invalid_hive_work_admission_id")
        if self.state not in _ALLOWED_TRANSITIONS:
            raise HiveWorkDispatcherError("invalid_hive_work_state")
        if (
            not isinstance(self.digest, str)
            or _DIGEST_RE.fullmatch(self.digest) is None
        ):
            raise HiveWorkDispatcherError("invalid_hive_work_digest")
        if (
            not isinstance(self.transitions, tuple)
            or len(self.transitions) != self.generation
        ):
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
        if execution_port is not None and not callable(
            getattr(execution_port, "execute", None)
        ):
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
        updated["pool_dispatches"] = _records({"pool_dispatches": [*records, _record_from_aggregate(aggregate)]})
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
        _validate_planner_input(planner_input, workpackage, intent, selection)
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
        if (
            not isinstance(scope_digest, str)
            or _DIGEST_RE.fullmatch(scope_digest) is None
        ):
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

    def _replace(
        self, aggregate: HiveWorkAggregate, *, now: datetime
    ) -> HiveWorkAggregate:
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
        updated["pool_dispatches"] = _records({"pool_dispatches": updated_records})
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

        if not isinstance(admission, AdmissionRecord) or not isinstance(
            fresh_lease, Mapping
        ):
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


    def leadership_workpackage(
        self, *, workpackage_id: str, expected_version: int
    ) -> WorkPackage:
        """Read one current prepared WorkPackage without creating or mutating it."""

        if (
            not isinstance(workpackage_id, str)
            or not workpackage_id
            or len(workpackage_id) > 128
            or any(ord(character) < 32 for character in workpackage_id)
            or isinstance(expected_version, bool)
            or type(expected_version) is not int
            or expected_version < 1
        ):
            raise HiveWorkDispatcherError("invalid_leadership_workpackage_request")
        document = self._control_plane.load_task9()
        raw_workpackages = document.get("workpackages")
        if not isinstance(raw_workpackages, list):
            raise HiveWorkDispatcherError("leadership_workpackage_unavailable")
        parsed = [_workpackage_from_payload(item) for item in raw_workpackages]
        matches = [
            item for item in parsed if item.workpackage_id == workpackage_id
        ]
        if len(matches) != 1:
            raise HiveWorkDispatcherError("leadership_workpackage_unavailable")
        workpackage = matches[0]
        if workpackage.version != expected_version:
            raise HiveWorkDispatcherError("stale_leadership_workpackage")
        if workpackage.state not in {"planned", "ready", "queued", "admission_planned"}:
            raise HiveWorkDispatcherError("leadership_workpackage_not_admissible")
        return workpackage

    def append_leadership_prepare(
        self, record: Mapping[str, object], *, now: datetime
    ) -> dict[str, object]:
        return _append_leadership_prepare(self, record, now=now)

    def replace_leadership_record(
        self,
        previous: Mapping[str, object],
        candidate: Mapping[str, object],
        *,
        now: datetime,
    ) -> dict[str, object]:
        return _replace_leadership_record(self, previous, candidate, now=now)

    def rehydrate_leadership(self, prepared_request_ref: str) -> dict[str, object]:
        return _rehydrate_leadership(self, prepared_request_ref)

    def revalidate_leadership_forward(
        self,
        prepared_request_ref: str,
        *,
        authority: AuthorityEngine,
        admission_store: AdmissionStore,
        principal_registry: PrincipalRegistry,
        repository_registry: RepositoryRegistry,
        now: datetime,
    ) -> dict[str, object]:
        return _revalidate_forward_bindings(
            self,
            prepared_request_ref,
            authority=authority,
            admission_store=admission_store,
            principal_registry=principal_registry,
            repository_registry=repository_registry,
            now=now,
        )


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
        (
            HiveWorkTransition(
                1, "persisted", _transition_digest(1, "persisted", digest)
            ),
        ),
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
    transitions = (
        *aggregate.transitions,
        HiveWorkTransition(
            generation, state, _transition_digest(generation, state, digest)
        ),
    )
    return replace(
        aggregate,
        generation=generation,
        state=state,
        digest=digest,
        transitions=transitions,
    )


def _bind(
    aggregate: HiveWorkAggregate, binding: AccountPoolBindingV1 | None
) -> HiveWorkAggregate:
    """Persist exactly the one D69 output before entering the admission bridge."""

    if aggregate.state != "persisted" or not isinstance(binding, AccountPoolBindingV1):
        raise HiveWorkDispatcherError("invalid_hive_work_binding")
    expected = _inventory_binding(
        aggregate.dynamic_inventory, aggregate.selection.agent_id
    )
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
    transitions = (
        *aggregate.transitions,
        HiveWorkTransition(
            generation,
            "bound",
            _transition_digest(generation, "bound", digest),
        ),
    )
    return replace(
        aggregate,
        bound_account_pool_binding=binding,
        bound_dynamic_pool_digest=_dynamic_pool_binding_digest(
            aggregate.selection.agent_id, binding
        ),
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
        if bound_dynamic_pool_digest is not None or state in {
            "bound",
            "bridge_returned",
        }:
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
    if (
        not isinstance(planner_input, Mapping)
        or "account_pool_binding" in planner_input
    ):
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
    raw_records = document.get("pool_dispatches")
    if type(raw_records) is not list:
        _fail("hive_work_store_unavailable")
    result: list[dict[str, object]] = []
    dispatch_ids: set[str] = set()
    pool_requests: set[str] = set()
    leadership_requests: set[str] = set()
    prepared_refs: set[str] = set()
    for raw in raw_records:
        if (
            type(raw) is not dict
            or type(raw.get("kind")) is not str
            or raw["kind"] not in _RECORD_KINDS
        ):
            _fail("invalid_hive_work_record")
        pool_record = raw["kind"] == _RECORD_KIND
        if pool_record:
            request_id = _aggregate_from_record(raw).intent.request_id
        else:
            parsed = _leadership_record(raw)
            request_id = parsed["request_id"]
            prepared_ref = parsed["prepared_request_ref"]
            if prepared_ref in prepared_refs:
                _fail("duplicate_leadership_prepared_ref")
            prepared_refs.add(prepared_ref)
        dispatch_id = raw.get("dispatch_id")
        if type(dispatch_id) is not str or dispatch_id in dispatch_ids:
            _fail("duplicate_hive_work_dispatch")
        if type(request_id) is not str or request_id in leadership_requests:
            _fail("duplicate_hive_work_request")
        if not pool_record and request_id in pool_requests:
            _fail("duplicate_hive_work_request")
        dispatch_ids.add(dispatch_id)
        if pool_record:
            pool_requests.add(request_id)
        else:
            leadership_requests.add(request_id)
        result.append(dict(raw))
    return result


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
    if (
        not isinstance(record, Mapping)
        or set(record) != _RECORD_KEYS
        or record.get("kind") != _RECORD_KIND
    ):
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
            HiveWorkTransition(raw["generation"], raw["state"], raw["digest"])
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
        "ready_since_utc": value.ready_since_utc.isoformat()
        if value.ready_since_utc is not None
        else None,
        "version": value.version,
    }


def _workpackage_from_payload(raw: object) -> WorkPackage:
    expected = {
        "workpackage_id",
        "dispatch_id",
        "owner_teamlead_principal_id",
        "objective",
        "scope",
        "write_paths",
        "success_criteria",
        "test_requirements",
        "release_policy",
        "depends_on_workpackage_ids",
        "resource_profile",
        "state",
        "ready_since_utc",
        "version",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_workpackage")
    ready = raw["ready_since_utc"]
    if ready is not None:
        if not isinstance(ready, str):
            raise HiveWorkDispatcherError("invalid_hive_workpackage")
        ready = datetime.fromisoformat(ready)
    return WorkPackage(
        raw["workpackage_id"],
        raw["dispatch_id"],
        raw["owner_teamlead_principal_id"],
        raw["objective"],
        tuple(raw["scope"]),
        tuple(raw["write_paths"]),
        tuple(raw["success_criteria"]),
        tuple(raw["test_requirements"]),
        raw["release_policy"],
        tuple(raw["depends_on_workpackage_ids"]),
        raw["resource_profile"],
        raw["state"],
        ready,
        raw["version"],
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
        "assignment_intent_id",
        "request_id",
        "dispatch_id",
        "workpackage_id",
        "repo_id",
        "parent_principal_id",
        "grant_id",
        "class_id",
        "dispatch_priority",
        "task_complexity",
        "model_policy_constraints",
        "scope_reservation_request",
        "expected_usage_bucket",
        "decision_refs",
        "context_digest",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_assignment_intent")
    return AssignmentIntent(
        raw["assignment_intent_id"],
        raw["request_id"],
        raw["dispatch_id"],
        raw["workpackage_id"],
        raw["repo_id"],
        raw["parent_principal_id"],
        raw["grant_id"],
        raw["class_id"],
        DispatchPriority(raw["dispatch_priority"]),
        TaskComplexity(raw["task_complexity"]),
        raw["model_policy_constraints"],
        raw["scope_reservation_request"],
        raw["expected_usage_bucket"],
        tuple(raw["decision_refs"]),
        raw["context_digest"],
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
        "schema_version",
        "grant_id",
        "issuer_principal_id",
        "subject_principal_id",
        "repo_id",
        "dispatch_id",
        "capabilities",
        "scope",
        "write_paths",
        "max_delegation_depth",
        "issued_at_utc",
        "expires_at_utc",
        "nonce_digest",
        "request_digest",
        "status",
        "version",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_delegation_grant")
    return DelegationGrant(
        raw["schema_version"],
        raw["grant_id"],
        raw["issuer_principal_id"],
        raw["subject_principal_id"],
        raw["repo_id"],
        raw["dispatch_id"],
        tuple(raw["capabilities"]),
        tuple(raw["scope"]),
        tuple(raw["write_paths"]),
        raw["max_delegation_depth"],
        datetime.fromisoformat(raw["issued_at_utc"]),
        datetime.fromisoformat(raw["expires_at_utc"]),
        raw["nonce_digest"],
        raw["request_digest"],
        raw["status"],
        raw["version"],
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
    expected = {
        "agent_id",
        "model_id",
        "band",
        "fairness_micro",
        "account_pool_binding",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HiveWorkDispatcherError("invalid_hive_selection")
    binding = raw["account_pool_binding"]
    return SelectionResult(
        raw["agent_id"],
        raw["model_id"],
        SelectionBand(raw["band"]),
        raw["fairness_micro"],
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
            entry["account_id"],
            entry["pool_id"],
            entry["authority_provider"],
            entry["runtime_provider"],
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


def _dynamic_pool_binding_digest(agent_id: str, binding: AccountPoolBindingV1) -> str:
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
        return (
            expected_lease_id is None
            or fresh_lease.get("lease_id") == expected_lease_id
        )
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
    match = re.fullmatch(
        r"(?P<prefix>.*)-attempt-(?P<attempt>[1-9][0-9]*)", admission_id
    )
    if match is None:
        return False
    attempt = int(match.group("attempt"))
    if not 2 <= attempt <= MAX_EXECUTION_ATTEMPTS:
        return False
    suffix = f"-attempt-{attempt}"
    return (
        admission_id
        == f"{base_admission_id[: MAX_ADMISSION_ID_LENGTH - len(suffix)]}{suffix}"
    )


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
        and _admission_id_matches_base(
            admission.admission_id, aggregate.base_admission_id
        )
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


def _transition_digest(
    generation: int, state: str, aggregate_digest: str | None
) -> str:
    return _digest(
        {
            "generation": generation,
            "state": state,
            "aggregate_digest": aggregate_digest,
        }
    )


def _digest(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
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


# Geschlossene Leadership-Projektion im bestehenden Task-9-Owner.

_LEADERSHIP_KIND = "leadership_dispatch_v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)

_PATH_BAD = re.compile(r"[\x00-\x1f\x7f]")

_LEADERSHIP_OPERATIONS = frozenset(
    {
        "native_spawn",
        "managed_replacement",
        "headless_assignment",
        "agent_claim",
        "agent_start",
        "agent_assign",
        "fleet_series_apply",
        "emergency_queen_start",
    }
)

_EXECUTION_KINDS = frozenset({"leadership_session", "capacity_effect"})

_STATES = frozenset(
    {"prepared", "granted", "executing", "completed", "blocked", "cancelled"}
)

_COMPLETION_STATES = frozenset(
    {"not_started", "executing", "completed", "failed"}
)

_NEXT = {
    "prepared": frozenset({"granted", "blocked", "cancelled"}),
    "granted": frozenset({"executing", "blocked", "cancelled"}),
    "executing": frozenset({"completed", "blocked"}),
    "completed": frozenset(),
    "blocked": frozenset(),
    "cancelled": frozenset(),
}

_SEED_KEYS = frozenset(
    {
        "schema_version",
        "dispatch_id",
        "request_id",
        "workpackage_id",
        "workpackage_version",
        "intent_id",
        "operation",
        "execution_kind",
        "actor_principal_id",
        "actor_version",
        "actor_config_digest",
        "actor_execution_binding_id",
        "execution_subject_id",
        "execution_subject_version",
        "repo_id",
        "scope_mode",
        "scope",
        "write_paths",
        "task_digest",
        "target_ref",
        "resource_binding",
        "actor_lease_id",
        "actor_lease_fence",
        "target_lease_expected",
        "actor_capacity_capability",
        "execution_capability",
        "ingress_generation",
        "created_at_utc",
        "expires_at_utc",
    }
)

_LEADERSHIP_RECORD_KEYS = frozenset(
    {
        "kind",
        "schema_version",
        "dispatch_id",
        "request_id",
        "prepared_request_ref",
        "operation",
        "execution_kind",
        "state",
        "generation",
        "request_digest",
        "admin_request_digest",
        "seed",
        "actor_grant_id",
        "actor_grant_digest",
        "execution_grant_id",
        "execution_grant_digest",
        "admission_id",
        "admission_revision",
        "completion_state",
        "transitions",
        "digest",
    }
)

_LEADERSHIP_TRANSITION_KEYS = frozenset({"generation", "state", "digest"})

_RECORD_KINDS = frozenset({"hive_work_dispatcher", _LEADERSHIP_KIND})

_TASK9_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)

def _fail(code: str) -> None:
    raise HiveWorkDispatcherError(code)

def _leadership_payload_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value

def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(code)
    return value

def _version(value: object, code: str) -> int:
    if isinstance(value, bool) or type(value) is not int or not 1 <= value <= 10**12:
        _fail(code)
    return value

def _path_list(value: object, *, allow_empty: bool) -> list[str]:
    if type(value) is not list or (not allow_empty and not value) or len(value) > 256:
        _fail("invalid_leadership_scope_paths")
    paths: list[str] = []
    for item in value:
        if (
            type(item) is not str
            or not 1 <= len(item) <= 512
            or _PATH_BAD.search(item) is not None
            or item.startswith(("/", "~"))
            or "\\" in item
            or "://" in item
            or any(part in {"", ".", ".."} for part in item.split("/"))
        ):
            _fail("invalid_leadership_scope_paths")
        paths.append(item)
    if len(set(paths)) != len(paths):
        _fail("duplicate_leadership_scope_path")
    return paths

def _resource_binding(value: object) -> dict[str, object]:
    keys = {
        "agent_id",
        "account_key",
        "budget_key",
        "model_id",
        "expected_usage_micro",
        "account_pool_binding",
    }
    if type(value) is not dict or set(value) != keys:
        _fail("invalid_leadership_resource_binding")
    pool = value["account_pool_binding"]
    if pool is not None:
        try:
            pool = account_pool_binding_from_payload(pool)
        except Exception:
            _fail("invalid_leadership_pool_binding")
    try:
        ResourceBinding(
            value["agent_id"],
            value["account_key"],
            value["budget_key"],
            value["model_id"],
            value["expected_usage_micro"],
            pool,
        )
    except Exception:
        _fail("invalid_leadership_resource_binding")
    return dict(value)

def _target_lease(value: object) -> dict[str, object]:
    keys = {"expected_state", "lease_id", "fence"}
    if type(value) is not dict or set(value) != keys:
        _fail("invalid_leadership_target_lease")
    state = value["expected_state"]
    lease_id = value["lease_id"]
    fence = value["fence"]
    if type(state) is not str or state not in {"available", "unclaimed", "claimed"}:
        _fail("invalid_leadership_target_lease")
    if lease_id is not None:
        _token(lease_id, "invalid_leadership_target_lease")
    if state == "claimed" and lease_id is None:
        _fail("invalid_leadership_target_lease")
    if state != "claimed" and lease_id is not None:
        _fail("invalid_leadership_target_lease")
    if type(fence) is not int or fence < 0:
        _fail("invalid_leadership_target_lease")
    try:
        LeaseBinding(state, lease_id)
    except AdmissionError:
        _fail("invalid_leadership_target_lease")
    return dict(value)

def _validate_seed(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _SEED_KEYS:
        _fail("invalid_leadership_seed")
    for name in (
        "dispatch_id",
        "request_id",
        "workpackage_id",
        "intent_id",
        "actor_principal_id",
        "execution_subject_id",
        "repo_id",
        "target_ref",
        "actor_capacity_capability",
        "execution_capability",
    ):
        _token(value[name], "invalid_leadership_seed")
    for name in ("actor_config_digest", "task_digest"):
        _leadership_payload_digest(value[name], "invalid_leadership_seed")
    for name in ("workpackage_version", "actor_version", "execution_subject_version", "ingress_generation"):
        _version(value[name], "invalid_leadership_seed")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _fail("unsupported_leadership_seed")
    if type(value["operation"]) is not str or value["operation"] not in _LEADERSHIP_OPERATIONS:
        _fail("invalid_leadership_operation")
    if type(value["execution_kind"]) is not str or value["execution_kind"] not in _EXECUTION_KINDS:
        _fail("invalid_leadership_execution_kind")
    if type(value["scope_mode"]) is not str or value["scope_mode"] not in {"read", "write"}:
        _fail("invalid_leadership_scope_mode")
    _path_list(value["scope"], allow_empty=False)
    _path_list(value["write_paths"], allow_empty=True)
    if value["actor_execution_binding_id"] is not None:
        _token(value["actor_execution_binding_id"], "invalid_leadership_seed")
    actor_lease = value["actor_lease_id"]
    actor_fence = value["actor_lease_fence"]
    if (actor_lease is None) != (actor_fence is None):
        _fail("invalid_leadership_actor_lease")
    if actor_lease is not None:
        _token(actor_lease, "invalid_leadership_actor_lease")
        if type(actor_fence) is not int or actor_fence < 0:
            _fail("invalid_leadership_actor_lease")
    resource = _resource_binding(value["resource_binding"])
    target = _target_lease(value["target_lease_expected"])
    binding_missing = value["actor_execution_binding_id"] is None
    lease_missing = actor_lease is None
    if binding_missing or lease_missing:
        if not (
            binding_missing
            and lease_missing
            and value["execution_kind"] == "leadership_session"
            and value["operation"] == "agent_start"
            and value["actor_principal_id"] == value["execution_subject_id"]
            and value["actor_version"] == value["execution_subject_version"]
            and target["expected_state"] in {"available", "unclaimed"}
            and target["lease_id"] is None
            and value["target_ref"] == resource["agent_id"]
        ):
            _fail("invalid_leadership_bootstrap_binding")
    for name in ("created_at_utc", "expires_at_utc"):
        if type(value[name]) is not str:
            _fail("invalid_leadership_seed_time")
    try:
        created = datetime.fromisoformat(value["created_at_utc"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(value["expires_at_utc"].replace("Z", "+00:00"))
        if (
            created.tzinfo is None
            or expires.tzinfo is None
            or created.utcoffset() != timezone.utc.utcoffset(created)
            or expires.utcoffset() != timezone.utc.utcoffset(expires)
            or not created < expires <= created + timedelta(seconds=120)
        ):
            _fail("invalid_leadership_seed_time")
    except (TypeError, ValueError, OverflowError):
        _fail("invalid_leadership_seed_time")
    return dict(value)

def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii") + b"\n"

def _seed_digest(seed: Mapping[str, object]) -> str:
    try:
        raw = _canonical_json(seed)
    except (TypeError, ValueError, RecursionError):
        _fail("invalid_leadership_seed")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def _leadership_transition_digest(generation: int, state: str, previous: str) -> str:
    raw = f"{generation}\0{state}\0{previous}".encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def _record_digest(value: Mapping[str, object]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "digest"}
    try:
        raw = _canonical_json(unsigned)
    except (TypeError, ValueError, RecursionError):
        _fail("invalid_leadership_record")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def _leadership_record(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _LEADERSHIP_RECORD_KEYS:
        _fail("invalid_leadership_record")
    seed = _validate_seed(value["seed"])
    for name in ("dispatch_id", "request_id", "prepared_request_ref"):
        _token(value[name], "invalid_leadership_record")
    for name in ("request_digest", "admin_request_digest"):
        _leadership_payload_digest(value[name], "invalid_leadership_record")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["kind"] != _LEADERSHIP_KIND
        or value["dispatch_id"] != seed["dispatch_id"]
        or value["request_id"] != seed["request_id"]
        or value["operation"] != seed["operation"]
        or value["execution_kind"] != seed["execution_kind"]
        or value["request_digest"] != _seed_digest(seed)
        or type(value["state"]) is not str
        or value["state"] not in _STATES
        or type(value["completion_state"]) is not str
        or value["completion_state"] not in _COMPLETION_STATES
    ):
        _fail("invalid_leadership_record")
    _version(value["generation"], "invalid_leadership_generation")
    for name in ("actor_grant_id", "execution_grant_id", "admission_id"):
        if value[name] is not None:
            _token(value[name], "invalid_leadership_record")
    for name in ("actor_grant_digest", "execution_grant_digest"):
        if value[name] is not None:
            _leadership_payload_digest(value[name], "invalid_leadership_record")
    revision = value["admission_revision"]
    if revision is not None and (
        isinstance(revision, bool) or type(revision) is not int or not 0 <= revision <= 10**12
    ):
        _fail("invalid_leadership_admission")
    grant_parts = (
        value["actor_grant_id"],
        value["actor_grant_digest"],
        value["execution_grant_id"],
        value["execution_grant_digest"],
    )
    if any(part is None for part in grant_parts) and any(part is not None for part in grant_parts):
        _fail("partial_leadership_grant_binding")
    has_grants = all(part is not None for part in grant_parts)
    has_admission = value["admission_id"] is not None and revision is not None
    if (value["admission_id"] is None) != (revision is None):
        _fail("partial_leadership_admission_binding")
    state = value["state"]
    completion = value["completion_state"]
    if state == "prepared" and (
        value["generation"] != 1
        or has_grants
        or has_admission
        or completion != "not_started"
    ):
        _fail("invalid_initial_leadership_prepare")
    if state == "granted" and (not has_grants or has_admission or completion != "not_started"):
        _fail("invalid_granted_leadership_record")
    if state == "executing" and (not has_grants or not has_admission or completion != "executing"):
        _fail("invalid_executing_leadership_record")
    if state == "completed" and (not has_grants or not has_admission or completion != "completed"):
        _fail("invalid_completed_leadership_record")
    if state == "cancelled" and (has_admission or completion != "not_started"):
        _fail("invalid_cancelled_leadership_record")
    if state == "blocked":
        if completion == "failed" and (not has_grants or not has_admission):
            _fail("invalid_blocked_leadership_record")
        if completion == "not_started" and has_admission:
            _fail("invalid_blocked_leadership_record")
        if completion not in {"failed", "not_started"}:
            _fail("invalid_blocked_leadership_record")
    transitions = value["transitions"]
    if type(transitions) is not list or len(transitions) != value["generation"]:
        _fail("invalid_leadership_transitions")
    previous_digest = value["request_digest"]
    previous_state = None
    for generation, item in enumerate(transitions, start=1):
        if (
            type(item) is not dict
            or set(item) != _LEADERSHIP_TRANSITION_KEYS
            or item["generation"] != generation
            or type(item["generation"]) is not int
            or type(item["state"]) is not str
            or item["state"] not in _STATES
            or type(item["digest"]) is not str
            or _DIGEST.fullmatch(item["digest"]) is None
            or (generation == 1 and item["state"] != "prepared")
            or (
                previous_state is not None
                and item["state"] not in _NEXT[previous_state]
            )
            or item["digest"] != _leadership_transition_digest(
                generation, item["state"], previous_digest
            )
        ):
            _fail("invalid_leadership_transitions")
        previous_state = item["state"]
        previous_digest = item["digest"]
    if transitions[-1]["state"] != state:
        _fail("invalid_leadership_transitions")
    if value["digest"] != _record_digest(value):
        _fail("leadership_record_digest_mismatch")
    return dict(value)

def _initial_prepare(record: Mapping[str, object]) -> bool:
    parsed = _leadership_record(dict(record))
    transitions = parsed["transitions"]
    return (
        parsed["state"] == "prepared"
        and parsed["generation"] == 1
        and parsed["actor_grant_id"] is None
        and parsed["actor_grant_digest"] is None
        and parsed["execution_grant_id"] is None
        and parsed["execution_grant_digest"] is None
        and parsed["admission_id"] is None
        and parsed["admission_revision"] is None
        and parsed["completion_state"] == "not_started"
        and transitions[0]["state"] == "prepared"
    )

def _next_record(
    previous: Mapping[str, object],
    updates: Mapping[str, object],
) -> dict[str, object]:
    old = _leadership_record(dict(previous))
    candidate = dict(old)
    candidate.update(updates)
    candidate["generation"] = old["generation"] + 1
    transition = {
        "generation": candidate["generation"],
        "state": candidate["state"],
        "digest": _leadership_transition_digest(
            candidate["generation"],
            candidate["state"],
            old["transitions"][-1]["digest"],
        ),
    }
    candidate["transitions"] = [*old["transitions"], transition]
    candidate["digest"] = _record_digest(candidate)
    return _leadership_record(candidate)

def _append_leadership_prepare(
    self: HiveWorkDispatcher,
    record: Mapping[str, object],
    *,
    now: datetime,
) -> dict[str, object]:
    candidate = _leadership_record(dict(record))
    if not _initial_prepare(candidate):
        _fail("invalid_initial_leadership_prepare")
    document = self._control_plane.load_task9()
    records = _records(document)
    updated = dict(document)
    updated["pool_dispatches"] = [*records, candidate]
    _records(updated)
    self._control_plane.replace_task9(
        updated, expected_revision=_revision(document), now=now
    )
    return candidate

def _replace_leadership_record(
    self: HiveWorkDispatcher,
    previous: Mapping[str, object],
    candidate: Mapping[str, object],
    *,
    now: datetime,
) -> dict[str, object]:
    old = _leadership_record(dict(previous))
    new = _leadership_record(dict(candidate))
    if (
        new["dispatch_id"] != old["dispatch_id"]
        or new["request_id"] != old["request_id"]
        or new["prepared_request_ref"] != old["prepared_request_ref"]
        or new["seed"] != old["seed"]
        or new["request_digest"] != old["request_digest"]
        or new["admin_request_digest"] != old["admin_request_digest"]
        or any(old[name] is not None and new[name] != old[name] for name in (
            "actor_grant_id", "actor_grant_digest", "execution_grant_id",
            "execution_grant_digest", "admission_id",
        ))
        or (old["admission_revision"] is not None and (
            new["admission_revision"] is None
            or new["admission_revision"] < old["admission_revision"]
        ))
        or new["generation"] != old["generation"] + 1
        or new["state"] not in _NEXT[old["state"]]
        or new["transitions"][:-1] != old["transitions"]
    ):
        _fail("leadership_transition_binding_mismatch")
    document = self._control_plane.load_task9()
    records = _records(document)
    matches = [
        index
        for index, item in enumerate(records)
        if item["kind"] == _LEADERSHIP_KIND
        and item["prepared_request_ref"] == old["prepared_request_ref"]
    ]
    if len(matches) != 1 or records[matches[0]] != old:
        _fail("stale_leadership_record")
    records[matches[0]] = new
    updated = dict(document)
    updated["pool_dispatches"] = records
    self._control_plane.replace_task9(
        updated, expected_revision=_revision(document), now=now
    )
    return new

def _require_current_grant(
    authority: object,
    *,
    grant_id: str,
    expected_digest: str,
    expected_request_digest: str,
    expected_subject_version: int,
    expected_config_digest: str | None,
    subject_id: str,
    principal_registry: PrincipalRegistry,
    repo_id: str,
    dispatch_id: str,
    scope: tuple[str, ...],
    write_paths: tuple[str, ...],
    capability: str,
) -> DelegationGrant:
    try:
        grant = authority.get_grant(grant_id)
    except (AuthorityError, AttributeError, TypeError, ValueError):
        _fail("leadership_grant_unavailable")
    try:
        subject = principal_registry.get(subject_id)
    except (AttributeError, KeyError, TypeError, ValueError):
        _fail("leadership_principal_unavailable")
    if (
        type(subject) is not Principal
        or subject.state != "active"
        or subject.repo_id != repo_id
        or subject.version != expected_subject_version
        or (expected_config_digest is not None and subject.config_digest != expected_config_digest)
    ):
        _fail("leadership_principal_binding_mismatch")
    if (
        type(grant) is not DelegationGrant
        or grant.binding_digest() != expected_digest
        or grant.request_digest != expected_request_digest
        or grant.issuer_principal_id != subject.parent_principal_id
        or grant.subject_principal_id != subject_id
        or grant.repo_id != repo_id
        or grant.dispatch_id != dispatch_id
        or grant.scope != scope
        or grant.write_paths != write_paths
        or capability not in grant.capabilities
    ):
        _fail("leadership_grant_binding_mismatch")
    try:
        decision = authority.validate_grant(
            grant_id,
            subject_principal_id=subject_id,
            repo_id=repo_id,
            dispatch_id=dispatch_id,
            scope=scope,
            write_paths=write_paths,
            capability=capability,
        )
    except (AuthorityError, AttributeError, TypeError, ValueError):
        _fail("leadership_grant_unavailable")
    if decision.allowed is not True:
        _fail("leadership_grant_denied")
    return grant

def _require_current_admission(
    admission_store: object,
    record: Mapping[str, object],
    *,
    principal_registry: object,
    repository_registry: RepositoryRegistry,
    now: datetime,
) -> None:
    parsed = _leadership_record(dict(record))
    if parsed["admission_id"] is None:
        _fail("leadership_admission_unavailable")
    seed = parsed["seed"]
    try:
        admission = admission_store.get(parsed["admission_id"])
        execution_subject = principal_registry.get(seed["execution_subject_id"])
    except (AdmissionError, AttributeError, KeyError, TypeError, ValueError):
        _fail("leadership_admission_unavailable")
    resource = seed["resource_binding"]
    pool = resource["account_pool_binding"]
    expected_resource = ResourceBinding(
        resource["agent_id"],
        resource["account_key"],
        resource["budget_key"],
        resource["model_id"],
        resource["expected_usage_micro"],
        None if pool is None else account_pool_binding_from_payload(pool),
    )
    target_lease = seed["target_lease_expected"]
    expected_lease = LeaseBinding(
        target_lease["expected_state"], target_lease["lease_id"]
    )
    expected_state = {
        "executing": AdmissionState.EXECUTING,
        "completed": AdmissionState.FINALIZED,
        "blocked": AdmissionState.EXECUTION_FAILED,
    }.get(parsed["state"])
    try:
        expected_scope_digest = repository_registry.scope_digest(
            seed["repo_id"], seed["scope_mode"], tuple(seed["write_paths"])
        )
    except (RepositoryError, AttributeError, TypeError, ValueError):
        _fail("leadership_scope_unavailable")
    if (
        type(execution_subject) is not Principal
        or execution_subject.state != "active"
        or execution_subject.repo_id != seed["repo_id"]
        or execution_subject.version != seed["execution_subject_version"]
        or not isinstance(admission.created_at_utc, datetime)
        or admission.created_at_utc.tzinfo is None
        or admission.created_at_utc.utcoffset() != timezone.utc.utcoffset(admission.created_at_utc)
        or admission.created_at_utc > now
        or not isinstance(admission.expires_at_utc, datetime)
        or admission.expires_at_utc.tzinfo is None
        or admission.expires_at_utc.utcoffset() != timezone.utc.utcoffset(admission.expires_at_utc)
        or now >= admission.expires_at_utc
        or expected_state is None
        or admission.admission_id != parsed["admission_id"]
        or admission.revision != parsed["admission_revision"]
        or admission.state is not expected_state
        or admission.request_id != seed["request_id"]
        or admission.dispatch_id != seed["dispatch_id"]
        or admission.workpackage_id != seed["workpackage_id"]
        or admission.assignment_intent_id != seed["intent_id"]
        or admission.repo_id != seed["repo_id"]
        or admission.principal_id != seed["execution_subject_id"]
        or admission.parent_principal_id != execution_subject.parent_principal_id
        or admission.grant_id != parsed["execution_grant_id"]
        or admission.grant_digest != parsed["execution_grant_digest"]
        or admission.work_item_version != seed["workpackage_version"]
        or admission.scope.mode != seed["scope_mode"]
        or admission.scope.paths != tuple(seed["write_paths"])
        or admission.scope.canonical_digest != expected_scope_digest
        or admission.resource != expected_resource
        or admission.lease_context != expected_lease
    ):
        _fail("leadership_admission_binding_mismatch")

def _revalidate_forward_bindings(
    self: HiveWorkDispatcher,
    prepared_request_ref: str,
    *,
    authority: object,
    admission_store: object,
    principal_registry: PrincipalRegistry,
    repository_registry: RepositoryRegistry,
    now: datetime,
) -> dict[str, object]:
    """Rebind live Authority/Admission owners before any forward effect."""

    record = _rehydrate_leadership(self, prepared_request_ref)
    seed = record["seed"]
    try:
        created = datetime.fromisoformat(seed["created_at_utc"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(seed["expires_at_utc"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError, OverflowError):
        _fail("invalid_leadership_seed_time")
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timezone.utc.utcoffset(now)
        or not created <= now < expires
    ):
        _fail("leadership_forward_expired")
    if record["state"] in {"prepared", "blocked", "cancelled", "completed"}:
        _fail("leadership_forward_state_denied")
    actor_binding_id = seed["actor_execution_binding_id"]
    if actor_binding_id is not None:
        try:
            binding = principal_registry.get_active_execution_binding(
                actor_binding_id,
                seed["actor_principal_id"],
                seed["repo_id"],
                now=now,
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            _fail("leadership_actor_binding_unavailable")
        if type(binding) is not ExecutionBinding or binding.binding_id != actor_binding_id:
            _fail("leadership_actor_binding_mismatch")
    _require_current_grant(
        authority,
        grant_id=record["actor_grant_id"],
        expected_digest=record["actor_grant_digest"],
        expected_request_digest=record["request_digest"],
        expected_subject_version=seed["actor_version"],
        expected_config_digest=seed["actor_config_digest"],
        subject_id=seed["actor_principal_id"],
        principal_registry=principal_registry,
        repo_id=seed["repo_id"],
        dispatch_id=seed["dispatch_id"],
        scope=tuple(seed["scope"]),
        write_paths=tuple(seed["write_paths"]),
        capability=seed["actor_capacity_capability"],
    )
    _require_current_grant(
        authority,
        grant_id=record["execution_grant_id"],
        expected_digest=record["execution_grant_digest"],
        expected_request_digest=record["request_digest"],
        expected_subject_version=seed["execution_subject_version"],
        expected_config_digest=None,
        subject_id=seed["execution_subject_id"],
        principal_registry=principal_registry,
        repo_id=seed["repo_id"],
        dispatch_id=seed["dispatch_id"],
        scope=tuple(seed["scope"]),
        write_paths=tuple(seed["write_paths"]),
        capability=seed["execution_capability"],
    )
    if record["state"] == "executing":
        _require_current_admission(
            admission_store,
            record,
            principal_registry=principal_registry,
            repository_registry=repository_registry,
            now=now,
        )
    return record

def _rehydrate_leadership(
    self: HiveWorkDispatcher, prepared_request_ref: str
) -> dict[str, object]:
    _token(prepared_request_ref, "invalid_leadership_reference")
    matches = [
        item
        for item in _records(self._control_plane.load_task9())
        if item["kind"] == _LEADERSHIP_KIND
        and item["prepared_request_ref"] == prepared_request_ref
    ]
    if len(matches) != 1:
        _fail("leadership_record_unavailable")
    return matches[0]
