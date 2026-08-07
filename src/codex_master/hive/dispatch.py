"""Immutable Hive request/dispatch/workpackage state machines."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from types import MappingProxyType
from typing import TypeVar

from codex_master.hive.messages import HiveMessage, HiveMessageError, _mapping, _text, _texts, _id, record_child_report
from codex_master.hive.types import DispatchPriority, TaskComplexity, validate_utc_datetime


class HiveDispatchError(ValueError):
    """Raised for invalid work objects or stale state transitions."""


MAX_LIST = 128
_PILOT_QUEENS = frozenset({"queen-codex-master"})
_PILOT_REPOSITORIES = frozenset({"codex-master"})
_GODBEE_PRINCIPAL = "godbee-main"
_SAGA_MODES = frozenset({"shadow", "enforced"})


def _version(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10**12:
        raise HiveDispatchError("invalid_dispatch_version")


def _state(value: object, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise HiveDispatchError(f"invalid_{field}_state")
    return value


def _mapping_safe(value: object, field: str) -> MappingProxyType:
    try:
        return MappingProxyType(dict(_mapping(value, field)))
    except HiveMessageError as exc:
        raise HiveDispatchError(str(exc)) from exc


def _time(value: object, field: str) -> datetime:
    try:
        return validate_utc_datetime(value, field=field)
    except ValueError as exc:
        raise HiveDispatchError(str(exc)) from exc


REQUEST_STATES = frozenset({
    "received", "classified", "planned", "gated", "delegated", "executing", "integrating", "completed",
    "blocked", "cancelled", "failed", "compensating", "partially_completed",
})
DISPATCH_STATES = frozenset({
    "planned", "queen_accepted", "workpackages_ready", "queued", "executing", "integrating", "reporting",
    "completed", "decision_required", "blocked", "cooperative_pause_requested", "paused", "failed",
    "compensating", "failed_final",
})
WORKPACKAGE_STATES = frozenset({
    "planned", "ready", "queued", "admission_planned", "conflict", "admitted", "executing", "integrating",
    "completed", "blocked", "decision_required", "failed", "compensating", "failed_final", "paused",
})

_REQUEST_TRANSITIONS = {
    "received": {"classified", "cancelled", "failed"},
    "classified": {"planned", "cancelled", "failed"},
    "planned": {"gated", "cancelled", "failed"},
    "gated": {"delegated", "blocked", "cancelled", "failed"},
    "delegated": {"executing", "blocked", "cancelled", "failed"},
    "executing": {"integrating", "blocked", "failed", "compensating", "cancelled"},
    "integrating": {"completed", "partially_completed", "failed"},
    "blocked": {"executing", "cancelled"},
    "failed": {"compensating", "partially_completed"},
    "compensating": {"partially_completed", "failed"},
}
_DISPATCH_TRANSITIONS = {
    "planned": {"queen_accepted", "blocked", "failed"},
    "queen_accepted": {"workpackages_ready", "blocked", "failed"},
    "workpackages_ready": {"queued", "blocked", "failed"},
    "queued": {"executing", "blocked", "cooperative_pause_requested", "failed"},
    "executing": {"integrating", "decision_required", "blocked", "cooperative_pause_requested", "failed", "compensating"},
    "integrating": {"reporting", "failed"},
    "reporting": {"completed", "failed", "compensating"},
    "decision_required": {"executing", "blocked", "failed"},
    "blocked": {"queued", "failed", "compensating"},
    "cooperative_pause_requested": {"paused", "failed"},
    "paused": {"queued", "failed"},
    "failed": {"compensating", "failed_final"},
    "compensating": {"failed_final", "failed"},
}
_WORKPACKAGE_TRANSITIONS = {
    "planned": {"ready", "blocked", "failed"},
    "ready": {"queued", "blocked", "failed"},
    "queued": {"admission_planned", "blocked", "failed", "paused"},
    "admission_planned": {"admitted", "conflict", "queued", "failed"},
    "conflict": {"queued", "failed"},
    "admitted": {"executing", "conflict", "failed"},
    "executing": {"integrating", "blocked", "decision_required", "failed", "paused", "compensating"},
    "integrating": {"completed", "failed"},
    "blocked": {"queued", "failed"},
    "decision_required": {"executing", "blocked", "failed"},
    "failed": {"compensating", "failed_final"},
    "compensating": {"failed_final", "failed"},
    "paused": {"queued", "failed"},
}


@dataclass(frozen=True, slots=True)
class GlobalRequest:
    request_id: str
    objective: str
    success_criteria: tuple[str, ...]
    constraints: tuple[str, ...]
    non_goals: tuple[str, ...]
    requested_by: str
    repositories_requested: tuple[str, ...]
    repositories_resolved: tuple[str, ...]
    dispatch_priority: DispatchPriority
    user_gates: tuple[str, ...]
    created_at_utc: datetime
    state: str = "received"
    version: int = 1

    def __post_init__(self) -> None:
        _id(self.request_id, "request")
        _text(self.objective, "objective")
        _texts(self.success_criteria, "success_criteria")
        _texts(self.constraints, "constraints")
        _texts(self.non_goals, "non_goals")
        _id(self.requested_by, "requested_by")
        for value in (*self.repositories_requested, *self.repositories_resolved):
            _id(value, "repo")
        if not isinstance(self.repositories_requested, tuple) or not isinstance(self.repositories_resolved, tuple):
            raise HiveDispatchError("invalid_repository_list")
        if not isinstance(self.dispatch_priority, DispatchPriority):
            raise HiveDispatchError("invalid_dispatch_priority")
        _texts(self.user_gates, "user_gates")
        _time(self.created_at_utc, "request_timestamp")
        _state(self.state, REQUEST_STATES, "request")
        _version(self.version)


@dataclass(frozen=True, slots=True)
class RepoDispatch:
    dispatch_id: str
    request_id: str
    repo_id: str
    queen_principal_id: str
    objective: str
    success_criteria: tuple[str, ...]
    constraints: tuple[str, ...]
    dispatch_priority: DispatchPriority
    effective_priority: DispatchPriority
    deadline_at_utc: datetime | None
    depends_on_dispatch_ids: tuple[str, ...]
    budget: Mapping[str, object]
    state: str = "planned"
    version: int = 1

    def __post_init__(self) -> None:
        for value, field in ((self.dispatch_id, "dispatch"), (self.request_id, "request"), (self.repo_id, "repo"), (self.queen_principal_id, "queen")):
            _id(value, field)
        _text(self.objective, "objective")
        _texts(self.success_criteria, "success_criteria")
        _texts(self.constraints, "constraints")
        if not isinstance(self.dispatch_priority, DispatchPriority) or not isinstance(self.effective_priority, DispatchPriority):
            raise HiveDispatchError("invalid_dispatch_priority")
        if self.deadline_at_utc is not None:
            _time(self.deadline_at_utc, "deadline")
        if not isinstance(self.depends_on_dispatch_ids, tuple) or len(self.depends_on_dispatch_ids) > MAX_LIST:
            raise HiveDispatchError("invalid_dispatch_dependencies")
        for value in self.depends_on_dispatch_ids:
            _id(value, "dispatch_dependency")
        self_budget = _mapping_safe(self.budget, "budget")
        if not isinstance(self.state, str):
            raise HiveDispatchError("invalid_dispatch_state")
        _state(self.state, DISPATCH_STATES, "dispatch")
        _version(self.version)
        object.__setattr__(self, "budget", self_budget)


@dataclass(frozen=True, slots=True)
class GlobalRequestPlan:
    """Bounded multi-repository plan; it never implies global atomicity."""

    request: GlobalRequest
    dispatches: tuple[RepoDispatch, ...]
    mode: str
    planning_reason: str
    user_gates: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, GlobalRequest):
            raise HiveDispatchError("invalid_global_request_plan")
        if not isinstance(self.dispatches, tuple) or not 0 <= len(self.dispatches) <= MAX_LIST:
            raise HiveDispatchError("invalid_global_dispatches")
        if self.mode not in _SAGA_MODES:
            raise HiveDispatchError("invalid_saga_mode")
        _text(self.planning_reason, "planning_reason", maximum=64)
        _texts(self.user_gates, "user_gates")
        resolved = tuple(self.request.repositories_resolved)
        dispatch_repos = tuple(item.repo_id for item in self.dispatches)
        if dispatch_repos != resolved:
            raise HiveDispatchError("global_dispatch_repository_mismatch")
        for item in self.dispatches:
            if item.request_id != self.request.request_id:
                raise HiveDispatchError("global_dispatch_request_mismatch")

    @property
    def ready_for_execution(self) -> bool:
        return self.planning_reason == "ready" and self.request.state == "planned"

    def public(self) -> dict[str, object]:
        return {
            "request_id": self.request.request_id,
            "actor_principal_id": self.request.requested_by,
            "mode": self.mode,
            "planning_reason": self.planning_reason,
            "state": self.request.state,
            "version": self.request.version,
            "repository_count": len(self.request.repositories_requested),
            "resolved_repository_count": len(self.request.repositories_resolved),
            "dispatches": [
                {
                    "dispatch_id": item.dispatch_id,
                    "repo_id": item.repo_id,
                    "queen_principal_id": item.queen_principal_id,
                    "state": item.state,
                    "version": item.version,
                    "dependency_count": len(item.depends_on_dispatch_ids),
                }
                for item in self.dispatches
            ],
            "user_gates": list(self.user_gates),
            "direct_write_paths": "not_returned",
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class GlobalSagaExecutionContext:
    """Explicit side effects for one authorized multi-repository saga."""

    pilot_queens: frozenset[str]
    pilot_repositories: frozenset[str]
    confirmed_gates: frozenset[str]
    create_global_request: Callable[[GlobalRequest], object] | None = None
    create_repo_dispatch: Callable[[RepoDispatch], object] | None = None
    execute_repo_dispatch: Callable[[RepoDispatch], Mapping[str, object]] | None = None
    compensate: Callable[[str, str, object | None], None] | None = None
    retry_dispatch: Callable[[str, int], Mapping[str, object]] | None = None
    cancel_request: Callable[[str, int], Mapping[str, object]] | None = None

    def ready_for(self, plan: GlobalRequestPlan) -> bool:
        return (
            plan.ready_for_execution
            and all(item.queen_principal_id in self.pilot_queens for item in plan.dispatches)
            and all(item.repo_id in self.pilot_repositories for item in plan.dispatches)
            and set(plan.user_gates).issubset(self.confirmed_gates)
            and all(callable(callback) for callback in (
                self.create_global_request, self.create_repo_dispatch,
                self.execute_repo_dispatch, self.compensate,
            ))
        )


def _saga_request_digest(
    actor_principal_id: str,
    objective: str,
    repositories: tuple[str, ...],
    priority: DispatchPriority,
    success_criteria: tuple[str, ...],
    constraints: tuple[str, ...],
) -> str:
    material = "\x1f".join((actor_principal_id, objective, priority.value, *repositories, *success_criteria, *constraints))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def plan_global_request(
    *,
    actor_principal_id: str,
    objective: str,
    repositories: tuple[str, ...],
    priority: DispatchPriority,
    success_criteria: tuple[str, ...],
    constraints: tuple[str, ...],
    repository_queens: Mapping[str, str] | None = None,
    user_gates: tuple[str, ...] = (),
    mode: str = "shadow",
) -> GlobalRequestPlan:
    """Plan independent repository dispatches without creating runtime state."""

    if actor_principal_id != _GODBEE_PRINCIPAL:
        raise HiveDispatchError("godbee_actor_required")
    _id(actor_principal_id, "actor")
    _text(objective, "objective")
    if not isinstance(repositories, tuple) or not 1 <= len(repositories) <= MAX_LIST:
        raise HiveDispatchError("invalid_global_repositories")
    for repo_id in repositories:
        _id(repo_id, "repo")
    if len(set(repositories)) != len(repositories):
        raise HiveDispatchError("duplicate_global_repository")
    try:
        priority = priority if isinstance(priority, DispatchPriority) else DispatchPriority(priority)
    except (TypeError, ValueError) as exc:
        raise HiveDispatchError("invalid_dispatch_priority") from exc
    _texts(success_criteria, "success_criteria")
    _texts(constraints, "constraints")
    _texts(user_gates, "user_gates")
    if mode not in _SAGA_MODES:
        raise HiveDispatchError("invalid_saga_mode")
    if repository_queens is not None and not isinstance(repository_queens, Mapping):
        raise HiveDispatchError("invalid_repository_registry")
    known: dict[str, str] = {}
    for repo_id, queen_id in dict(repository_queens or {}).items():
        _id(repo_id, "repo")
        _id(queen_id, "queen")
        known[repo_id] = queen_id
    resolved = tuple(repo_id for repo_id in repositories if repo_id in known)
    unknown = tuple(repo_id for repo_id in repositories if repo_id not in known)
    normalized_gates = set(user_gates)
    lowered_constraints = " ".join(constraints).lower()
    if "breaking" in lowered_constraints:
        normalized_gates.add("breaking_changes")
    if "destruct" in lowered_constraints or "force-push" in lowered_constraints:
        normalized_gates.add("global_destruction")
    missing_gate = any(
        gate not in user_gates for gate in normalized_gates if gate in {"breaking_changes", "global_destruction"}
    )
    planning_reason = "unknown_repository" if unknown else ("user_gate_required" if missing_gate else "ready")
    digest = _saga_request_digest(actor_principal_id, objective, repositories, priority, tuple(success_criteria), tuple(constraints))
    request_id = f"request-{digest[:24]}"
    request = GlobalRequest(
        request_id,
        objective,
        tuple(success_criteria),
        tuple(constraints),
        (),
        actor_principal_id,
        repositories,
        resolved,
        priority,
        tuple(sorted(normalized_gates)),
        datetime.now(timezone.utc),
        state="planned" if planning_reason == "ready" else "blocked",
    )
    dispatches = tuple(
        RepoDispatch(
            f"dispatch-{hashlib.sha256((digest + repo_id).encode('utf-8')).hexdigest()[:24]}",
            request_id,
            repo_id,
            known[repo_id],
            objective,
            tuple(success_criteria),
            tuple(constraints),
            priority,
            priority,
            None,
            (),
            {"repo_id": repo_id, "saga": "independent"},
            state="planned" if planning_reason == "ready" else "blocked",
        )
        for index, repo_id in enumerate(resolved)
    )
    return GlobalRequestPlan(request, dispatches, mode, planning_reason, tuple(sorted(normalized_gates)))


def execute_global_request(
    plan: GlobalRequestPlan, context: GlobalSagaExecutionContext | None = None
) -> Mapping[str, object]:
    """Execute only an explicitly authorized saga, compensating in reverse order."""

    if not isinstance(plan, GlobalRequestPlan):
        raise HiveDispatchError("invalid_global_request_plan")
    public_plan = plan.public()
    if plan.mode != "enforced":
        return {"allowed": False, "reason_code": "shadow_only", "mutation_performed": False, "plan": public_plan, "raw_output": "not_returned"}
    if context is None or not context.ready_for(plan):
        return {"allowed": False, "reason_code": "saga_gate_blocked", "mutation_performed": False, "plan": public_plan, "raw_output": "not_returned"}
    steps: list[tuple[str, str, object | None]] = []
    try:
        if not callable(context.create_global_request):
            raise HiveDispatchError("saga_callback_unavailable")
        steps.append(("global_request", plan.request.request_id, None))
        steps[-1] = ("global_request", plan.request.request_id, context.create_global_request(plan.request))
        for dispatch in plan.dispatches:
            if not callable(context.create_repo_dispatch) or not callable(context.execute_repo_dispatch):
                raise HiveDispatchError("saga_callback_unavailable")
            steps.append(("repo_dispatch", dispatch.dispatch_id, None))
            steps[-1] = ("repo_dispatch", dispatch.dispatch_id, context.create_repo_dispatch(dispatch))
            steps.append(("repo_execute", dispatch.dispatch_id, None))
            result = context.execute_repo_dispatch(dispatch)
            if not isinstance(result, Mapping):
                raise HiveDispatchError("saga_result_invalid")
            steps[-1] = ("repo_execute", dispatch.dispatch_id, dict(result))
        return {
            "allowed": True,
            "reason_code": "saga_executed",
            "state": "completed",
            "mutation_performed": True,
            "completed_dispatch_count": len(plan.dispatches),
            "plan": public_plan,
            "raw_output": "not_returned",
        }
    except Exception:
        compensation_complete = True
        for kind, identifier, result in reversed(steps):
            try:
                if not callable(context.compensate):
                    raise HiveDispatchError("saga_compensation_unavailable")
                context.compensate(kind, identifier, result)
            except Exception:
                compensation_complete = False
        completed_dispatches = sum(1 for kind, _identifier, result in steps if kind == "repo_execute" and result is not None)
        return {
            "allowed": False,
            "reason_code": "saga_partially_completed",
            "state": "partially_completed",
            "mutation_performed": False,
            "completed_dispatch_count": completed_dispatches,
            "compensation_attempted": True,
            "compensation_complete": compensation_complete,
            "plan": public_plan,
            "raw_output": "not_returned",
        }


def retry_repo_dispatch(
    dispatch_id: str, *, expected_version: int, context: GlobalSagaExecutionContext | None = None
) -> Mapping[str, object]:
    _id(dispatch_id, "dispatch")
    _version(expected_version)
    if context is None or not callable(context.retry_dispatch):
        return {"allowed": False, "reason_code": "saga_gate_blocked", "dispatch_id": dispatch_id, "raw_output": "not_returned"}
    try:
        context.retry_dispatch(dispatch_id, expected_version)
    except Exception:
        return {"allowed": False, "reason_code": "saga_retry_unavailable", "dispatch_id": dispatch_id, "raw_output": "not_returned"}
    return {"allowed": True, "reason_code": "repo_dispatch_retry_requested", "dispatch_id": dispatch_id, "raw_output": "not_returned"}


def cancel_global_request(
    request_id: str, *, expected_version: int, context: GlobalSagaExecutionContext | None = None
) -> Mapping[str, object]:
    _id(request_id, "request")
    _version(expected_version)
    if context is None or not callable(context.cancel_request):
        return {"allowed": False, "reason_code": "saga_gate_blocked", "request_id": request_id, "raw_output": "not_returned"}
    try:
        context.cancel_request(request_id, expected_version)
    except Exception:
        return {"allowed": False, "reason_code": "saga_cancel_unavailable", "request_id": request_id, "raw_output": "not_returned"}
    return {"allowed": True, "reason_code": "global_request_cancel_requested", "request_id": request_id, "raw_output": "not_returned"}


@dataclass(frozen=True, slots=True)
class WorkPackage:
    workpackage_id: str
    dispatch_id: str
    owner_teamlead_principal_id: str
    objective: str
    scope: tuple[str, ...]
    write_paths: tuple[str, ...]
    success_criteria: tuple[str, ...]
    test_requirements: tuple[str, ...]
    release_policy: str
    depends_on_workpackage_ids: tuple[str, ...]
    resource_profile: Mapping[str, object]
    state: str = "planned"
    ready_since_utc: datetime | None = None
    version: int = 1

    def __post_init__(self) -> None:
        for value, field in ((self.workpackage_id, "workpackage"), (self.dispatch_id, "dispatch"), (self.owner_teamlead_principal_id, "teamlead")):
            _id(value, field)
        _text(self.objective, "objective")
        _texts(self.scope, "scope")
        _texts(self.write_paths, "write_paths")
        _texts(self.success_criteria, "success_criteria")
        _texts(self.test_requirements, "test_requirements")
        _text(self.release_policy, "release_policy", maximum=128)
        if not isinstance(self.depends_on_workpackage_ids, tuple) or len(self.depends_on_workpackage_ids) > MAX_LIST:
            raise HiveDispatchError("invalid_workpackage_dependencies")
        for value in self.depends_on_workpackage_ids:
            _id(value, "workpackage_dependency")
        object.__setattr__(self, "resource_profile", _mapping_safe(self.resource_profile, "resource_profile"))
        _state(self.state, WORKPACKAGE_STATES, "workpackage")
        if self.ready_since_utc is not None:
            _time(self.ready_since_utc, "ready_timestamp")
        _version(self.version)


@dataclass(frozen=True, slots=True)
class AssignmentIntent:
    assignment_intent_id: str
    request_id: str
    dispatch_id: str
    workpackage_id: str
    repo_id: str
    parent_principal_id: str
    grant_id: str
    class_id: str
    dispatch_priority: DispatchPriority
    task_complexity: TaskComplexity
    model_policy_constraints: Mapping[str, object]
    scope_reservation_request: Mapping[str, object]
    expected_usage_bucket: str
    decision_refs: tuple[str, ...]
    context_digest: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.assignment_intent_id, "assignment_intent"), (self.request_id, "request"), (self.dispatch_id, "dispatch"),
            (self.workpackage_id, "workpackage"), (self.repo_id, "repo"), (self.parent_principal_id, "parent_principal"),
            (self.grant_id, "grant"), (self.class_id, "class"),
        ):
            _id(value, field)
        if not isinstance(self.dispatch_priority, DispatchPriority) or not isinstance(self.task_complexity, TaskComplexity):
            raise HiveDispatchError("invalid_assignment_policy")
        object.__setattr__(self, "model_policy_constraints", _mapping_safe(self.model_policy_constraints, "model_policy"))
        object.__setattr__(self, "scope_reservation_request", _mapping_safe(self.scope_reservation_request, "scope_reservation"))
        _text(self.expected_usage_bucket, "usage_bucket", maximum=128)
        _texts(self.decision_refs, "decision_refs")
        _text(self.context_digest, "context_digest", maximum=192)


@dataclass(frozen=True, slots=True)
class QueenAssignmentPlan:
    """Immutable pilot assignment plan shared by Shadow and Enforced paths."""

    queen_principal_id: str
    dispatch_id: str
    workpackage_id: str
    repo_id: str
    teamlead_principal_id: str
    specialist_principal_id: str
    writer_class_id: str
    agent_id: str
    account_key: str
    model_id: str
    model_role: str
    task_complexity: TaskComplexity
    scope: tuple[str, ...]
    write_paths: tuple[str, ...]
    mode: str
    pilot_enabled: bool
    account_confirmed: bool
    authority_verified: bool
    repository_verified: bool
    scope_verified: bool
    lease_available: bool
    selection_band: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.queen_principal_id, "queen"), (self.dispatch_id, "dispatch"), (self.workpackage_id, "workpackage"),
            (self.repo_id, "repo"), (self.teamlead_principal_id, "teamlead"), (self.specialist_principal_id, "specialist"),
            (self.writer_class_id, "class"), (self.agent_id, "agent"),
        ):
            _id(value, field)
        if (
            not isinstance(self.model_id, str)
            or not 1 <= len(self.model_id) <= 128
            or any(not (char.isalnum() or char in {".", "_", ":", "/", "-"}) for char in self.model_id)
        ):
            raise HiveDispatchError("invalid_model")
        _text(self.account_key, "account_key", maximum=256)
        if self.queen_principal_id not in _PILOT_QUEENS or self.repo_id not in _PILOT_REPOSITORIES:
            raise HiveDispatchError("pilot_allowlist_denied")
        if self.writer_class_id not in {"spezialistin", "specialist"}:
            raise HiveDispatchError("writer_role_denied")
        if self.model_role != "primary" or not isinstance(self.model_role, str):
            raise HiveDispatchError("primary_model_required")
        if not isinstance(self.task_complexity, TaskComplexity):
            raise HiveDispatchError("invalid_assignment_complexity")
        _texts(self.scope, "assignment_scope")
        _texts(self.write_paths, "assignment_write_paths")
        if self.mode not in {"shadow", "enforced"}:
            raise HiveDispatchError("invalid_assignment_mode")
        for value in (
            self.pilot_enabled, self.account_confirmed, self.authority_verified,
            self.repository_verified, self.scope_verified, self.lease_available,
        ):
            if not isinstance(value, bool):
                raise HiveDispatchError("invalid_assignment_gate")
        if self.selection_band not in {"none", "primary"}:
            raise HiveDispatchError("selection_feature_disabled")
        if self.selection_band != "none":
            raise HiveDispatchError("selection_feature_disabled")

    @property
    def gates_ready(self) -> bool:
        return all((
            self.pilot_enabled, self.account_confirmed, self.authority_verified,
            self.repository_verified, self.scope_verified, self.lease_available,
        ))

    def public(self) -> dict[str, object]:
        return {
            "queen_principal_id": self.queen_principal_id,
            "dispatch_id": self.dispatch_id,
            "workpackage_id": self.workpackage_id,
            "repo_id": self.repo_id,
            "teamlead_principal_id": self.teamlead_principal_id,
            "specialist_principal_id": self.specialist_principal_id,
            "writer_class_id": self.writer_class_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "model_role": self.model_role,
            "task_complexity": self.task_complexity.value,
            "scope": {"path_count": len(self.scope), "write_path_count": len(self.write_paths)},
            "mode": self.mode,
            "pilot_enabled": self.pilot_enabled,
            "account_confirmed": self.account_confirmed,
            "authority_verified": self.authority_verified,
            "repository_verified": self.repository_verified,
            "scope_verified": self.scope_verified,
            "lease_available": self.lease_available,
            "selection_band": "disabled",
            "account_key": "not_returned",
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class QueenAssignmentExecutionContext:
    """Injected side effects for one explicitly authorized pilot execution."""

    pilot_queens: frozenset[str]
    pilot_repositories: frozenset[str]
    confirmed_accounts: frozenset[str]
    primary_models: frozenset[str]
    sp_features_enabled: bool
    create_teamlead_principal: Callable[[QueenAssignmentPlan], object] | None = None
    create_specialist_principal: Callable[[QueenAssignmentPlan], object] | None = None
    issue_grant: Callable[[QueenAssignmentPlan], object] | None = None
    reserve_admission: Callable[[QueenAssignmentPlan], object] | None = None
    execute_assignment: Callable[[QueenAssignmentPlan], Mapping[str, object]] | None = None
    compensate: Callable[[str, QueenAssignmentPlan, object | None], None] | None = None

    def ready_for(self, plan: QueenAssignmentPlan) -> bool:
        return (
            not self.sp_features_enabled
            and plan.queen_principal_id in self.pilot_queens
            and plan.repo_id in self.pilot_repositories
            and plan.account_key in self.confirmed_accounts
            and plan.model_id in self.primary_models
            and plan.gates_ready
            and all(callable(callback) for callback in (
                self.create_teamlead_principal, self.create_specialist_principal,
                self.issue_grant, self.reserve_admission, self.execute_assignment, self.compensate,
            ))
        )


def plan_queen_assignment(
    *, queen_id: str, dispatch_id: str, workpackage: Mapping[str, object]
) -> QueenAssignmentPlan:
    """Build the one planner result used by both Shadow and Enforced modes."""

    if not isinstance(workpackage, Mapping):
        raise HiveDispatchError("invalid_workpackage_plan")
    try:
        complexity = workpackage["task_complexity"]
        if not isinstance(complexity, TaskComplexity):
            complexity = TaskComplexity(complexity)
        scope = workpackage["scope"]
        write_paths = workpackage["write_paths"]
        if not isinstance(scope, (tuple, list)) or not isinstance(write_paths, (tuple, list)):
            raise HiveDispatchError("invalid_workpackage_plan")
        return QueenAssignmentPlan(
            queen_id,
            dispatch_id,
            workpackage["workpackage_id"],
            workpackage["repo_id"],
            workpackage["teamlead_principal_id"],
            workpackage["specialist_principal_id"],
            workpackage["writer_class_id"],
            workpackage["agent_id"],
            workpackage["account_key"],
            workpackage["model_id"],
            workpackage["model_role"],
            complexity,
            tuple(scope),
            tuple(write_paths),
            workpackage.get("mode", "shadow"),
            workpackage.get("pilot_enabled", False),
            workpackage.get("account_confirmed", False),
            workpackage.get("authority_verified", False),
            workpackage.get("repository_verified", False),
            workpackage.get("scope_verified", False),
            workpackage.get("lease_available", False),
            workpackage.get("selection_band", "none"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, HiveDispatchError):
            raise
        raise HiveDispatchError("invalid_workpackage_plan") from exc


def execute_queen_assignment(
    plan: QueenAssignmentPlan, context: QueenAssignmentExecutionContext | None = None
) -> Mapping[str, object]:
    """Execute one pilot assignment transaction, compensating in reverse order."""

    if not isinstance(plan, QueenAssignmentPlan):
        raise HiveDispatchError("invalid_queen_assignment_plan")
    if plan.mode != "enforced":
        return {"allowed": False, "reason_code": "shadow_only", "mutation_performed": False, "plan": plan.public(), "raw_output": "not_returned"}
    if context is None or not context.ready_for(plan):
        return {"allowed": False, "reason_code": "pilot_gate_blocked", "mutation_performed": False, "plan": plan.public(), "raw_output": "not_returned"}
    steps: list[tuple[str, object | None]] = []
    callbacks = (
        ("teamlead", context.create_teamlead_principal),
        ("specialist", context.create_specialist_principal),
        ("grant", context.issue_grant),
        ("admission", context.reserve_admission),
        ("assignment", context.execute_assignment),
    )
    try:
        for name, callback in callbacks:
            if not callable(callback):
                raise HiveDispatchError("assignment_callback_unavailable")
            steps.append((name, None))
            result = callback(plan)
            if name == "assignment" and not isinstance(result, Mapping):
                raise HiveDispatchError("assignment_result_invalid")
            steps[-1] = (name, result)
        return {
            "allowed": True,
            "reason_code": "assignment_executed",
            "mutation_performed": True,
            "plan": plan.public(),
            "result": dict(steps[-1][1]) if isinstance(steps[-1][1], Mapping) else {},
            "raw_output": "not_returned",
        }
    except Exception:
        compensation_complete = True
        for name, result in reversed(steps):
            try:
                if not callable(context.compensate):
                    raise HiveDispatchError("compensation_unavailable")
                context.compensate(name, plan, result)
            except Exception:
                compensation_complete = False
        return {
            "allowed": False,
            "reason_code": "assignment_transaction_failed",
            "mutation_performed": False,
            "compensation_attempted": True,
            "compensation_complete": compensation_complete,
            "plan": plan.public(),
            "raw_output": "not_returned",
        }


_T = TypeVar("_T")


def _transition(item: _T, target: str, expected_version: int, transitions: Mapping[str, set[str]], version: int) -> _T:
    if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version != version:
        raise HiveDispatchError("stale_dispatch_version")
    current = getattr(item, "state")
    if target == current:
        return item
    if target not in transitions.get(current, set()):
        raise HiveDispatchError(f"invalid_transition:{current}->{target}")
    return replace(item, state=target, version=version + 1)


def transition_request(request: GlobalRequest, target: str, *, expected_version: int) -> GlobalRequest:
    if not isinstance(request, GlobalRequest):
        raise HiveDispatchError("invalid_request")
    return _transition(request, target, expected_version, _REQUEST_TRANSITIONS, request.version)


def transition_dispatch(dispatch: RepoDispatch, target: str, *, expected_version: int) -> RepoDispatch:
    if not isinstance(dispatch, RepoDispatch):
        raise HiveDispatchError("invalid_dispatch")
    return _transition(dispatch, target, expected_version, _DISPATCH_TRANSITIONS, dispatch.version)


def transition_workpackage(workpackage: WorkPackage, target: str, *, expected_version: int) -> WorkPackage:
    if not isinstance(workpackage, WorkPackage):
        raise HiveDispatchError("invalid_workpackage")
    return _transition(workpackage, target, expected_version, _WORKPACKAGE_TRANSITIONS, workpackage.version)


def transition_workpackage_from_report(
    workpackage: WorkPackage, message: HiveMessage, *, expected_version: int
) -> WorkPackage:
    """Apply only a correlated child-report status through the work state graph."""

    if not isinstance(workpackage, WorkPackage) or not isinstance(message, HiveMessage):
        raise HiveDispatchError("invalid_report_transition")
    if message.workpackage_id != workpackage.workpackage_id:
        raise HiveDispatchError("report_workpackage_mismatch")
    report = record_child_report(message)
    target = report["status"]
    if not isinstance(target, str) or target not in WORKPACKAGE_STATES:
        raise HiveDispatchError("unsupported_report_status")
    return transition_workpackage(workpackage, target, expected_version=expected_version)


_PAUSE_FORBIDDEN_MARKERS = frozenset({
    "sp0", "sp1", "sp2", "sp3", "selection", "fairness", "model", "lease", "kill", "interrupt", "restart",
})


def request_cooperative_pause(workpackage_id: str, *, reason: str) -> Mapping[str, object]:
    """Request a checkpointed pause; this planning adapter never stops a process."""

    _id(workpackage_id, "workpackage")
    _text(reason, "pause_reason", maximum=256)
    lowered = reason.casefold()
    if any(marker in lowered for marker in _PAUSE_FORBIDDEN_MARKERS):
        raise HiveDispatchError("pause_source_not_allowed")
    return {
        "allowed": True,
        "reason_code": "cooperative_pause_requested",
        "workpackage_id": workpackage_id,
        "reason": reason,
        "next_state": "cooperative_pause_requested",
        "checkpoint_required": True,
        "report_required": True,
        "hard_kill": False,
        "lease_takeover": False,
        "mutation_performed": False,
        "raw_output": "not_returned",
    }


def acknowledge_checkpoint(message: HiveMessage) -> Mapping[str, object]:
    """Accept only an explicit safe checkpoint report for a requested pause."""

    if not isinstance(message, HiveMessage) or message.message_type != "progress.report":
        raise HiveDispatchError("checkpoint_report_required")
    if message.workpackage_id is None:
        raise HiveDispatchError("checkpoint_workpackage_required")
    checkpoint = message.payload.get("checkpoint")
    checkpoint_state = message.payload.get("checkpoint_state")
    pause_requested = message.payload.get("pause_requested")
    origin = message.payload.get("origin", "work_orchestration")
    if checkpoint is not True or checkpoint_state != "safe" or pause_requested is not True:
        raise HiveDispatchError("unsafe_checkpoint")
    if not isinstance(origin, str) or origin not in {"work_orchestration", "teamlead", "queen"}:
        raise HiveDispatchError("checkpoint_source_not_allowed")
    report = record_child_report(message)
    return {
        "allowed": True,
        "reason_code": "safe_checkpoint_acknowledged",
        "workpackage_id": message.workpackage_id,
        "message_id": message.message_id,
        "correlation_id": message.correlation_id,
        "payload_digest": report["payload_digest"],
        "next_state": "paused",
        "hard_kill": False,
        "lease_takeover": False,
        "mutation_performed": False,
        "raw_output": "not_returned",
    }


def transition_workpackage_at_checkpoint(
    workpackage: WorkPackage, message: HiveMessage, *, expected_version: int
) -> WorkPackage:
    """Move an executing workpackage to paused only after checkpoint evidence."""

    acknowledge_checkpoint(message)
    return transition_workpackage(workpackage, "paused", expected_version=expected_version)


def resume_paused_workpackage(workpackage_id: str) -> Mapping[str, object]:
    """Return a revalidation plan; resumption itself stays outside this adapter."""

    _id(workpackage_id, "workpackage")
    return {
        "allowed": False,
        "reason_code": "resume_revalidation_required",
        "workpackage_id": workpackage_id,
        "next_state": "queued",
        "requires_fresh_admission": True,
        "requires_scope_revalidation": True,
        "lease_takeover": False,
        "hard_kill": False,
        "mutation_performed": False,
        "raw_output": "not_returned",
    }


__all__ = [
    "AssignmentIntent",
    "DISPATCH_STATES",
    "GlobalRequest",
    "GlobalRequestPlan",
    "GlobalSagaExecutionContext",
    "HiveDispatchError",
    "QueenAssignmentExecutionContext",
    "QueenAssignmentPlan",
    "RepoDispatch",
    "REQUEST_STATES",
    "WORKPACKAGE_STATES",
    "WorkPackage",
    "cancel_global_request",
    "execute_queen_assignment",
    "execute_global_request",
    "plan_global_request",
    "plan_queen_assignment",
    "retry_repo_dispatch",
    "request_cooperative_pause",
    "acknowledge_checkpoint",
    "resume_paused_workpackage",
    "transition_dispatch",
    "transition_request",
    "transition_workpackage",
    "transition_workpackage_from_report",
    "transition_workpackage_at_checkpoint",
]
