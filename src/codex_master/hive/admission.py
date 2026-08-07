"""Hive admission boundary re-exporting the single reservation core.

The implementation lives in :mod:`codex_master.admission`; this module gives
the Hive package the planned import boundary without introducing a second
state machine or a second conflict detector.
"""

from __future__ import annotations

from datetime import datetime

from codex_master.admission import (
    AdmissionError,
    AdmissionPriority,
    AdmissionRecord,
    AdmissionState,
    AdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from codex_master.hive.authority import AuthorityEngine, DelegationGrant
from codex_master.hive.dispatch import AssignmentIntent, QueenAssignmentPlan, WorkPackage
from codex_master.hive.repositories import RepositoryRegistry


class HiveAdmissionError(ValueError):
    """Raised when an assignment cannot be bound to authoritative admission."""


def create_assignment_admission(
    *,
    plan: QueenAssignmentPlan,
    workpackage: WorkPackage,
    intent: AssignmentIntent,
    grant: DelegationGrant,
    authority: AuthorityEngine,
    repositories: RepositoryRegistry,
    admission_id: str,
    lease_context: LeaseBinding,
    budget_key: str,
    expected_usage_micro: int,
    priority: AdmissionPriority,
    now: datetime,
    capability: str = "hive.specialist.assign",
    ttl_seconds: int = 30,
) -> AdmissionRecord:
    """Bind one verified assignment to an immutable planned admission.

    This function performs only bounded authoritative reads and constructs a
    local ``PLANNED`` record.  It does not reserve capacity, consume a grant,
    claim a lease, start a provider, or mutate a repository.
    """

    if not all(isinstance(value, expected) for value, expected in (
        (plan, QueenAssignmentPlan), (workpackage, WorkPackage),
        (intent, AssignmentIntent), (grant, DelegationGrant),
        (authority, AuthorityEngine), (repositories, RepositoryRegistry),
        (lease_context, LeaseBinding), (priority, AdmissionPriority),
    )):
        raise HiveAdmissionError("invalid_assignment_admission_input")
    if plan.mode != "enforced":
        raise HiveAdmissionError("assignment_shadow_only")
    if not plan.gates_ready:
        raise HiveAdmissionError("assignment_gate_blocked")
    if workpackage.state not in {"ready", "queued", "admission_planned"}:
        raise HiveAdmissionError("workpackage_not_admissible")
    if (
        plan.workpackage_id != workpackage.workpackage_id
        or plan.dispatch_id != workpackage.dispatch_id
        or plan.teamlead_principal_id != workpackage.owner_teamlead_principal_id
        or plan.scope != workpackage.scope
        or plan.write_paths != workpackage.write_paths
    ):
        raise HiveAdmissionError("workpackage_binding_mismatch")
    if (
        intent.dispatch_id != plan.dispatch_id
        or intent.workpackage_id != plan.workpackage_id
        or intent.repo_id != plan.repo_id
        or intent.parent_principal_id != plan.teamlead_principal_id
        or intent.grant_id != grant.grant_id
        or intent.class_id != plan.writer_class_id
        or intent.task_complexity is not plan.task_complexity
        or intent.dispatch_priority.value != priority.dispatch
    ):
        raise HiveAdmissionError("assignment_intent_mismatch")
    if (
        grant.issuer_principal_id != plan.teamlead_principal_id
        or grant.subject_principal_id != plan.specialist_principal_id
        or grant.repo_id != plan.repo_id
        or grant.dispatch_id != plan.dispatch_id
    ):
        raise HiveAdmissionError("grant_binding_mismatch")
    try:
        current_grant = authority.get_grant(grant.grant_id)
        decision = authority.validate_grant(
            current_grant.grant_id,
            subject_principal_id=plan.specialist_principal_id,
            repo_id=plan.repo_id,
            dispatch_id=plan.dispatch_id,
            scope=workpackage.scope,
            write_paths=workpackage.write_paths,
            capability=capability,
        )
        scope_mode = "write" if workpackage.write_paths else "read"
        binding_paths = tuple(workpackage.write_paths) if scope_mode == "write" else tuple(workpackage.scope)
        scope_digest = repositories.scope_digest(plan.repo_id, scope_mode, binding_paths)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HiveAdmissionError("authoritative_admission_unavailable") from exc
    if current_grant != grant:
        raise HiveAdmissionError("grant_state_changed")
    if not decision.allowed:
        raise HiveAdmissionError(decision.reason_code)
    return create_admission(
        admission_id=admission_id,
        request_id=intent.request_id,
        dispatch_id=plan.dispatch_id,
        workpackage_id=plan.workpackage_id,
        assignment_intent_id=intent.assignment_intent_id,
        repo_id=plan.repo_id,
        principal_id=plan.specialist_principal_id,
        parent_principal_id=plan.teamlead_principal_id,
        grant_id=current_grant.grant_id,
        grant_digest=current_grant.binding_digest(),
        work_item_version=workpackage.version,
        scope=ScopeBinding(scope_mode, binding_paths, scope_digest),
        resource=ResourceBinding(plan.agent_id, plan.account_key, budget_key, plan.model_id, expected_usage_micro),
        lease_context=lease_context,
        priority=priority,
        now=now,
        ttl_seconds=ttl_seconds,
    )

ExecutionAdmission = AdmissionRecord

__all__ = [
    "AdmissionError",
    "AdmissionPriority",
    "AdmissionRecord",
    "AdmissionState",
    "AdmissionStore",
    "ExecutionAdmission",
    "HiveAdmissionError",
    "LeaseBinding",
    "ResourceBinding",
    "ScopeBinding",
    "create_admission",
    "create_assignment_admission",
]
