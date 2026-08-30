from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest

from codex_master.hive.dispatch import (
    AssignmentIntent,
    GlobalRequest,
    GlobalRequestPlan,
    GlobalSagaExecutionContext,
    HiveDispatchError,
    QueenAssignmentExecutionContext,
    RepoDispatch,
    WorkPackage,
    acknowledge_checkpoint,
    cancel_global_request,
    execute_global_request,
    execute_queen_assignment,
    plan_global_request,
    plan_queen_assignment,
    retry_repo_dispatch,
    request_cooperative_pause,
    resume_paused_workpackage,
    transition_dispatch,
    transition_request,
    transition_workpackage,
    transition_workpackage_at_checkpoint,
    transition_workpackage_from_report,
)
from codex_master.hive.messages import validate_message
from codex_master.hive.types import DispatchPriority, TaskComplexity


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def request() -> GlobalRequest:
    return GlobalRequest("request-one", "Implement a bounded task", ("tests pass",), (), (), "godbee-main", ("repo-one",), ("repo-one",), DispatchPriority.DP1, (), NOW)


def dispatch() -> RepoDispatch:
    return RepoDispatch("dispatch-one", "request-one", "repo-one", "queen-one", "Implement a bounded task", ("tests pass",), (), DispatchPriority.DP1, DispatchPriority.DP1, None, (), {"max_micro": 10})


def workpackage() -> WorkPackage:
    return WorkPackage("workpackage-one", "dispatch-one", "lead-one", "Implement a bounded task", ("src",), ("src/task.py",), ("tests pass",), ("pytest",), "teamlead_commit", (), {"complexity": "complex"})


def global_plan(mode: str = "shadow", *, repositories: tuple[str, ...] = ("repo-one",), constraints: tuple[str, ...] = (), user_gates: tuple[str, ...] = ()) -> GlobalRequestPlan:
    return plan_global_request(
        actor_principal_id="godbee-main", objective="Coordinate bounded work", repositories=repositories,
        priority=DispatchPriority.DP1, success_criteria=("tests pass",), constraints=constraints,
        repository_queens={repo_id: f"queen-{repo_id.removeprefix('repo-')}" for repo_id in repositories if repo_id in {"repo-one", "repo-two"}},
        user_gates=user_gates, mode=mode,
    )


def clocked_global_plan(now: object) -> GlobalRequestPlan:
    return plan_global_request(
        actor_principal_id="godbee-main",
        objective="Coordinate bounded work",
        repositories=("repo-one",),
        priority=DispatchPriority.DP1,
        success_criteria=("tests pass",),
        constraints=(),
        repository_queens={"repo-one": "queen-one"},
        now=now,
    )


@pytest.mark.parametrize(
    ("sample", "expected"),
    (
        (NOW, NOW),
        (datetime(2026, 8, 6, 14, 0, tzinfo=timezone(timedelta(hours=2))), NOW),
    ),
    ids=("utc", "aware_offset_canonicalized_to_utc"),
)
def test_global_request_plan_samples_valid_clock_once_and_canonicalizes_aware_time(
    sample: datetime,
    expected: datetime,
) -> None:
    samples: list[datetime] = []

    def clock() -> datetime:
        samples.append(sample)
        return sample

    plan = clocked_global_plan(clock)

    assert samples == [sample]
    assert plan.request.created_at_utc == expected


@pytest.mark.parametrize(
    "clock",
    (
        lambda: (_ for _ in ()).throw(HiveDispatchError("private_hive_dispatch_detail")),
        lambda: (_ for _ in ()).throw(ValueError("private_value_detail")),
        lambda: (_ for _ in ()).throw(TypeError("private_type_detail")),
        lambda: "2026-08-06T12:00:00Z",
        lambda: 1_786_017_600,
        lambda: datetime(2026, 8, 6, 12, 0),
    ),
    ids=("hive_dispatch_error", "value_error", "type_error", "wrong_string", "wrong_number", "naive_datetime"),
)
def test_global_request_plan_rejects_adversarial_clock_without_detail_leak(
    clock: Callable[[], object],
) -> None:
    samples = 0

    def counted_clock() -> object:
        nonlocal samples
        samples += 1
        return clock()

    with pytest.raises(HiveDispatchError, match=r"^invalid_request_timestamp$") as raised:
        clocked_global_plan(counted_clock)

    assert samples == 1
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True
    assert "private_" not in str(raised.value)


def test_global_request_plan_rejects_invalid_request_before_clock_sample() -> None:
    samples = 0

    def clock() -> datetime:
        nonlocal samples
        samples += 1
        return NOW

    with pytest.raises(HiveDispatchError, match=r"^godbee_actor_required$"):
        plan_global_request(
            actor_principal_id="queen-one",
            objective="Coordinate bounded work",
            repositories=("repo-one",),
            priority=DispatchPriority.DP1,
            success_criteria=("tests pass",),
            constraints=(),
            repository_queens={"repo-one": "queen-one"},
            now=clock,
        )

    assert samples == 0


def test_global_request_plan_rejects_noncallable_clock_without_sample() -> None:
    with pytest.raises(HiveDispatchError, match=r"^invalid_planning_clock$"):
        clocked_global_plan(object())


def test_state_machines_enforce_order_and_are_idempotent_on_same_version() -> None:
    planned = request()
    classified = transition_request(planned, "classified", expected_version=1)
    assert classified.version == 2
    assert transition_request(classified, "classified", expected_version=2) == classified
    with pytest.raises(HiveDispatchError, match="invalid_transition"):
        transition_request(classified, "completed", expected_version=2)
    with pytest.raises(HiveDispatchError, match="stale_dispatch_version"):
        transition_request(classified, "planned", expected_version=1)


def test_global_request_plan_binds_known_repositories_and_keeps_unknown_parts_visible() -> None:
    plan = global_plan(repositories=("repo-one", "foreign-repo"))
    assert plan.planning_reason == "unknown_repository"
    assert plan.request.state == "blocked"
    assert plan.public()["resolved_repository_count"] == 1
    assert plan.public()["direct_write_paths"] == "not_returned"
    assert execute_global_request(plan)["reason_code"] == "shadow_only"


def test_global_request_plan_requires_explicit_risk_gates_and_godbee_actor() -> None:
    blocked = global_plan(constraints=("breaking change",))
    assert blocked.planning_reason == "user_gate_required"
    assert blocked.user_gates == ("breaking_changes",)
    ready = global_plan(constraints=("breaking change",), user_gates=("breaking_changes",))
    assert ready.ready_for_execution is True
    with pytest.raises(HiveDispatchError, match="godbee_actor_required"):
        plan_global_request(
            actor_principal_id="queen-one", objective="x", repositories=("repo-one",),
            priority=DispatchPriority.DP1, success_criteria=("ok",), constraints=(),
            repository_queens={"repo-one": "queen-one"},
        )


def test_global_request_enforced_runs_each_repo_through_injected_saga_callbacks() -> None:
    events: list[str] = []
    context = GlobalSagaExecutionContext(
        frozenset({"queen-one", "queen-two"}), frozenset({"repo-one", "repo-two"}), frozenset(),
        lambda _request: events.append("global") or "request-record",
        lambda dispatch_item: events.append(f"create:{dispatch_item.repo_id}") or "dispatch-record",
        lambda dispatch_item: events.append(f"execute:{dispatch_item.repo_id}") or {"status": "accepted"},
        lambda kind, identifier, _result: events.append(f"compensate:{kind}:{identifier}"),
    )
    result = execute_global_request(global_plan("enforced", repositories=("repo-one", "repo-two")), context)
    assert result["allowed"] is True
    assert result["completed_dispatch_count"] == 2
    assert events == ["global", "create:repo-one", "execute:repo-one", "create:repo-two", "execute:repo-two"]


def test_global_request_partial_failure_compensates_without_fake_global_atomicity() -> None:
    events: list[str] = []
    context = GlobalSagaExecutionContext(
        frozenset({"queen-one", "queen-two"}), frozenset({"repo-one", "repo-two"}), frozenset(),
        lambda _request: events.append("global") or "request-record",
        lambda dispatch_item: events.append(f"dispatch:{dispatch_item.repo_id}") or "dispatch-record",
        lambda dispatch_item: {"status": "accepted"} if events.append(f"execute:{dispatch_item.repo_id}") is None and dispatch_item.repo_id == "repo-one" else (_ for _ in ()).throw(RuntimeError("provider")),
        lambda kind, _identifier, _result: events.append(f"compensate:{kind}"),
    )
    result = execute_global_request(global_plan("enforced", repositories=("repo-one", "repo-two")), context)
    assert result["reason_code"] == "saga_partially_completed"
    assert result["state"] == "partially_completed"
    assert result["completed_dispatch_count"] == 1
    assert result["compensation_complete"] is True
    assert events == [
        "global", "dispatch:repo-one", "execute:repo-one", "dispatch:repo-two", "execute:repo-two",
        "compensate:repo_execute", "compensate:repo_dispatch", "compensate:repo_execute",
        "compensate:repo_dispatch", "compensate:global_request",
    ]


def test_global_saga_retry_and_cancel_are_closed_without_injected_callbacks() -> None:
    assert retry_repo_dispatch("dispatch-one", expected_version=1)["reason_code"] == "saga_gate_blocked"
    assert cancel_global_request("request-one", expected_version=1)["reason_code"] == "saga_gate_blocked"
    events: list[tuple[str, object, object]] = []
    context = GlobalSagaExecutionContext(
        frozenset(), frozenset(), frozenset(),
        retry_dispatch=lambda dispatch_id, version: events.append(("retry", dispatch_id, version)) or {"ok": True},
        cancel_request=lambda request_id, version: events.append(("cancel", request_id, version)) or {"ok": True},
    )
    assert retry_repo_dispatch("dispatch-one", expected_version=2, context=context)["allowed"] is True
    assert cancel_global_request("request-one", expected_version=3, context=context)["allowed"] is True
    assert events == [("retry", "dispatch-one", 2), ("cancel", "request-one", 3)]


def test_dispatch_and_workpackage_state_machines_cover_pause_conflict_and_completion() -> None:
    item = dispatch()
    for target in ("queen_accepted", "workpackages_ready", "queued", "executing", "cooperative_pause_requested", "paused", "queued"):
        item = transition_dispatch(item, target, expected_version=item.version)
    assert item.state == "queued"
    work = workpackage()
    for target in ("ready", "queued", "admission_planned", "conflict", "queued", "admission_planned", "admitted", "executing", "integrating", "completed"):
        work = transition_workpackage(work, target, expected_version=work.version)
    assert work.state == "completed"


def test_assignment_intent_keeps_model_and_scope_metadata_bounded() -> None:
    intent = AssignmentIntent(
        "intent-one", "request-one", "dispatch-one", "workpackage-one", "repo-one", "lead-one", "grant-one", "spezialistin",
        DispatchPriority.DP1, TaskComplexity.COMPLEX, {"primary_only": True}, {"mode": "write", "path_count": 1},
        "standard", ("decision-one",), "sha256:context",
    )
    assert intent.task_complexity is TaskComplexity.COMPLEX
    assert intent.model_policy_constraints["primary_only"] is True
    assert queen_plan(model_id="gpt-5.4-mini").model_id == "gpt-5.4-mini"


def child_report(message_type: str = "result.report", *, workpackage_id: str = "workpackage-one", status: str = "completed", **payload_fields: object):
    report_payload = {"status": status, "raw_output": "not_returned", "result": "private"}
    report_payload.update(payload_fields)
    return validate_message({
        "schema_version": 1, "message_id": "report-one", "correlation_id": "request-one", "causation_id": None,
        "message_type": message_type,
        "sender": {"principal_id": "specialist-one", "class_id": "spezialistin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "repo-one", "dispatch_id": "dispatch-one", "workpackage_id": workpackage_id,
        "dispatch_priority": "DP1", "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": report_payload,
        "raw_output": "not_returned",
    })


def test_workpackage_report_transition_is_correlated_and_uses_state_graph() -> None:
    item = workpackage()
    for target in ("ready", "queued", "admission_planned", "admitted", "executing"):
        item = transition_workpackage(item, target, expected_version=item.version)
    item = transition_workpackage_from_report(
        item, child_report(status="integrating"), expected_version=item.version
    )
    item = transition_workpackage_from_report(item, child_report(), expected_version=item.version)
    assert item.state == "completed"
    with pytest.raises(HiveDispatchError, match="report_workpackage_mismatch"):
        transition_workpackage_from_report(item, child_report(workpackage_id="other-workpackage"), expected_version=item.version)


def test_cooperative_pause_requires_orchestration_reason_and_safe_checkpoint() -> None:
    request = request_cooperative_pause("workpackage-one", reason="higher_priority_slot_required")
    assert request["checkpoint_required"] is True
    assert request["hard_kill"] is False
    with pytest.raises(HiveDispatchError, match="pause_source_not_allowed"):
        request_cooperative_pause("workpackage-one", reason="sp3 fairness preemption")
    checkpoint = child_report(
        "progress.report", status="executing", checkpoint=True, checkpoint_state="safe",
        pause_requested=True, origin="work_orchestration",
    )
    acknowledged = acknowledge_checkpoint(checkpoint)
    assert acknowledged["reason_code"] == "safe_checkpoint_acknowledged"
    item = workpackage()
    for target in ("ready", "queued", "admission_planned", "admitted", "executing"):
        item = transition_workpackage(item, target, expected_version=item.version)
    paused = transition_workpackage_at_checkpoint(item, checkpoint, expected_version=item.version)
    assert paused.state == "paused"


def test_cooperative_pause_rejects_unsafe_reports_and_resume_stays_revalidation_gated() -> None:
    with pytest.raises(HiveDispatchError, match="unsafe_checkpoint"):
        acknowledge_checkpoint(child_report("progress.report", status="executing"))
    resumed = resume_paused_workpackage("workpackage-one")
    assert resumed["allowed"] is False
    assert resumed["reason_code"] == "resume_revalidation_required"
    assert resumed["requires_fresh_admission"] is True


def queen_plan(mode: str = "shadow", **overrides):
    values = {
        "workpackage_id": "workpackage-one", "repo_id": "codex-master",
        "teamlead_principal_id": "lead-one", "specialist_principal_id": "specialist-one",
        "writer_class_id": "spezialistin", "agent_id": "a1", "account_key": "sha256:" + "a" * 64,
        "model_id": "gpt-primary", "model_role": "primary", "task_complexity": "complex",
        "scope": ("src",), "write_paths": ("src/task.py",), "mode": mode,
        "pilot_enabled": True, "account_confirmed": True, "authority_verified": True,
        "repository_verified": True, "scope_verified": True, "lease_available": True,
        "selection_band": "none",
    }
    values.update(overrides)
    return plan_queen_assignment(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-one",
        workpackage=values,
    )


def test_queen_assignment_shadow_and_closed_default_never_mutate() -> None:
    plan = queen_plan()
    assert execute_queen_assignment(plan)["reason_code"] == "shadow_only"
    assert execute_queen_assignment(queen_plan("enforced"))["reason_code"] == "pilot_gate_blocked"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("repo_id", "foreign-repo", "pilot_allowlist_denied"),
        ("writer_class_id", "queen", "writer_role_denied"),
        ("writer_class_id", "godbee", "writer_role_denied"),
        ("selection_band", "primary", "selection_feature_disabled"),
    ),
)
def test_queen_assignment_plan_rejects_unapproved_writers_repositories_and_selection(
    field: str, value: str, reason: str
) -> None:
    with pytest.raises(HiveDispatchError, match=reason):
        queen_plan("enforced", **{field: value})


def test_queen_assignment_context_keeps_account_model_and_sp_gates_closed() -> None:
    plan = queen_plan("enforced")
    context = QueenAssignmentExecutionContext(
        frozenset({"queen-codex-master"}), frozenset({"codex-master"}), frozenset(), frozenset({"gpt-primary"}), False
    )
    assert not context.ready_for(plan)
    context = QueenAssignmentExecutionContext(
        frozenset({"queen-codex-master"}), frozenset({"codex-master"}), frozenset({plan.account_key}), frozenset({"secondary"}), False
    )
    assert not context.ready_for(plan)
    context = QueenAssignmentExecutionContext(
        frozenset({"queen-codex-master"}), frozenset({"codex-master"}), frozenset({plan.account_key}), frozenset({plan.model_id}), True
    )
    assert not context.ready_for(plan)


def test_queen_assignment_enforced_runs_in_order_and_compensates_reverse_order() -> None:
    events: list[str] = []
    context = QueenAssignmentExecutionContext(
        frozenset({"queen-codex-master"}), frozenset({"codex-master"}), frozenset({"sha256:" + "a" * 64}), frozenset({"gpt-primary"}), False,
        lambda _plan: events.append("teamlead") or "teamlead-created",
        lambda _plan: events.append("specialist") or "specialist-created",
        lambda _plan: events.append("grant") or "grant-created",
        lambda _plan: events.append("admission") or "admission-created",
        lambda _plan: events.append("assignment") or {"status": "accepted"},
        lambda name, _plan, _result: events.append(f"compensate:{name}"),
    )
    result = execute_queen_assignment(
        queen_plan("enforced"), context, step_executor=lambda _name, callback, plan: callback(plan)
    )
    assert result["allowed"] is True
    assert events == ["teamlead", "specialist", "grant", "admission", "assignment"]

    events.clear()
    failing = QueenAssignmentExecutionContext(
        context.pilot_queens, context.pilot_repositories, context.confirmed_accounts, context.primary_models, False,
        context.create_teamlead_principal, context.create_specialist_principal, context.issue_grant,
        context.reserve_admission, lambda _plan: (_ for _ in ()).throw(RuntimeError("assignment")), context.compensate,
    )
    failed = execute_queen_assignment(
        queen_plan("enforced"), failing, step_executor=lambda _name, callback, plan: callback(plan)
    )
    assert failed["reason_code"] == "assignment_transaction_failed"
    assert events[-5:] == [
        "compensate:assignment", "compensate:admission", "compensate:grant",
        "compensate:specialist", "compensate:teamlead",
    ]
    cancel_global_request,
    execute_global_request,
    plan_global_request,
    retry_repo_dispatch,
