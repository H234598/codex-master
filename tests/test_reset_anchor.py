from datetime import datetime, timezone

from codex_master.selection.reset_anchor import (
    AnchorRecord,
    AnchorStateMachine,
    LimitObservation,
    ResetAnchorPlanner,
    anchor_due,
)


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def test_verified_remaining_full_unanchored_window_is_passively_due() -> None:
    record = AnchorRecord("sha256:" + "a" * 64, "grace", 0, None, None, None)
    observation = LimitObservation("remaining", 100, "rolling_unanchored", "verified", NOW)
    updated = AnchorStateMachine().transition(record, observation, now=NOW)
    assert updated.state == "due"
    assert anchor_due(updated, now=NOW) is True


def due_record(*, attempt_count: int = 0, cooldown_until_utc=None) -> AnchorRecord:
    return AnchorRecord("sha256:" + "a" * 64, "due", attempt_count, None, cooldown_until_utc, NOW)


def test_proactive_anchor_dry_run_is_allowlisted_and_never_mutates() -> None:
    record = due_record()
    planner = ResetAnchorPlanner(record, allowed_anchor_keys=(record.anchor_key,))
    result = planner.dry_run(now=NOW)
    assert result["allowed"] is True
    assert result["reason_code"] == "anchor_due"
    assert result["mutation_performed"] is False
    assert result["plan"]["attempt_number"] == 1
    assert planner.execute(planner.plan_due(now=NOW))["reason_code"] == "selection_proactive_anchor_safety_gate"


def test_proactive_anchor_allowlist_cooldown_and_attempt_limits_fail_closed() -> None:
    record = due_record()
    assert ResetAnchorPlanner(record).dry_run(now=NOW)["reason_code"] == "anchor_allowlist_blocked"
    cooldown = ResetAnchorPlanner(due_record(cooldown_until_utc=NOW.replace(hour=13)), allowed_anchor_keys=(record.anchor_key,))
    assert cooldown.dry_run(now=NOW)["reason_code"] == "anchor_cooldown"
    exhausted = ResetAnchorPlanner(due_record(attempt_count=3), allowed_anchor_keys=(record.anchor_key,))
    assert exhausted.dry_run(now=NOW)["reason_code"] == "anchor_attempt_limit"


def test_proactive_anchor_execute_requires_all_safety_evidence_and_stays_blocked() -> None:
    record = due_record()
    planner = ResetAnchorPlanner(
        record, allowed_anchor_keys=(record.anchor_key,), execute_enabled=True, kill_switch_active=False,
        hard_sandbox_verified=True, token_budget_verified=True, runtime_limit_verified=True,
        no_tools_verified=True, empty_workspace_verified=True, no_repository_data_verified=True,
        fixed_internal_task_verified=True,
    )
    status = planner.safety_status(now=NOW)
    assert status.gate_ready is True
    plan = planner.plan_due(now=NOW)
    assert plan is not None
    result = planner.execute(plan)
    assert result["allowed"] is False
    assert result["reason_code"] == "selection_proactive_anchor_safety_gate"
