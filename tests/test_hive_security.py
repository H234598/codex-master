import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import pytest

from codex_master.admission import (
    AdmissionPriority,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from codex_master.hive.dispatch import (
    HiveDispatchError,
    plan_global_request,
    request_cooperative_pause,
)
from codex_master.hive.messages import HiveMessageError, validate_message
from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.hive.types import DispatchPriority
from codex_master.selection.reset_anchor import AnchorRecord, ResetAnchorPlanner


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64


def test_private_state_rejects_path_symlink_hardlink_and_oversize_matrix(tmp_path: Path) -> None:
    store = HiveStateStore(tmp_path / "state")
    with pytest.raises(HiveStateError, match="invalid_state_path"):
        store.replace_json(PurePosixPath("../escape.json"), {"ok": True})

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    linked = tmp_path / "state" / "linked.json"
    linked.symlink_to(outside)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.replace_json(PurePosixPath("linked.json"), {"ok": True})

    hardlink = tmp_path / "state" / "hardlinked.json"
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    os.link(source, hardlink)
    with pytest.raises(HiveStateError, match="state_file_untrusted"):
        store.read_json(PurePosixPath("hardlinked.json"), max_bytes=4096)

    with pytest.raises(HiveStateError, match="state_oversize"):
        store.replace_json(PurePosixPath("large.json"), {"value": "x" * (4 * 1024 * 1024)})


def test_global_request_and_pause_security_gates_reject_forged_or_preemptive_inputs() -> None:
    with pytest.raises(HiveDispatchError, match="godbee_actor_required"):
        plan_global_request(
            actor_principal_id="queen-codex-master",
            objective="inspect",
            repositories=("codex-master",),
            priority=DispatchPriority.DP1,
            success_criteria=("report",),
            constraints=(),
        )

    blocked = plan_global_request(
        actor_principal_id="godbee-main",
        objective="force-push migration",
        repositories=("codex-master",),
        priority=DispatchPriority.DP0,
        success_criteria=("report",),
        constraints=("breaking and force-push changes",),
        repository_queens={"codex-master": "queen-codex-master"},
    )
    assert blocked.planning_reason == "user_gate_required"
    assert blocked.request.state == "blocked"

    for reason in ("selection fairness", "model rotation", "lease takeover", "hard kill"):
        with pytest.raises(HiveDispatchError, match="pause_source_not_allowed"):
            request_cooperative_pause("workpackage-one", reason=reason)


def test_public_admission_and_saga_projections_omit_private_bindings() -> None:
    admission = create_admission(
        admission_id="adm-one", request_id="req-one", dispatch_id="dispatch-one", workpackage_id="workpackage-one",
        assignment_intent_id="intent-one", repo_id="codex-master", principal_id="specialist-one",
        parent_principal_id="lead-one", grant_id="grant-one", grant_digest="sha256:private-grant",
        work_item_version=1, scope=ScopeBinding("write", ("src/private.py",), "sha256:private-scope"),
        resource=ResourceBinding("agent-one", "hmac:private-account", "standard", "gpt-primary", 1),
        lease_context=LeaseBinding("claimed", "lease-private"),
        priority=AdmissionPriority("DP1", "selection"), now=NOW,
    )
    admission_public = admission.public()
    assert "private-account" not in json.dumps(admission_public)
    assert "private.py" not in json.dumps(admission_public)
    assert "private-grant" not in json.dumps(admission_public)
    assert "principal_id" not in admission_public

    plan = plan_global_request(
        actor_principal_id="godbee-main", objective="inspect", repositories=("codex-master",),
        priority=DispatchPriority.DP1, success_criteria=("report",), constraints=(),
        repository_queens={"codex-master": "queen-codex-master"},
    )
    public = plan.public()
    assert public["direct_write_paths"] == "not_returned"
    assert "budget" not in public
    assert "private" not in json.dumps(public)


def test_message_and_proactive_execute_boundaries_are_fail_closed() -> None:
    with pytest.raises(HiveMessageError, match="invalid_message_fields"):
        validate_message({"schema_version": 1, "raw_output": "terminal output"})

    key = DIGEST
    record = AnchorRecord(key, "due", 0, None, None, NOW)
    planner = ResetAnchorPlanner(
        record, allowed_anchor_keys=(key,), execute_enabled=True, kill_switch_active=False,
        hard_sandbox_verified=True, token_budget_verified=True, runtime_limit_verified=True,
        no_tools_verified=True, empty_workspace_verified=True, no_repository_data_verified=True,
        fixed_internal_task_verified=True,
    )
    plan = planner.plan_due(now=NOW)
    assert plan is not None
    result = planner.execute(plan)
    assert result["reason_code"] == "selection_proactive_anchor_safety_gate"
    assert result["mutation_performed"] is False
    assert result["safety"]["gate_ready"] is True


@pytest.mark.parametrize("payload", [None, [], {"schema_version": 1}, {"schema_version": 1, "models": {}}])
def test_security_matrix_rejects_non_mapping_public_documents(payload: object, tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    store = HiveStateStore(tmp_path / "hive")
    path.replace(tmp_path / "hive" / "state.json")
    if isinstance(payload, dict):
        assert store.read_json(PurePosixPath("state.json"), max_bytes=4096) == payload
    else:
        with pytest.raises(HiveStateError, match="invalid_state_document"):
            store.read_json(PurePosixPath("state.json"), max_bytes=4096)
