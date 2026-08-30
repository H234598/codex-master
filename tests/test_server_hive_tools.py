from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from codex_master import server
from codex_master.hive.dispatch import HiveDispatchError
from codex_master.hive.events import HiveEventStore
from codex_master.hive.messages import validate_message
from codex_master.hive.config import load_agent_class_catalog, load_hive_config


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def test_server_exposes_additive_read_only_hive_tools() -> None:
    names = {tool["name"] for tool in server.TOOLS}
    assert {"hive_status", "godbee_status", "queen_list", "agent_selection_status"} <= names
    assert server.call_validated_tool("hive_status", {})["raw_output"] == "not_returned"


def test_server_runtime_factory_can_forward_read_only_assembly() -> None:
    classes = load_agent_class_catalog(server.repo_root() / "codex-agent-classes.json")
    config = load_hive_config(server.repo_root() / "codex-hive.json", classes)
    with patch.object(server, "load_agent_class_catalog", return_value=classes), patch.object(
        server, "load_hive_config", return_value=config
    ), patch.object(server, "build_hive_runtime", return_value=object()) as builder:
        result = server.build_current_hive_runtime(repository_roots={}, read_only=True)

    assert result is not None
    builder.assert_called_once_with(
        config,
        classes,
        repository_roots={},
        state_root=server.STATE_ROOT / "hive",
        materialize_principals=False,
        read_only=True,
        now=None,
    )


def queen_workpackage(mode: str = "enforced") -> dict[str, object]:
    return {
        "workpackage_id": "workpackage-one", "repo_id": "codex-master",
        "teamlead_principal_id": "lead-one", "specialist_principal_id": "specialist-one",
        "writer_class_id": "spezialistin", "agent_id": "agent-one", "account_key": "sha256:" + "a" * 64,
        "model_id": "gpt-primary", "model_role": "primary", "task_complexity": "complex",
        "scope": ("src",), "write_paths": ("src/task.py",), "mode": mode,
        "pilot_enabled": True, "account_confirmed": True, "authority_verified": True,
        "repository_verified": True, "scope_verified": True, "lease_available": True,
        "selection_band": "none",
    }


def test_server_queen_adapter_is_closed_without_context_and_not_an_mcp_tool() -> None:
    result = server.execute_server_queen_assignment(
        queen_id="queen-codex-master", dispatch_id="dispatch-one", workpackage=queen_workpackage()
    )
    assert result["reason_code"] == "pilot_gate_blocked"
    assert "execute_server_queen_assignment" not in {tool["name"] for tool in server.TOOLS}


def test_server_queen_adapter_accepts_only_explicit_injected_callbacks() -> None:
    events: list[str] = []
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64}, primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: events.append("teamlead") or "lead",
        create_specialist_principal=lambda _plan: events.append("specialist") or "specialist",
        issue_grant=lambda _plan: events.append("grant") or "grant",
        reserve_admission=lambda _plan: events.append("admission") or "admission",
        execute_assignment=lambda _plan: events.append("assignment") or {"status": "accepted"},
        compensate=lambda *_args: events.append("compensate"),
    )
    result = server.execute_server_queen_assignment(
        queen_id="queen-codex-master", dispatch_id="dispatch-one", workpackage=queen_workpackage(), context=context
    )
    assert result["reason_code"] == "assignment_executed"
    assert events == ["teamlead", "specialist", "grant", "admission", "assignment"]
    with pytest.raises(HiveDispatchError, match="pilot_allowlist_denied"):
        server.execute_server_queen_assignment(
            queen_id="queen-codex-master", dispatch_id="dispatch-one",
            workpackage={**queen_workpackage(), "repo_id": "foreign-repo"}, context=context,
        )


def test_server_queen_adapter_persists_queue_and_completion_events(tmp_path) -> None:
    events = HiveEventStore(tmp_path / "hive")
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64}, primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: "lead",
        create_specialist_principal=lambda _plan: "specialist",
        issue_grant=lambda _plan: "grant",
        reserve_admission=lambda _plan: "admission",
        execute_assignment=lambda _plan: {"status": "accepted"},
        compensate=lambda *_args: None,
    )

    result = server.execute_server_queen_assignment(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-one",
        workpackage=queen_workpackage(),
        context=context,
        event_store=events,
    )

    assert result["reason_code"] == "assignment_executed"
    _, report_events = events.read_report_sources()
    assert [event["status"] for event in report_events] == ["queued", "completed"]


def test_server_pause_preview_is_checkpointed_and_never_selection_driven() -> None:
    assert server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=False
    )["reason_code"] == "assignment_not_pausable"
    assert server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True, selection_source=True
    )["reason_code"] == "selection_preemption_forbidden"
    pending = server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True
    )
    assert pending["reason_code"] == "checkpoint_required"
    checkpoint = validate_message({
        "schema_version": 1, "message_id": "report-one", "correlation_id": "request-one", "causation_id": None,
        "message_type": "progress.report",
        "sender": {"principal_id": "specialist-one", "class_id": "spezialistin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "codex-master", "dispatch_id": "dispatch-one", "workpackage_id": "workpackage-one",
        "dispatch_priority": "DP1", "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": {"status": "executing", "checkpoint": True, "checkpoint_state": "safe", "pause_requested": True, "origin": "work_orchestration", "raw_output": "not_returned"},
        "raw_output": "not_returned",
    })
    ready = server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True, checkpoint=checkpoint
    )
    assert ready["reason_code"] == "safe_checkpoint_ready"
    assert ready["mutation_performed"] is False
