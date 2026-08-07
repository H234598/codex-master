from datetime import datetime, timedelta, timezone

import pytest

from codex_master.hive.messages import HiveMessageError, validate_message
from codex_master.hive.status import (
    aggregate_godbee_status,
    aggregate_queen_status,
    aggregate_teamlead_status,
    proactive_anchor_status,
)


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def report(
    message_id: str,
    *,
    status: str,
    workpackage_id: str = "workpackage-one",
    dispatch_id: str = "dispatch-one",
    correlation_id: str = "request-one",
    message_type: str = "progress.report",
):
    return validate_message({
        "schema_version": 1,
        "message_id": message_id,
        "correlation_id": correlation_id,
        "causation_id": None,
        "message_type": message_type,
        "sender": {"principal_id": "specialist-one", "class_id": "spezialistin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "codex-master",
        "dispatch_id": dispatch_id,
        "workpackage_id": workpackage_id,
        "dispatch_priority": "DP1",
        "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": {"status": status, "raw_output": "not_returned", "private": "not_returned"},
        "raw_output": "not_returned",
    })


def test_hierarchical_aggregates_keep_teamlead_queen_and_godbee_scopes_separate() -> None:
    progress = report("report-one", status="executing")
    escalation = report("report-two", status="blocked", message_type="escalation")
    foreign = report("report-three", status="failed", workpackage_id="workpackage-two", dispatch_id="dispatch-two", correlation_id="request-two")

    teamlead = aggregate_teamlead_status("workpackage-one", (progress, escalation, foreign))
    queen = aggregate_queen_status("dispatch-one", (progress, escalation, foreign))
    godbee = aggregate_godbee_status("request-one", (progress, escalation, foreign))

    assert teamlead["status"] == "blocked"
    assert teamlead["report_count"] == 2
    assert queen["report_count"] == 2
    assert godbee["report_count"] == 2
    assert teamlead["escalation_count"] == 1
    assert teamlead["raw_output"] == "not_returned"


def test_aggregate_failure_and_decision_statuses_dominate_progress() -> None:
    reports = (
        report("report-one", status="executing"),
        report("report-two", status="decision_required", message_type="decision.request"),
        report("report-three", status="failed", message_type="result.report"),
    )
    result = aggregate_teamlead_status("workpackage-one", reports)
    assert result["status"] == "failed"
    assert result["status_counts"] == {"decision_required": 1, "executing": 1, "failed": 1}
    assert result["payload_digest_count"] == 3


def test_aggregate_defaults_to_unknown_and_rejects_invalid_report_inputs() -> None:
    assert aggregate_queen_status("dispatch-one") == {
        "scope": "dispatch", "dispatch_id": "dispatch-one", "status": "unknown", "report_count": 0,
        "status_counts": {}, "blocked_count": 0, "escalation_count": 0, "correlation_ids": [],
        "payload_digest_count": 0, "raw_output": "not_returned",
    }
    with pytest.raises(HiveMessageError, match="invalid_child_report"):
        aggregate_teamlead_status("workpackage-one", (object(),))
    with pytest.raises(ValueError, match="invalid_aggregate_reports"):
        aggregate_teamlead_status("workpackage-one", tuple(report(f"report-{index}", status="executing") for index in range(257)))


def test_proactive_anchor_status_is_dry_run_only_by_default() -> None:
    result = proactive_anchor_status()
    assert result["mode"] == "dry_run_only"
    assert result["execute_reason_code"] == "selection_proactive_anchor_safety_gate"
    assert result["safety"]["kill_switch_active"] is True
    assert result["raw_output"] == "not_returned"
