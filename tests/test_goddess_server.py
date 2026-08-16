from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from codex_master import server
from codex_master.goddess_reporting import ReporterStateStore
from codex_master.hive.events import HiveEventStore


def test_report_tools_are_published_with_closed_schemas():
    names = {tool["name"] for tool in server.TOOLS}
    assert {
        "fleet_overview",
        "fleet_status_compact",
        "goddess_report_status",
        "goddess_report_run",
        "goddess_report_list",
    } <= names
    name, args = server.validate_tool_call(
        "goddess_report_run",
        {"bucket_start": "2026-08-16T10:00:00Z", "partial": False},
    )
    assert name == "goddess_report_run"
    assert args["partial"] is False


def test_report_run_writes_sanitized_report_and_state(tmp_path, monkeypatch):
    bucket = datetime(2026, 8, 16, 10, tzinfo=UTC)
    state = ReporterStateStore(tmp_path / "state" / "reporter.json")
    monkeypatch.setattr(server, "_goddess_report_state", lambda: state)
    monkeypatch.setattr(server, "GODDESS_REPORT_LEADER_FILE", tmp_path / "state" / "leader.lock")
    monkeypatch.setattr(server, "_goddess_vault_root", lambda: tmp_path / "vault")
    monkeypatch.setattr(
        server,
        "_fleet_overview_local_admin",
        lambda **_kwargs: json.dumps({
            "agents": [{
                "agent_id": "g1",
                "series_display": "G",
                "provider": "gemini_api",
                "account_id": "gem-a",
                "account_label": "Gemini A",
                "state": "active",
            }],
            "account_limits": [],
            "warnings": [],
        }),
    )

    result = server._goddess_report_run_local(bucket=bucket, partial=False, replace=False)

    assert result["ok"] is True
    assert result["status"] == "final"
    assert "g1" in result["markdown"]
    assert result["vault_path"]
    assert "raw" not in result["markdown"].lower()
    assert state.load()["buckets"]


def test_report_run_includes_task_rows_from_private_logs(tmp_path, monkeypatch):
    bucket = datetime(2026, 8, 16, 10, tzinfo=UTC)
    state = ReporterStateStore(tmp_path / "reporter.json")
    assignment_log = tmp_path / "assignments.jsonl"
    assignment_log.write_text(
        json.dumps({
            "assignment_id": "done-1",
            "created_at_utc": "2026-08-16T10:05:00Z",
            "agent": "g1",
        }) + "\n" + json.dumps({
            "assignment_id": "open-1",
            "created_at_utc": "2026-08-16T09:30:00Z",
            "agent": "g2",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "ASSIGNMENT_LOG", assignment_log)
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    events = server.FleetPaths.from_state_root(server.STATE_ROOT).events
    events.parent.mkdir(parents=True)
    events.write_text(
        json.dumps({
            "assignment_id": "done-1",
            "at_utc": "2026-08-16T10:20:00Z",
            "status": "completed",
        }) + "\n" + json.dumps({
            "assignment_id": "open-1",
            "at_utc": "2026-08-16T10:10:00Z",
            "status": "rate_limited",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "_goddess_report_state", lambda: state)
    monkeypatch.setattr(server, "_goddess_vault_root", lambda: tmp_path / "vault")
    monkeypatch.setattr(
        server,
        "_fleet_overview_local_admin",
        lambda **_kwargs: json.dumps({"agents": [], "account_limits": [], "warnings": []}),
    )

    result = server._goddess_report_run_unlocked(bucket=bucket, partial=False, replace=False)

    assert "- done-1 (completed; g1)" in result["markdown"]
    assert "- open-1 (rate_limited; g2)" in result["markdown"]
    assert "Taskaggregation ist in diesem Reporterpfad nicht angeschlossen" not in result["markdown"]


def test_report_run_includes_persistent_hive_queue_completion(tmp_path, monkeypatch):
    bucket = datetime(2026, 8, 16, 10, tzinfo=UTC)
    state_root = tmp_path / "state"
    store = HiveEventStore(state_root / "hive")
    store.append_queue_transition(
        "workpackage-one",
        "queued",
        at_utc=datetime(2026, 8, 16, 10, 5, tzinfo=UTC),
        agent_id="agent-one",
    )
    store.append_queue_transition(
        "workpackage-one",
        "completed",
        at_utc=datetime(2026, 8, 16, 10, 20, tzinfo=UTC),
        agent_id="agent-one",
    )
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "ASSIGNMENT_LOG", tmp_path / "missing-assignments.jsonl")
    monkeypatch.setattr(server, "_goddess_report_state", lambda: ReporterStateStore(tmp_path / "reporter.json"))
    monkeypatch.setattr(server, "_goddess_vault_root", lambda: tmp_path / "vault")
    monkeypatch.setattr(
        server,
        "_fleet_overview_local_admin",
        lambda **_kwargs: json.dumps({"agents": [], "account_limits": [], "warnings": []}),
    )

    result = server._goddess_report_run_unlocked(bucket=bucket, partial=False, replace=False)

    assert "- workpackage-one (completed; agent-one)" in result["markdown"]


def test_report_run_serializes_leader_access(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_goddess_report_state", lambda: ReporterStateStore(tmp_path / "state.json"))
    monkeypatch.setattr(server, "GODDESS_REPORT_LEADER_FILE", tmp_path / "leader.lock")
    lease = server.ReporterLeaderLease(tmp_path / "leader.lock")
    lease.acquire()
    try:
        result = server._goddess_report_run_local(bucket=None, partial=False, replace=False)
    finally:
        lease.release()
    assert result["ok"] is False
    assert result["error"] == "goddess_report_leader_busy"


def test_report_run_backfills_all_eligible_buckets_in_order(tmp_path, monkeypatch):
    state = ReporterStateStore(tmp_path / "state.json")
    state.save({
        "schema_version": 1,
        "buckets": {
            "2026-08-16T08:00:00Z/PT1H": {
                "status": "final",
                "content_sha256": "a",
            }
        },
    })
    monkeypatch.setattr(server, "_goddess_report_state", lambda: state)
    monkeypatch.setattr(server, "GODDESS_REPORT_LEADER_FILE", tmp_path / "leader.lock")
    eligible = (
        datetime(2026, 8, 16, 9, tzinfo=UTC),
        datetime(2026, 8, 16, 10, tzinfo=UTC),
    )
    monkeypatch.setattr(server, "eligible_buckets", lambda **_kwargs: eligible, raising=False)
    processed = []

    def run_unlocked(*, bucket, partial, replace):
        processed.append((bucket, partial, replace))
        return {"ok": True, "bucket_id": bucket.isoformat(), "changed": True}

    monkeypatch.setattr(server, "_goddess_report_run_unlocked", run_unlocked)

    result = server._goddess_report_run_local(bucket=None, partial=False, replace=False)

    assert result["ok"] is True
    assert result["status"] == "batch"
    assert [item[0] for item in processed] == list(eligible)
    assert result["reports"] == [
        {"ok": True, "bucket_id": item.isoformat(), "changed": True}
        for item in eligible
    ]


def test_goddess_report_systemd_units_are_bounded_and_retryable():
    root = Path(__file__).resolve().parents[1] / "systemd" / "user"
    service = (root / "codex-master-goddess-report.service").read_text(encoding="utf-8")
    timer = (root / "codex-master-goddess-report.timer").read_text(encoding="utf-8")

    assert "ExecStart=%h/.local/bin/codex-master-mcp goddess report run" in service
    assert "CapabilityBoundingSet=" in service
    assert "NoNewPrivileges=yes" in service
    assert "IPAddressDeny=any" in service
    assert "ReadWritePaths=%h/.local/state/codex-master-mcp" in service
    assert "OnCalendar=hourly" in timer
    assert "Persistent=true" in timer
    assert "RandomizedDelaySec=5m" in timer


def test_fleet_overview_compact_and_limit_filter_are_structured(monkeypatch):
    monkeypatch.setattr(server, "_fleet_overview_local_admin", lambda **_kwargs: "Biene | Zustand\ng1 | aktiv")
    compact = server.call_tool("fleet_overview", {"format": "compact", "include_limits": False})
    assert compact == {
        "overview": "Biene | Zustand\ng1 | aktiv",
        "format": "compact",
        "raw_output": "not_returned",
    }


def test_goddess_report_cli_has_status_route(monkeypatch, capsys):
    monkeypatch.setattr(server, "_goddess_report_status_local", lambda: {"state": "ready"})
    assert server.main_cli(["goddess", "report", "status"]) == 0
    assert json.loads(capsys.readouterr().out) == {"state": "ready"}


def test_report_status_is_degraded_when_hive_binding_state_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_goddess_report_state", lambda: ReporterStateStore(tmp_path / "state.json"))
    monkeypatch.setattr(server, "_goddess_binding_status", lambda _now: (None, "hive_binding_state_unavailable"))
    monkeypatch.setattr(server, "_goddess_vault_root", lambda: tmp_path / "vault")

    result = server._goddess_report_status_local()

    assert result["state"] == "degraded"
    assert result["reporter_required"] is None
