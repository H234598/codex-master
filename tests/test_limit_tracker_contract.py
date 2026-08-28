from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from codex_master import limit_tracker_contract as limit_tracker


def _timestamp(hours: float) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).isoformat()


def test_preferred_delta_window_uses_5h_then_weekly_then_monthly() -> None:
    assert limit_tracker.preferred_delta_window({"main": {"windows": [{"name": "5h"}]}}) == "short"
    assert limit_tracker.preferred_delta_window({"weekly": {"name": "weekly"}}) == "weekly"
    assert limit_tracker.preferred_delta_window({"monthly": {"name": "monthly"}}) == "monthly"


def test_spark_window_is_evaluated_separately(monkeypatch, tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    snapshot = {
        "account": "nufker",
        "weekly": {"name": "weekly", "used": 20, "reset_at": _timestamp(4), "duration_seconds": 604800},
        "models": {
            "gpt-5.3-codex-spark": {
                "windows": [{"name": "5h", "used": 95, "reset_at": _timestamp(1), "duration_seconds": 18000}]
            }
        },
    }
    (snapshot_dir / "nufker.json").write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setattr(limit_tracker, "SNAPSHOTS", snapshot_dir)
    monkeypatch.setattr(limit_tracker, "HISTORY_DB", tmp_path / "history.sqlite3")
    result = limit_tracker.evaluate_account("nufker")
    assert result["spark"]["available"] is True
    assert result["spark"]["windows"][0]["pool"] == "spark"
    assert result["five_hour_projection"]["available"] is False


def test_emergency_display_and_spark_priority_are_reversible(monkeypatch, tmp_path) -> None:
    state_root = tmp_path / "state"
    overrides = state_root / "overrides.json"
    priority = state_root / "priority.json"
    monkeypatch.setattr(limit_tracker, "STATE_ROOT", state_root)
    monkeypatch.setattr(limit_tracker, "CODEX_USAGE_EMERGENCY_OVERRIDES", overrides)
    monkeypatch.setattr(limit_tracker, "SPARK_PRIORITY_STATE", priority)
    limit_tracker.set_emergency_display_override("nufker", enabled=True, limit_window="spark")
    limit_tracker.set_spark_priority("nufker", enabled=True)
    assert json.loads(overrides.read_text())["nufker"]["delta_enabled"] is True
    assert limit_tracker.spark_priority_active("nufker") is True
    limit_tracker.set_emergency_display_override("nufker", enabled=False)
    limit_tracker.set_spark_priority("nufker", enabled=False)
    assert json.loads(overrides.read_text()) == {}
    assert limit_tracker.spark_priority_active("nufker") is False


def test_emergency_queen_request_is_idempotent_and_serial(monkeypatch, tmp_path) -> None:
    state_root = tmp_path / "state"
    request_file = state_root / "request.json"
    state_file = state_root / "state.json"
    monkeypatch.setattr(limit_tracker, "STATE_ROOT", state_root)
    monkeypatch.setattr(limit_tracker, "EMERGENCY_QUEEN_REQUEST", request_file)
    monkeypatch.setattr(limit_tracker, "EMERGENCY_QUEEN_STATE", state_file)
    monkeypatch.setattr(limit_tracker, "_queen_candidates", lambda: ["/tmp/approved-a.md", "/tmp/approved-b.md"])
    monkeypatch.setattr(limit_tracker.secrets, "choice", lambda values: values[0])

    first = limit_tracker.request_emergency_queen_work(reason="test")
    second = limit_tracker.request_emergency_queen_work(reason="duplicate")
    assert first["queued"] is True
    assert second["duplicate"] is True
    assert limit_tracker.emergency_queen_status()["state"] == "requested"

    running = limit_tracker.set_emergency_queen_running(first["state"]["generation"], "q1")
    assert running["state"]["state"] == "running"
    registered = limit_tracker.register_emergency_queen_child(first["state"]["generation"], "b1")
    assert registered["state"]["children"] == ["b1"]
    unregistered = limit_tracker.unregister_emergency_queen_child(first["state"]["generation"], "b1")
    assert unregistered["state"]["children"] == []
    advanced = limit_tracker.advance_emergency_queen(
        first["state"]["generation"], emergency_active=True, completed_plan="/tmp/approved-a.md"
    )
    assert advanced["state"]["state"] == "next"
    assert advanced["state"]["current_plan"] == "/tmp/approved-b.md"
    draining = limit_tracker.advance_emergency_queen(
        first["state"]["generation"], emergency_active=False, completed_plan="/tmp/approved-b.md"
    )
    assert draining["state"]["state"] == "draining"
    finished = limit_tracker.finish_emergency_queen(first["state"]["generation"])
    assert finished["state"]["state"] == "idle"
