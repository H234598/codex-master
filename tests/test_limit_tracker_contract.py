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


def test_queen_candidates_only_returns_approved_plan_files(monkeypatch, tmp_path) -> None:
    plans = tmp_path / "Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!"
    plans.mkdir(parents=True)
    (plans / "approved.md").write_text("Status: approved", encoding="utf-8")
    (plans / "draft.md").write_text("Status: draft", encoding="utf-8")
    monkeypatch.setattr(limit_tracker.Path, "home", classmethod(lambda cls: tmp_path))

    assert limit_tracker._queen_candidates() == [str(plans / "approved.md")]


def test_emergency_recommendation_distinguishes_hot_and_recovered_windows() -> None:
    hot = {
        "five_hour_tracker": {"five_hour_windows_until_weekly_reset": 2},
        "weekly_monthly": [{"window": "weekly", "used_percent": 90, "deviation_from_limit_pp": 90}],
        "five_hour_projection": {"deviation_from_limit_pp": 20},
    }
    recovered = {
        "weekly_monthly": [{"window": "weekly", "deviation_from_limit_pp": -20}],
        "five_hour_projection": {"deviation_from_limit_pp": -20},
    }

    assert limit_tracker.emergency_recommendation(hot) == "activate"
    assert limit_tracker.emergency_recommendation(recovered, active_fast=True) == "flex"


def test_emergency_refresh_needed_only_spends_a_pull_for_fast_or_hot_weekly_state() -> None:
    hot = {
        "five_hour_tracker": {"five_hour_windows_until_weekly_reset": 5},
        "weekly_monthly": [{"window": "weekly", "used_percent": 80}],
    }

    assert limit_tracker.emergency_refresh_needed({}) is False
    assert limit_tracker.emergency_refresh_needed(hot) is True
    assert limit_tracker.emergency_refresh_needed({}, active_fast=True) is True


def test_refresh_usage_snapshots_runs_bounded_local_usage_command(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class Completed:
        returncode = 0

    def run(argv, **kwargs):
        calls.append({"argv": argv, **kwargs})
        return Completed()

    monkeypatch.setenv("CODEX_USAGE_COMMAND", "/mock/codex-usage")
    monkeypatch.setenv("CODEX_USAGE_CONFIG", "")
    monkeypatch.setattr(limit_tracker.subprocess, "run", run)

    assert limit_tracker.refresh_usage_snapshots() == {"attempted": True, "ok": True, "returncode": 0, "error": None}
    assert calls[0]["argv"] == ["/mock/codex-usage", "once", "--format", "json"]
    assert calls[0]["timeout"] == 120


def test_set_emergency_queen_blocked_persists_matching_generation_only(monkeypatch, tmp_path) -> None:
    state_root = tmp_path / "state"
    monkeypatch.setattr(limit_tracker, "STATE_ROOT", state_root)
    monkeypatch.setattr(limit_tracker, "EMERGENCY_QUEEN_STATE", state_root / "state.json")
    limit_tracker._write_state(
        limit_tracker.EMERGENCY_QUEEN_STATE,
        limit_tracker._queen_state_payload(
            state="running", generation=3, reason="test", plans=[], current_plan=None,
            emergency_active=True, queen_agent="queen",
        ),
    )

    assert limit_tracker.set_emergency_queen_blocked(2, "stale")["updated"] is False
    blocked = limit_tracker.set_emergency_queen_blocked(3, "waiting")
    assert blocked["updated"] is True
    assert blocked["state"]["state"] == "blocked"
    assert blocked["state"]["blocked_reason"] == "waiting"
