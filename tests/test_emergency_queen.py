from __future__ import annotations

from unittest.mock import patch

from codex_master import server


def _requested_state() -> dict[str, object]:
    return {
        "state": "requested",
        "generation": 7,
        "queen_agent": None,
        "current_plan": "/tmp/approved.md",
        "plans": ["/tmp/approved.md"],
        "emergency_active": True,
        "reason": "test",
        "blocked_reason": None,
    }


def test_emergency_queen_does_not_promote_teamleader_q_series():
    blocked = {"state": {**_requested_state(), "state": "blocked"}}
    with patch.object(server, "emergency_queen_status", return_value=_requested_state()), \
         patch.object(server, "set_emergency_queen_blocked", return_value=blocked) as mark_blocked:
        result = server.ensure_emergency_queen()

    assert result["status"] == "blocked"
    assert result["error_code"] == "queen_spawn_unavailable"
    assert result["reason"] == "hive_queen_runtime_not_materialized"
    mark_blocked.assert_called_once_with(7, "queen_spawn_unavailable:hive_queen_runtime_not_materialized")


def test_emergency_queen_uses_explicit_runtime_target_only(monkeypatch):
    monkeypatch.setattr(server, "_emergency_queen_agent_candidates", lambda: ["queen-runtime-1"])
    running = {"state": {**_requested_state(), "state": "running", "queen_agent": "queen-runtime-1"}}
    with patch.object(server, "emergency_queen_status", return_value=_requested_state()), \
         patch.object(server, "start_agent_with_lease", return_value={"status": "started"}) as start, \
         patch.object(server, "set_emergency_queen_running", return_value=running) as mark_running, \
         patch.object(server, "repo_root", return_value="/tmp"):
        result = server.ensure_emergency_queen()

    assert result["status"] == "started"
    assert result["agent"] == "queen-runtime-1"
    start.assert_called_once()
    assert start.call_args.kwargs["agent_class"] == "koenigin"
    assert start.call_args.kwargs["lifecycle"] == "persistent"
    mark_running.assert_called_once_with(7, "queen-runtime-1")
