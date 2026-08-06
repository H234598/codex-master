from __future__ import annotations

from pathlib import Path

from codex_master import server
from codex_master.fleet_registry import (
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    AgentDescriptor,
    AuthKind,
    InventorySnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    build_inventory,
)
from codex_master.fleet_service import AccountGateDecision


class FakeService:
    def __init__(self, snapshot: FleetSnapshot) -> None:
        self.snapshot = snapshot

    def load(self) -> FleetSnapshot:
        return self.snapshot

    def account_gate(self, agent: str, **_kwargs: object) -> AccountGateDecision:
        return AccountGateDecision(agent != "d1", "limit_active" if agent == "d1" else "ready", "project", 3)


def test_applet_snapshot_v3_is_series_bounded_and_filters_limited_targets(monkeypatch, tmp_path: Path) -> None:
    snapshot = FleetSnapshot(
        1, 3,
        (FleetAccount("project", "Project", Provider.GEMINI_API, AuthKind.API_KEY,
                      SecretState.CONFIGURED, LimitState.READY, True, None,
                      "2026-08-05T12:00:00+00:00", None),),
        tuple(FleetSeries(prefix, prefix.upper(), 1, RunnerKind.GEMINI_CLI,
                          Provider.GEMINI_API, "model", "project", True)
              for prefix in ("d", "e", "f")),
    )
    inventory = build_inventory(snapshot, tmp_path)
    monkeypatch.setattr(server, "published_agent_inventory", lambda: (inventory, True))
    monkeypatch.setattr(server, "_readonly_fleet_service", lambda: FakeService(snapshot))
    monkeypatch.setattr(server, "status_agent", lambda agent, **_kwargs: {
        "running": False, "limit_state": {"limited": agent == "d1"},
    })

    payload = server.applet_status(["d1", "e1", "f1"], schema_version=3)

    assert [row["prefix"] for row in payload["series"]] == ["d", "e", "f"]
    assert [row["polled_count"] for row in payload["series"]] == [1, 1, 1]
    assert "d1" not in payload["dispatch_targets"]
    assert "e1" in payload["dispatch_targets"]
    assert "f1" in payload["dispatch_targets"]
    assert set(payload) == {
        "schema_version",
        "generation",
        "fleet_snapshot_degraded",
        "watchdog_snapshot_degraded",
        "dispatch_targets",
        "series",
        "native_agents",
        "raw_output",
    }


def test_applet_snapshot_separates_legacy_native_agents(monkeypatch, tmp_path: Path) -> None:
    descriptor = AgentDescriptor(
        "a1", "a", 1, "Native A", RunnerKind.CODEX_CLI, Provider.OPENAI_CHATGPT,
        "primary", "legacy", tmp_path / "a1", "codex-a1", True,
    )
    inventory = InventorySnapshot(
        ("a1",), {"a1": descriptor}, {"a-series": ("a1",)}, {"a1": 0}, ("a",),
    )
    monkeypatch.setattr(server, "published_agent_inventory", lambda: (inventory, False))
    monkeypatch.setattr(
        server,
        "_readonly_fleet_service",
        lambda: (_ for _ in ()).throw(server.AgentError("fleet_registry_unavailable")),
    )
    monkeypatch.setattr(server, "status_agent", lambda agent, **_kwargs: {
        "running": False, "limit_state": {"state": "ready"},
    })

    payload = server.applet_status(["a1"], schema_version=3)

    assert payload["series"] == []
    assert payload["native_agents"] == [{
        "id": "a1", "label": "Native A", "running": False, "limit_state": "ready",
    }]
    assert payload["dispatch_targets"] == ["a1"]


def test_applet_snapshot_exposes_degraded_sources(monkeypatch, tmp_path: Path) -> None:
    descriptor = AgentDescriptor(
        "a1", "a", 1, "Native A", RunnerKind.CODEX_CLI, Provider.OPENAI_CHATGPT,
        "primary", "legacy", tmp_path / "a1", "codex-a1", True,
    )
    inventory = InventorySnapshot(
        ("a1",), {"a1": descriptor}, {"a-series": ("a1",)}, {"a1": 0}, ("a",),
    )
    monkeypatch.setattr(server, "published_agent_inventory", lambda: (inventory, False))
    monkeypatch.setattr(
        server,
        "_readonly_fleet_service",
        lambda: (_ for _ in ()).throw(ValueError("invalid fleet")),
    )
    monkeypatch.setattr(
        server,
        "create_fleet_snapshot",
        lambda **_: (_ for _ in ()).throw(OSError("proc unavailable")),
    )
    monkeypatch.setattr(server, "status_agent", lambda agent, **_kwargs: {
        "running": False, "limit_state": {"state": "ready"},
    })

    payload = server.applet_status([], schema_version=3)

    assert payload["fleet_snapshot_degraded"] is True
    assert payload["watchdog_snapshot_degraded"] is True


def test_applet_snapshot_chooses_earliest_valid_reset_instant(monkeypatch, tmp_path: Path) -> None:
    snapshot = FleetSnapshot(
        1, 3,
        (FleetAccount("project", "Project", Provider.GEMINI_API, AuthKind.API_KEY,
                      SecretState.CONFIGURED, LimitState.READY, True, None,
                      "2026-08-05T12:00:00+00:00", None),),
        (FleetSeries("d", "D", 2, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
                     "model", "project", True),),
    )
    inventory = build_inventory(snapshot, tmp_path)
    monkeypatch.setattr(server, "published_agent_inventory", lambda: (inventory, True))
    monkeypatch.setattr(server, "_readonly_fleet_service", lambda: FakeService(snapshot))
    resets = {
        "d1": "2026-08-05T12:00:00+02:00",
        "d2": "2026-08-05T09:30:00Z",
    }
    monkeypatch.setattr(server, "status_agent", lambda agent, **_kwargs: {
        "running": False,
        "limit_state": {"state": "limited", "limited": True, "blocked_until_utc": resets[agent]},
    })

    payload = server.applet_status(["d1", "d2"], schema_version=3)

    assert payload["series"][0]["blocked_until_utc"] == "2026-08-05T09:30:00Z"
