from __future__ import annotations

import json
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
from codex_master.resource_monitor import ResourceOperatorStatus


class FakeService:
    def __init__(self, snapshot: FleetSnapshot) -> None:
        self.snapshot = snapshot

    def load(self) -> FleetSnapshot:
        return self.snapshot

    def account_gate(self, agent: str, **_kwargs: object) -> AccountGateDecision:
        return AccountGateDecision(agent != "d1", "limit_active" if agent == "d1" else "ready", "project", 3)


def resource_operator_status() -> ResourceOperatorStatus:
    return ResourceOperatorStatus(
        schema_version=1,
        generation=41,
        state="blocked",
        bottleneck="thermal",
        current={"cpu": 12.0, "io": 8.0, "memory": 20.0},
        mean_1m={"cpu": 11.0, "io": 7.0, "memory": 19.0},
        mean_10m={"cpu": 10.0, "io": 6.0, "memory": 18.0},
        peak_10m={"cpu": 13.0, "io": 9.0, "memory": 21.0},
        trend={"cpu": "stable", "io": "rising", "memory": "falling"},
        confidence="high",
        preferred_profiles=("cpu_low",),
        avoid_profiles=("io_high",),
        reason_codes=("temperature_pressure_high",),
    )


def test_applet_status_v4_has_exact_resource_projection_and_one_generation(monkeypatch) -> None:
    base = {
        "schema_version": 2,
        "mode": "read_only",
        "counts": {"tracked": 0, "running": 0, "sleeping": 0, "overflow": 0},
        "agents": [],
        "native_agents": {
            "bridge_state": "ready",
            "counts": {"active": 0, "unconfirmed": 0, "overflow": 0},
            "agents": [],
            "truncated": False,
        },
        "raw_output": "not_returned",
    }
    reads = 0

    def read_status() -> ResourceOperatorStatus:
        nonlocal reads
        reads += 1
        return resource_operator_status()

    monkeypatch.setattr(server, "applet_status_v2", lambda _agents: dict(base))
    monkeypatch.setattr(server, "_read_resource_operator_status", read_status)

    payload = server.applet_status(["a1"], schema_version=4)

    assert reads == 1
    assert set(payload) == {*base, "resource"}
    assert payload["schema_version"] == 4
    assert payload["resource"] == {
        "schema_version": 1,
        "generation": 41,
        "state": "blocked",
        "bottleneck": "thermal",
        "trend": {"cpu": "stable", "io": "rising", "memory": "falling"},
        "confidence": "high",
        "preferred_profiles": ["cpu_low"],
        "avoid_profiles": ["io_high"],
        "raw_output": "not_returned",
    }


def test_applet_status_v1_to_v3_remain_byte_contract_compatible(monkeypatch) -> None:
    row = {
        "agent": "a1",
        "activity_state": "sleeping",
        "backend_state": "ok",
        "control_state": "ready",
        "auth_state": "ready",
        "identity_state": "stopped",
        "lease_state": "unclaimed",
    }
    monkeypatch.setattr(server, "applet_agent_observation", lambda *_args, **_kwargs: dict(row))
    monkeypatch.setattr(
        server,
        "managed_applet_inventory",
        lambda: {"running_agents": [], "overflow": 0, "visible_running_agents": []},
    )
    monkeypatch.setattr(
        server,
        "native_agent_status",
        lambda **_kwargs: {
            "bridge_state": "ready",
            "counts": {"active": 0, "unconfirmed": 0, "overflow": 0},
            "agents": [],
            "truncated": False,
        },
    )
    monkeypatch.setattr(
        server,
        "published_agent_inventory",
        lambda: (InventorySnapshot((), {}, {}, {}, ()), False),
    )
    monkeypatch.setattr(
        server,
        "_readonly_fleet_service",
        lambda: (_ for _ in ()).throw(server.AgentError("fleet_registry_unavailable")),
    )
    monkeypatch.setattr(server, "create_fleet_snapshot", lambda **_kwargs: object())
    monkeypatch.setattr(
        server,
        "_read_resource_operator_status",
        lambda: (_ for _ in ()).throw(AssertionError("v1-v3 must not read resources")),
        raising=False,
    )

    payloads = [
        server.applet_status(["a1"], schema_version=1),
        server.applet_status([], schema_version=2),
        server.applet_status([], schema_version=3),
    ]

    assert [json.dumps(payload, sort_keys=True, separators=(",", ":")) for payload in payloads] == [
        (
            '{"activity_state":"sleeping","agents":[{"activity_state":"sleeping",'
            '"agent":"a1","auth_state":"ready","backend_state":"ok","control_state":"ready",'
            '"identity_state":"stopped","lease_state":"unclaimed"}],"backend_state":"ok",'
            '"control_state":"ready","counts":{"blocked":0,"issues":0,"ready":1,"running":0,'
            '"sleeping":1,"tracked":1},"mode":"read_only","raw_output":"not_returned","schema_version":1}'
        ),
        (
            '{"agents":[],"counts":{"overflow":0,"running":0,"sleeping":0,"tracked":0},'
            '"mode":"read_only","native_agents":{"agents":[],"bridge_state":"ready",'
            '"counts":{"active":0,"overflow":0,"unconfirmed":0},"truncated":false},'
            '"raw_output":"not_returned","schema_version":2}'
        ),
        (
            '{"dispatch_targets":[],"fleet_snapshot_degraded":true,"generation":0,'
            '"native_agents":[],"raw_output":"not_returned","schema_version":3,'
            '"series":[],"watchdog_snapshot_degraded":false}'
        ),
    ]


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
