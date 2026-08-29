from __future__ import annotations

import io
import hashlib
import json
import signal
import subprocess
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_master import server
from codex_master.fleet_registry import (
    AgentDescriptor,
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    build_inventory,
)
from codex_master.fleet_service import AccountGateDecision, FleetSecretError, GeminiGateDecision


class RecordingInput(io.BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.closed_value = b""

    def close(self) -> None:
        self.closed_value = self.getvalue()
        super().close()


class CompletedProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"") -> None:
        self.pid = 81235
        self.stdin = RecordingInput()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.env: dict[str, str] | None = None

    def poll(self) -> int:
        return 0

    def wait(self) -> int:
        return 0


@dataclass
class FakeService:
    snapshot: FleetSnapshot
    secret: str = "private-secret"
    gate_code: str = "gemini_ready"
    usage_records: list[dict[str, object]] = field(default_factory=list)
    event_records: list[dict[str, object]] = field(default_factory=list)
    reservations: list[object] = field(default_factory=list)
    releases: list[dict[str, object]] = field(default_factory=list)

    def account_gate(self, _agent: str) -> AccountGateDecision:
        return AccountGateDecision(True, "ready", "gemini-project", self.snapshot.generation)

    def gemini_headless_gate(self, _agent: str) -> GeminiGateDecision:
        reason = (
            "Gemini dashboard limits are unknown; only observed counters are available."
            if self.gate_code == "gemini_limits_unknown"
            else "Gemini request admitted."
        )
        return GeminiGateDecision(
            "allow", self.gate_code, reason, "info", False,
            "gemini-project", "gemini-3-flash-preview",
        )

    def load(self) -> FleetSnapshot:
        return self.snapshot

    def read_secret(self, _account_id: str, *, expected_generation: int) -> str:
        assert expected_generation == self.snapshot.generation
        return self.secret

    def mark_limited(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("limit marking was not expected")

    def reserve_gemini_request(self, account_id: str, *, model: str | None = None) -> object:
        reservation = (account_id, model, "reservation")
        self.reservations.append(reservation)
        return reservation

    def release_gemini_request(self, reservation: object, **kwargs: object) -> None:
        self.releases.append({"reservation": reservation, **kwargs})

    def record_gemini_usage(self, account_id: str, **kwargs: object) -> None:
        self.usage_records.append({"account_id": account_id, **kwargs})

    def record_gemini_event(self, **kwargs: object) -> None:
        self.event_records.append(dict(kwargs))


def _snapshot(tmp_path: Path) -> FleetSnapshot:
    account = FleetAccount(
        "gemini-project", "Gemini project", Provider.GEMINI_API, AuthKind.API_KEY,
        SecretState.CONFIGURED, LimitState.READY, True,
        None, "2026-08-05T12:00:00+00:00", None,
    )
    series = FleetSeries(
        "d", "Gemini", 1, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", True,
    )
    return FleetSnapshot(1, 4, (account,), (series,))


def test_headless_assignment_keeps_prompt_and_secret_out_of_argv_and_metadata(
    tmp_path: Path, monkeypatch,
) -> None:
    snapshot = _snapshot(tmp_path)
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", tmp_path / "d1",
        "codex_agent_d1_mcp", True, executable,
    )
    inventory = build_inventory(snapshot, tmp_path)
    inventory = type(inventory)(
        inventory.agent_ids, {"d1": descriptor}, inventory.by_series,
        inventory.positions, inventory.series_prefixes,
    )
    fake_service = FakeService(snapshot, gate_code="gemini_limits_unknown")
    process = CompletedProcess(
        b'{"type":"message","role":"assistant","content":"answer"}\n'
        b'{"type":"result","stats":{"input_tokens":2,"output_tokens":3}}\n',
    )
    captured_env: dict[str, str] = {}

    def launch(*_args: object, **kwargs: object) -> CompletedProcess:
        captured_env.update(kwargs["env"])  # type: ignore[arg-type]
        return process

    popen = Mock(side_effect=launch)
    metadata: dict[str, object] = {
        "headless_job": {"state": "ready", "agent": "d1"},
    }

    monkeypatch.setattr(server, "current_agent_inventory", lambda: inventory)
    monkeypatch.setattr(server, "current_fleet_service", lambda: fake_service)
    monkeypatch.setattr(server, "read_meta", lambda _agent: dict(metadata))
    monkeypatch.setattr(server, "write_meta", lambda _agent, value: metadata.update(value))
    monkeypatch.setattr(server, "subprocess", type("Subprocess", (), {"Popen": popen, "PIPE": object()}))
    monkeypatch.setattr(server, "release_agent", Mock())

    result = server.run_headless_assignment(
        "d1", "private prompt", {"state": "held", "held_by_this_server": True}, 5,
    )

    argv = popen.call_args.args[0]
    assert "private prompt" not in argv
    assert "-p" not in argv
    assert "--approval-mode=auto_edit" in argv
    assert popen.call_args.kwargs["cwd"] == tmp_path / "d1"
    assert process.stdin.closed_value == b"private prompt"
    assert result["response"] == "answer"
    assert result["status"] == "completed"
    assert captured_env["GEMINI_API_KEY"] == "private-secret"
    assert captured_env["HOME"] == str(tmp_path / "d1")
    assert metadata["headless_job"]["state"] == "completed"  # type: ignore[index]
    assert "private prompt" not in repr(metadata)
    assert "private-secret" not in repr(metadata)
    assert fake_service.usage_records[-1]["gate_action"] == "allow"
    assert fake_service.usage_records[-1]["gate_code"] == "gemini_limits_unknown"
    assert fake_service.event_records[-1]["gate_action"] == "allow"
    assert fake_service.event_records[-1]["gate_code"] == "gemini_limits_unknown"


def test_headless_exception_preserves_unknown_allow_gate_in_ledgers(
    tmp_path: Path, monkeypatch,
) -> None:
    snapshot = _snapshot(tmp_path)
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", tmp_path / "d1",
        "codex_agent_d1_mcp", True, executable,
    )
    inventory = build_inventory(snapshot, tmp_path)
    inventory = type(inventory)(
        inventory.agent_ids, {"d1": descriptor}, inventory.by_series,
        inventory.positions, inventory.series_prefixes,
    )
    fake_service = FakeService(snapshot, gate_code="gemini_limits_unknown")
    monkeypatch.setattr(
        fake_service,
        "read_secret",
        Mock(side_effect=FleetSecretError("credential unavailable")),
    )
    metadata: dict[str, object] = {"headless_job": {"state": "ready", "agent": "d1"}}

    monkeypatch.setattr(server, "current_agent_inventory", lambda: inventory)
    monkeypatch.setattr(server, "current_fleet_service", lambda: fake_service)
    monkeypatch.setattr(server, "read_meta", lambda _agent: dict(metadata))
    monkeypatch.setattr(server, "write_meta", lambda _agent, value: metadata.update(value))
    monkeypatch.setattr(server, "release_agent", Mock())

    with pytest.raises(FleetSecretError, match="credential unavailable"):
        server.run_headless_assignment(
            "d1", "private prompt", {"state": "held", "held_by_this_server": True}, 5,
        )

    assert fake_service.usage_records[-1]["gate_action"] == "allow"
    assert fake_service.usage_records[-1]["gate_code"] == "gemini_limits_unknown"
    assert fake_service.event_records[-1]["gate_action"] == "allow"
    assert fake_service.event_records[-1]["gate_code"] == "gemini_limits_unknown"


def test_headless_start_only_reserves_a_ready_slot(monkeypatch) -> None:
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", Path("/tmp/d1"),
        "codex_agent_d1_mcp", True, Path("/tmp/gemini"),
    )
    inventory = type("Inventory", (), {"agents": {"d1": descriptor}})()
    service = Mock()
    service.account_gate.return_value = AccountGateDecision(True, "ready", "gemini-project", 9)
    service.gemini_headless_gate.return_value = GeminiGateDecision(
        "allow", "gemini_ready", "Gemini request admitted.", "info", False,
        "gemini-project", "gemini-3-flash-preview",
    )
    marker: dict[str, object] = {}
    monkeypatch.setattr(server, "current_agent_inventory", lambda: inventory)
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, value: marker.update(value))
    monkeypatch.setattr(server, "_headless_public_gate", lambda _agent: {"allowed": True, "reason": "ready"})
    monkeypatch.setattr(server, "agent_lease_status", lambda _agent: {"state": "free"})

    result = server._start_headless_agent_unlocked("d1")

    assert result["status"] == "ready"
    assert result["backend"] == "headless_job"
    assert result["gate"]["action"] == "allow"
    assert marker["state"] == "ready"


def test_headless_start_routes_gemini_rotation_to_selected_slot(monkeypatch) -> None:
    descriptors = {
        "d1": AgentDescriptor(
            "d1", "d", 1, "Gemini D1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "gemini-3-flash", "gemini-project-1", Path("/tmp/d1"),
            "codex_agent_d1_mcp", True, Path("/tmp/gemini"),
        ),
        "e1": AgentDescriptor(
            "e1", "e", 1, "Gemini E1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "gemini-3.1-flash-lite", "gemini-project-2", Path("/tmp/e1"),
            "codex_agent_e1_mcp", True, Path("/tmp/gemini"),
        ),
    }
    markers: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "_headless_descriptor", descriptors.get)
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda agent: (
            {
                "action": "rotate_account",
                "diagnostic_code": "gemini_rpm_exhausted",
                "target_agent_id": "e1",
                "raw_output": "not_returned",
            }
            if agent == "d1"
            else {
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project-2",
                "raw_output": "not_returned",
            }
        ),
    )
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: AccountGateDecision(True, "ready", "gemini-project-2", 9),
    )
    monkeypatch.setattr(server.HEADLESS_JOBS, "status", lambda _agent: {"status": "not_running"})
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(
        server,
        "_write_headless_marker",
        lambda agent, marker: markers.append((agent, dict(marker))),
    )
    monkeypatch.setattr(server, "agent_lease_status", lambda _agent: {"state": "free"})
    monkeypatch.setattr(server, "_headless_public_gate", lambda _agent: {"allowed": True})

    result = server._start_headless_agent_unlocked("d1")

    assert markers[0][0] == "e1"
    assert result["agent"] == "e1"
    assert result["requested_agent"] == "d1"
    assert result["selected_agent"] == "e1"
    assert result["gate"]["diagnostic_code"] == "gemini_limits_unknown"
    assert result["routing_gate"]["action"] == "rotate_account"

    monkeypatch.setattr(server.HEADLESS_JOBS, "status", lambda _agent: {"status": "running"})
    already_running = server._start_headless_agent_unlocked("d1")

    assert already_running["requested_agent"] == "d1"
    assert already_running["selected_agent"] == "e1"
    assert already_running["gate"]["diagnostic_code"] == "gemini_limits_unknown"
    assert already_running["routing_gate"]["action"] == "rotate_account"


def test_headless_assignment_rejects_invalid_timeout_before_claim(monkeypatch) -> None:
    claim = Mock()
    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: object())
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)

    with pytest.raises(server.AgentError, match="headless_timeout_invalid"):
        server._assign_headless_agent(
            "d1",
            role="exploriererin",
            task="inspect",
            scope=[],
            timeout_seconds=0,
        )

    claim.assert_not_called()


@pytest.mark.parametrize(("action", "status"), [
    ("defer_until", "deferred"),
    ("reject", "failed"),
])
def test_headless_assignment_returns_blocking_gate_before_claim_or_process(
    monkeypatch, action: str, status: str,
) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    claim = Mock()
    run = Mock()
    gate = {
        "action": action,
        "diagnostic_code": "gemini_local_rate_limited",
        "defer_until": "2026-08-03T12:10:00Z",
        "reason": "Gemini local request rate limit active.",
        "raw_output": "not_returned",
    }

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(server, "_gemini_headless_gate", lambda *_args: gate)
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)
    monkeypatch.setattr(server, "_run_headless_process", run)

    result = server._assign_headless_agent(
        "d1",
        role="exploriererin",
        task="inspect",
        scope=[],
        timeout_seconds=5,
    )

    assert result["status"] == status
    assert result["gate"] == gate
    claim.assert_not_called()
    run.assert_not_called()


def test_p1w1_headless_session_admission_denies_before_rate_reservation_or_claim(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    events: list[str] = []
    marker = Mock()
    claim = Mock(return_value={"status": "already_held", "lease": {"state": "held", "held_by_this_server": True}})
    record = Mock()
    run = Mock()
    service = Mock()
    reserve_headless_inflight = Mock()

    def acquire_admission_lock() -> object:
        events.append("admission_lock")
        return nullcontext()

    def deny_session_admission(*_args: object, **_kwargs: object) -> dict[str, object]:
        events.append("admission")
        raise server.AgentCapacityError(
            "capacity unavailable",
            {
                "error_code": "spawn_capacity_unavailable",
                "retryable": True,
                "retry_after_seconds": 1.0,
                "reason_codes": ["session_metrics_unavailable"],
                "errors": [],
            },
        )

    monkeypatch.setattr(server, "require_spawn_capacity", deny_session_admission)
    monkeypatch.setattr(server, "spawn_admission_lock", acquire_admission_lock)
    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_gemini_headless_gate", lambda *_args: {
        "action": "allow",
        "diagnostic_code": "gemini_limits_unknown",
        "account_id": "gemini-project",
        "raw_output": "not_returned",
    })
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)
    monkeypatch.setattr(server, "reserve_headless_inflight", reserve_headless_inflight)
    monkeypatch.setattr(server, "record_assignment", record)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: marker(_agent, _marker))
    monkeypatch.setattr(server, "_run_headless_process", run)

    with pytest.raises(server.AgentCapacityError, match="capacity unavailable"):
        server._assign_headless_agent(
            "d1",
            role="exploriererin",
            task="inspect",
            scope=[],
            timeout_seconds=5,
            allow_subagents=False,
        )

    assert events == ["admission_lock", "admission"]
    reserve_headless_inflight.assert_not_called()
    service.reserve_gemini_request.assert_not_called()
    claim.assert_not_called()
    record.assert_not_called()
    marker.assert_not_called()
    run.assert_not_called()


def test_p1w1_headless_cgroup_preflight_denies_before_rate_reservation_or_claim(
    monkeypatch,
) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    events: list[str] = []
    marker = Mock()
    claim = Mock(return_value={"status": "already_held", "lease": {"state": "held", "held_by_this_server": True}})
    record = Mock()
    run = Mock()
    service = Mock()
    reserve_headless_inflight = Mock()

    def acquire_admission_lock() -> object:
        events.append("admission_lock")
        return nullcontext()

    def deny_cgroup_preflight(*_args: object, **_kwargs: object) -> dict[str, object]:
        events.append("admission")
        raise server.AgentCapacityError(
            "capacity unavailable",
            {
                "error_code": "spawn_capacity_unavailable",
                "retryable": True,
                "retry_after_seconds": 1.0,
                "reason_codes": ["cgroup_preflight_failed"],
                "errors": [],
            },
        )

    monkeypatch.setattr(server, "require_spawn_capacity", deny_cgroup_preflight)
    monkeypatch.setattr(server, "spawn_admission_lock", acquire_admission_lock)
    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_gemini_headless_gate", lambda *_args: {
        "action": "allow",
        "diagnostic_code": "gemini_limits_unknown",
        "account_id": "gemini-project",
        "raw_output": "not_returned",
    })
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)
    monkeypatch.setattr(server, "reserve_headless_inflight", reserve_headless_inflight)
    monkeypatch.setattr(server, "record_assignment", record)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: marker(_agent, _marker))
    monkeypatch.setattr(server, "_run_headless_process", run)

    with pytest.raises(server.AgentCapacityError, match="capacity unavailable"):
        server._assign_headless_agent(
            "d1",
            role="exploriererin",
            task="inspect",
            scope=[],
            timeout_seconds=5,
            allow_subagents=False,
        )

    assert events == ["admission_lock", "admission"]
    reserve_headless_inflight.assert_not_called()
    service.reserve_gemini_request.assert_not_called()
    claim.assert_not_called()
    record.assert_not_called()
    marker.assert_not_called()
    run.assert_not_called()


def test_headless_assignment_routes_gemini_rotation_before_claim(monkeypatch) -> None:
    descriptors = {
        "d1": AgentDescriptor(
            "d1", "d", 1, "Gemini D1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "gemini-3-flash", "gemini-project-1", Path("/tmp/d1"),
            "codex_agent_d1_mcp", True, Path("/tmp/gemini"),
        ),
        "e1": AgentDescriptor(
            "e1", "e", 1, "Gemini E1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "gemini-3.1-flash-lite", "gemini-project-2", Path("/tmp/e1"),
            "codex_agent_e1_mcp", True, Path("/tmp/gemini"),
        ),
    }
    prompts: list[dict[str, object]] = []
    order: list[str] = []
    run = Mock(return_value={"agent": "e1", "status": "completed"})
    reservation = {"reservation_id": "headless-rotation"}
    service = Mock()

    def gate(agent: str) -> dict[str, object]:
        order.append(f"gate:{agent}")
        if agent == "d1":
            return {
                "action": "rotate_account",
                "diagnostic_code": "gemini_rpm_exhausted",
                "target_agent_id": "e1",
                "raw_output": "not_returned",
            }
        return {
            "action": "allow",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project-2",
            "raw_output": "not_returned",
        }

    def reserve_headless_inflight_call(_agent: str, _assignment_id: str) -> dict[str, object]:
        order.append("inflight")
        return reservation

    def acquire_admission_lock() -> object:
        return nullcontext()

    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "_headless_descriptor", descriptors.get)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", lambda **kwargs: prompts.append(kwargs) or "prompt")
    monkeypatch.setattr(server, "_gemini_headless_gate", gate)
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", acquire_admission_lock)
    monkeypatch.setattr(server, "reserve_headless_inflight", reserve_headless_inflight_call)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(
        server,
        "_claim_agent_unlocked",
        lambda agent: order.append(f"claim:{agent}") or {
            "status": "already_held",
            "lease": {"state": "held", "held_by_this_server": True},
        },
    )
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: None)
    monkeypatch.setattr(server, "_run_headless_process", run)

    result = server._assign_headless_agent(
        "d1", role="exploriererin", task="inspect", scope=[], timeout_seconds=5,
    )

    assert order == ["gate:d1", "gate:e1", "inflight", "claim:e1"]
    assert run.call_args.args[0] == "e1"
    assert run.call_args.kwargs["headless_inflight_reservation"] is reservation
    assert prompts[0]["agent"] == "e1"
    assert prompts[0]["model"] == "gemini-3.1-flash-lite"
    assert result["agent"] == "e1"
    assert result["requested_agent"] == "d1"
    assert result["selected_agent"] == "e1"
    assert result["routed_from"] == "d1"
    assert result["gate"]["diagnostic_code"] == "gemini_limits_unknown"
    assert result["routing_gate"]["action"] == "rotate_account"


def test_headless_assignment_releases_preclaim_reservation_when_claim_fails(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    reservation = {"reservation_id": "headless-inflight-claim"}
    order: list[str] = []
    service = Mock()
    release_calls: list[tuple[object, str, str]] = []

    def reserve_headless_inflight_call(_agent: str, _assignment_id: str) -> dict[str, object]:
        order.append("inflight")
        return reservation

    def release_headless_inflight_call(
        reservation_id: object,
        agent: str,
        assignment_id: str,
    ) -> None:
        release_calls.append((reservation_id, agent, assignment_id))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "prompt")
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda _agent: {
            "action": "allow",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", reserve_headless_inflight_call)
    monkeypatch.setattr(server, "release_headless_inflight", release_headless_inflight_call)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())

    def fail_claim(agent: str) -> dict[str, object]:
        order.append(f"claim:{agent}")
        raise server.AgentError("claim_failed")

    monkeypatch.setattr(server, "_claim_agent_unlocked", fail_claim)

    with pytest.raises(server.AgentError, match="claim_failed"):
        server._assign_headless_agent(
            "d1", role="exploriererin", task="inspect", scope=[], timeout_seconds=5,
        )

    assert order == ["inflight", "claim:d1"]
    assert len(release_calls) == 1
    assert release_calls[0][0] == "headless-inflight-claim"
    assert release_calls[0][1] == "d1"
    assert isinstance(release_calls[0][2], str)
    service.reserve_gemini_request.assert_not_called()
    service.release_gemini_request.assert_not_called()


def test_headless_process_releases_preclaim_reservation_when_start_fails(
    tmp_path: Path, monkeypatch,
) -> None:
    snapshot = _snapshot(tmp_path)
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", tmp_path / "d1",
        "codex_agent_d1_mcp", True, executable,
    )
    inventory = build_inventory(snapshot, tmp_path)
    inventory = type(inventory)(
        inventory.agent_ids, {"d1": descriptor}, inventory.by_series,
        inventory.positions, inventory.series_prefixes,
    )
    fake_service = FakeService(snapshot, gate_code="gemini_limits_unknown")
    reservation = ("gemini-project", "preclaim-reservation")
    metadata: dict[str, object] = {"headless_job": {"state": "ready", "agent": "d1"}}

    monkeypatch.setattr(server, "current_agent_inventory", lambda: inventory)
    monkeypatch.setattr(server, "current_fleet_service", lambda: fake_service)
    monkeypatch.setattr(server, "read_meta", lambda _agent: dict(metadata))
    monkeypatch.setattr(server, "write_meta", lambda _agent, value: metadata.update(value))
    monkeypatch.setattr(
        server,
        "subprocess",
        type("Subprocess", (), {"Popen": Mock(side_effect=OSError("start failed")), "PIPE": object()}),
    )
    monkeypatch.setattr(server, "release_agent", Mock())

    with pytest.raises(server.AgentError, match="headless_start_failed"):
        server._run_headless_process(
            "d1",
            "private prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            reservation=reservation,
            structured_gate=fake_service.gemini_headless_gate("d1").public(),
        )

    assert fake_service.releases == [{
        "reservation": reservation,
        "outcome": "provider_error",
        "reset_at_utc": None,
    }]


def test_headless_process_releases_preclaim_reservation_on_prestart_validation_error(
    tmp_path: Path, monkeypatch,
) -> None:
    snapshot = _snapshot(tmp_path)
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", tmp_path / "d1",
        "codex_agent_d1_mcp", True, tmp_path / "gemini",
    )
    fake_service = FakeService(snapshot, gate_code="gemini_limits_unknown")
    reservation = ("gemini-project", "preclaim-reservation")
    release_agent = Mock()

    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "current_fleet_service", lambda: fake_service)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {"state": "failed"})
    monkeypatch.setattr(server, "release_agent", release_agent)

    with pytest.raises(server.AgentError, match="headless_slot_not_ready"):
        server._run_headless_process(
            "d1",
            "private prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            reservation=reservation,
            structured_gate=fake_service.gemini_headless_gate("d1").public(),
        )

    assert fake_service.releases == [{
        "reservation": reservation,
        "outcome": "provider_error",
    }]
    release_agent.assert_called_once_with("d1", force=True)


def test_headless_assignment_rejects_rotation_from_gemini_to_openai_before_claim(monkeypatch) -> None:
    descriptors = {
        "d1": AgentDescriptor(
            "d1", "d", 1, "Gemini D1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
            "gemini-3-flash", "gemini-project", Path("/tmp/d1"),
            "codex_agent_d1_mcp", True, Path("/tmp/gemini"),
        ),
        "o1": AgentDescriptor(
            "o1", "o", 1, "OpenAI O1", RunnerKind.CODEX_CLI, Provider.OPENAI_API,
            "gpt-5", "openai-project", Path("/tmp/o1"),
            "codex_agent_o1_mcp", True, Path("/tmp/codex"),
        ),
    }
    claim = Mock()

    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "_headless_descriptor", descriptors.get)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "prompt")
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda _agent: {
            "action": "rotate_account",
            "diagnostic_code": "gemini_rpm_exhausted",
            "target_agent_id": "o1",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)

    with pytest.raises(server.AgentError, match="headless_rotation_target_invalid"):
        server._assign_headless_agent(
            "d1", role="exploriererin", task="inspect", scope=[], timeout_seconds=5,
        )

    claim.assert_not_called()


def test_headless_assignment_rejects_context_over_budget_before_gate_or_claim(monkeypatch) -> None:
    descriptor = type("Descriptor", (), {"model": "gemini-3-flash-preview"})()
    claim = Mock()
    gate = Mock()
    prompt = Mock(return_value="bounded assignment prompt")

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "assignment_prompt", prompt)
    monkeypatch.setattr(server, "_gemini_headless_gate", gate)
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)

    with pytest.raises(server.AgentError, match="headless_context_budget_exceeded"):
        server._assign_headless_agent(
            "d1",
            role="exploriererin",
            task="t" * 3_000,
            scope=[],
            context=["x" * 600, "y" * 401],
            timeout_seconds=5,
        )

    gate.assert_not_called()
    prompt.assert_not_called()
    claim.assert_not_called()


def test_headless_assignment_allows_task_and_context_at_exact_budget(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    reservation = {"reservation_id": "headless-inflight-budget"}
    prompt = Mock(return_value="bounded assignment prompt")
    service = Mock()

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", prompt)
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda _agent: {
            "action": "allow",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args, **_kwargs: reservation)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", lambda _agent: {
        "status": "already_held",
        "lease": {"state": "held", "held_by_this_server": True},
    })
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: None)
    monkeypatch.setattr(server, "_run_headless_process", lambda *_args, **_kwargs: {"status": "completed"})

    result = server._assign_headless_agent(
        "d1",
        role="exploriererin",
        task="t" * 3_000,
        scope=[],
        context=["x" * 600, "y" * 400],
        timeout_seconds=5,
    )

    assert result["status"] == "completed"
    prompt.assert_called_once()


def test_headless_assignment_passes_subagent_admission_to_prompt(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    captured: dict[str, object] = {}
    reservation = {"reservation_id": "headless-inflight-subagent"}

    def fake_prompt(**kwargs: object) -> str:
        captured.update(kwargs)
        return "bounded assignment prompt"

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "assignment_prompt", fake_prompt)
    monkeypatch.setattr(server, "current_fleet_service", lambda: FakeService(_snapshot(Path("/tmp"))))
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args, **_kwargs: reservation)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", lambda _agent: {
        "status": "already_held",
        "lease": {"held_by_this_server": True},
    })
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: None)
    monkeypatch.setattr(server, "_run_headless_process", lambda *_args, **_kwargs: {"status": "completed"})

    result = server._assign_headless_agent(
        "d1",
        role="exploriererin",
        task="inspect",
        scope=[],
        timeout_seconds=5,
    )

    assert result["status"] == "completed"
    assert captured["subagent_admission"] is None


def test_p1w1_headless_calls_central_admission_before_rate_reservation(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    events: list[str] = []
    service = Mock()
    headless_inflight_reservation = object()
    captured_headless_inflight: dict[str, object | None] = {}

    def run_with_booking(
        _agent: str,
        _prompt: str,
        _lease: dict[str, object],
        _timeout_seconds: float,
        *,
        headless_inflight_reservation: object | None = None,
        **_kwargs: object,
    ) -> dict[str, object]:
        captured_headless_inflight["value"] = headless_inflight_reservation
        service.reserve_gemini_request("gemini-project", model="gemini-3-flash-preview")
        return {"agent": "d1", "status": "completed"}

    def reserve_headless_inflight_call(*_args: object, **_kwargs: object) -> object:
        events.append("inflight")
        return headless_inflight_reservation

    def acquire_admission_lock() -> object:
        events.append("admission_lock")
        return nullcontext()

    service.reserve_gemini_request.side_effect = (
        lambda account_id, *, model=None: events.append(f"reserve:{account_id}:{model}") or object()
    )

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(server, "_gemini_headless_gate", lambda *_args: {
        "action": "allow",
        "diagnostic_code": "gemini_limits_unknown",
        "account_id": "gemini-project",
        "raw_output": "not_returned",
    })
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: events.append("admission") or {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", acquire_admission_lock)
    monkeypatch.setattr(server, "reserve_headless_inflight", reserve_headless_inflight_call)
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", lambda _agent: {
        "status": "already_held",
        "lease": {"state": "held", "held_by_this_server": True},
    })
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: None)
    monkeypatch.setattr(server, "_run_headless_process", run_with_booking)

    result = server._assign_headless_agent(
        "d1",
        role="exploriererin",
        task="inspect",
        scope=[],
        timeout_seconds=5,
        allow_subagents=False,
    )

    assert result["status"] == "completed"
    assert events == ["admission_lock", "admission", "inflight", "reserve:gemini-project:gemini-3-flash-preview"]
    assert captured_headless_inflight["value"] is headless_inflight_reservation


def test_s5a_headless_assignment_releases_inflight_when_claim_fails_before_runner(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    release_calls: list[tuple[object, str, str]] = []

    def release_headless_inflight_call(
        reservation_id: object,
        agent: str,
        assignment_id: str,
    ) -> None:
        release_calls.append((reservation_id, agent, assignment_id))

    marker = Mock()
    write_marker = Mock()
    run_headless_process = Mock()

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda *_args: {
            "action": "allow",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(server, "require_spawn_capacity", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args, **_kwargs: {"reservation_id": "inflight-claim"})
    monkeypatch.setattr(server, "release_headless_inflight", release_headless_inflight_call)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", Mock(side_effect=server.AgentError("claim failed")))
    monkeypatch.setattr(server, "record_assignment", Mock())
    monkeypatch.setattr(server, "_headless_marker", marker)
    monkeypatch.setattr(server, "_write_headless_marker", write_marker)
    monkeypatch.setattr(server, "_run_headless_process", run_headless_process)

    with pytest.raises(server.AgentError, match="claim failed"):
        server._assign_headless_agent(
            "d1",
            role="exploriererin",
            task="inspect",
            scope=[],
            timeout_seconds=5,
        )

    assert len(release_calls) == 1
    assert release_calls[0][0] == "inflight-claim"
    assert release_calls[0][1] == "d1"
    assert isinstance(release_calls[0][2], str)
    marker.assert_not_called()
    write_marker.assert_not_called()
    run_headless_process.assert_not_called()


def test_s5a_headless_assignment_releases_inflight_when_record_or_marker_fails_before_runner(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()

    def run_assignment(*, record_fails: bool, marker_fails: bool) -> None:
        release_calls: list[tuple[object, str, str]] = []

        def release_headless_inflight_call(
            reservation_id: object,
            agent: str,
            assignment_id: str,
        ) -> None:
            release_calls.append((reservation_id, agent, assignment_id))

        record = Mock(
            side_effect=server.AgentError("record failed")
        ) if record_fails else Mock()
        write_marker = Mock(side_effect=server.AgentError("marker failed")) if marker_fails else Mock()

        marker = Mock(return_value={})
        run_headless_process = Mock()

        monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
        monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
        monkeypatch.setattr(
            server,
            "_gemini_headless_gate",
            lambda *_args: {
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
        )
        monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
        monkeypatch.setattr(server, "require_spawn_capacity", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
        monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args, **_kwargs: {"reservation_id": "inflight-record-or-marker"})
        monkeypatch.setattr(server, "release_headless_inflight", release_headless_inflight_call)
        monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
        monkeypatch.setattr(server, "_claim_agent_unlocked", lambda _agent: {
            "status": "already_held",
            "lease": {"state": "held", "held_by_this_server": True},
        })
        monkeypatch.setattr(server, "record_assignment", record)
        monkeypatch.setattr(server, "_headless_marker", marker)
        monkeypatch.setattr(server, "_write_headless_marker", write_marker)
        monkeypatch.setattr(server, "_run_headless_process", run_headless_process)

        with pytest.raises(server.AgentError, match="failed"):
            server._assign_headless_agent(
                "d1",
                role="exploriererin",
                task="inspect",
                scope=[],
                timeout_seconds=5,
            )

        assert len(release_calls) == 1
        assert release_calls[0][0] == "inflight-record-or-marker"
        assert release_calls[0][1] == "d1"
        assert isinstance(release_calls[0][2], str)
        run_headless_process.assert_not_called()
        if record_fails:
            record.assert_called_once()
            write_marker.assert_not_called()
            marker.assert_not_called()
        else:
            record.assert_called_once()
            write_marker.assert_called_once()
            marker.assert_called_once()

    run_assignment(record_fails=True, marker_fails=False)
    run_assignment(record_fails=False, marker_fails=True)


def test_s5b_headless_runner_releases_bound_inflight_on_gate_and_lease_failures(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    release_calls: list[tuple[object, str, str]] = []
    service = Mock()

    def release_headless_inflight_call(
        reservation_id: object,
        agent: str,
        assignment_id: str,
    ) -> None:
        release_calls.append((reservation_id, agent, assignment_id))

    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {"state": "ready"})
    monkeypatch.setattr(server, "_gemini_headless_gate", lambda *_args: {
        "action": "defer_until",
        "diagnostic_code": "gemini_limits_unknown",
        "account_id": "gemini-project",
        "raw_output": "not_returned",
    })
    monkeypatch.setattr(server, "release_headless_inflight", release_headless_inflight_call)
    monkeypatch.setattr(server, "release_agent", Mock())

    with pytest.raises(server.AgentError, match="headless_lease_not_held"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "pending", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-lease",
            headless_inflight_reservation={"reservation_id": "inflight-lease"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
        )

    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-lease", "d1", "assignment-lease")
    assert service.method_calls == []

    release_calls.clear()
    result = server._run_headless_process(
        "d1",
        "prompt",
        {"state": "held", "held_by_this_server": True},
        5,
        role="arbeitsbiene",
        assignment_id="assignment-gate",
        headless_inflight_reservation={"reservation_id": "inflight-gate"},
        structured_gate={
            "action": "defer_until",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )

    assert result["status"] == "deferred"
    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-gate", "d1", "assignment-gate")
    service.reserve_gemini_request.assert_not_called()
    assert service.record_gemini_usage.call_count == 1
    assert service.record_gemini_usage.call_args.kwargs["status"] == "failed"
    assert service.record_gemini_usage.call_args.kwargs["gate_action"] == "defer_until"
    assert service.record_gemini_usage.call_args.kwargs["gate_code"] == "gemini_limits_unknown"
    assert service.record_gemini_event.call_count == 1
    assert service.record_gemini_event.call_args.kwargs["event_type"] == "headless_gate"
    assert service.record_gemini_event.call_args.kwargs["status"] == "deferred"
    assert service.record_gemini_event.call_args.kwargs["assignment_id"] == "assignment-gate"

    monkeypatch.setattr(
        server,
        "_headless_marker",
        lambda _agent: (_ for _ in ()).throw(server.AgentError("metadata unreadable")),
    )
    release_calls.clear()
    service.reset_mock()

    with pytest.raises(server.AgentError, match="metadata unreadable"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-metadata",
            headless_inflight_reservation={"reservation_id": "inflight-metadata"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
        )

    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-metadata", "d1", "assignment-metadata")
    assert service.method_calls == []
    assert service.reserve_gemini_request.call_count == 0
    assert service.read_secret.call_count == 0


def test_s5b_headless_runner_releases_bound_inflight_on_provider_start_and_rate_errors(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("."),
        },
    )()
    service = Mock()

    def make_plan() -> Mock:
        plan = Mock()
        plan.unset_env = set()
        plan.secret_env_name = "GEMINI_API_KEY"
        plan.env = {}
        plan.argv = ("cmd",)
        return plan

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    def build_common_monkeypatch() -> None:
        monkeypatch.setattr(server, "current_fleet_service", lambda: service)
        monkeypatch.setattr(server, "release_headless_inflight", release_headless_inflight_call)
        monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
        monkeypatch.setattr(server, "_headless_marker", lambda _agent: {"state": "ready"})
        monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
        monkeypatch.setattr(server, "_headless_admission_gate", lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1))
        monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("."))
        monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
        monkeypatch.setattr(server, "build_runner_plan", lambda *_args: make_plan())
        monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
        service.load.return_value = object()

    release_calls: list[tuple[object, str, str]] = []

    def release_headless_inflight_call(
        reservation_id: object,
        agent: str,
        assignment_id: str,
    ) -> None:
        release_calls.append((reservation_id, agent, assignment_id))

    # provider/service reservation failure
    build_common_monkeypatch()
    service.reserve_gemini_request.side_effect = server.AgentError("reserve failed")
    monkeypatch.setattr(server.subprocess, "Popen", Mock())
    monkeypatch.setattr(server, "release_agent", Mock())

    with pytest.raises(server.AgentError, match="reserve failed"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-provider",
            headless_inflight_reservation={"reservation_id": "inflight-provider"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )

    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-provider", "d1", "assignment-provider")
    release_calls.clear()

    # process start failure
    build_common_monkeypatch()
    service.reset_mock()
    service.reserve_gemini_request.side_effect = None
    service.reserve_gemini_request.return_value = object()
    service.read_secret.return_value = "sekret"
    monkeypatch.setattr(server.subprocess, "Popen", Mock(side_effect=OSError("no")))

    with pytest.raises(server.AgentError, match="headless_start_failed"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-start",
            headless_inflight_reservation={"reservation_id": "inflight-start"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )

    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-start", "d1", "assignment-start")
    release_calls.clear()

    # provider rate limit failure
    build_common_monkeypatch()
    service.reset_mock()
    service.reserve_gemini_request.side_effect = server.FleetRateLimitError("rate limited", 30)

    with pytest.raises(server.FleetRateLimitError):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-rate",
            headless_inflight_reservation={"reservation_id": "inflight-rate"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )

    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-rate", "d1", "assignment-rate")


def test_headless_retry_policy_caps_existing_gemini_home_settings(tmp_path: Path) -> None:
    settings_path = tmp_path / ".gemini" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        '{"general":{"maxAttempts":10,"retryFetchErrors":true},"privacy":{"usageStatisticsEnabled":false}}\n',
        encoding="utf-8",
    )

    server._ensure_gemini_headless_retry_policy(tmp_path)

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["general"] == {"maxAttempts": 1, "retryFetchErrors": False}
    assert settings["privacy"]["usageStatisticsEnabled"] is False


def test_headless_retry_policy_refreshes_managed_home_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = tmp_path / ".gemini" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        '{"general":{"maxAttempts":1,"retryFetchErrors":false}}\n',
        encoding="utf-8",
    )
    marker_path = tmp_path / server.FLEET_AGENT_MARKER_FILE
    marker_path.write_text("{}\n", encoding="utf-8")
    marker_path.chmod(0o600)
    marker = {
        "runner": server.RunnerKind.GEMINI_CLI.value,
        "files": {".gemini/settings.json": "0" * 64},
    }
    monkeypatch.setattr(
        server,
        "_fleet_read_current_agent_marker",
        lambda *_args, **_kwargs: (b"", marker, None),
    )

    server._ensure_gemini_headless_retry_policy(tmp_path)

    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert json.loads(settings_path.read_text(encoding="utf-8"))["general"]["maxAttempts"] == 1
    assert marker["files"][".gemini/settings.json"] == hashlib.sha256(
        settings_path.read_bytes()
    ).hexdigest()


def test_stale_headless_force_recovery_signals_only_verified_process_group(monkeypatch) -> None:
    home = Path("/tmp/managed-d1")
    descriptor = type("Descriptor", (), {"home": home})()
    marker = {
        "state": "running",
        "process": {
            "pid": 81236,
            "pgid": 81236,
            "proc_start_ticks": 42,
            "home_tag": hashlib.sha256(str(home).encode("utf-8")).hexdigest(),
        },
    }
    signals: list[tuple[int, int]] = []

    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_process_start_ticks", lambda _pid: 42)
    monkeypatch.setattr(server.os, "getpgid", lambda _pid: 81236)
    monkeypatch.setattr(server.os, "getpgrp", lambda: 99999)

    def fake_killpg(pgid: int, signum: int) -> None:
        signals.append((pgid, signum))
        if signum == 0:
            raise ProcessLookupError

    monkeypatch.setattr(server.os, "killpg", fake_killpg)

    assert server._recover_headless_process("d1", marker) == "stopped"
    assert signals == [(81236, signal.SIGTERM), (81236, 0)]


def test_force_stop_recovers_stale_headless_marker(monkeypatch) -> None:
    descriptor = type("Descriptor", (), {"home": Path("/tmp/managed-d1")})()
    marker = {"state": "running", "assignment_id": "assignment-1"}
    written: dict[str, object] = {}
    release = Mock(return_value={"lease": {"state": "unclaimed"}})

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    recover = Mock(return_value="stopped")
    monkeypatch.setattr(server, "_recover_headless_process", recover)
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, value: written.update(value))
    monkeypatch.setattr(server, "agent_lease_status", lambda _agent: {"state": "free"})
    monkeypatch.setattr(server, "release_agent", release)

    result = server._stop_agent_unlocked("d1", force=True)

    assert result["status"] == "stopped"
    recover.assert_called_once_with("d1", marker)
    assert written["state"] == "disabled"
    release.assert_called_once_with("d1", force=True)


def test_s5c_cancel_releases_marker_bound_inflight_only_after_verified_recovery(monkeypatch) -> None:
    marker: dict[str, object] = {}
    release_calls: list[tuple[object, str, str]] = []
    written: list[dict[str, object]] = []
    release_outcomes = {"count": 0}

    def write_marker(_agent: str, value: dict[str, object]) -> None:
        written.append(dict(value))

    def release_headless_inflight_call(
        reservation_id: object,
        _agent: str,
        assignment_id: str,
    ) -> dict[str, str] | None:
        release_calls.append((reservation_id, _agent, assignment_id))
        release_outcomes["count"] += 1
        if release_outcomes["count"] == 1:
            return {"status": "released"}
        if release_outcomes["count"] == 2:
            return None
        raise server.AgentError("release failed")

    request_cancel = Mock(
        side_effect=[
            {"status": "running"},
            {"status": "not_running"},
            {"status": "not_running"},
            {"status": "not_running"},
            {"status": "not_running"},
        ]
    )
    recover = Mock(side_effect=[
        "identity_unverified",
        "stopped",
        "stopped",
        "stopped",
    ])

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: object())
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", request_cancel)
    monkeypatch.setattr(server, "_recover_headless_process", recover)
    monkeypatch.setattr(server, "_write_headless_marker", write_marker)
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        release_headless_inflight_call,
    )

    marker = {
        "state": "running",
        "assignment_id": "assignment-cancel",
        "headless_inflight_reservation_id": "inflight-cancel",
        "process": {},
    }
    result_running = server.cancel_headless_job("d1")
    assert result_running["status"] == "running"
    assert len(release_calls) == 0
    assert written[-1]["state"] == "cancelling"
    assert written[-1]["headless_inflight_reservation_id"] == "inflight-cancel"

    marker = {
        "state": "running",
        "assignment_id": "assignment-cancel",
        "headless_inflight_reservation_id": "inflight-cancel",
        "process": {},
    }
    written.clear()
    result_unverified = server.cancel_headless_job("d1")
    assert result_unverified["status"] == "identity_unverified"
    assert len(release_calls) == 0
    assert written == []
    assert marker["headless_inflight_reservation_id"] == "inflight-cancel"

    marker = {
        "state": "running",
        "assignment_id": "assignment-cancel",
        "headless_inflight_reservation_id": "inflight-cancel",
        "process": {},
    }
    written.clear()
    result_stopped = server.cancel_headless_job("d1")
    assert result_stopped["status"] == "cancelled"
    assert release_calls == [("inflight-cancel", "d1", "assignment-cancel")]
    assert "headless_inflight_reservation_id" not in written[-1]
    assert written[-1]["state"] == "cancelled"
    assert "process" not in written[-1]

    marker = {
        "state": "running",
        "assignment_id": "assignment-cancel",
        "headless_inflight_reservation_id": "inflight-cancel",
        "process": {},
    }
    written.clear()
    result_stopped_none = server.cancel_headless_job("d1")
    assert result_stopped_none["status"] == "cancelled"
    assert release_calls == [
        ("inflight-cancel", "d1", "assignment-cancel"),
        ("inflight-cancel", "d1", "assignment-cancel"),
    ]
    assert written[-1]["headless_inflight_reservation_id"] == "inflight-cancel"
    assert written[-1]["state"] == "cancelled"
    assert "process" not in written[-1]

    marker = {
        "state": "running",
        "assignment_id": "assignment-cancel",
        "headless_inflight_reservation_id": "inflight-cancel",
        "process": {},
    }
    written.clear()
    result_stopped_raise = server.cancel_headless_job("d1")
    assert result_stopped_raise["status"] == "cancelled"
    assert release_calls == [
        ("inflight-cancel", "d1", "assignment-cancel"),
        ("inflight-cancel", "d1", "assignment-cancel"),
        ("inflight-cancel", "d1", "assignment-cancel"),
    ]
    assert written[-1]["headless_inflight_reservation_id"] == "inflight-cancel"
    assert written[-1]["state"] == "cancelled"
    assert "process" not in written[-1]


def test_s5c_force_stop_recovers_stale_headless_marker(monkeypatch) -> None:
    release_calls: list[tuple[object, str, str]] = []
    written: dict[str, object] = {}

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: type("Descriptor", (), {
        "home": Path("/tmp/managed-d1"),
    })())
    marker = {
        "state": "cancelling",
        "assignment_id": "assignment-force-stop",
        "headless_inflight_reservation_id": "inflight-force-stop",
        "process": {},
    }
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server.HEADLESS_JOBS, "status", lambda _agent: {"status": "not_running"})
    monkeypatch.setattr(server, "_recover_headless_process", lambda *_args: "stopped")
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, value: written.update(value))
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, agent, assignment_id: (
            release_calls.append((
                reservation_id,
                agent,
                assignment_id,
            ))
            or {"status": "released"}
        ),
    )
    monkeypatch.setattr(server, "agent_lease_status", lambda _agent: {"state": "held", "held_by_this_server": True})
    monkeypatch.setattr(server, "release_agent", lambda _agent, force=False: {"lease": {"state": "unclaimed"}})

    result = server._stop_agent_unlocked("d1", force=True)

    assert result["status"] == "stopped"
    assert release_calls == [("inflight-force-stop", "d1", "assignment-force-stop")]
    assert written["state"] == "disabled"
    assert "headless_inflight_reservation_id" not in written
    assert written["assignment_id"] == "assignment-force-stop"


@pytest.mark.parametrize(
    (
        "terminal_status",
        "result_returncode",
        "result_timed_out",
        "result_cancelled",
        "result_stdout",
        "expect_error",
    ),
    [
        (
            "completed",
            0,
            False,
            False,
            b'{"type":"init","session_id":"session"}\n'
            b'{"type":"result","response":"ok","stats":{"input_tokens":0,"output_tokens":0}}\n',
            None,
        ),
        (
            "timeout",
            124,
            True,
            False,
            b'{"type":"init","session_id":"session"}\n'
            b'{"type":"result","response":"ok","stats":{"input_tokens":0,"output_tokens":0}}\n',
            None,
        ),
        (
            "cancelled",
            143,
            False,
            True,
            b'{"type":"init","session_id":"session"}\n'
            b'{"type":"result","response":"ok","stats":{"input_tokens":0,"output_tokens":0}}\n',
            None,
        ),
        (
            "failed",
            17,
            False,
            False,
            b'{"type":"init","session_id":"session"}\n'
            b'{"type":"result","response":"nope","stats":{"input_tokens":0,"output_tokens":0}}\n',
            None,
        ),
        ("parse_error", 17, False, False, b"not-json\n", "invalid_headless_output"),
    ],
)
def test_s5d_headless_terminal_result_releases_bound_inflight_once(
    monkeypatch,
    terminal_status: str,
    result_returncode: int,
    result_timed_out: bool,
    result_cancelled: bool,
    result_stdout: bytes,
    expect_error: str | None,
) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("/tmp/managed-d1"),
        },
    )()

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    class RunResult:
        def __init__(self, returncode: int, timed_out: bool, cancelled: bool) -> None:
            self.returncode = returncode
            self.stdout = result_stdout
            self.stderr = b""
            self.stdout_truncated = False
            self.stderr_truncated = False
            self.timed_out = timed_out
            self.cancelled = cancelled

    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "sekret"
    release_calls: list[tuple[object, str, str]] = []
    writes: list[dict[str, object]] = []
    events: list[str] = []
    finish_calls: list[str] = []
    marker: dict[str, object] = {"state": "ready"}

    def write_headless_marker(_agent: str, value: dict[str, object]) -> None:
        marker.update(value)
        writes.append(dict(value))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1),
    )
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("/tmp/managed-d1"))
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "build_runner_plan",
        lambda *_args: type(
            "Plan",
            (),
            {
                "unset_env": set(),
                "env": {},
                "secret_env_name": "GEMINI_API_KEY",
                "argv": ("cmd",),
            },
        )(),
    )
    monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
    monkeypatch.setattr(
        server,
        "subprocess",
        type(
            "Subprocess",
            (),
            {"Popen": Mock(return_value=Mock(pid=None, stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.BytesIO())),
             "PIPE": object()},
        ),
    )
    monkeypatch.setattr(server, "run_bounded_process", lambda *_args, **_kwargs: RunResult(
        result_returncode,
        result_timed_out,
        result_cancelled,
    ))
    monkeypatch.setattr(server, "_write_headless_marker", write_headless_marker)
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, _agent, assignment_id: (
            release_calls.append((reservation_id, _agent, assignment_id))
            or events.append("release")
            or {"status": "released"}
        ),
    )

    def finish(_job: object, run_result: object) -> None:
        finish_calls.append(f"finish:{getattr(run_result, 'returncode', None)}")
        events.append(f"finish:{getattr(run_result, 'returncode', None)}")

    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", finish)
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", lambda *_args, **_kwargs: {"status": "not_running"})

    if expect_error is None:
        result = server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-terminal",
            headless_inflight_reservation={"reservation_id": "inflight-terminal"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )
        assert result["status"] == terminal_status
    else:
        with pytest.raises(server.AgentError, match=expect_error):
            server._run_headless_process(
                "d1",
                "prompt",
                {"state": "held", "held_by_this_server": True},
                5,
                role="arbeitsbiene",
                assignment_id="assignment-terminal",
                headless_inflight_reservation={"reservation_id": "inflight-terminal"},
                structured_gate={
                    "action": "allow",
                    "diagnostic_code": "gemini_limits_unknown",
                    "account_id": "gemini-project",
                    "raw_output": "not_returned",
                },
                release_lease_on_completion=False,
            )

    assert writes[1]["headless_inflight_reservation_id"] == "inflight-terminal"
    expected_final_state = "failed" if expect_error is not None else terminal_status
    assert writes[1]["state"] == expected_final_state
    assert writes[-1]["state"] == expected_final_state
    assert "headless_inflight_reservation_id" not in writes[-1]
    assert events == [f"finish:{result_returncode}", "release"]
    assert len(finish_calls) == 1
    assert len(release_calls) == 1
    assert release_calls[0] == ("inflight-terminal", "d1", "assignment-terminal")


def test_s5d_headless_recovery_releases_once_after_confirmed_process_end(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("/tmp/managed-d1"),
        },
    )()

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    class Process:
        def __init__(self) -> None:
            self.returncode = 0

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 17
            return self.returncode

        def poll(self) -> int:
            return self.returncode

    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "sekret"
    release_calls: list[tuple[object, str, str]] = []
    writes: list[dict[str, object]] = []
    finish_calls: list[str] = []
    marker: dict[str, object] = {"state": "ready"}

    def write_headless_marker(_agent: str, value: dict[str, object]) -> None:
        marker.update(value)
        writes.append(dict(value))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "_write_headless_marker", write_headless_marker)
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1),
    )
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("/tmp/managed-d1"))
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "build_runner_plan",
        lambda *_args: type(
            "Plan",
            (),
            {
                "unset_env": set(),
                "env": {},
                "secret_env_name": "GEMINI_API_KEY",
                "argv": ("cmd",),
            },
        )(),
    )
    monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
    monkeypatch.setattr(
        server,
        "subprocess",
        type("Subprocess", (), {"Popen": Mock(return_value=Process()), "PIPE": object()}),
    )
    monkeypatch.setattr(server, "run_bounded_process", Mock(side_effect=RuntimeError("runner failed")))
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, _agent, assignment_id: (
            release_calls.append((reservation_id, _agent, assignment_id))
            or {"status": "released"}
        ),
    )
    monkeypatch.setattr(server, "release_agent", lambda *_args, **_kwargs: {"lease": {"state": "unclaimed"}})

    def finish(_job: object, run_result: object) -> None:
        finish_calls.append(f"finish:{getattr(run_result, 'returncode', None)}")

    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", finish)
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", lambda *_args, **_kwargs: {"status": "not_running"})

    with pytest.raises(RuntimeError, match="runner failed"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-recovery",
            headless_inflight_reservation={"reservation_id": "inflight-recovery"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )

    assert finish_calls == ["finish:17"]
    assert release_calls == [("inflight-recovery", "d1", "assignment-recovery")]
    assert writes[0]["state"] == "running"
    assert writes[0]["headless_inflight_reservation_id"] == "inflight-recovery"
    assert writes[1]["state"] == "failed"
    assert writes[-1]["state"] == "failed"
    assert "headless_inflight_reservation_id" not in writes[-1]


def test_s5d_headless_recovery_keeps_inflight_when_process_end_is_unconfirmed(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("/tmp/managed-d1"),
        },
    )()

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    class Process:
        def wait(self, timeout: float | None = None) -> None:
            return None

        def poll(self) -> None:
            return None

    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "sekret"
    release_calls: list[tuple[object, str, str]] = []
    writes: list[dict[str, object]] = []
    finish_calls: list[str] = []
    marker: dict[str, object] = {"state": "ready"}

    def write_headless_marker(_agent: str, value: dict[str, object]) -> None:
        marker.update(value)
        writes.append(dict(value))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "_write_headless_marker", write_headless_marker)
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1),
    )
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("/tmp/managed-d1"))
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "build_runner_plan",
        lambda *_args: type(
            "Plan",
            (),
            {
                "unset_env": set(),
                "env": {},
                "secret_env_name": "GEMINI_API_KEY",
                "argv": ("cmd",),
            },
        )(),
    )
    monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
    monkeypatch.setattr(
        server,
        "subprocess",
        type("Subprocess", (), {"Popen": Mock(return_value=Process()), "PIPE": object()}),
    )
    monkeypatch.setattr(server, "run_bounded_process", Mock(side_effect=RuntimeError("runner failed")))
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, _agent, assignment_id: (
            release_calls.append((reservation_id, _agent, assignment_id))
            or {"status": "released"}
        ),
    )
    monkeypatch.setattr(server, "release_agent", lambda *_args, **_kwargs: {"lease": {"state": "unclaimed"}})

    def finish(_job: object, run_result: object) -> None:
        finish_calls.append(f"finish:{getattr(run_result, 'returncode', None)}")

    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", finish)
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", lambda *_args, **_kwargs: {"status": "not_running"})

    with pytest.raises(RuntimeError, match="runner failed"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="arbeitsbiene",
            assignment_id="assignment-recovery-unconfirmed",
            headless_inflight_reservation={"reservation_id": "inflight-recovery-unconfirmed"},
            structured_gate={
                "action": "allow",
                "diagnostic_code": "gemini_limits_unknown",
                "account_id": "gemini-project",
                "raw_output": "not_returned",
            },
            release_lease_on_completion=False,
        )

    assert finish_calls == []
    assert release_calls == []
    assert writes[-1]["state"] == "running"
    assert writes[-1]["headless_inflight_reservation_id"] == "inflight-recovery-unconfirmed"


def _build_provider_limited_output(
    quota_scope: str,
    retry_delay: str | None = None,
) -> bytes:
    details: list[dict[str, object]] = [
        {
            "@type": "type.googleapis.com/google.rpc.QuotaFailure",
            "violations": [
                {
                    "quotaDimensions": (
                        {"model": "gemini-3-flash-preview"}
                        if quota_scope == "model"
                        else {"provider": "gemini"}
                        if quota_scope == "unknown"
                        else {}
                    ),
                },
            ],
        },
    ]
    if retry_delay is not None:
        details.append({
            "@type": "type.googleapis.com/google.rpc.RetryInfo",
            "retryDelay": retry_delay,
        })
    return (
        b'{"type":"init","session_id":"session","model":"gemini-3-flash-preview"}\n'
        + json.dumps({"type": "error", "status": "RESOURCE_EXHAUSTED", "error": {
            "code": 429,
            "reset_at_utc": "2026-08-03T12:00:00Z",
            "details": details,
        }}).encode("utf-8")
        + b"\n"
        + b'{"type":"result","response":"","stats":{"input_tokens":0,"output_tokens":0}}\n'
    )


def test_g8_b2_headless_terminal_account_limited_model_scope_uses_model_limited_usage_path(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("/tmp/managed-d1"),
        },
    )()

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    class RunResult:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 17
            self.stdout = stdout
            self.stderr = b""
            self.stdout_truncated = False
            self.stderr_truncated = False
            self.timed_out = False
            self.cancelled = False

    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "sekret"
    release_calls: list[tuple[object, str, str]] = []
    writes: list[dict[str, object]] = []

    def write_headless_marker(_agent: str, value: dict[str, object]) -> None:
        writes.append(dict(value))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {"state": "ready"})
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1),
    )
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("/tmp/managed-d1"))
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "build_runner_plan",
        lambda *_args: type(
            "Plan",
            (),
            {"unset_env": set(), "env": {}, "secret_env_name": "GEMINI_API_KEY", "argv": ("cmd",)},
        )(),
    )
    monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
    monkeypatch.setattr(server, "subprocess", type(
        "Subprocess",
        (),
        {"Popen": Mock(return_value=Mock(pid=None, stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.BytesIO())),
         "PIPE": object()},
    ))
    monkeypatch.setattr(server, "run_bounded_process", lambda *_args, **_kwargs: RunResult(
        _build_provider_limited_output("model", "120s"),
    ))
    monkeypatch.setattr(server, "_write_headless_marker", write_headless_marker)
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, _agent, assignment_id: (
            release_calls.append((reservation_id, _agent, assignment_id))
            or {"status": "released"}
        ),
    )
    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", lambda *_args, **_kwargs: {"status": "not_running"})

    result = server._run_headless_process(
        "d1",
        "prompt",
        {"state": "held", "held_by_this_server": True},
        5,
        role="arbeitsbiene",
        assignment_id="assignment-model-limited",
        headless_inflight_reservation={"reservation_id": "inflight-model-limited"},
        structured_gate={"action": "allow", "diagnostic_code": "gemini_limits_unknown", "account_id": "gemini-project", "raw_output": "not_returned"},
        release_lease_on_completion=False,
    )

    assert result["status"] == "failed"
    assert release_calls == [("inflight-model-limited", "d1", "assignment-model-limited")]
    assert writes[0]["state"] == "running"
    assert writes[-1]["state"] == "failed"

    usage = service.record_gemini_usage.call_args.kwargs
    assert usage["status"] == "rate_limited"
    observed = usage["quota_observation"]
    assert observed is not None
    assert observed.scope == "model"
    assert observed.retry_after_seconds == 120
    event = service.record_gemini_event.call_args.kwargs
    assert event.get("quota_observation") is None
    assert "quota_observation" not in event
    service.mark_limited.assert_not_called()
    release_event = service.release_gemini_request.call_args.kwargs
    assert release_event["outcome"] == "provider_error"
    assert "reset_at_utc" not in release_event or release_event["reset_at_utc"] is None


@pytest.mark.parametrize(
    ("quota_scope", "retry_delay", "expected_observation_scope", "expected_retry_seconds"),
    [
        ("account", None, "account", None),
        ("model", None, "model", None),
        ("unknown", "120s", "unknown", 120),
    ],
)
def test_g8_b2_headless_terminal_account_limited_fallbacks_to_accountwide_path(
    monkeypatch,
    quota_scope: str,
    retry_delay: str | None,
    expected_observation_scope: str,
    expected_retry_seconds: int | None,
) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": Path("/tmp/managed-d1"),
        },
    )()

    class Inventory:
        def __init__(self) -> None:
            self.agents = {"d1": descriptor}

    class RunResult:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 17
            self.stdout = stdout
            self.stderr = b""
            self.stdout_truncated = False
            self.stderr_truncated = False
            self.timed_out = False
            self.cancelled = False

    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "sekret"
    release_calls: list[tuple[object, str, str]] = []
    writes: list[dict[str, object]] = []

    def write_headless_marker(_agent: str, value: dict[str, object]) -> None:
        writes.append(dict(value))

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {"state": "ready"})
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: Mock(allowed=True, account_id="gemini-project", generation=1),
    )
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: Path("/tmp/managed-d1"))
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "build_runner_plan",
        lambda *_args: type(
            "Plan",
            (),
            {"unset_env": set(), "env": {}, "secret_env_name": "GEMINI_API_KEY", "argv": ("cmd",)},
        )(),
    )
    monkeypatch.setattr(server, "build_inventory", lambda _snapshot, _root: Inventory())
    monkeypatch.setattr(server, "subprocess", type(
        "Subprocess",
        (),
        {"Popen": Mock(return_value=Mock(pid=None, stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.BytesIO())),
         "PIPE": object()},
    ))
    monkeypatch.setattr(server, "run_bounded_process", lambda *_args, **_kwargs: RunResult(
        _build_provider_limited_output(quota_scope, retry_delay),
    ))
    monkeypatch.setattr(server, "_write_headless_marker", write_headless_marker)
    monkeypatch.setattr(
        server,
        "release_headless_inflight",
        lambda reservation_id, _agent, assignment_id: (
            release_calls.append((reservation_id, _agent, assignment_id))
            or {"status": "released"}
        ),
    )
    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "request_cancel", lambda *_args, **_kwargs: {"status": "not_running"})

    server._run_headless_process(
        "d1",
        "prompt",
        {"state": "held", "held_by_this_server": True},
        5,
        role="arbeitsbiene",
        assignment_id="assignment-account-limited",
        headless_inflight_reservation={"reservation_id": "inflight-account-limited"},
        structured_gate={"action": "allow", "diagnostic_code": "gemini_limits_unknown", "account_id": "gemini-project", "raw_output": "not_returned"},
        release_lease_on_completion=False,
    )

    assert service.record_gemini_usage.call_count == 1
    usage = service.record_gemini_usage.call_args.kwargs
    event_record = service.record_gemini_event.call_args.kwargs
    assert usage["status"] == "rate_limited"
    event_observation = usage.get("quota_observation")
    assert event_observation is not None
    assert event_observation.scope == expected_observation_scope
    assert event_observation.retry_after_seconds == expected_retry_seconds
    assert event_record.get("quota_observation") is None
    assert "quota_observation" not in event_record
    assert service.mark_limited.call_args.kwargs == {
        "reason": "gemini_resource_exhausted",
        "reset_at_utc": usage.get("next_reset_at_utc"),
    }
    event = service.release_gemini_request.call_args.kwargs
    assert event["outcome"] == "rate_limited"
    assert event["reset_at_utc"] == usage.get("next_reset_at_utc")
    assert "quota_dimensions" not in repr(usage)
    assert "quota_details" not in repr(usage)



def test_generic_headless_assignment_preserves_requested_role(monkeypatch) -> None:
    assign = Mock(return_value={"status": "accepted"})
    monkeypatch.setattr(server, "single_agent_id", lambda _selector, _operation: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: object())
    monkeypatch.setattr(server, "require_fleet_recovery_ready", Mock())
    monkeypatch.setattr(server, "_assign_headless_agent", assign)

    response = server.handle_rpc({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "agent_assign",
            "arguments": {
                "agent": "d1",
                "role": "exploriererin",
                "task": "inspect",
            },
        },
    })

    assert response is not None
    assert response["result"]["isError"] is False
    assert assign.call_args.kwargs["role"] == "exploriererin"


def test_headless_assignment_never_provider_falls_back_from_explicit_target(monkeypatch) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {"model": "gemini-3-flash-preview", "account_id": "gemini-project"},
    )()
    route = Mock(side_effect=AssertionError("implicit headless fallback is forbidden"))
    service = Mock()
    reservation = {"reservation_id": "headless-inflight-nofallback"}

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "i1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda _agent: {
            "action": "allow",
            "diagnostic_code": "gemini_limits_unknown",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(
        server,
        "require_spawn_capacity",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args, **_kwargs: reservation)
    monkeypatch.setattr(server, "_headless_route_candidates", route)
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(server, "_claim_agent_unlocked", lambda _agent: {
        "status": "already_held",
        "lease": {"held_by_this_server": True},
    })
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, _marker: None)
    monkeypatch.setattr(
        server,
        "_run_headless_process",
        lambda agent, *_args, **_kwargs: {
            "agent": agent,
            "status": "failed",
            "error": {"kind": "provider_unavailable", "retryable": True},
        },
    )

    result = server._assign_headless_agent(
        "i1",
        role="exploriererin",
        task="inspect",
        scope=[],
        timeout_seconds=5,
    )

    assert result["agent"] == "i1"
    assert result["requested_agent"] == "i1"
    assert result["routed_from"] is None
    assert result["error"]["kind"] == "provider_unavailable"
    route.assert_not_called()


def test_headless_write_assignment_fails_closed_before_claim_or_process(monkeypatch) -> None:
    descriptor = type("Descriptor", (), {"model": "gemini-3-flash-preview"})()
    claim = Mock()
    record = Mock()
    run = Mock()

    monkeypatch.setattr(
        server, "canonical_agent_id", lambda _agent, **_kwargs: "i1"
    )
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "_claim_agent_unlocked", claim)
    monkeypatch.setattr(server, "record_assignment", record)
    monkeypatch.setattr(server, "_run_headless_process", run)

    with pytest.raises(server.AgentError, match="headless_write_scope_unenforced") as exc_info:
        server._assign_headless_agent(
            "i1",
            role="arbeitsbiene",
            task="fix",
            scope=["src"],
            write_paths=["src/file.py"],
            timeout_seconds=5,
        )

    error = exc_info.value
    assert error.payload == {
        "code": "headless_write_scope_unenforced",
        "explanation": "headless writes lack isolated worktree and diff attribution",
        "action": "use an isolated worktree or submit a read-only headless assignment",
    }
    assert server.public_error_payload(error) == {
        "error": "headless_write_scope_unenforced",
        **error.payload,
    }
    claim.assert_not_called()
    record.assert_not_called()
    run.assert_not_called()


def test_headless_write_assignment_binds_attestation_before_claim_and_passes_worktree(
    tmp_path: Path, monkeypatch
) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "home": tmp_path / "managed-home",
        },
    )()
    attested_worktree = tmp_path / "attested-worktree"
    scope_store = Mock()
    scope_store.has_available.return_value = True
    scope_store.bind.return_value = SimpleNamespace(
        worktree_path=attested_worktree,
        attestation_id="a" * 32,
    )
    events: list[str] = []
    run = Mock(
        return_value={
            "agent": "i1",
            "status": "failed",
            "write_scope": {
                "ok": False,
                "code": "headless_write_scope_violation",
                "changed_count": 2,
                "attributed_count": 1,
                "out_of_scope_count": 1,
                "paths": "not_returned",
                "raw_output": "not_returned",
            },
        }
    )

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "i1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", lambda **_kwargs: "bounded assignment prompt")
    monkeypatch.setattr(
        server,
        "_gemini_headless_gate",
        lambda _agent: {
            "action": "allow",
            "diagnostic_code": "gemini_ready",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "_headless_write_scope_store", lambda: scope_store)
    monkeypatch.setattr(server, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(server, "current_fleet_service", lambda: SimpleNamespace(load=lambda: SimpleNamespace(generation=4)))
    monkeypatch.setattr(server, "require_spawn_capacity", lambda *_args, **_kwargs: {"allowed": True})
    monkeypatch.setattr(server, "spawn_admission_lock", lambda: nullcontext())
    monkeypatch.setattr(server, "reserve_headless_inflight", lambda *_args: {"reservation_id": "r1"})
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())
    monkeypatch.setattr(
        server,
        "_claim_agent_unlocked",
        lambda _agent: events.append("claim") or {
            "status": "already_held",
            "lease": {"state": "held", "held_by_this_server": True},
        },
    )
    monkeypatch.setattr(server, "record_assignment", lambda _record: events.append("record"))
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: {})
    monkeypatch.setattr(server, "_write_headless_marker", lambda *_args: None)
    monkeypatch.setattr(
        server,
        "_run_headless_process",
        lambda *_args, **kwargs: events.append("run") or run(*_args, **kwargs),
    )

    result = server._assign_headless_agent(
        "i1",
        role="arbeitsbiene",
        task="fix",
        scope=["src"],
        write_paths=["src/file.py"],
        timeout_seconds=5,
    )

    assert result["status"] == "failed"
    assert result["write_scope"]["code"] == "headless_write_scope_violation"
    scope_store.bind.assert_called_once()
    assert events.index("record") < events.index("run")
    assert run.call_args.kwargs["write_scope_binding"].worktree_path == attested_worktree


def test_worktree_create_registers_public_attestation_without_path_leak(
    tmp_path: Path, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    for args in (
        ("git", "init", "--quiet"),
        ("git", "config", "user.email", "test@example.invalid"),
        ("git", "config", "user.name", "Headless Test"),
    ):
        subprocess.run(args, cwd=repository, check=True, capture_output=True, text=True)
    (repository / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(
        ("git", "add", "README.md"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ("git", "commit", "--quiet", "-m", "baseline"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_store = server.HeadlessWriteScopeStore(tmp_path / "state")
    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda *_args: None)
    monkeypatch.setattr(server, "canonical_agent_id", lambda value: value)
    monkeypatch.setattr(server, "repo_root", lambda: repository)
    monkeypatch.setattr(server, "_headless_write_scope_store", lambda: scope_store)

    result = server.worktree_create_for_agent(
        "d1", path=".codex-master-worktrees/agent-d1"
    )

    assert result["write_scope"]["state"] == "available"
    attestation_id = result["write_scope"]["attestation_id"]
    assert result["path_kind"] == "repo_relative"
    assert str(repository) not in repr(result)
    attestation = scope_store.read(attestation_id)
    assert attestation.agent_id == "d1"
    assert attestation.worktree_path.name == "agent-d1"


def test_worktree_create_rejects_target_swap_after_git_operation(
    tmp_path: Path, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = repository / ".codex-master-worktrees" / "agent-d1"
    calls: list[list[str]] = []

    def fake_run_command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:3] == ["git", "worktree", "add"]:
            target.rmdir()
            target.symlink_to(outside, target_is_directory=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda *_args: None)
    monkeypatch.setattr(server, "canonical_agent_id", lambda value: value)
    monkeypatch.setattr(server, "repo_root", lambda: repository)
    monkeypatch.setattr(server, "run_command", fake_run_command)

    with pytest.raises(server.AgentError, match="headless_attestation_invalid"):
        server.worktree_create_for_agent(
            "d1", path=".codex-master-worktrees/agent-d1"
        )

    assert calls[-1][:3] == ["git", "worktree", "add"]
    assert target.is_symlink()


def test_headless_write_runner_revalidates_and_uses_attested_cwd(monkeypatch, tmp_path: Path) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": tmp_path / "managed-home",
        },
    )()
    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "secret"
    scope_store = Mock()
    scope_store.finalize.return_value = server.ScopeResult(True, "ok", 1, 1, 0)
    binding = SimpleNamespace(worktree_path=tmp_path / "attested-worktree")
    marker: dict[str, object] = {"state": "ready"}
    process = Mock(pid=None, stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.BytesIO())
    run_result = SimpleNamespace(
        returncode=0,
        stdout=b'{"type":"result","response":"ok","stats":{"input_tokens":1,"output_tokens":1}}\n',
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
        cancelled=False,
    )
    plan = SimpleNamespace(
        unset_env=set(), env={}, secret_env_name="GEMINI_API_KEY", argv=("gemini",)
    )

    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: SimpleNamespace(allowed=True, account_id="gemini-project", generation=4),
    )
    monkeypatch.setattr(server, "build_inventory", lambda *_args: SimpleNamespace(agents={"d1": descriptor}))
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: tmp_path / "gemini")
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(server, "build_runner_plan", lambda *_args: plan)
    monkeypatch.setattr(server, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(server.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(server, "run_bounded_process", lambda *_args, **_kwargs: run_result)
    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", lambda *_args: None)
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, value: marker.update(value))

    result = server._run_headless_process(
        "d1",
        "prompt",
        {"state": "held", "held_by_this_server": True},
        5,
        role="arbeitsbiene",
        assignment_id="assignment-1",
        structured_gate={
            "action": "allow",
            "diagnostic_code": "gemini_ready",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
        write_scope_binding=binding,
        write_scope_store=scope_store,
        release_lease_on_completion=False,
    )

    assert result["status"] == "completed"
    assert result["write_scope"]["code"] == "ok"
    assert process is server.subprocess.Popen.return_value
    assert server.subprocess.Popen.call_args.kwargs["cwd"] == binding.worktree_path
    scope_store.revalidate.assert_called_once_with(
        binding, tmp_path, provider_generation=4
    )
    scope_store.finalize.assert_called_once_with(binding)


def test_headless_write_scope_violation_cannot_report_completed(monkeypatch, tmp_path: Path) -> None:
    descriptor = type(
        "Descriptor",
        (),
        {
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project",
            "provider": server.Provider.GEMINI_API,
            "runner": server.RunnerKind.GEMINI_CLI,
            "home": tmp_path / "managed-home",
        },
    )()
    service = Mock()
    service.load.return_value = object()
    service.read_secret.return_value = "secret"
    scope_store = Mock()
    scope_store.finalize.return_value = server.ScopeResult(
        False, "headless_write_scope_violation", 2, 1, 1
    )
    binding = SimpleNamespace(worktree_path=tmp_path / "attested-worktree")
    marker: dict[str, object] = {"state": "ready"}
    process = Mock(pid=None, stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.BytesIO())
    run_result = SimpleNamespace(
        returncode=0,
        stdout=b'{"type":"result","response":"unsafe","stats":{"input_tokens":1,"output_tokens":1}}\n',
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
        cancelled=False,
    )
    plan = SimpleNamespace(
        unset_env=set(), env={}, secret_env_name="GEMINI_API_KEY", argv=("gemini",)
    )

    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "_headless_marker", lambda _agent: marker)
    monkeypatch.setattr(server, "status_agent", lambda *_args, **_kwargs: {"identity_guard": {"ok": True}})
    monkeypatch.setattr(
        server,
        "_headless_admission_gate",
        lambda _agent: SimpleNamespace(allowed=True, account_id="gemini-project", generation=4),
    )
    monkeypatch.setattr(server, "build_inventory", lambda *_args: SimpleNamespace(agents={"d1": descriptor}))
    monkeypatch.setattr(server, "_headless_executable", lambda _descriptor: tmp_path / "gemini")
    monkeypatch.setattr(server, "_ensure_gemini_headless_retry_policy", lambda *_args: None)
    monkeypatch.setattr(server, "build_runner_plan", lambda *_args: plan)
    monkeypatch.setattr(server, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(server.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(server, "run_bounded_process", lambda *_args, **_kwargs: run_result)
    monkeypatch.setattr(server.HEADLESS_JOBS, "register", lambda *_args: None)
    monkeypatch.setattr(server.HEADLESS_JOBS, "finish", lambda *_args: None)
    monkeypatch.setattr(server, "_write_headless_marker", lambda _agent, value: marker.update(value))

    result = server._run_headless_process(
        "d1",
        "prompt",
        {"state": "held", "held_by_this_server": True},
        5,
        role="arbeitsbiene",
        assignment_id="assignment-1",
        structured_gate={
            "action": "allow",
            "diagnostic_code": "gemini_ready",
            "account_id": "gemini-project",
            "raw_output": "not_returned",
        },
        write_scope_binding=binding,
        write_scope_store=scope_store,
        release_lease_on_completion=False,
    )

    assert result["status"] == "failed"
    assert result["error"]["kind"] == "headless_write_scope_violation"
    assert result["response"] == ""


def test_gemini_bootstrap_plan_is_dry_and_secret_free() -> None:
    result = server.fleet_gemini_bootstrap_plan()

    assert result["status"] == "provider_probe_required"
    assert result["account_count"] == 3
    assert result["series_count"] == 3
    assert [item["prefix"] for item in result["series"]] == ["d", "e", "f"]
    assert "secret" not in repr(result)
    assert "private-secret" not in repr(result)
