from __future__ import annotations

import io
import hashlib
import json
import signal
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
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

    def reserve_gemini_request(self, account_id: str) -> object:
        reservation = (account_id, "reservation")
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
    reservation = object()
    service = Mock()
    service.reserve_gemini_request.side_effect = (
        lambda account_id: order.append(f"reserve:{account_id}") or reservation
    )

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

    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "_headless_descriptor", descriptors.get)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "assignment_prompt", lambda **kwargs: prompts.append(kwargs) or "prompt")
    monkeypatch.setattr(server, "_gemini_headless_gate", gate)
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
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

    assert order[-3:] == ["gate:e1", "reserve:gemini-project-2", "claim:e1"]
    assert run.call_args.args[0] == "e1"
    assert run.call_args.kwargs["reservation"] is reservation
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
    reservation = object()
    order: list[str] = []
    service = Mock()
    service.reserve_gemini_request.side_effect = (
        lambda account_id: order.append(f"reserve:{account_id}") or reservation
    )
    service.release_gemini_request.side_effect = (
        lambda _reservation, **kwargs: order.append(f"release:{kwargs['outcome']}")
    )

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
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda _agent: nullcontext())

    def fail_claim(agent: str) -> dict[str, object]:
        order.append(f"claim:{agent}")
        raise server.AgentError("claim_failed")

    monkeypatch.setattr(server, "_claim_agent_unlocked", fail_claim)

    with pytest.raises(server.AgentError, match="claim_failed"):
        server._assign_headless_agent(
            "d1", role="exploriererin", task="inspect", scope=[], timeout_seconds=5,
        )

    assert order == ["reserve:gemini-project", "claim:d1", "release:provider_error"]
    service.release_gemini_request.assert_called_once_with(
        reservation, outcome="provider_error",
    )


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
    prompt = Mock(return_value="bounded assignment prompt")
    service = Mock()
    service.reserve_gemini_request.return_value = object()

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

    def fake_prompt(**kwargs: object) -> str:
        captured.update(kwargs)
        return "bounded assignment prompt"

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "d1")
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: descriptor)
    monkeypatch.setattr(server, "skill_matches", lambda *_args: [])
    monkeypatch.setattr(server, "scope_check", lambda *_args: {"allowed": True})
    monkeypatch.setattr(server, "assignment_prompt", fake_prompt)
    monkeypatch.setattr(server, "current_fleet_service", lambda: FakeService(_snapshot(Path("/tmp"))))
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


def test_headless_retry_policy_refreshes_managed_home_marker(tmp_path: Path) -> None:
    settings_path = tmp_path / ".gemini" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        '{"general":{"maxAttempts":1,"retryFetchErrors":false}}\n',
        encoding="utf-8",
    )
    marker_path = tmp_path / server.FLEET_AGENT_MARKER_FILE
    marker_path.write_text(
        json.dumps({"files": {".gemini/settings.json": "0" * 64}}) + "\n",
        encoding="utf-8",
    )
    marker_path.chmod(0o600)

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
    service.reserve_gemini_request.return_value = object()

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

    monkeypatch.setattr(server, "canonical_agent_id", lambda _agent: "i1")
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


def test_gemini_bootstrap_plan_is_dry_and_secret_free() -> None:
    result = server.fleet_gemini_bootstrap_plan()

    assert result["status"] == "provider_probe_required"
    assert result["account_count"] == 3
    assert result["series_count"] == 3
    assert [item["prefix"] for item in result["series"]] == ["d", "e", "f"]
    assert "secret" not in repr(result)
    assert "private-secret" not in repr(result)
