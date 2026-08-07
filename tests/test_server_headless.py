from __future__ import annotations

import io
import hashlib
import json
import signal
from contextlib import nullcontext
from dataclasses import dataclass
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
from codex_master.fleet_service import AccountGateDecision


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

    def account_gate(self, _agent: str) -> AccountGateDecision:
        return AccountGateDecision(True, "ready", "gemini-project", self.snapshot.generation)

    def load(self) -> FleetSnapshot:
        return self.snapshot

    def read_secret(self, _account_id: str, *, expected_generation: int) -> str:
        assert expected_generation == self.snapshot.generation
        return self.secret

    def mark_limited(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("limit marking was not expected")

    def reserve_gemini_request(self, account_id: str) -> object:
        return (account_id, "reservation")

    def release_gemini_request(self, *_args: object, **_kwargs: object) -> None:
        return None


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
    fake_service = FakeService(snapshot)
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
    assert process.stdin.closed_value == b"private prompt"
    assert result["response"] == "answer"
    assert result["status"] == "completed"
    assert captured_env["GEMINI_API_KEY"] == "private-secret"
    assert captured_env["HOME"] == str(tmp_path / "d1")
    assert metadata["headless_job"]["state"] == "completed"  # type: ignore[index]
    assert "private prompt" not in repr(metadata)
    assert "private-secret" not in repr(metadata)


def test_headless_start_only_reserves_a_ready_slot(monkeypatch) -> None:
    descriptor = AgentDescriptor(
        "d1", "d", 1, "Gemini 1", RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
        "gemini-3-flash-preview", "gemini-project", Path("/tmp/d1"),
        "codex_agent_d1_mcp", True, Path("/tmp/gemini"),
    )
    inventory = type("Inventory", (), {"agents": {"d1": descriptor}})()
    service = Mock()
    service.account_gate.return_value = AccountGateDecision(True, "ready", "gemini-project", 9)
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
    assert marker["state"] == "ready"


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


def test_headless_assignment_passes_subagent_admission_to_prompt(monkeypatch) -> None:
    descriptor = type("Descriptor", (), {"model": "gemini-3-flash-preview"})()
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
    assert settings["general"] == {"maxAttempts": 2, "retryFetchErrors": False}
    assert settings["privacy"]["usageStatisticsEnabled"] is False


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


def test_gemini_bootstrap_plan_is_dry_and_secret_free() -> None:
    result = server.fleet_gemini_bootstrap_plan()

    assert result["status"] == "provider_probe_required"
    assert result["account_count"] == 3
    assert result["series_count"] == 3
    assert [item["prefix"] for item in result["series"]] == ["d", "e", "f"]
    assert "secret" not in repr(result)
    assert "private-secret" not in repr(result)
