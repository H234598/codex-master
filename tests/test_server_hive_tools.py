import contextlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_master import server
from codex_master.hive.dispatch import HiveDispatchError
from codex_master.hive.events import HiveEventStore
from codex_master.hive.messages import validate_message
from codex_master.hive.config import load_agent_class_catalog, load_hive_config


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
GREEN_HIVE_PROBE = {
    "allowed": True,
    "reason_code": "probe_ready",
    "raw_output": "not_returned",
}


@pytest.mark.parametrize(
    "reason_code",
    ("probe_missing", "probe_stale", "probe_invalid", "probe_red"),
)
def test_server_hive_probe_gate_rejects_every_non_green_probe(reason_code: str) -> None:
    with patch.object(
        server,
        "read_probe_gate",
        return_value={
                "allowed": False,
                "reason_code": reason_code,
                "raw_output": "not_returned",
        },
    ), pytest.raises(server.AgentError, match="hive_spawn_probe_blocked") as raised:
        server.require_hive_probe_for_spawn(operation="agent_start")
    assert raised.value.payload == {
        "error_code": "hive_spawn_probe_blocked",
        "operation": "agent_start",
        "reason_code": reason_code,
        "raw_output": "not_returned",
    }


def test_server_hive_probe_gate_requires_exact_fresh_green_result() -> None:
    with patch.object(
        server,
        "read_probe_gate",
        return_value={"allowed": False, "reason_code": "probe_stale", "raw_output": "not_returned"},
    ):
        with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked") as raised:
            server.require_hive_probe_for_spawn(operation="agent_start")
    assert raised.value.payload == {
        "error_code": "hive_spawn_probe_blocked",
        "operation": "agent_start",
        "reason_code": "probe_stale",
        "raw_output": "not_returned",
    }

    with patch.object(
        server,
        "read_probe_gate",
        return_value={"allowed": True, "reason_code": "probe_ready", "raw_output": "not_returned"},
    ):
        result = server.require_hive_probe_for_spawn(operation="agent_start")
    assert result["allowed"] is True
    assert result["reason_code"] == "probe_ready"


def test_server_hive_probe_gate_has_no_injectable_green_dto() -> None:
    with pytest.raises(TypeError):
        server.require_hive_probe_for_spawn(
            operation="native_spawn",
            probe_gate=GREEN_HIVE_PROBE,
        )


@pytest.mark.parametrize(
    "probe_gate",
    (
        {"allowed": True, "reason_code": "probe_stale", "raw_output": "not_returned"},
        {"allowed": True, "reason_code": "probe_ready", "raw_output": "returned"},
        {"allowed": True, "reason_code": "probe_ready", "raw_output": "not_returned", "extra": True},
    ),
)
def test_server_hive_probe_gate_rejects_malformed_green_claims(probe_gate: dict[str, object]) -> None:
    with patch.object(
        server, "read_probe_gate", return_value=probe_gate
    ), pytest.raises(server.AgentError, match="hive_spawn_probe_blocked") as raised:
        server.require_hive_probe_for_spawn(operation="agent_start")

    assert raised.value.payload == {
        "error_code": "hive_spawn_probe_blocked",
        "operation": "agent_start",
        "reason_code": "probe_gate_unavailable",
        "raw_output": "not_returned",
    }


def test_spawn_entrypoints_check_hive_probe_before_reservation_or_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    recovery_gates: list[str] = []

    def blocked(*, operation: str, **_kwargs: object) -> dict[str, object]:
        calls.append(operation)
        raise server.AgentError("hive_spawn_probe_blocked")

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", blocked)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: object())
    monkeypatch.setattr(
        server,
        "emergency_queen_status",
        lambda: {"state": "requested", "generation": 1, "current_plan": None},
    )
    monkeypatch.setattr(
        server,
        "set_emergency_queen_blocked",
        lambda *_args, **_kwargs: {"state": "blocked"},
    )

    def blocked_recovery_gate(operation: str) -> None:
        recovery_gates.append(operation)
        blocked(operation=operation)

    monkeypatch.setattr(server, "require_fleet_recovery_ready", blocked_recovery_gate)

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.start_agent_with_lease("a1")
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.assign_agent(
            "a1",
            role="arbeitsbiene",
            task="task",
            scope=["src"],
            write_paths=["src/task.py"],
        )
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server._start_headless_agent_unlocked("d1")
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server._assign_headless_agent(
            "d1", role="exploriererin", task="task", scope=["src"]
        )
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.run_headless_assignment("d1", "task", {}, 1)
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.reserve_managed_replacement("session-one")
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.reserve_headless_inflight("agent-one", "assignment-one")
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.reserve_native_agent_spawn(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "spawn_agent",
                "session_id": "parent",
            }
        )
    assert server.ensure_emergency_queen()["status"] == "blocked"
    mcp_start_result = server.call_tool("agent_start", {"agent": "a1"})
    assert mcp_start_result["results"][0]["error"] == "hive_spawn_probe_blocked"
    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.call_tool(
            "agent_assign_readonly", {"agent": "a1", "scope": ["src"], "task": "task"}
        )

    assert calls == [
        "agent_start",
        "agent_assign",
        "agent_start",
        "agent_assign",
        "headless_assignment",
        "managed_replacement",
        "headless_assignment",
        "native_spawn",
        "agent_start",
        "agent_assign",
    ]
    assert recovery_gates == ["agent_start", "agent_assign"]


def test_red_probe_blocks_new_hive_side_effects_before_locks_or_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_operations: list[str] = []
    later_gates: list[str] = []
    lifecycle_lock_attempts: list[str] = []

    def blocked_probe(*, operation: str, **_kwargs: object) -> dict[str, object]:
        probe_operations.append(operation)
        raise server.AgentError("hive_spawn_probe_blocked")

    def recovery_after_probe() -> dict[str, object]:
        later_gates.append("fleet_recovery_status")
        raise AssertionError("recovery gate ran after a red probe")

    class UnexpectedLifecycleLock:
        def __enter__(self) -> None:
            lifecycle_lock_attempts.append("agent_lifecycle_lock")
            raise AssertionError("lifecycle mutation started after a red probe")

        def __exit__(self, *_args: object) -> bool:
            return False

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", blocked_probe)
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: object())
    monkeypatch.setattr(server, "fleet_recovery_status", recovery_after_probe)
    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: UnexpectedLifecycleLock(),
    )
    attempts = (
        ("agent_claim", lambda: server.claim_agent("a1")),
        ("agent_assign", lambda: server.assign_agent("a1", role="arbeitsbiene", task="task", scope=["src"], write_paths=["src/task.py"])),
        ("agent_start", lambda: server.start_agent_with_lease("a1")),
    )
    for expected_operation, attempt in attempts:
        with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
            attempt()

    assert probe_operations == [operation for operation, _attempt in attempts]
    assert later_gates == []
    assert lifecycle_lock_attempts == []


def test_red_probe_allows_account_limit_auth_secret_configuration_and_skill_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resource evidence is not an administrative or diagnostic lockout."""

    class AccountProbeReached(RuntimeError):
        pass

    class AccountConfigurationReached(RuntimeError):
        pass

    class AccountSecretReached(RuntimeError):
        pass

    class SkillSyncReached(RuntimeError):
        pass

    class AccountProbeService:
        @staticmethod
        def probe_account(*_args: object, **_kwargs: object) -> None:
            raise AccountProbeReached()

    class AccountConfigurationService:
        @staticmethod
        def load() -> None:
            raise AccountConfigurationReached()

    class AccountSecretService:
        @staticmethod
        def set_secret(*_args: object, **_kwargs: object) -> None:
            raise AccountSecretReached()

    class SkillSyncService:
        @staticmethod
        def load() -> None:
            raise SkillSyncReached()

    def capacity_gate_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pure administration consulted the resource-capacity gate")

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "require_hive_probe_for_spawn", capacity_gate_used)
    monkeypatch.setattr(server, "hive_capacity_probe_guard", capacity_gate_used)
    monkeypatch.setattr(
        server,
        "fleet_recovery_status",
        lambda: {"state": "ready", "blocking": False},
    )

    monkeypatch.setattr(server, "current_fleet_service", AccountProbeService)
    with pytest.raises(AccountProbeReached):
        server.fleet_account_probe(account_id="account-one", expected_generation=1)

    monkeypatch.setattr(server, "current_fleet_service", AccountConfigurationService)
    with pytest.raises(AccountConfigurationReached):
        server.fleet_account_upsert(
            account_id="account-one",
            label="Account one",
            provider="openai_chatgpt",
            auth_kind="none",
            enabled=True,
            expected_generation=1,
        )

    monkeypatch.setattr(server, "current_fleet_service", AccountSecretService)
    with pytest.raises(AccountSecretReached):
        server.fleet_account_set_secret(
            account_id="account-one", secret="test-only", expected_generation=1
        )

    monkeypatch.setattr(server, "current_fleet_service", SkillSyncService)
    with pytest.raises(SkillSyncReached):
        server.fleet_sync_skill_projections()


def test_red_probe_reaches_fleet_series_delete_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TeardownReached(Exception):
        pass

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "current_fleet_service",
        lambda: (_ for _ in ()).throw(TeardownReached()),
    )

    with pytest.raises(TeardownReached):
        server.fleet_series_delete(
            prefix="d",
            expected_generation=1,
            confirmed_remove_ids=["d1"],
            yes=True,
        )


def test_red_probe_allows_absent_home_delete_reservations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Delete-only reservations never materialize a runnable fleet home."""

    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"

    def capacity_guard_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("delete reservation consulted the resource-capacity gate")

    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "LOCK_DIR", state_root / "locks")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "hive_capacity_probe_guard", capacity_guard_used)

    reservations = server._fleet_reserve_absent_homes(["d1"])

    assert (pool_root / "d1").is_dir()
    assert server._fleet_release_reservations(reservations) is True
    assert not (pool_root / "d1").exists()


def test_red_probe_blocks_series_create_before_starting_a_recovery_journal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned: list[str] = []

    def blocked_probe(*, operation: str, **_kwargs: object) -> None:
        planned.append(operation)
        raise server.AgentError("hive_spawn_probe_blocked")

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", blocked_probe)
    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(server, "current_fleet_service", lambda: object())
    monkeypatch.setattr(
        server,
        "_fleet_series_plan_with_service",
        lambda *_args, **_kwargs: (
            {},
            object(),
            object(),
            None,
            object(),
            {"create_ids": ["d1"]},
        ),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.fleet_series_apply(
            prefix="d",
            count=1,
            runner="codex_cli",
            provider="ollama_local",
            model="model",
            account_id=None,
            expected_generation=1,
        )

    assert planned == ["fleet_series_apply"]


def test_native_reservation_rechecks_the_probe_at_the_registry_write_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_state = {"green": True}
    writes: list[dict[str, object]] = []

    @contextlib.contextmanager
    def flip_probe_after_precheck():
        probe_state["green"] = False
        yield

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: GREEN_HIVE_PROBE
        if probe_state["green"]
        else {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "spawn_admission_lock", flip_probe_after_precheck)
    monkeypatch.setattr(server, "native_agent_registry_lock", contextlib.nullcontext)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(server, "spawn_admission_decision", lambda: {"allowed": True})
    monkeypatch.setattr(
        server,
        "_read_native_agent_registry",
        lambda: (
            {
                "sessions": [
                    {
                        "session_id": "a1",
                        "activity_state": "active",
                        "updated_at": server.time.time(),
                    }
                ],
                "reservations": [],
            },
            "ready",
        ),
    )
    monkeypatch.setattr(
        server,
        "_write_native_agent_registry",
        lambda payload: writes.append(payload),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.reserve_native_agent_spawn(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "spawn_agent",
                "session_id": "a1",
            }
        )
    assert writes == []


def test_lifecycle_start_rechecks_the_probe_after_the_agent_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_state = {"green": True}

    @contextlib.contextmanager
    def flip_probe_after_lock(*_args: object, **_kwargs: object):
        probe_state["green"] = False
        yield

    def sink_reached(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("start sink ran after a red probe")

    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(server, "agent_lifecycle_lock", flip_probe_after_lock)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: GREEN_HIVE_PROBE
        if probe_state["green"]
        else {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "_start_agent_unlocked", sink_reached)

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.start_agent("a1")


def test_applet_start_rechecks_the_probe_after_the_agent_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_state = {"green": True}

    @contextlib.contextmanager
    def flip_probe_after_lock(*_args: object, **_kwargs: object):
        probe_state["green"] = False
        yield

    def sink_reached(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("applet start sink ran after a red probe")

    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(server, "agent_lifecycle_lock", flip_probe_after_lock)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: GREEN_HIVE_PROBE
        if probe_state["green"]
        else {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "read_applet_action_key", lambda: b"key")
    monkeypatch.setattr(
        server,
        "validate_applet_action_token",
        lambda *_args: {"a": "start", "g": "a1", "f": "fingerprint"},
    )
    monkeypatch.setattr(server, "applet_agent_observation", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "codex_usage_watchdog_status", lambda *_args: {})
    monkeypatch.setattr(server, "read_meta", lambda *_args: {})
    monkeypatch.setattr(server, "applet_action_state", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "applet_action_fingerprint_for", lambda *_args: "fingerprint")
    monkeypatch.setattr(server, "applet_action_allowed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(server, "_start_agent_with_lease_unlocked", sink_reached)

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.applet_action("start", "a1", "context-token")


def test_lifecycle_lease_start_rechecks_the_probe_after_the_agent_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_state = {"green": True}

    @contextlib.contextmanager
    def flip_probe_after_lock(*_args: object, **_kwargs: object):
        probe_state["green"] = False
        yield

    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(server, "agent_lifecycle_lock", flip_probe_after_lock)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: GREEN_HIVE_PROBE
        if probe_state["green"]
        else {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "_start_agent_with_lease_unlocked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("lease start sink ran after a red probe")
        ),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.start_agent_with_lease("a1")


def test_direct_headless_start_rechecks_before_the_process_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def green_precheck(**_kwargs: object) -> dict[str, object]:
        probe_state["green"] = False
        return GREEN_HIVE_PROBE

    probe_state = {"green": True}
    monkeypatch.setattr(server, "require_hive_probe_for_spawn", green_precheck)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: GREEN_HIVE_PROBE
        if probe_state["green"]
        else {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "_run_headless_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("headless process sink ran after a red probe")
        ),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.run_headless_assignment("a1", "task", {}, 1)


def test_fleet_home_creation_rechecks_probe_before_mkdir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    root_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
            server._fleet_create_home(root_fd, "a1", {})
    finally:
        os.close(root_fd)

    assert not (tmp_path / "a1").exists()


def test_capacity_guard_does_not_relabel_a_sink_oserror_as_probe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(server, "read_probe_gate", lambda: GREEN_HIVE_PROBE)

    with pytest.raises(OSError, match="sink failure"):
        with server.hive_capacity_probe_guard("agent_start"):
            raise OSError("sink failure")


def test_new_lease_claim_rechecks_probe_before_writing_a_new_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "ensure_state", lambda: None)
    monkeypatch.setattr(server, "read_agent_lease_record", lambda _agent: None)
    monkeypatch.setattr(
        server,
        "write_agent_lease",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("lease sink ran after a red probe")
        ),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server._claim_agent_unlocked("a1")


def test_red_probe_allows_real_control_lease_in_a_private_temp_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_root = tmp_path / "state"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "RAW_DIR", state_root / "raw")
    monkeypatch.setattr(server, "META_DIR", state_root / "meta")
    monkeypatch.setattr(server, "LOCK_DIR", state_root / "locks")
    monkeypatch.setattr(server, "LEASE_DIR", state_root / "leases")
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )

    with server.agent_lifecycle_lock("a1"):
        claim = server._claim_agent_unlocked(
            "a1", ttl_seconds=60, enforce_recovery_gate=False
        )

    assert claim["status"] == "claimed"
    assert claim["lease"]["state"] == "held"
    assert claim["lease"]["held_by_this_server"] is True
    assert (state_root / "leases" / "a1.json").is_file()


def test_red_probe_allows_pure_send_and_report_to_a_running_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Completed:
        returncode = 0

    def capacity_or_recovery_gate_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pure communication must not use a capacity gate")

    monkeypatch.setattr(
        server, "require_hive_probe_for_spawn", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(
        server, "require_fleet_recovery_ready", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(
        server, "hive_capacity_probe_guard", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(
        server, "agent_lifecycle_lock", lambda *_args, **_kwargs: contextlib.nullcontext()
    )
    monkeypatch.setattr(server, "require_invocation_status", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "agent_config", lambda _agent: {"session": "a1"})
    monkeypatch.setattr(server, "tmux_alive", lambda _session: True)
    monkeypatch.setattr(server, "require_managed_tmux_session", lambda _agent: None)
    monkeypatch.setattr(
        server,
        "wait_agent_input_ready",
        lambda *_args, **_kwargs: {"ready": True},
    )
    monkeypatch.setattr(server, "run_tmux", lambda *_args, **_kwargs: Completed())
    monkeypatch.setattr(
        server, "_tmux_args_for_session", lambda _session, args: list(args)
    )
    monkeypatch.setattr(server, "list_assignments", lambda *_args, **_kwargs: {"records": []})
    monkeypatch.setattr(
        server,
        "agent_lease_status",
        lambda _agent: {"state": "unclaimed", "raw_output": "not_returned"},
    )

    assert server.send_agent("a1", "status")["status"] == "sent"
    assert server.request_agent_report("a1")["status"] == "report_requested"


def test_red_probe_allows_agent_assign_that_only_sends_to_a_running_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OllamaDescriptor:
        model = "local-model"

    def capacity_or_recovery_gate_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("send-only assignment must not use a capacity gate")

    monkeypatch.setattr(
        server, "require_hive_probe_for_spawn", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(
        server, "require_fleet_recovery_ready", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(
        server, "hive_capacity_probe_guard", capacity_or_recovery_gate_used
    )
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: None)
    monkeypatch.setattr(server, "_ollama_descriptor", lambda _agent: OllamaDescriptor())
    monkeypatch.setattr(
        server,
        "spawn_admission_decision",
        lambda *_args, **_kwargs: {"allowed": True, "reason_codes": []},
    )
    monkeypatch.setattr(
        server, "agent_lifecycle_lock", lambda *_args, **_kwargs: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        server, "_resource_gate_composer_scope", lambda: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        server,
        "claim_for_agent_mutation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("send-only assignment claimed new capacity")
        ),
    )
    monkeypatch.setattr(
        server,
        "agent_lease_status",
        lambda _agent: {"state": "unclaimed", "raw_output": "not_returned"},
    )
    monkeypatch.setattr(
        server,
        "ensure_assignment_session_model",
        lambda *_args, **_kwargs: {
            "status": "unchanged",
            "previous_model": "local-model",
            "model": "local-model",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "send_agent",
        lambda *_args, **_kwargs: {"status": "sent", "raw_output": "not_returned"},
    )
    monkeypatch.setattr(server, "record_assignment", lambda _record: None)

    result = server.assign_agent(
        "a1", role="exploriererin", task="status", scope=["src"]
    )

    assert result["status"] == "assigned"
    assert result["send"]["status"] == "sent"


def test_red_probe_blocks_assignment_model_switch_before_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "agent_config", lambda _agent: {"session": "a1"})
    monkeypatch.setattr(server, "tmux_alive", lambda _session: True)
    monkeypatch.setattr(server, "require_managed_tmux_session", lambda _agent: None)
    monkeypatch.setattr(server, "_ollama_descriptor", lambda _agent: None)
    monkeypatch.setattr(
        server,
        "read_meta",
        lambda _agent: {"model": "old-model", "model_reasoning_effort": "low"},
    )
    monkeypatch.setattr(
        server,
        "status_agent",
        lambda _agent: (_ for _ in ()).throw(
            AssertionError("model-switch stop branch ran after a red probe")
        ),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.ensure_assignment_session_model(
            "a1",
            model="new-model",
            reasoning_effort="low",
            lease={"state": "unclaimed", "held_by_this_server": False},
        )


def test_red_probe_allows_safe_stop_interrupt_release_and_applet_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle_lock_attempts: list[str] = []

    class LifecycleLock:
        def __enter__(self) -> None:
            lifecycle_lock_attempts.append("entered")

        def __exit__(self, *_args: object) -> bool:
            return False

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: LifecycleLock(),
    )
    monkeypatch.setattr(server, "_stop_agent_unlocked", lambda *_args, **_kwargs: {"status": "stopped"})
    monkeypatch.setattr(server, "_interrupt_agent_unlocked", lambda *_args, **_kwargs: {"status": "interrupted"})
    monkeypatch.setattr(server, "_release_agent_unlocked", lambda *_args, **_kwargs: {"status": "released"})

    assert server.stop_agent("a1")["status"] == "stopped"
    assert server.interrupt_agent("a1")["status"] == "interrupted"
    assert server.release_agent("a1")["status"] == "released"

    class AppletStopReached(RuntimeError):
        pass

    class AppletStopLock:
        def __enter__(self) -> None:
            lifecycle_lock_attempts.append("applet_stop")
            raise AppletStopReached()

        def __exit__(self, *_args: object) -> bool:
            return False

    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: AppletStopLock(),
    )
    with pytest.raises(AppletStopReached):
        server.applet_action("stop", "a1", "context-token")

    assert lifecycle_lock_attempts == ["entered", "entered", "entered", "applet_stop"]

    applet_claims: list[dict[str, object]] = []
    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(server, "read_applet_action_key", lambda: b"key")
    monkeypatch.setattr(
        server,
        "validate_applet_action_token",
        lambda *_args: {"a": "stop", "g": "a1", "f": "fingerprint"},
    )
    monkeypatch.setattr(server, "applet_agent_observation", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "codex_usage_watchdog_status", lambda *_args: {})
    monkeypatch.setattr(server, "read_meta", lambda *_args: {})
    monkeypatch.setattr(server, "applet_action_state", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "applet_action_fingerprint_for", lambda *_args: "fingerprint")
    monkeypatch.setattr(server, "applet_action_allowed", lambda *_args, **_kwargs: True)

    def safe_shutdown_claim(*_args: object, **kwargs: object) -> dict[str, object]:
        applet_claims.append(kwargs)
        return {"lease": {}}

    monkeypatch.setattr(server, "_claim_agent_unlocked", safe_shutdown_claim)
    assert server.applet_action("stop", "a1", "context-token")["status"] == "completed"
    assert applet_claims == [{"ttl_seconds": 60, "enforce_recovery_gate": False}]


def test_red_probe_blocks_applet_start_before_the_start_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def start_sink_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("applet start reached its start sink after a red probe")

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(
        server, "agent_lifecycle_lock", lambda *_args, **_kwargs: contextlib.nullcontext()
    )
    monkeypatch.setattr(server, "read_applet_action_key", lambda: b"key")
    monkeypatch.setattr(
        server,
        "validate_applet_action_token",
        lambda *_args: {"a": "start", "g": "a1", "f": "fingerprint"},
    )
    monkeypatch.setattr(server, "applet_agent_observation", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "codex_usage_watchdog_status", lambda *_args: {})
    monkeypatch.setattr(server, "read_meta", lambda *_args: {})
    monkeypatch.setattr(server, "applet_action_state", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        server, "applet_action_fingerprint_for", lambda *_args: "fingerprint"
    )
    monkeypatch.setattr(server, "applet_action_allowed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(server, "_start_agent_with_lease_unlocked", start_sink_used)

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server.applet_action("start", "a1", "context-token")


def test_red_probe_allows_interrupt_after_a_safe_shutdown_lease_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_shutdown_claims: list[dict[str, object]] = []

    class Process:
        returncode = 0

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(server, "_headless_descriptor", lambda _agent: None)
    monkeypatch.setattr(
        server,
        "agent_config",
        lambda _agent, *_args: {"session": "a1"},
    )
    monkeypatch.setattr(server, "tmux_alive", lambda _session: True)
    monkeypatch.setattr(server, "require_managed_tmux_session", lambda _agent: None)
    monkeypatch.setattr(
        server,
        "_tmux_args_for_session",
        lambda _session, arguments, **_kwargs: arguments,
    )
    monkeypatch.setattr(server, "run_tmux", lambda *_args, **_kwargs: Process())

    def safe_shutdown_claim(*_args: object, **kwargs: object) -> dict[str, object]:
        safe_shutdown_claims.append(kwargs)
        return {"status": "claimed", "lease": {"lease_id": "lease-one"}}

    monkeypatch.setattr(server, "_claim_agent_unlocked", safe_shutdown_claim)

    assert server.interrupt_agent("a1")["status"] == "interrupt_sent"
    assert safe_shutdown_claims == [{"enforce_recovery_gate": False}]


def test_red_probe_allows_dedicated_g_migration_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    def unexpected_probe_gate(**_kwargs: object) -> None:
        raise AssertionError("dedicated recovery consulted the spawn probe")

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", unexpected_probe_gate)
    monkeypatch.setattr(server, "_g_migration_paths", lambda _service: object())
    monkeypatch.setattr(
        server,
        "fleet_mutation_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(server, "_g_migration_read_journal", lambda *_args: None)

    assert server._recover_g_series_migration_for_authorized_caller(
        service=object(), pool_root=tmp_path
    ) is None


def test_red_probe_allows_existing_g_migration_journal_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    journal = object()
    recovered = object()

    class Service:
        @staticmethod
        def load() -> object:
            return object()

    def unexpected_probe_gate(**_kwargs: object) -> None:
        raise AssertionError("existing migration journal consulted the spawn probe")

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", unexpected_probe_gate)
    monkeypatch.setattr(server, "_g_migration_paths", lambda _service: object())
    monkeypatch.setattr(
        server,
        "fleet_mutation_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(server, "_g_migration_read_journal", lambda *_args: journal)
    monkeypatch.setattr(
        server,
        "_g_migration_recover_locked",
        lambda *_args: recovered,
    )

    assert server._apply_g_series_migration_for_authorized_caller(
        service=Service(), manifest=object(), pool_root=tmp_path
    ) is recovered


def test_red_probe_recovers_a_pending_q_transaction_before_journal_blocks_new_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovered: list[object] = []

    def blocked_probe(**_kwargs: object) -> None:
        raise server.AgentError("hive_spawn_probe_blocked")

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", blocked_probe)
    monkeypatch.setattr(server, "current_fleet_service", lambda: object())
    monkeypatch.setattr(
        server,
        "fleet_mutation_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        server,
        "_fleet_recover_pending_q_inplace",
        lambda service, paths: recovered.append((service, paths)),
    )

    with pytest.raises(server.FleetRecoveryBlockedError, match="fleet_recovery_pending"):
        server.fleet_series_apply(
            prefix="q",
            count=1,
            runner="codex_cli",
            provider="ollama_local",
            model="model",
            account_id=None,
            expected_generation=1,
        )

    assert len(recovered) == 1


def test_red_probe_allows_recovery_then_worktree_management(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resumed: list[str] = []

    class WorktreeReached(RuntimeError):
        pass

    def capacity_gate_used(**_kwargs: object) -> None:
        raise AssertionError("worktree management consulted the resource-capacity gate")

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(server, "require_hive_probe_for_spawn", capacity_gate_used)
    monkeypatch.setattr(server, "hive_capacity_probe_guard", capacity_gate_used)
    monkeypatch.setattr(
        server,
        "fleet_recovery_status",
        lambda: {"state": "ready", "blocking": False},
    )
    monkeypatch.setattr(
        server,
        "_resume_headless_rollback_records",
        lambda: resumed.append("resumed"),
    )
    monkeypatch.setattr(
        server,
        "canonical_agent_id",
        lambda _agent: (_ for _ in ()).throw(WorktreeReached()),
    )

    with pytest.raises(WorktreeReached):
        server.worktree_create_for_agent("a1")

    assert resumed == ["resumed"]


def test_red_probe_allows_existing_home_cutover_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_master.fleet_home_v2_cutover import FleetHomeV2PlanHandle

    class ProductCore:
        @staticmethod
        def apply(_handle: FleetHomeV2PlanHandle) -> dict[str, str]:
            return {"operation": "apply"}

        @staticmethod
        def verify(_handle: FleetHomeV2PlanHandle) -> dict[str, str]:
            return {"operation": "verify"}

        @staticmethod
        def recover(_handle: FleetHomeV2PlanHandle) -> dict[str, str]:
            return {"operation": "recover"}

        @staticmethod
        def rollback(_handle: FleetHomeV2PlanHandle) -> dict[str, str]:
            return {"operation": "rollback"}

    def capacity_gate_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("existing-home cutover consulted the resource-capacity gate")

    handle = object.__new__(FleetHomeV2PlanHandle)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server, "require_resource_capacity_preflight", capacity_gate_used
    )
    monkeypatch.setattr(server, "hive_capacity_probe_guard", capacity_gate_used)
    monkeypatch.setattr(
        server,
        "fleet_recovery_status",
        lambda: {"state": "ready", "blocking": False},
    )
    monkeypatch.setattr(server, "_fleet_home_v2_product_service", ProductCore)

    for operation in ("apply", "verify", "recover", "rollback"):
        assert server.fleet_home_v2_cutover_operation(
            operation=operation, plan_handle=handle
        ) == {"operation": operation}


def test_red_probe_blocks_direct_headless_process_before_provider_or_popen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fleet_service_attempts: list[str] = []
    popen_attempts: list[str] = []

    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": False,
            "reason_code": "probe_red",
            "raw_output": "not_returned",
        },
    )
    monkeypatch.setattr(
        server,
        "current_fleet_service",
        lambda: fleet_service_attempts.append("fleet") or object(),
    )
    monkeypatch.setattr(
        server.subprocess,
        "Popen",
        lambda *_args, **_kwargs: popen_attempts.append("popen"),
    )

    with pytest.raises(server.AgentError, match="hive_spawn_probe_blocked"):
        server._run_headless_process(
            "d1",
            "prompt",
            {"state": "held", "held_by_this_server": True},
            5,
            role="exploriererin",
        )

    assert fleet_service_attempts == []
    assert popen_attempts == []


def test_red_probe_allows_dry_run_watchdogs_and_emergency_queen_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_probe_gate(**_kwargs: object) -> None:
        raise AssertionError("read-only diagnostic consulted the spawn probe")

    class FleetService:
        @staticmethod
        def gemini_usage_watchdog() -> dict[str, object]:
            return {
                "provider": "gemini_api",
                "state": "ready",
                "accounts": [],
                "stale_or_unknown_accounts": [],
                "raw_output": "not_returned",
            }

    monkeypatch.setattr(server, "require_hive_probe_for_spawn", unexpected_probe_gate)
    monkeypatch.setattr(server, "agent_ids", lambda _agent: [])
    monkeypatch.setattr(server, "current_agent_inventory", lambda: object())
    monkeypatch.setattr(server, "create_fleet_snapshot", lambda **_kwargs: None)
    monkeypatch.setattr(server, "current_fleet_service", FleetService)

    assert server.fleet_usage_watchdog(dry_run=True)["result_count"] == 0
    assert server.fleet_watchdog(dry_run=True, action="none")["status"] == "ok"

    monkeypatch.setattr(
        server,
        "emergency_queen_status",
        lambda: {"state": "requested", "generation": 1, "current_plan": None},
    )
    monkeypatch.setattr(server, "_emergency_queen_agent_candidates", lambda: ["q1"])
    assert server.ensure_emergency_queen(dry_run=True)["status"] == "would_start"


def test_red_probe_routes_watchdogs_to_safe_shutdown_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_only_modes: list[bool] = []

    class FleetService:
        @staticmethod
        def gemini_usage_watchdog() -> dict[str, object]:
            return {
                "provider": "gemini_api",
                "state": "ready",
                "accounts": [],
                "stale_or_unknown_accounts": [],
                "raw_output": "not_returned",
            }

    def blocked_gate(_operation: str) -> None:
        raise server.AgentError("hive_spawn_probe_blocked")

    def run_selected(selected: list[str], callback: object) -> dict[str, object]:
        assert callable(callback)
        return {"results": [callback(agent) for agent in selected]}

    def safe_watchdog(*_args: object, safe_shutdown_only: bool, **_kwargs: object) -> dict[str, object]:
        safe_only_modes.append(safe_shutdown_only)
        return {"status": "safe"}

    def safe_usage(*_args: object, safe_shutdown_only: bool, **_kwargs: object) -> dict[str, object]:
        safe_only_modes.append(safe_shutdown_only)
        return {"status": "safe"}

    monkeypatch.setattr(server, "require_fleet_recovery_ready", blocked_gate)
    monkeypatch.setattr(server, "agent_ids", lambda _agent: ["a1"])
    monkeypatch.setattr(server, "current_agent_inventory", lambda: object())
    monkeypatch.setattr(server, "agent_config", lambda *_args: {"home": "/tmp", "session": "a1"})
    monkeypatch.setattr(server, "create_fleet_snapshot", lambda **_kwargs: None)
    monkeypatch.setattr(server, "multi_agent_result", run_selected)
    monkeypatch.setattr(
        server,
        "call_agent_lifecycle",
        lambda _agent, callback: callback(),
    )
    monkeypatch.setattr(server, "_watchdog_agent_unlocked", safe_watchdog)
    monkeypatch.setattr(server, "_usage_watchdog_agent_unlocked", safe_usage)
    monkeypatch.setattr(server, "current_fleet_service", FleetService)
    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(
        server,
        "agent_lifecycle_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )

    assert server.fleet_watchdog(dry_run=False, action="interrupt")["status"] == "ok"
    assert server.fleet_usage_watchdog(dry_run=False)["result_count"] == 1
    assert server.watchdog_agent(
        "a1",
        idle_seconds=1,
        action="interrupt",
        report_grace_seconds=1,
        require_lease=True,
        manage_unclaimed=False,
        dry_run=False,
    )["status"] == "safe"
    assert server.usage_watchdog_agent("a1", dry_run=False)["status"] == "safe"
    assert safe_only_modes == [True, True, True, True]


def test_server_exposes_additive_read_only_hive_tools() -> None:
    names = {tool["name"] for tool in server.TOOLS}
    assert {
        "hive_status",
        "godbee_status",
        "queen_list",
        "agent_selection_status",
        "hive_test_index_status",
        "hive_test_plan",
        "hive_test_run",
        "hive_test_status",
        "hive_test_invalidate",
    } <= names
    assert server.call_validated_tool("hive_status", {})["raw_output"] == "not_returned"


def test_server_runtime_factory_can_forward_read_only_assembly() -> None:
    classes = load_agent_class_catalog(server.repo_root() / "codex-agent-classes.json")
    config = load_hive_config(server.repo_root() / "codex-hive.json", classes)
    with patch.object(server, "load_agent_class_catalog", return_value=classes), patch.object(
        server, "load_hive_config", return_value=config
    ), patch.object(server, "build_hive_runtime", return_value=object()) as builder:
        result = server.build_current_hive_runtime(repository_roots={}, read_only=True)

    assert result is not None
    builder.assert_called_once_with(
        config,
        classes,
        repository_roots={},
        state_root=server.STATE_ROOT / "hive",
        materialize_principals=False,
        read_only=True,
        now=None,
    )


def test_server_denies_test_mutations_without_queen_or_teamlead_principal() -> None:
    with pytest.raises(server.AgentError, match="authority.scope_denied"):
        server.call_tool(
            "hive_test_run",
            {"test_id": "pytest:tests/test_x.py:test_x", "index_digest": "sha256:" + "a" * 64},
            principal_class="arbeitsbiene",
        )


def queen_workpackage(mode: str = "enforced") -> dict[str, object]:
    return {
        "workpackage_id": "workpackage-one", "repo_id": "codex-master",
        "teamlead_principal_id": "lead-one", "specialist_principal_id": "specialist-one",
        "writer_class_id": "spezialistin", "agent_id": "agent-one", "account_key": "sha256:" + "a" * 64,
        "model_id": "gpt-primary", "model_role": "primary", "task_complexity": "complex",
        "scope": ("src",), "write_paths": ("src/task.py",), "mode": mode,
        "pilot_enabled": True, "account_confirmed": True, "authority_verified": True,
        "repository_verified": True, "scope_verified": True, "lease_available": True,
        "selection_band": "none",
    }


def test_server_queen_adapter_is_closed_without_context_and_not_an_mcp_tool() -> None:
    with patch.object(server, "agent_lifecycle_lock", return_value=contextlib.nullcontext()), \
         patch.object(server, "hive_capacity_probe_guard", return_value=contextlib.nullcontext()):
        result = server.execute_server_queen_assignment(
            queen_id="queen-codex-master", dispatch_id="dispatch-one", workpackage=queen_workpackage()
        )
    assert result["reason_code"] == "pilot_gate_blocked"
    assert "execute_server_queen_assignment" not in {tool["name"] for tool in server.TOOLS}


def test_server_queen_adapter_accepts_only_explicit_injected_callbacks() -> None:
    events: list[str] = []
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64}, primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: events.append("teamlead") or "lead",
        create_specialist_principal=lambda _plan: events.append("specialist") or "specialist",
        issue_grant=lambda _plan: events.append("grant") or "grant",
        reserve_admission=lambda _plan: events.append("admission") or "admission",
        execute_assignment=lambda _plan: events.append("assignment") or {"status": "accepted"},
        compensate=lambda *_args: events.append("compensate"),
    )
    with patch.object(server, "agent_lifecycle_lock", return_value=contextlib.nullcontext()), \
         patch.object(server, "hive_capacity_probe_guard", return_value=contextlib.nullcontext()):
        result = server.execute_server_queen_assignment(
            queen_id="queen-codex-master", dispatch_id="dispatch-one", workpackage=queen_workpackage(), context=context
        )
        assert result["reason_code"] == "assignment_executed"
        assert events == ["teamlead", "specialist", "grant", "admission", "assignment"]
        with pytest.raises(HiveDispatchError, match="pilot_allowlist_denied"):
            server.execute_server_queen_assignment(
                queen_id="queen-codex-master", dispatch_id="dispatch-one",
                workpackage={**queen_workpackage(), "repo_id": "foreign-repo"}, context=context,
            )


def test_server_queen_bridge_rechecks_each_forward_sink_after_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks: list[str] = []
    compensated: list[str] = []
    probe_is_green = {"value": True}

    @contextlib.contextmanager
    def mutation_lock(_agent: str):
        probe_is_green["value"] = False
        yield

    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64}, primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: callbacks.append("teamlead"),
        create_specialist_principal=lambda _plan: callbacks.append("specialist"),
        issue_grant=lambda _plan: callbacks.append("grant"),
        reserve_admission=lambda _plan: callbacks.append("admission"),
        execute_assignment=lambda _plan: callbacks.append("assignment") or {"status": "unexpected"},
        compensate=lambda name, *_args: compensated.append(name),
    )
    monkeypatch.setattr(server, "agent_lifecycle_lock", mutation_lock)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": probe_is_green["value"],
            "reason_code": "probe_ready" if probe_is_green["value"] else "probe_red",
            "raw_output": "not_returned",
        },
    )

    result = server.execute_server_queen_assignment(
        queen_id="queen-codex-master", dispatch_id="dispatch-one", workpackage=queen_workpackage(), context=context
    )

    assert result["reason_code"] == "assignment_transaction_failed"
    assert callbacks == []
    assert compensated == ["teamlead"]


def test_server_queen_adapter_persists_queue_and_completion_events(tmp_path) -> None:
    events = HiveEventStore(tmp_path / "hive")
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64}, primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: "lead",
        create_specialist_principal=lambda _plan: "specialist",
        issue_grant=lambda _plan: "grant",
        reserve_admission=lambda _plan: "admission",
        execute_assignment=lambda _plan: {"status": "accepted"},
        compensate=lambda *_args: None,
    )

    with patch.object(server, "agent_lifecycle_lock", return_value=contextlib.nullcontext()), \
         patch.object(server, "hive_capacity_probe_guard", return_value=contextlib.nullcontext()):
        result = server.execute_server_queen_assignment(
            queen_id="queen-codex-master",
            dispatch_id="dispatch-one",
            workpackage=queen_workpackage(),
            context=context,
            event_store=events,
        )

    assert result["reason_code"] == "assignment_executed"
    _, report_events = events.read_report_sources()
    assert [event["status"] for event in report_events] == ["queued", "completed"]


def test_server_pause_preview_is_checkpointed_and_never_selection_driven() -> None:
    assert server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=False
    )["reason_code"] == "assignment_not_pausable"
    assert server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True, selection_source=True
    )["reason_code"] == "selection_preemption_forbidden"
    pending = server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True
    )
    assert pending["reason_code"] == "checkpoint_required"
    checkpoint = validate_message({
        "schema_version": 1, "message_id": "report-one", "correlation_id": "request-one", "causation_id": None,
        "message_type": "progress.report",
        "sender": {"principal_id": "specialist-one", "class_id": "spezialistin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "codex-master", "dispatch_id": "dispatch-one", "workpackage_id": "workpackage-one",
        "dispatch_priority": "DP1", "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": {"status": "executing", "checkpoint": True, "checkpoint_state": "safe", "pause_requested": True, "origin": "work_orchestration", "raw_output": "not_returned"},
        "raw_output": "not_returned",
    })
    ready = server.server_cooperative_pause_preview(
        "workpackage-one", reason="higher_priority_slot_required", assignment_pausable=True, checkpoint=checkpoint
    )
    assert ready["reason_code"] == "safe_checkpoint_ready"
    assert ready["mutation_performed"] is False
