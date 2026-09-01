from __future__ import annotations

import contextlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_master import server
from codex_master.fleet_recovery import (
    EntryPhase,
    FleetRecoveryJournal,
    GMigrationJournal,
    GMigrationPhase,
    MutationKind,
    RecoveryEntry,
    RecoveryOperation,
    RecoveryPhase,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)


def _account(account_id: str = "acct") -> FleetAccount:
    return FleetAccount(
        account_id,
        "Account",
        Provider.OLLAMA_LOCAL,
        AuthKind.NONE,
        SecretState.NOT_REQUIRED,
        LimitState.READY,
        True,
        None,
        None,
        None,
    )


def _series(
    prefix: str = "a",
    count: int = 1,
    *,
    model: str = "model",
    enabled: bool = True,
) -> FleetSeries:
    return FleetSeries(
        prefix,
        "Series",
        count,
        RunnerKind.CODEX_CLI,
        Provider.OLLAMA_LOCAL,
        model,
        None,
        enabled,
    )


def _snapshot(*series: FleetSeries, generation: int = 4) -> FleetSnapshot:
    return FleetSnapshot(1, generation, (), series)


def _entry(agent_id: str = "a1") -> RecoveryEntry:
    return RecoveryEntry(
        MutationKind.CREATED,
        agent_id,
        ".codex-fleet-remove-create-0123456789abcdef0123456789abcdef",
        None,
        "1" * 64,
        None,
        None,
        None,
        None,
        (),
        EntryPhase.INTENT,
        None,
    )


def _journal(*entries: RecoveryEntry) -> FleetRecoveryJournal:
    return FleetRecoveryJournal(
        1,
        "a" * 32,
        RecoveryOperation.SERIES_APPLY,
        "b" * 64,
        4,
        5,
        None,
        RecoveryPhase.PREPARED,
        entries,
        (),
    )


def test_low_level_resource_compatibility_seams_return_none() -> None:
    assert server._resource_meminfo() is None
    assert server._cpu_counters() is None
    assert server._effective_cpu_count() is None
    assert server._g_migration_crash_point("after_prepare") is None


def test_decode_and_read_teamleader_registry_strict(tmp_path, monkeypatch) -> None:
    digest = "a" * 64
    registry = tmp_path / "teamleaders.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": server.TEAMLEADER_REGISTRY_SCHEMA_VERSION,
                "principals": [{"digest": digest, "class": "koenigin", "agent_id": None}],
            }
        ),
        encoding="utf-8",
    )
    registry.chmod(0o600)
    monkeypatch.setattr(server, "TEAMLEADER_REGISTRY_FILE", registry)

    assert server._decode_teamleader_registry(registry.read_text(encoding="utf-8")) == {
        digest
    }
    assert server._read_teamleader_principals_strict(missing_ok=False) == {digest}


def test_decode_teamleader_registry_rejects_duplicate_digest() -> None:
    digest = "a" * 64
    payload = {
        "schema_version": server.TEAMLEADER_REGISTRY_SCHEMA_VERSION,
        "principals": [
            {"digest": digest, "class": "koenigin", "agent_id": None},
            {"digest": digest, "class": "koenigin", "agent_id": None},
        ],
    }
    with pytest.raises(server.AgentError, match="teamleader registry is unavailable"):
        server._decode_teamleader_registry(json.dumps(payload))


def test_native_subagent_parent_from_transcript_reads_only_active_home(
    tmp_path, monkeypatch
) -> None:
    home = tmp_path / "codex-home"
    transcript = home / "sessions" / "2026" / "run.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(
        json.dumps(
            {
                "type": "session_meta",
                "payload": {
                    "id": "child-456",
                    "source": {
                        "subagent": {
                            "thread_spawn": {
                                "parent_thread_id": "codex_agent_q1_mcp",
                            }
                        }
                    },
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    transcript.chmod(0o600)
    monkeypatch.setattr(server, "active_codex_home_path", lambda: home)

    assert (
            server._native_subagent_parent_from_transcript(
                {"transcript_path": str(transcript)}, "child-456"
            )
            == "codex_agent_q1_mcp"
        )
    assert server._native_subagent_parent_from_transcript({"transcript_path": "rel"}, "x") is None


def test_headless_process_start_ticks_parses_proc_stat(monkeypatch) -> None:
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, encoding=None: "123 (cmd with spaces) S "
        + " ".join(str(i) for i in range(1, 25)),
    )
    assert server._headless_process_start_ticks(123) == 19


def test_headless_route_candidates_canonicalizes_single_requested_agent(monkeypatch) -> None:
    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: f"canon-{agent}")
    assert server._headless_route_candidates("d1", "skill", ["a"]) == ["canon-d1"]


def test_private_text_peek_and_home_file_snapshot(tmp_path) -> None:
    private_file = tmp_path / "secret.txt"
    private_file.write_text("private text", encoding="utf-8")
    private_file.chmod(0o600)
    assert server._fleet_peek_optional_private_text(private_file, 64, "boom") == "private text"
    assert server._fleet_peek_optional_private_text(tmp_path / "missing", 64, "boom") is None

    home_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        data, mode, stat_result = server._fleet_home_file_snapshot(home_fd, "secret.txt")
    finally:
        os.close(home_fd)
    assert data == b"private text"
    assert mode == 0o600
    assert stat_result.st_size == len(b"private text")


def test_fleet_created_homes_match_verifies_identity(monkeypatch, tmp_path) -> None:
    expected = tmp_path.stat()
    monkeypatch.setattr(server, "pool_root_lock", lambda _root: contextlib.nullcontext())
    monkeypatch.setattr(server, "pool_root_operation", lambda *_a, **_k: contextlib.nullcontext(tmp_path))
    monkeypatch.setattr(server, "_fleet_verify_home", lambda *_a, **_k: expected)

    assert server._fleet_created_homes_match([("a1", expected, {})]) is True


def test_fleet_write_recovery_backup_restores_absent_home(monkeypatch, tmp_path) -> None:
    restored: dict[str, bytes] = {}
    monkeypatch.setattr(server, "path_present_no_follow", lambda _path: False)
    monkeypatch.setattr(server, "_fleet_restore_home", lambda _home, backup: restored.update(backup))
    monkeypatch.setattr(server, "_fleet_existing_home_ok", lambda _home, _artifacts: True)

    server._fleet_write_recovery_backup(tmp_path / "a1", {"codex": b"runner"})

    assert restored == {"codex": b"runner"}


def test_fleet_plan_reports_counts_and_requires_confirmation() -> None:
    current = _snapshot(_series("a", 2), generation=4)
    service = SimpleNamespace(
        load=lambda: current,
        series_gate=lambda *_a, **_k: SimpleNamespace(allowed=True, reason="ready"),
    )

    plan, loaded, planned, existing, normalized = server._fleet_plan(
        service,
        prefix="a",
        count=1,
        runner="codex_cli",
        provider="ollama_local",
        model="model",
        account_id=None,
        enabled=True,
        expected_generation=4,
        confirmed_remove_ids=["a2"],
    )

    assert loaded is current
    assert planned.generation == 5
    assert existing == _series("a", 2)
    assert normalized.count == 1
    assert plan["remove_count"] == 1
    assert plan["confirmation_required"] is True
    assert plan["raw_output"] == "not_returned"


def test_fleet_require_removable_accepts_stopped_unleased_agent(monkeypatch) -> None:
    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "agent_config", lambda _agent: {"session": "codex_agent_a1_mcp"})
    monkeypatch.setattr(server, "tmux_alive", lambda _session: False)
    monkeypatch.setattr(server, "agent_home_process_summary", lambda _agent: {"process_count": 0})
    monkeypatch.setattr(server, "agent_lease_status", lambda *_a, **_k: {"state": "unclaimed"})

    assert server._fleet_require_removable("a1") is None


def test_fleet_series_recovery_entries_covers_create_update_and_remove(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path)
    current = _snapshot(_series("a", 2, model="old"), generation=4)
    planned = _snapshot(_series("a", 2, model="new"), _series("b", 1), generation=5)

    entries = server._fleet_series_recovery_entries(current, planned, ["a2"])

    kinds = [(entry.agent_id, entry.kind) for entry in entries]
    assert ("a1", MutationKind.BACKUP) in kinds
    assert ("a1", MutationKind.CREATED) in kinds
    assert ("b1", MutationKind.CREATED) in kinds
    assert ("a2", MutationKind.TOMBSTONE) in kinds
    assert all(entry.phase is EntryPhase.INTENT for entry in entries)


def test_fleet_recovery_transaction_append_entry_persists_and_returns_index(tmp_path, monkeypatch) -> None:
    persisted: list[FleetRecoveryJournal] = []
    transaction = server._FleetRecoveryTransaction(
        server.FleetPaths.from_state_root(tmp_path),
        _journal(),
    )
    monkeypatch.setattr(
        server,
        "_fleet_store_recovery_journal",
        lambda journal, _paths: persisted.append(journal),
    )

    index = transaction.append_entry(_entry("a2"))

    assert index == 0
    assert transaction.journal.entries == (_entry("a2"),)
    assert persisted == [transaction.journal]


def test_fleet_series_disable_locked_stops_series_and_commits(monkeypatch, tmp_path) -> None:
    current = _snapshot(_series("a", 2), generation=4)
    planned = replace(current, generation=5, series=(replace(current.series[0], enabled=False),))
    service = SimpleNamespace(load=Mock(return_value=current), commit_snapshot=Mock(return_value=planned))
    transaction = SimpleNamespace(
        journal=_journal(),
        paths=server.FleetPaths.from_state_root(tmp_path),
        advance=Mock(),
    )
    stopped: list[str] = []
    monkeypatch.setattr(server, "require_fleet_recovery_ready", lambda _operation: None)
    monkeypatch.setattr(server, "current_fleet_service", lambda: service)
    monkeypatch.setattr(server._FleetRecoveryTransaction, "begin", Mock(return_value=transaction))
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path)
    monkeypatch.setattr(server, "temporary_agent_inventory", lambda _inventory: contextlib.nullcontext())
    monkeypatch.setattr(server, "stop_agent", lambda agent, **_kwargs: stopped.append(agent))
    monkeypatch.setattr(server, "update_watchdog_marker", lambda *_a: None)
    monkeypatch.setattr(server, "publish_agent_inventory", lambda _inventory: None)
    monkeypatch.setattr(server, "_fleet_remove_complete_recovery_journal", lambda *_a: True)

    result = server._fleet_series_disable_locked(prefix="a", expected_generation=4)

    assert stopped == ["a1", "a2"]
    service.commit_snapshot.assert_called_once_with(planned, expected_generation=4)
    assert result == {
        "mutation_performed": True,
        "generation": 5,
        "disabled": "a",
        "raw_output": "not_returned",
    }


def test_g_migration_mark_degraded_redacts_authoritative_generation(monkeypatch, tmp_path) -> None:
    journal = GMigrationJournal(
        1,
        "m" * 32,
        1,
        7,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        (),
        ("v1:m:1",),
        (),
        (),
        GMigrationPhase.CAS_PENDING,
        None,
        (),
    )
    stored: list[GMigrationJournal] = []
    monkeypatch.setattr(server, "_g_migration_store_journal", lambda *_args: stored.append(_args[-1]))

    server._g_migration_mark_degraded(SimpleNamespace(), server.FleetPaths.from_state_root(tmp_path), journal, 99)

    assert stored[0].phase is GMigrationPhase.DEGRADED
    assert stored[0].authoritative_generation is None
    assert stored[0].blocking_error_codes == ("migration_recovery_degraded",)


def test_goddess_helpers_parse_env_state_and_binding_status(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CODEX_PROGRAMMING_VAULT", str(tmp_path / "vault"))
    assert server._goddess_vault_root() == tmp_path / "vault"
    monkeypatch.setattr(server, "GODDESS_REPORT_STATE_FILE", tmp_path / "state.json")
    assert server._goddess_report_state().path == tmp_path / "state.json"

    runtime = SimpleNamespace(
        principals=SimpleNamespace(
            list=lambda limit: [],
            public_bindings=lambda: [],
        )
    )
    monkeypatch.setattr(server, "build_current_hive_runtime", lambda **_kwargs: runtime)
    monkeypatch.setattr(server, "active_reporter_required", lambda *_a, **_k: True)
    assert server._goddess_binding_status(datetime(2026, 8, 16, tzinfo=UTC)) == (True, None)


def test_parse_report_timestamp_normalizes_to_utc_and_rejects_naive() -> None:
    assert server._parse_report_timestamp("2026-08-16T12:30:00+02:00", "from") == datetime(
        2026, 8, 16, 10, 30, tzinfo=UTC
    )
    with pytest.raises(server.AgentError, match="from must be RFC3339"):
        server._parse_report_timestamp("2026-08-16T12:30:00", "from")


def test_assignment_report_output_meaningful_filters_empty_and_accepts_content() -> None:
    assert server._is_assignment_report_output_meaningful("", running=False) is False
    assert server._is_assignment_report_output_meaningful("finished useful work", running=True) is True


def test_usage_watchdog_agent_unlocked_clear_path(monkeypatch) -> None:
    monkeypatch.setattr(server, "canonical_agent_id", lambda agent: agent)
    monkeypatch.setattr(server, "agent_config", lambda _agent: {"session": "codex_agent_a1_mcp"})
    monkeypatch.setattr(server, "tmux_alive", lambda _session: False)
    monkeypatch.setattr(
        server,
        "agent_lease_status",
        lambda *_a, **_k: {"state": "unclaimed", "held_by_this_server": False},
    )
    monkeypatch.setattr(server, "codex_usage_watchdog_status", lambda _agent, **_kwargs: {"blocked": False})

    result = server._usage_watchdog_agent_unlocked("a1", dry_run=True)

    assert result["usage_watchdog_state"] == "clear"
    assert result["action_taken"] == "none"
    assert result["raw_output"] == "not_returned"
    assert result["response_output"] == "not_returned"


def test_cli_binding_helpers_return_structured_errors(capsys, monkeypatch) -> None:
    assert server._observability_serve_cli(["--port", "80"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "invalid_observability_configuration"
    }

    monkeypatch.setattr(server, "resource_monitor_status", lambda: {"state": "ready"})
    assert server._resource_monitor_status_cli([]) == 0
    assert json.loads(capsys.readouterr().out) == {"state": "ready"}


def test_applet_schema_command_and_resource_projection_contracts() -> None:
    assert server.normalize_applet_schema_version(1) == 1
    assert server.normalize_applet_schema_version(2) == 2
    with pytest.raises(server.AgentError, match="schema_version must be an integer"):
        server.normalize_applet_schema_version(True)
    assert server.command_error_text("") == "no stderr"
    assert server._unavailable_applet_resource_projection() == {
        "schema_version": 1,
        "generation": 0,
        "state": "unavailable",
        "bottleneck": "unknown",
        "trend": {},
        "confidence": "low",
        "preferred_profiles": [],
        "avoid_profiles": [],
        "raw_output": "not_returned",
    }
