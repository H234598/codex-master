from __future__ import annotations

import json
import hashlib
import os
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_master import server
from codex_master.fleet_recovery import (
    ArtifactDigest,
    DescriptorState,
    EntryPhase,
    FileIdentity,
    FleetRecoveryJournal,
    FleetRecoveryValidationError,
    MutationKind,
    RecoveryActionKind,
    RecoveryEntry,
    RecoveryOperation,
    RecoveryPhase,
    advance_recovery_phase,
    classify_descriptor,
    normalize_recovery_document,
    plan_reconciliation,
    recovery_document,
)
from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.fleet_service import FleetPaths


def sample_entry(kind: MutationKind = MutationKind.CREATED, agent_id: str = "d1") -> RecoveryEntry:
    return RecoveryEntry(
        kind=kind,
        agent_id=agent_id,
        hidden_name=".codex-fleet-remove-create-0123456789abcdef0123456789abcdef",
        old_descriptor_fingerprint=None,
        new_descriptor_fingerprint="1" * 64,
        old_materialization_fingerprint=None,
        new_materialization_fingerprint="2" * 64,
        source_identity=None,
        target_identity=FileIdentity(1, 2, 0o40700, os.geteuid(), os.getegid(), 1),
        manifest=(ArtifactDigest("codex", 0o700, "3" * 64),),
        phase=EntryPhase.PUBLIC,
        result_code=None,
    )


def sample_journal(*entries: RecoveryEntry) -> FleetRecoveryJournal:
    return FleetRecoveryJournal(
        schema_version=1,
        journal_id="a" * 32,
        operation=RecoveryOperation.SERIES_APPLY,
        pool_root_digest="b" * 64,
        expected_generation=2,
        planned_generation=3,
        authoritative_generation=None,
        phase=RecoveryPhase.MATERIALIZING,
        entries=entries or (sample_entry(),),
        blocking_error_codes=(),
    )


def test_recovery_document_roundtrip_is_exact_and_frozen() -> None:
    journal = sample_journal()
    assert normalize_recovery_document(recovery_document(journal)) == journal
    with pytest.raises(FrozenInstanceError):
        journal.phase = RecoveryPhase.COMPLETE  # type: ignore[misc]


def test_recovery_document_rejects_unknown_fields() -> None:
    raw = recovery_document(sample_journal())
    raw["secret"] = "must-not-be-accepted"
    with pytest.raises(FleetRecoveryValidationError) as caught:
        normalize_recovery_document(raw)
    assert caught.value.code == "invalid_fleet_recovery"


def test_recovery_paths_and_reentrant_mutation_lock(tmp_path: Path) -> None:
    paths = FleetPaths.from_state_root(tmp_path)
    assert paths.recovery == tmp_path / "fleet" / "recovery.json"
    assert paths.mutation_lock == tmp_path / "fleet" / "mutation.lock"
    with patch.object(server.fcntl, "flock") as flock:
        with server.fleet_mutation_lock(paths):
            with server.fleet_mutation_lock(paths):
                pass
    assert [call.args[1] for call in flock.call_args_list] == [
        server.fcntl.LOCK_EX | server.fcntl.LOCK_NB,
        server.fcntl.LOCK_UN,
    ]
    assert paths.mutation_lock.is_file()
    assert not paths.mutation_lock.is_symlink()
    assert os.stat(paths.mutation_lock).st_uid == os.geteuid()
    assert (os.stat(paths.mutation_lock).st_mode & 0o777) == 0o600


def test_mutation_lock_timeout_is_bounded(tmp_path: Path) -> None:
    paths = FleetPaths.from_state_root(tmp_path)
    with patch.object(server.fcntl, "flock", side_effect=BlockingIOError):
        with pytest.raises(server.AgentError, match="could_not_acquire_fleet_mutation_lock"):
            with server.fleet_mutation_lock(paths, timeout_seconds=0):
                pass


def test_recovery_store_fsyncs_file_and_parent(tmp_path: Path) -> None:
    paths = FleetPaths.from_state_root(tmp_path)
    calls: list[int] = []
    with patch.object(server.os, "fsync", side_effect=lambda fd: calls.append(fd)):
        server._fleet_store_recovery_journal(sample_journal(), paths)
    assert server._fleet_load_recovery_journal(paths) == sample_journal()
    assert len(calls) == 2


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "oversize", "mode"])
def test_recovery_load_rejects_unsafe_journal(tmp_path: Path, unsafe: str) -> None:
    paths = FleetPaths.from_state_root(tmp_path)
    paths.root.mkdir(parents=True, mode=0o700)
    valid = (json.dumps(recovery_document(sample_journal())) + "\n").encode()
    if unsafe == "symlink":
        target = paths.root / "outside.json"
        target.write_bytes(valid)
        target.chmod(0o600)
        paths.recovery.symlink_to(target)
    elif unsafe == "hardlink":
        target = paths.root / "linked.json"
        target.write_bytes(valid)
        target.chmod(0o600)
        os.link(target, paths.recovery)
    elif unsafe == "oversize":
        paths.recovery.write_bytes(b"x" * (server.MAX_RECOVERY_DOCUMENT_BYTES + 1))
        paths.recovery.chmod(0o600)
    else:
        paths.recovery.write_bytes(valid)
        paths.recovery.chmod(0o644)
    with pytest.raises(server.AgentError, match="fleet_recovery_state_invalid"):
        server._fleet_load_recovery_journal(paths)


def test_recovery_phase_requires_authoritative_generation() -> None:
    with pytest.raises(FleetRecoveryValidationError):
        advance_recovery_phase(sample_journal(), RecoveryPhase.RECONCILING)
    pending = advance_recovery_phase(sample_journal(), RecoveryPhase.CAS_PENDING)
    advanced = advance_recovery_phase(
        pending,
        RecoveryPhase.RECONCILING,
        authoritative_generation=3,
    )
    assert advanced.authoritative_generation == 3


@pytest.mark.parametrize(
    ("authoritative", "old", "new", "expected"),
    [
        (None, "1" * 64, "2" * 64, DescriptorState.ABSENT),
        ("1" * 64, "1" * 64, "2" * 64, DescriptorState.OLD),
        ("2" * 64, "1" * 64, "2" * 64, DescriptorState.NEW),
        ("3" * 64, "1" * 64, "2" * 64, DescriptorState.THIRD),
    ],
)
def test_descriptor_classification_is_complete(authoritative, old, new, expected) -> None:
    assert classify_descriptor(authoritative, old, new) is expected


@pytest.mark.parametrize(
    ("kind", "state", "expected"),
    [
        (MutationKind.CREATED, DescriptorState.ABSENT, RecoveryActionKind.QUARANTINE_CREATED),
        (MutationKind.CREATED, DescriptorState.NEW, RecoveryActionKind.VERIFY_CREATED),
        (MutationKind.BACKUP, DescriptorState.OLD, RecoveryActionKind.RESTORE_BACKUP),
        (MutationKind.TOMBSTONE, DescriptorState.OLD, RecoveryActionKind.RESTORE_TOMBSTONE),
        (MutationKind.RESERVATION, DescriptorState.NEW, RecoveryActionKind.RELEASE_RESERVATION),
    ],
)
def test_reconciliation_plan_maps_each_mutation_class(kind, state, expected) -> None:
    entry = replace(sample_entry(kind), old_descriptor_fingerprint="0" * 64)
    journal = sample_journal(entry)
    old = entry.old_descriptor_fingerprint
    new = entry.new_descriptor_fingerprint
    authoritative = {
        entry.agent_id: {
            DescriptorState.ABSENT: None,
            DescriptorState.OLD: old,
            DescriptorState.NEW: new,
            DescriptorState.THIRD: "3" * 64,
        }[state]
    }
    plan = plan_reconciliation(journal, authoritative)
    assert plan.actions[0].kind is expected
    assert plan.has_third is (state is DescriptorState.THIRD)


def test_restore_backup_resumes_after_quarantine_cleanup_failure(tmp_path: Path) -> None:
    root = tmp_path / "pool"
    root.mkdir()
    target = root / "d1"
    hidden_name = ".codex-fleet-remove-backup-0123456789abcdef0123456789abcdef"
    hidden = root / hidden_name
    target.mkdir()
    hidden.mkdir()
    (target / "new").write_text("new", encoding="utf-8")
    (hidden / "old").write_text("old", encoding="utf-8")
    entry = replace(sample_entry(MutationKind.BACKUP), hidden_name=hidden_name)

    with patch.object(server.shutil, "rmtree", side_effect=OSError("busy")):
        assert not server._fleet_recovery_entry_action(
            root, entry, RecoveryActionKind.RESTORE_BACKUP, DescriptorState.OLD,
        )
    assert target.is_dir()
    assert not hidden.exists()
    assert (root / f"{hidden_name}-restore").is_dir()

    assert server._fleet_recovery_entry_action(
        root, entry, RecoveryActionKind.RESTORE_BACKUP, DescriptorState.OLD,
    )
    assert (target / "old").read_text(encoding="utf-8") == "old"
    assert not (root / f"{hidden_name}-restore").exists()


def test_recovery_fingerprint_excludes_private_home_path() -> None:
    descriptor = AgentDescriptor(
        "d1", "d", 1, "D 1", RunnerKind.CODEX_CLI, Provider.OLLAMA_LOCAL,
        "model", None, Path("/private/home"), "session", True,
    )
    from codex_master.fleet_recovery import descriptor_fingerprint

    fingerprint = descriptor_fingerprint(descriptor)
    assert isinstance(fingerprint, str)
    assert "/private/home" not in fingerprint


def test_recovery_status_is_data_sparse_and_does_not_scan_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    journal = replace(
        sample_journal(),
        pool_root_digest=hashlib.sha256(
            server._pool_root_digest_text(pool_root).encode("utf-8")
        ).hexdigest(),
        phase=RecoveryPhase.DEGRADED,
        authoritative_generation=3,
        blocking_error_codes=("fleet_registry_commit_diverged",),
    )
    server._fleet_store_recovery_journal(journal)

    with (
        patch.object(server, "tmux_alive", side_effect=AssertionError),
        patch.object(server, "agent_home_process_summary", side_effect=AssertionError),
        patch.object(server.subprocess, "run", side_effect=AssertionError),
        patch.object(server.subprocess, "Popen", side_effect=AssertionError),
    ):
        result = server.fleet_recovery_status()

    assert result == {
        "state": "degraded",
        "blocking": True,
        "retryable": True,
        "generation": 3,
        "entry_count": 1,
        "blocking_error_count": 1,
        "raw_output": "not_returned",
    }
    serialized = json.dumps(result)
    assert str(tmp_path) not in serialized
    assert journal.journal_id not in serialized
    assert journal.entries[0].hidden_name not in serialized


def test_recovery_status_marks_root_mismatch_invalid_without_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    server._fleet_store_recovery_journal(sample_journal())

    result = server.fleet_recovery_status()

    assert result == {
        "state": "invalid",
        "blocking": True,
        "retryable": False,
        "generation": None,
        "entry_count": 0,
        "blocking_error_count": 0,
        "error_code": "fleet_recovery_state_invalid",
        "raw_output": "not_returned",
    }
    assert str(tmp_path) not in json.dumps(result)


def test_recovery_status_marks_oserror_invalid_without_details() -> None:
    with patch.object(server, "_fleet_load_recovery_journal", side_effect=OSError("private state")):
        result = server.fleet_recovery_status()

    assert result == {
        "state": "unavailable",
        "blocking": True,
        "retryable": True,
        "generation": None,
        "entry_count": 0,
        "blocking_error_count": 0,
        "error_code": "fleet_recovery_unavailable",
        "raw_output": "not_returned",
    }


def test_recovery_gate_blocks_mutations_and_preserves_public_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    journal = replace(
        sample_journal(),
        pool_root_digest=hashlib.sha256(
            server._pool_root_digest_text(pool_root).encode("utf-8")
        ).hexdigest(),
        phase=RecoveryPhase.DEGRADED,
    )
    server._fleet_store_recovery_journal(journal)

    with pytest.raises(server.FleetRecoveryBlockedError) as caught:
        server.require_fleet_recovery_ready("fleet_account_mutation")
    payload = server.public_error_payload(caught.value)

    assert payload["error"] == "fleet_recovery_degraded"
    assert payload["state"] == "degraded"
    assert payload["blocking"] is True
    assert journal.journal_id not in json.dumps(payload)
    with pytest.raises(server.AgentError, match="fleet_recovery_unknown_operation"):
        server.require_fleet_recovery_ready("agent_status")


def test_missing_recovery_journal_is_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", tmp_path / "pool")
    assert server.fleet_recovery_status() == {
        "state": "ready",
        "blocking": False,
        "retryable": False,
        "generation": None,
        "entry_count": 0,
        "blocking_error_count": 0,
        "raw_output": "not_returned",
    }


def test_complete_journal_with_wrong_authoritative_generation_is_not_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    journal = replace(
        sample_journal(),
        pool_root_digest=hashlib.sha256(
            server._pool_root_digest_text(pool_root).encode("utf-8")
        ).hexdigest(),
        phase=RecoveryPhase.COMPLETE,
        authoritative_generation=999,
    )
    server._fleet_store_recovery_journal(journal)

    result = server.fleet_recovery_retry()

    assert result["state"] == "degraded"
    assert result["blocking"] is True
    assert server._fleet_load_recovery_journal() is not None


def test_emergency_controls_diagnosis_and_recovery_remain_reachable_when_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    pool_root = tmp_path / "pool"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "AGENT_POOL_ROOT", pool_root)
    blocked = replace(
        sample_journal(),
        pool_root_digest=hashlib.sha256(
            server._pool_root_digest_text(pool_root).encode("utf-8")
        ).hexdigest(),
        phase=RecoveryPhase.DEGRADED,
    )
    server._fleet_store_recovery_journal(blocked)

    with (
        patch.object(server, "agent_lifecycle_lock", return_value=nullcontext()),
        patch.object(server, "ensure_state"),
        patch.object(
            server,
            "read_agent_lease_record",
            return_value=None,
        ),
        patch.object(
            server,
            "public_agent_lease",
            return_value={"state": "unclaimed", "held_by_this_server": False},
        ),
    ):
        released = server.release_agent("a")
    assert released["status"] == "not_held"

    with (
        patch.object(server, "agent_lifecycle_lock", return_value=nullcontext()),
        patch.object(server, "tmux_alive", return_value=False),
        patch.object(server, "agent_config", return_value={"session": "codex-a"}),
        patch.object(server, "agent_lease_status", return_value={
            "state": "unclaimed",
            "held_by_this_server": False,
        }),
        patch.object(server, "agent_home_process_summary", return_value={"process_count": 0}),
        patch.object(server, "release_agent", return_value={
            "lease": {"state": "unclaimed"},
        }),
        patch.object(server, "close_runner_execution_fd"),
    ):
        stopped = server.stop_agent("a")
    assert stopped["status"] == "not_running"

    with (
        patch.object(server, "agent_lifecycle_lock", return_value=nullcontext()),
        patch.object(server, "tmux_alive", return_value=True),
        patch.object(server, "require_managed_tmux_session"),
        patch.object(server, "run_tmux", return_value=server.subprocess.CompletedProcess([], 0)),
        patch.object(
            server,
            "claim_agent",
            side_effect=server.FleetRecoveryBlockedError("fleet_recovery_degraded", {}),
        ),
        patch.object(server, "_claim_agent_unlocked", return_value={
            "status": "claimed",
            "lease": {"state": "held", "lease_id": "emergency"},
        }) as claim,
    ):
        interrupted = server.interrupt_agent("a")
    assert interrupted["status"] == "interrupt_sent"
    claim.assert_called_once_with("a1", enforce_recovery_gate=False)

    with patch.object(server, "status_agent", return_value={"agent": "a1", "raw_output": "not_returned"}):
        diagnosed = server.call_tool("agent_status", {"agent": "a1"})
    assert diagnosed["results"][0]["agent"] == "a1"

    with patch.object(server, "fleet_mutation_lock", return_value=nullcontext()), patch.object(
        server, "_fleet_load_recovery_journal", return_value=None
    ):
        recovered = server.fleet_recovery_retry()
    assert recovered["state"] == "ready"
