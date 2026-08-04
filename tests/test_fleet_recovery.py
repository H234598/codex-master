from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import os

import pytest
from unittest.mock import patch

from codex_master.fleet_recovery import (
    ArtifactDigest,
    DescriptorState,
    EntryPhase,
    FileIdentity,
    FleetRecoveryValidationError,
    FleetRecoveryJournal,
    MutationKind,
    RecoveryAction,
    RecoveryPlan,
    RecoveryActionKind,
    RecoveryEntry,
    RecoveryOperation,
    RecoveryPhase,
    MAX_RECOVERY_DOCUMENT_BYTES,
    classify_descriptor,
    descriptor_fingerprint,
    materialization_fingerprint,
    normalize_recovery_document,
    plan_reconciliation,
    recovery_document,
    advance_recovery_phase,
)
from codex_master.fleet_registry import AgentDescriptor, FleetSnapshot, Provider, RunnerKind
from codex_master.server import AgentError, FleetPaths


def prepare_unsafe_recovery_file(paths: FleetPaths, unsafe: str) -> None:
    paths.root.mkdir(parents=True, mode=0o700, exist_ok=True)
    paths.root.chmod(0o700)
    valid = (json.dumps(recovery_document(sample_journal())) + "\n").encode()
    if unsafe == "symlink":
        target = paths.root / "outside.json"
        target.write_bytes(valid)
        target.chmod(0o600)
        paths.recovery.symlink_to(target)
        return
    if unsafe == "hardlink":
        target = paths.root / "linked.json"
        target.write_bytes(valid)
        target.chmod(0o600)
        os.link(target, paths.recovery)
        return
    if unsafe == "oversize":
        paths.recovery.write_bytes(b"x" * (MAX_RECOVERY_DOCUMENT_BYTES + 1))
        paths.recovery.chmod(0o600)
        return
    if unsafe == "mode":
        paths.recovery.write_bytes(valid)
        paths.recovery.chmod(0o644)
        return
    raise AssertionError(unsafe)


def sample_entry(kind: MutationKind = MutationKind.CREATED) -> RecoveryEntry:
    return RecoveryEntry(
        kind=kind,
        agent_id="d1",
        hidden_name=".codex-fleet-remove-create-0123456789abcdef0123456789abcdef",
        old_descriptor_fingerprint=None,
        new_descriptor_fingerprint="1" * 64,
        old_materialization_fingerprint=None,
        new_materialization_fingerprint="2" * 64,
        source_identity=None,
        target_identity=FileIdentity(1, 2, 0o40700, 1000, 1000, 1),
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


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.update(schema_version=2),
        lambda raw: raw.update(journal_id="z" * 32),
        lambda raw: raw.update(pool_root_digest="x" * 64),
        lambda raw: raw.update(expected_generation=True),
        lambda raw: raw.update(planned_generation=99),
        lambda raw: raw.update(phase="unknown"),
        lambda raw: raw["entries"][0].update(kind="unknown"),
        lambda raw: raw["entries"][0]["manifest"][0].update(relative_path="../escape"),
        lambda raw: raw["entries"][0].update(manifest=[raw["entries"][0]["manifest"][0]] * 2),
    ],
)
def test_recovery_document_rejects_invalid_contract(mutate) -> None:
    raw = recovery_document(sample_journal())
    mutate(raw)
    with pytest.raises(FleetRecoveryValidationError) as caught:
        normalize_recovery_document(raw)
    assert caught.value.code == "invalid_fleet_recovery"


def test_recovery_document_rejects_more_than_one_thousand_entries() -> None:
    raw = recovery_document(sample_journal())
    raw["entries"] = [raw["entries"][0]] * 1001
    with pytest.raises(FleetRecoveryValidationError) as caught:
        normalize_recovery_document(raw)
    assert caught.value.code == "invalid_fleet_recovery"


def test_recovery_document_rejects_oversize_documents() -> None:
    artifact_manifest = tuple(
        ArtifactDigest(
            f"segment{i}/" + ("x" * 180),
            0o700,
            "3" * 64,
        )
        for i in range(64)
    )
    raw_entry = sample_entry()
    raw_entry = replace(raw_entry, manifest=artifact_manifest)
    raw = recovery_document(sample_journal(*[raw_entry] * 1000))
    payload = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    assert len(payload) > MAX_RECOVERY_DOCUMENT_BYTES
    with pytest.raises(FleetRecoveryValidationError) as caught:
        normalize_recovery_document(raw)
    assert caught.value.code == "invalid_fleet_recovery"


def descriptor(model: str) -> AgentDescriptor:
    return AgentDescriptor(
        "d1",
        "d",
        1,
        "D1",
        RunnerKind.CODEX_CLI,
        Provider.OLLAMA_LOCAL,
        model,
        None,
        Path("/private/pool/d1"),
        "codex_agent_d1_mcp",
        True,
    )


@pytest.mark.parametrize(
    ("authoritative", "old", "new", "expected"),
    [
        (None, "a" * 64, "b" * 64, DescriptorState.ABSENT),
        ("a" * 64, "a" * 64, "b" * 64, DescriptorState.OLD),
        ("b" * 64, "a" * 64, "b" * 64, DescriptorState.NEW),
        ("c" * 64, "a" * 64, "b" * 64, DescriptorState.THIRD),
    ],
)
def test_descriptor_classification(authoritative, old, new, expected) -> None:
    assert classify_descriptor(authoritative, old, new) is expected


@pytest.mark.parametrize(
    ("kind", "state", "action"),
    [
        (MutationKind.CREATED, DescriptorState.ABSENT, RecoveryActionKind.QUARANTINE_CREATED),
        (MutationKind.CREATED, DescriptorState.OLD, RecoveryActionKind.QUARANTINE_CREATED),
        (MutationKind.CREATED, DescriptorState.NEW, RecoveryActionKind.VERIFY_CREATED),
        (MutationKind.CREATED, DescriptorState.THIRD, RecoveryActionKind.QUARANTINE_CREATED),
        (MutationKind.BACKUP, DescriptorState.ABSENT, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.BACKUP, DescriptorState.OLD, RecoveryActionKind.RESTORE_BACKUP),
        (MutationKind.BACKUP, DescriptorState.NEW, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.BACKUP, DescriptorState.THIRD, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.TOMBSTONE, DescriptorState.ABSENT, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.TOMBSTONE, DescriptorState.OLD, RecoveryActionKind.RESTORE_TOMBSTONE),
        (MutationKind.TOMBSTONE, DescriptorState.NEW, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.TOMBSTONE, DescriptorState.THIRD, RecoveryActionKind.RETAIN_QUARANTINE),
        (MutationKind.RESERVATION, DescriptorState.ABSENT, RecoveryActionKind.RELEASE_RESERVATION),
        (MutationKind.RESERVATION, DescriptorState.OLD, RecoveryActionKind.RELEASE_RESERVATION),
        (MutationKind.RESERVATION, DescriptorState.NEW, RecoveryActionKind.RELEASE_RESERVATION),
        (MutationKind.RESERVATION, DescriptorState.THIRD, RecoveryActionKind.RELEASE_RESERVATION),
    ],
)
def test_reconciliation_matrix_is_complete(kind, state, action) -> None:
    entry = sample_entry(kind)
    old = entry.old_descriptor_fingerprint or "4" * 64
    new = entry.new_descriptor_fingerprint or "5" * 64
    entry = replace(
        entry,
        old_descriptor_fingerprint=old,
        new_descriptor_fingerprint=new,
    )
    journal = sample_journal(entry)
    authoritative = {
        DescriptorState.ABSENT: None,
        DescriptorState.OLD: old,
        DescriptorState.NEW: new,
        DescriptorState.THIRD: "6" * 64,
    }[state]
    plan = plan_reconciliation(journal, {"d1": authoritative})
    assert plan.actions == (RecoveryAction(action, 0, "d1", state),)
    assert plan.has_third is (state is DescriptorState.THIRD)


def test_descriptor_fingerprint_returns_hash_not_private_path() -> None:
    value = descriptor_fingerprint(descriptor("old"))
    assert value is not None and len(value) == 64
    assert "/private/pool" not in value


def test_materialization_fingerprint_is_deterministic() -> None:
    value = materialization_fingerprint(descriptor("old"), sample_entry().manifest)
    value_repeat = materialization_fingerprint(descriptor("old"), sample_entry().manifest)
    assert value == value_repeat


_TRANSITIONS = {
    RecoveryPhase.PREPARED: frozenset({RecoveryPhase.MATERIALIZING, RecoveryPhase.DEGRADED}),
    RecoveryPhase.MATERIALIZING: frozenset({RecoveryPhase.CAS_PENDING, RecoveryPhase.DEGRADED}),
    RecoveryPhase.CAS_PENDING: frozenset({RecoveryPhase.RECONCILING, RecoveryPhase.DEGRADED}),
    RecoveryPhase.RECONCILING: frozenset({RecoveryPhase.VERIFIED, RecoveryPhase.DEGRADED}),
    RecoveryPhase.VERIFIED: frozenset({RecoveryPhase.PUBLISHED, RecoveryPhase.DEGRADED}),
    RecoveryPhase.PUBLISHED: frozenset({RecoveryPhase.COMPLETE, RecoveryPhase.DEGRADED}),
    RecoveryPhase.COMPLETE: frozenset(),
    RecoveryPhase.DEGRADED: frozenset({RecoveryPhase.RECONCILING}),
}


def test_advance_recovery_phase_accepts_valid_transitions() -> None:
    base = replace(sample_journal(), phase=RecoveryPhase.PREPARED)
    journal = advance_recovery_phase(base, RecoveryPhase.MATERIALIZING)
    journal = advance_recovery_phase(journal, RecoveryPhase.CAS_PENDING)
    journal = advance_recovery_phase(
        journal,
        RecoveryPhase.RECONCILING,
        authoritative_generation=journal.expected_generation + 1,
    )
    journal = advance_recovery_phase(
        journal,
        RecoveryPhase.VERIFIED,
        authoritative_generation=journal.expected_generation + 1,
    )
    journal = advance_recovery_phase(
        journal,
        RecoveryPhase.PUBLISHED,
        authoritative_generation=journal.expected_generation + 1,
    )
    journal = advance_recovery_phase(
        journal,
        RecoveryPhase.COMPLETE,
        authoritative_generation=journal.expected_generation + 1,
    )
    degraded = advance_recovery_phase(
        base,
        RecoveryPhase.DEGRADED,
        blocking_error_codes=("fleet_create_rollback_diverged", "fleet_create_rollback_diverged"),
    )
    assert journal.phase is RecoveryPhase.COMPLETE
    assert degraded.phase is RecoveryPhase.DEGRADED


def test_advance_recovery_phase_rejects_invalid_edges() -> None:
    all_phases = set(RecoveryPhase)
    for source, targets in _TRANSITIONS.items():
        for target in all_phases:
            if target in targets:
                continue
            with pytest.raises(FleetRecoveryValidationError):
                base = replace(sample_journal(), phase=source)
                advance_recovery_phase(base, target)


def test_advance_recovery_phase_rejects_missing_authoritative_generation_when_needed() -> None:
    journal = replace(sample_journal(), phase=RecoveryPhase.CAS_PENDING)
    with pytest.raises(FleetRecoveryValidationError):
        advance_recovery_phase(journal, RecoveryPhase.RECONCILING)


def test_advance_recovery_phase_rejects_blocking_errors_in_later_phases() -> None:
    journal = replace(sample_journal(), phase=RecoveryPhase.RECONCILING)
    with pytest.raises(FleetRecoveryValidationError):
        advance_recovery_phase(
            journal,
            RecoveryPhase.VERIFIED,
            authoritative_generation=journal.expected_generation + 1,
            blocking_error_codes=("fleet_update_rollback_diverged",),
        )


def test_recovery_load_rejects_unsafe_journal(tmp_path: Path) -> None:
    from codex_master.server import (
        _fleet_load_recovery_journal,
    )

    paths = FleetPaths.from_state_root(tmp_path)
    for unsafe in ["symlink", "hardlink", "oversize", "mode"]:
        if paths.recovery.exists():
            paths.recovery.unlink()
        prepare_unsafe_recovery_file(paths, unsafe)
        with pytest.raises(AgentError) as caught:
            _fleet_load_recovery_journal(paths)
        assert caught.value.args[0] == "fleet_recovery_state_invalid"


def test_recovery_store_fsyncs_file_and_parent_before_success(tmp_path: Path) -> None:
    from codex_master.server import (
        _fleet_store_recovery_journal,
        _fleet_load_recovery_journal as real_load,
    )

    calls: list[int] = []
    paths = FleetPaths.from_state_root(tmp_path)
    journal = sample_journal()

    def fsync(fd: int) -> None:
        calls.append(fd)

    with patch.object(__import__("os"), "fsync", side_effect=fsync):
        _fleet_store_recovery_journal(journal, paths)

    loaded = real_load(paths)
    assert loaded == journal
    assert len(calls) == 2


def test_reconciler_continues_every_mutation_class_after_first_failure(tmp_path: Path) -> None:
    from codex_master.server import (
        _fleet_execute_recovery_plan,
        _FleetRecoveryTransaction,
    )
    from codex_master.fleet_recovery import RecoveryAction

    entries = tuple(
        replace(
            sample_entry(kind),
            agent_id=f"d{index}",
            hidden_name=f".codex-fleet-remove-test-{index:032x}",
        )
        for index, kind in enumerate(MutationKind, 1)
    )
    journal = replace(
        sample_journal(*entries),
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=3,
    )
    paths = FleetPaths.from_state_root(tmp_path)
    transaction = _FleetRecoveryTransaction(paths, journal)
    action_kinds = (
        RecoveryActionKind.QUARANTINE_CREATED,
        RecoveryActionKind.RESTORE_BACKUP,
        RecoveryActionKind.RESTORE_TOMBSTONE,
        RecoveryActionKind.RELEASE_RESERVATION,
    )
    plan = RecoveryPlan(
        tuple(
            RecoveryAction(action_kind, index, entries[index].agent_id, DescriptorState.OLD)
            for index, action_kind in enumerate(action_kinds)
        ),
        False,
    )
    authoritative = FleetSnapshot(1, 3, (), ())
    calls: list[RecoveryActionKind] = []

    def execute(action, entry, authoritative_agent):
        assert entry is entries[action.entry_index]
        assert authoritative_agent is None
        calls.append(action.kind)
        return action.kind is not RecoveryActionKind.QUARANTINE_CREATED

    with patch.object(__import__("codex_master.server", fromlist=["_fleet_execute_recovery_action"]), "_fleet_execute_recovery_action", side_effect=execute):
        errors, blocking = _fleet_execute_recovery_plan(transaction, plan, authoritative)

    assert calls == list(action_kinds)
    assert blocking is True
    assert "fleet_create_rollback_diverged" in errors


def test_recovery_plan_execution_reloads_authoritative_snapshot_for_verify(tmp_path: Path) -> None:
    from codex_master.server import (
        FLEET_TOMBSTONE_PREFIX,
        _fleet_execute_recovery_plan,
        _FleetRecoveryTransaction,
        _fleet_verify_authoritative_materialization,
    )
    from codex_master.fleet_recovery import (
        RecoveryAction,
        RecoveryActionKind,
        RecoveryPlan,
        DescriptorState,
    )
    from unittest.mock import Mock

    class _Service:
        def __init__(self, snapshot: FleetSnapshot):
            self.snapshot = snapshot
            self.load = Mock(return_value=snapshot)

    entries = (
        replace(
            sample_entry(MutationKind.CREATED),
            agent_id="d1",
            hidden_name=f"{FLEET_TOMBSTONE_PREFIX}create-verify",
        ),
    )
    plan = RecoveryPlan(
        (RecoveryAction(RecoveryActionKind.RETAIN_QUARANTINE, 0, "d1", DescriptorState.NEW),),
        has_third=False,
    )
    journal = replace(
        sample_journal(*entries),
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=1,
    )
    transaction = _FleetRecoveryTransaction(FleetPaths.from_state_root(tmp_path), journal)
    authoritative = FleetSnapshot(1, 1, (), ())
    reloaded = FleetSnapshot(1, 1, (), ())
    service = _Service(reloaded)
    verified: list[FleetSnapshot] = []

    def execute(action, entry, authoritative_agent):
        return True

    with patch.object(
        __import__("codex_master.server", fromlist=["current_fleet_service"]),
        "current_fleet_service",
        return_value=service,
    ):
        with patch.object(
            __import__("codex_master.server", fromlist=["_fleet_execute_recovery_action"]),
            "_fleet_execute_recovery_action",
            side_effect=execute,
        ):
            with patch.object(
                __import__("codex_master.server", fromlist=["_fleet_verify_authoritative_materialization"]),
                "_fleet_verify_authoritative_materialization",
                side_effect=lambda snapshot, actual: verified.append(snapshot) or _fleet_verify_authoritative_materialization(snapshot, actual),
            ):
                _fleet_execute_recovery_plan(transaction, plan, authoritative)

    assert service.load.call_count == 2
    assert verified and verified[0] == reloaded
