from __future__ import annotations

from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import hashlib
import json
import os
from types import MappingProxyType

import pytest
from unittest.mock import patch

from codex_master import server
from codex_master.fleet_recovery import (
    ArtifactDigest,
    DescriptorState,
    EntryPhase,
    FileIdentity,
    FleetRecoveryValidationError,
    FleetRecoveryJournal,
    GMigrationRecoveryError,
    GMigrationAlias,
    GMigrationHomeIdentity,
    GMigrationJournal,
    GMigrationPhase,
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
    g_migration_alias_view,
    g_migration_journal_document,
    normalize_g_migration_journal,
)
from codex_master.fleet_migration_materialization import MemberIdAllocation
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


def test_recovery_document_rejects_foreign_blocking_error_code_types() -> None:
    raw = recovery_document(sample_journal())
    raw["blocking_error_codes"] = [[]]
    with pytest.raises(FleetRecoveryValidationError) as caught:
        normalize_recovery_document(raw)
    assert caught.value.code == "invalid_fleet_recovery"


@pytest.mark.parametrize(
    "journal",
    [
        replace(sample_journal(), schema_version=2),
        sample_journal(replace(sample_entry(), result_code="foreign_result_code")),
    ],
)
def test_recovery_document_rejects_directly_constructed_invalid_journal(
    journal: FleetRecoveryJournal,
) -> None:
    with pytest.raises(FleetRecoveryValidationError) as caught:
        recovery_document(journal)
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
    raw = recovery_document(sample_journal(raw_entry))
    raw["entries"] = raw["entries"] * 1000
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


def test_intent_without_identity_only_verifies_unchanged_public_state() -> None:
    entry = replace(
        sample_entry(MutationKind.CREATED),
        old_descriptor_fingerprint="4" * 64,
        phase=EntryPhase.INTENT,
        source_identity=None,
        target_identity=None,
    )
    plan = plan_reconciliation(sample_journal(entry), {"d1": "4" * 64})

    assert plan.actions == (
        RecoveryAction(RecoveryActionKind.VERIFY_UNCHANGED, 0, "d1", DescriptorState.OLD),
    )


G_DIGEST_A = "sha256:" + "a" * 64
G_DIGEST_B = "sha256:" + "b" * 64
G_DIGEST_C = "sha256:" + "c" * 64
G_DIGEST_D = "sha256:" + "d" * 64
G_DIGEST_E = "sha256:" + "e" * 64
G_MEMBER_ID = "11111111-1111-4111-8111-111111111111"
G_MIGRATION_ID = "f" * 32


def sample_g_journal() -> GMigrationJournal:
    return GMigrationJournal(
        schema_version=1,
        migration_id=G_MIGRATION_ID,
        manifest_version=1,
        expected_registry_generation=218,
        source_projection_digest=G_DIGEST_A,
        source_snapshot_digest=G_DIGEST_B,
        plan_digest=G_DIGEST_C,
        candidate_digest=G_DIGEST_D,
        binding_evidence_digest=G_DIGEST_E,
        allocations=(MemberIdAllocation("v1:m:1", G_MEMBER_ID),),
        source_ids=("g1", "m1"),
        home_identities=(
            GMigrationHomeIdentity(
                "m1",
                FileIdentity(1, 2, 0o40700, 1000, 1000, 1),
                "rollback-m1",
            ),
        ),
        aliases=(
            GMigrationAlias("m1", "g2", G_MEMBER_ID, 219, G_MIGRATION_ID),
        ),
        phase=GMigrationPhase.PREPARED,
        authoritative_generation=None,
        blocking_error_codes=(),
    )


def test_g_journal_is_closed_frozen_sorted_and_redacted() -> None:
    journal = sample_g_journal()
    assert normalize_g_migration_journal(g_migration_journal_document(journal)) == journal
    aliases = g_migration_alias_view(journal)
    assert type(aliases) is MappingProxyType
    with pytest.raises(TypeError):
        aliases["other"] = "g3"  # type: ignore[index]
    raw = g_migration_journal_document(journal)
    raw["binding"] = "marker-binding"
    with pytest.raises(GMigrationRecoveryError, match="migration_journal_invalid"):
        normalize_g_migration_journal(raw)
    assert "marker-binding" not in str(journal)
    assert G_MEMBER_ID not in repr(journal)


def test_g_journal_repr_and_str_redact_every_private_value() -> None:
    journal = sample_g_journal()
    public = f"{journal!r}\n{journal!s}"
    for private_value in (
        G_MIGRATION_ID,
        G_DIGEST_A,
        G_DIGEST_B,
        G_DIGEST_C,
        G_DIGEST_D,
        G_DIGEST_E,
        "g1",
        "m1",
        "g2",
        "v1:m:1",
        "rollback-m1",
        G_MEMBER_ID,
        "prepared",
    ):
        assert private_value not in public
    assert normalize_g_migration_journal(g_migration_journal_document(journal)) == journal


def test_g_alias_view_rejects_duplicate_cycle_and_wrong_generation() -> None:
    journal = sample_g_journal()
    invalid = (
        replace(
            journal,
            aliases=journal.aliases + (journal.aliases[0],),
        ),
        replace(
            journal,
            aliases=(
                journal.aliases[0],
                GMigrationAlias("g2", "m1", G_MEMBER_ID, 219, G_MIGRATION_ID),
            ),
        ),
        replace(
            journal,
            aliases=(replace(journal.aliases[0], expected_generation=218),),
        ),
    )
    for candidate in invalid:
        with pytest.raises(GMigrationRecoveryError, match="migration_journal_invalid"):
            g_migration_alias_view(candidate)


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


def test_recovery_store_keeps_foreign_temp_swapped_before_replace(tmp_path: Path) -> None:
    import codex_master.server as server_module

    paths = FleetPaths.from_state_root(tmp_path)
    journal = sample_journal()
    foreign = replace(journal, journal_id="c" * 32)
    foreign_payload = (
        json.dumps(
            recovery_document(foreign),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    real_fsync = os.fsync
    real_replace = os.replace
    swapped = False

    def swap_temp_during_fsync(fd: int) -> None:
        nonlocal swapped
        real_fsync(fd)
        if swapped:
            return
        temp_paths = list(paths.root.glob(f".{paths.recovery.name}.*.tmp"))
        assert len(temp_paths) == 1
        foreign_path = paths.root / "foreign-recovery.tmp"
        foreign_path.write_bytes(foreign_payload)
        foreign_path.chmod(0o600)
        real_replace(foreign_path, temp_paths[0])
        swapped = True

    with patch.object(server_module.os, "fsync", side_effect=swap_temp_during_fsync):
        with pytest.raises(AgentError) as caught:
            server_module._fleet_store_recovery_journal(journal, paths)

    assert caught.value.args[0] == "fleet_recovery_state_invalid"
    assert swapped is True
    temp_paths = list(paths.root.glob(f".{paths.recovery.name}.*.tmp"))
    assert len(temp_paths) == 1
    assert temp_paths[0].read_bytes() == foreign_payload
    assert not paths.recovery.exists()


def test_recovery_remove_keeps_journal_swapped_after_load(tmp_path: Path) -> None:
    import codex_master.server as server_module

    paths = FleetPaths.from_state_root(tmp_path)
    expected = replace(sample_journal(), phase=RecoveryPhase.COMPLETE)
    foreign = replace(expected, journal_id="c" * 32)
    server_module._fleet_store_recovery_journal(expected, paths)
    foreign_path = paths.root / "foreign-recovery.json"
    foreign_path.write_text(
        json.dumps(
            recovery_document(foreign),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    foreign_path.chmod(0o600)
    real_open_parent = server_module.open_directory_no_follow_matching
    real_replace = os.replace
    open_count = 0
    swapped = False

    def open_parent_then_swap(*args, **kwargs):
        nonlocal open_count, swapped
        open_count += 1
        if open_count == 2:
            real_replace(foreign_path, paths.recovery)
            swapped = True
        return real_open_parent(*args, **kwargs)

    with patch.object(
        server_module,
        "open_directory_no_follow_matching",
        side_effect=open_parent_then_swap,
    ):
        assert server_module._fleet_remove_complete_recovery_journal(expected, paths) is False

    assert swapped is True
    assert server_module._fleet_load_recovery_journal(paths) == foreign


def test_recovery_remove_fails_closed_when_parent_fsync_fails(tmp_path: Path) -> None:
    import codex_master.server as server_module

    paths = FleetPaths.from_state_root(tmp_path)
    expected = replace(sample_journal(), phase=RecoveryPhase.COMPLETE)
    server_module._fleet_store_recovery_journal(expected, paths)

    with patch.object(server_module.os, "fsync", side_effect=OSError("parent fsync failed")):
        assert server_module._fleet_remove_complete_recovery_journal(expected, paths) is False

    assert not paths.recovery.exists()


def test_recovery_remove_complete_journal_unlinks_and_fsyncs_parent(tmp_path: Path) -> None:
    import codex_master.server as server_module

    paths = FleetPaths.from_state_root(tmp_path)
    expected = replace(sample_journal(), phase=RecoveryPhase.COMPLETE)
    server_module._fleet_store_recovery_journal(expected, paths)

    assert server_module._fleet_remove_complete_recovery_journal(expected, paths) is True
    assert not paths.recovery.exists()


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

    class _Service:
        def load(self) -> FleetSnapshot:
            return authoritative

    with patch.object(
        __import__("codex_master.server", fromlist=["_fleet_execute_recovery_action"]),
        "_fleet_execute_recovery_action",
        side_effect=execute,
    ), patch.object(
        server,
        "current_fleet_service",
        return_value=_Service(),
    ):
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


def test_recovery_plan_execution_blocks_if_post_plan_load_fails(tmp_path: Path) -> None:
    from codex_master.server import (
        _fleet_execute_recovery_plan,
        _FleetRecoveryTransaction,
    )
    from codex_master.fleet_registry import FleetSnapshot

    entries = (replace(sample_entry(), agent_id="d1"),)
    journal = replace(
        sample_journal(*entries),
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=1,
    )
    transaction = _FleetRecoveryTransaction(
        FleetPaths.from_state_root(tmp_path),
        journal,
    )
    plan = RecoveryPlan(
        (RecoveryAction(RecoveryActionKind.RETAIN_QUARANTINE, 0, "d1", DescriptorState.NEW),),
        has_third=False,
    )
    authoritative = FleetSnapshot(1, 1, (), ())

    class _Service:
        def __init__(self) -> None:
            self.calls = 0

        def load(self) -> FleetSnapshot:
            self.calls += 1
            if self.calls == 1:
                return authoritative
            raise OSError("post-load failure")

    service = _Service()
    with patch.object(
        __import__("codex_master.server", fromlist=["current_fleet_service"]),
        "current_fleet_service",
        return_value=service,
    ):
        with patch.object(
            __import__("codex_master.server", fromlist=["_fleet_execute_recovery_action"]),
            "_fleet_execute_recovery_action",
            return_value=True,
        ):
            errors, blocking = _fleet_execute_recovery_plan(
                transaction,
                plan,
                authoritative,
            )

    assert errors == ("fleet_recovery_incomplete",)
    assert blocking is True


def test_reconcile_disallows_legacy_inputs_without_persistent_journal() -> None:
    from codex_master.server import (
        _fleet_reconcile_divergent_materialization,
    )
    from codex_master.fleet_registry import FleetSnapshot

    current = FleetSnapshot(1, 1, (), ())
    planned = FleetSnapshot(1, 2, (), ())
    authoritative = FleetSnapshot(1, 2, (), ())
    assert not _fleet_reconcile_divergent_materialization(
        current,
        planned,
        authoritative,
        created=[],
        backups=[],
        staged=[],
    )


def test_reconcile_uses_persisted_journal_when_transaction_memory_is_empty(
    tmp_path: Path,
) -> None:
    import codex_master.server as server_module

    entry = replace(
        sample_entry(MutationKind.TOMBSTONE),
        old_descriptor_fingerprint="4" * 64,
        new_descriptor_fingerprint=None,
    )
    persisted = replace(
        sample_journal(entry),
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=2,
    )
    paths = FleetPaths.from_state_root(tmp_path)
    server_module._fleet_store_recovery_journal(persisted, paths)
    transaction = server_module._FleetRecoveryTransaction(
        paths,
        replace(persisted, entries=()),
    )
    current = FleetSnapshot(1, 2, (), ())
    planned = FleetSnapshot(1, 3, (), ())
    observed: list[tuple[FleetRecoveryJournal, RecoveryPlan]] = []

    def execute(actual_transaction, recovery_plan, authoritative):
        assert authoritative == current
        observed.append((actual_transaction.journal, recovery_plan))
        return (), False

    with patch.object(
        server_module,
        "_fleet_execute_recovery_plan",
        side_effect=execute,
    ):
        assert server_module._fleet_reconcile_divergent_materialization(
            current,
            planned,
            current,
            transaction=transaction,
        )

    assert observed == [
        (
            persisted,
            RecoveryPlan(
                (
                    RecoveryAction(
                        RecoveryActionKind.RETAIN_QUARANTINE,
                        0,
                        "d1",
                        DescriptorState.ABSENT,
                    ),
                ),
                False,
            ),
        ),
    ]
    assert transaction.journal == persisted


@pytest.mark.parametrize("persisted_state", ["missing", "invalid"])
def test_reconcile_fails_closed_without_persisted_journal(
    tmp_path: Path,
    persisted_state: str,
) -> None:
    import codex_master.server as server_module

    journal = replace(
        sample_journal(),
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=2,
    )
    paths = FleetPaths.from_state_root(tmp_path)
    transaction = server_module._FleetRecoveryTransaction(paths, journal)
    persisted = None
    load_error = AgentError("fleet_recovery_state_invalid") if persisted_state == "invalid" else None
    current = FleetSnapshot(1, 2, (), ())
    planned = FleetSnapshot(1, 3, (), ())

    with patch.object(
        server_module,
        "_fleet_load_recovery_journal",
        return_value=persisted,
        side_effect=load_error,
    ), patch.object(
        server_module,
        "_fleet_execute_recovery_plan",
        return_value=((), False),
    ) as execute:
        assert not server_module._fleet_reconcile_divergent_materialization(
            current,
            planned,
            current,
            transaction=transaction,
        )

    execute.assert_not_called()


def test_reconcile_accepts_persisted_empty_registry_only_journal(tmp_path: Path) -> None:
    import codex_master.server as server_module

    current = FleetSnapshot(1, 2, (), ())
    planned = FleetSnapshot(1, 3, (), ())
    journal = replace(
        sample_journal(),
        operation=RecoveryOperation.REGISTRY_ONLY,
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=current.generation,
        entries=(),
    )
    paths = FleetPaths.from_state_root(tmp_path)
    server_module._fleet_store_recovery_journal(journal, paths)
    transaction = server_module._FleetRecoveryTransaction(paths, journal)

    class _Service:
        def load(self) -> FleetSnapshot:
            return current

    with patch.object(server_module, "current_fleet_service", return_value=_Service()):
        assert server_module._fleet_reconcile_divergent_materialization(
            current,
            planned,
            current,
            transaction=transaction,
        )

    assert transaction.journal == journal


@pytest.mark.parametrize(
    "operation",
    (
        RecoveryOperation.SERIES_APPLY,
        RecoveryOperation.SERIES_DISABLE,
        RecoveryOperation.SERIES_DELETE,
    ),
)
def test_reconcile_rejects_empty_non_registry_only_journal(
    tmp_path: Path,
    operation: RecoveryOperation,
) -> None:
    import codex_master.server as server_module

    current = FleetSnapshot(1, 2, (), ())
    planned = FleetSnapshot(1, 3, (), ())
    journal = replace(
        sample_journal(),
        operation=operation,
        phase=RecoveryPhase.RECONCILING,
        authoritative_generation=current.generation,
        entries=(),
    )
    paths = FleetPaths.from_state_root(tmp_path)
    server_module._fleet_store_recovery_journal(journal, paths)
    transaction = server_module._FleetRecoveryTransaction(paths, journal)

    with patch.object(
        server_module,
        "_fleet_execute_recovery_plan",
        return_value=((), False),
    ) as execute:
        assert not server_module._fleet_reconcile_divergent_materialization(
            current,
            planned,
            current,
            transaction=transaction,
        )

    execute.assert_not_called()


def test_registry_only_publish_rejects_different_generation_before_snapshot_divergence(
    tmp_path: Path,
) -> None:
    import codex_master.server as server_module

    current = FleetSnapshot(1, 2, (), ())
    stored = FleetSnapshot(1, 3, (), ())
    authoritative = FleetSnapshot(1, 4, (), ())
    state = tmp_path / "state"
    pool = tmp_path / "pool"
    before_inventory = server_module.build_inventory(current, pool)

    class _Service:
        def load(self) -> FleetSnapshot:
            return authoritative

    with patch.object(server_module, "STATE_ROOT", state), patch.object(
        server_module,
        "AGENT_POOL_ROOT",
        pool,
    ), server_module.temporary_agent_inventory(before_inventory):
        transaction = server_module._FleetRecoveryTransaction.begin(
            RecoveryOperation.REGISTRY_ONLY,
            current,
            stored,
            (),
        )
        transaction.advance(RecoveryPhase.MATERIALIZING)
        transaction.advance(RecoveryPhase.CAS_PENDING)

        with pytest.raises(AgentError) as caught:
            server_module._fleet_publish_recovery_commit(
                _Service(),
                stored,
                transaction,
            )

        assert str(caught.value) == "fleet_inventory_publish_failed"
        persisted = server_module._fleet_load_recovery_journal(transaction.paths)
        assert persisted == transaction.journal
        assert persisted is not None
        assert persisted.phase is RecoveryPhase.CAS_PENDING
        assert persisted.blocking_error_codes == ()
        assert server_module.current_agent_inventory() == before_inventory


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
        patch.object(server, "read_agent_lease_record", return_value=None),
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
        patch.object(server, "agent_lease_status", return_value={"state": "unclaimed", "held_by_this_server": False}),
        patch.object(server, "agent_home_process_summary", return_value={"process_count": 0}),
        patch.object(server, "release_agent", return_value={"lease": {"state": "unclaimed"}}),
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
