from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping, TypeVar

from .fleet_registry import AgentDescriptor


MAX_RECOVERY_DOCUMENT_BYTES = 1024 * 1024
MAX_RECOVERY_ENTRIES = 1000
RECOVERY_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_JOURNAL_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_AGENT_ID_RE = re.compile(r"[a-z](?:[1-9]|[1-9][0-9]|100)\Z")
_HIDDEN_NAME_RE = re.compile(r"\.codex-fleet-remove-[a-z0-9-]{1,96}\Z")
_ARTIFACT_RE = re.compile(r"[A-Za-z0-9._-][A-Za-z0-9._/-]{0,199}\Z")


class FleetRecoveryValidationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RecoveryOperation(str, Enum):
    SERIES_APPLY = "series_apply"
    SERIES_DISABLE = "series_disable"
    SERIES_DELETE = "series_delete"
    REGISTRY_ONLY = "registry_only"


class RecoveryPhase(str, Enum):
    PREPARED = "prepared"
    MATERIALIZING = "materializing"
    CAS_PENDING = "cas_pending"
    RECONCILING = "reconciling"
    VERIFIED = "verified"
    PUBLISHED = "published"
    COMPLETE = "complete"
    DEGRADED = "degraded"


class MutationKind(str, Enum):
    CREATED = "created"
    BACKUP = "backup"
    TOMBSTONE = "tombstone"
    RESERVATION = "reservation"


class EntryPhase(str, Enum):
    INTENT = "intent"
    STAGED = "staged"
    PUBLIC = "public"
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    VERIFIED = "verified"
    FAILED = "failed"


class DescriptorState(str, Enum):
    ABSENT = "absent"
    OLD = "old"
    NEW = "new"
    THIRD = "third"


class RecoveryActionKind(str, Enum):
    QUARANTINE_CREATED = "quarantine_created"
    VERIFY_CREATED = "verify_created"
    RESTORE_BACKUP = "restore_backup"
    RESTORE_TOMBSTONE = "restore_tombstone"
    RELEASE_RESERVATION = "release_reservation"
    RETAIN_QUARANTINE = "retain_quarantine"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    relative_path: str
    mode: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RecoveryEntry:
    kind: MutationKind
    agent_id: str
    hidden_name: str
    old_descriptor_fingerprint: str | None
    new_descriptor_fingerprint: str | None
    old_materialization_fingerprint: str | None
    new_materialization_fingerprint: str | None
    source_identity: FileIdentity | None
    target_identity: FileIdentity | None
    manifest: tuple[ArtifactDigest, ...]
    phase: EntryPhase
    result_code: str | None


@dataclass(frozen=True, slots=True)
class FleetRecoveryJournal:
    schema_version: int
    journal_id: str
    operation: RecoveryOperation
    pool_root_digest: str
    expected_generation: int
    planned_generation: int
    authoritative_generation: int | None
    phase: RecoveryPhase
    entries: tuple[RecoveryEntry, ...]
    blocking_error_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecoveryAction:
    kind: RecoveryActionKind
    entry_index: int
    agent_id: str
    descriptor_state: DescriptorState


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    actions: tuple[RecoveryAction, ...]
    has_third: bool


ROOT_FIELDS = frozenset({
    "schema_version", "journal_id", "operation", "pool_root_digest",
    "expected_generation", "planned_generation", "authoritative_generation",
    "phase", "entries", "blocking_error_codes",
})
ENTRY_FIELDS = frozenset({
    "kind", "agent_id", "hidden_name", "old_descriptor_fingerprint",
    "new_descriptor_fingerprint", "old_materialization_fingerprint",
    "new_materialization_fingerprint", "source_identity", "target_identity",
    "manifest", "phase", "result_code",
})
IDENTITY_FIELDS = frozenset({"dev", "ino", "mode", "uid", "gid", "nlink"})
ARTIFACT_FIELDS = frozenset({"relative_path", "mode", "sha256"})
RESULT_CODES = frozenset({
    "fleet_create_rollback_diverged",
    "fleet_update_rollback_diverged",
    "fleet_tombstone_rollback_diverged",
    "fleet_registry_delete_reservation_diverged",
    "fleet_recovery_incomplete",
    "fleet_registry_commit_diverged",
})


def _fail() -> None:
    raise FleetRecoveryValidationError("invalid_fleet_recovery")


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail()
    return value


def _exact_fields(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    raw = _mapping(value)
    if set(raw) != fields:
        _fail()
    return raw


def _integer(value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _fail()
    return value


_EnumT = TypeVar("_EnumT", bound=Enum)


def _enum(enum_type: type[_EnumT], value: object) -> _EnumT:
    if not isinstance(value, str):
        _fail()
    try:
        return enum_type(value)  # type: ignore[arg-type]
    except ValueError:
        _fail()


def _optional_sha256(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        _fail()
    return value


def _identity(value: object) -> FileIdentity | None:
    if value is None:
        return None
    raw = _exact_fields(value, IDENTITY_FIELDS)
    return FileIdentity(
        _integer(raw["dev"], minimum=0, maximum=2**63 - 1),
        _integer(raw["ino"], minimum=1, maximum=2**63 - 1),
        _integer(raw["mode"], minimum=0, maximum=0o177777),
        _integer(raw["uid"], minimum=0, maximum=2**32 - 1),
        _integer(raw["gid"], minimum=0, maximum=2**32 - 1),
        _integer(raw["nlink"], minimum=1, maximum=2**31 - 1),
    )


def _artifact(value: object) -> ArtifactDigest:
    raw = _exact_fields(value, ARTIFACT_FIELDS)
    path = raw["relative_path"]
    digest = raw["sha256"]
    if (
        not isinstance(path, str)
        or not _ARTIFACT_RE.fullmatch(path)
        or path.startswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
    ):
        _fail()
    return ArtifactDigest(
        path,
        _integer(raw["mode"], minimum=0, maximum=0o7777),
        digest,
    )


def _entry(value: object) -> RecoveryEntry:
    raw = _exact_fields(value, ENTRY_FIELDS)
    agent_id = raw["agent_id"]
    hidden_name = raw["hidden_name"]
    manifest_raw = raw["manifest"]
    result_code = raw["result_code"]
    if (
        not isinstance(agent_id, str)
        or not _AGENT_ID_RE.fullmatch(agent_id)
        or not isinstance(hidden_name, str)
        or not _HIDDEN_NAME_RE.fullmatch(hidden_name)
        or not isinstance(manifest_raw, list)
        or len(manifest_raw) > 64
        or (
            result_code is not None
            and (not isinstance(result_code, str) or result_code not in RESULT_CODES)
        )
    ):
        _fail()
    manifest = tuple(_artifact(item) for item in manifest_raw)
    if len({item.relative_path for item in manifest}) != len(manifest):
        _fail()
    return RecoveryEntry(
        _enum(MutationKind, raw["kind"]),
        agent_id,
        hidden_name,
        _optional_sha256(raw["old_descriptor_fingerprint"]),
        _optional_sha256(raw["new_descriptor_fingerprint"]),
        _optional_sha256(raw["old_materialization_fingerprint"]),
        _optional_sha256(raw["new_materialization_fingerprint"]),
        _identity(raw["source_identity"]),
        _identity(raw["target_identity"]),
        manifest,
        _enum(EntryPhase, raw["phase"]),
        result_code,
    )


def normalize_recovery_document(value: object) -> FleetRecoveryJournal:
    raw = _exact_fields(value, ROOT_FIELDS)
    journal_id = raw["journal_id"]
    pool_digest = raw["pool_root_digest"]
    entries_raw = raw["entries"]
    errors_raw = raw["blocking_error_codes"]
    if (
        _integer(raw["schema_version"], minimum=1, maximum=1) != RECOVERY_SCHEMA_VERSION
        or not isinstance(journal_id, str)
        or not _JOURNAL_ID_RE.fullmatch(journal_id)
        or not isinstance(pool_digest, str)
        or not _SHA256_RE.fullmatch(pool_digest)
        or not isinstance(entries_raw, list)
        or len(entries_raw) > MAX_RECOVERY_ENTRIES
        or not isinstance(errors_raw, list)
        or len(errors_raw) > len(RESULT_CODES)
        or any(error not in RESULT_CODES for error in errors_raw)
        or errors_raw != sorted(set(errors_raw))
    ):
        _fail()
    expected = _integer(raw["expected_generation"], minimum=1, maximum=2**63 - 2)
    planned = _integer(raw["planned_generation"], minimum=2, maximum=2**63 - 1)
    authoritative_raw = raw["authoritative_generation"]
    authoritative = (
        None
        if authoritative_raw is None
        else _integer(authoritative_raw, minimum=1, maximum=2**63 - 1)
    )
    if planned != expected + 1:
        _fail()
    entries = tuple(_entry(item) for item in entries_raw)
    if len({(item.kind, item.agent_id) for item in entries}) != len(entries):
        _fail()
    return FleetRecoveryJournal(
        RECOVERY_SCHEMA_VERSION,
        journal_id,
        _enum(RecoveryOperation, raw["operation"]),
        pool_digest,
        expected,
        planned,
        authoritative,
        _enum(RecoveryPhase, raw["phase"]),
        entries,
        tuple(errors_raw),
    )


def recovery_document(journal: FleetRecoveryJournal) -> dict[str, object]:
    def identity_document(identity: FileIdentity | None) -> dict[str, int] | None:
        if identity is None:
            return None
        return {
            "dev": identity.dev,
            "ino": identity.ino,
            "mode": identity.mode,
            "uid": identity.uid,
            "gid": identity.gid,
            "nlink": identity.nlink,
        }

    return {
        "schema_version": journal.schema_version,
        "journal_id": journal.journal_id,
        "operation": journal.operation.value,
        "pool_root_digest": journal.pool_root_digest,
        "expected_generation": journal.expected_generation,
        "planned_generation": journal.planned_generation,
        "authoritative_generation": journal.authoritative_generation,
        "phase": journal.phase.value,
        "entries": [
            {
                "kind": entry.kind.value,
                "agent_id": entry.agent_id,
                "hidden_name": entry.hidden_name,
                "old_descriptor_fingerprint": entry.old_descriptor_fingerprint,
                "new_descriptor_fingerprint": entry.new_descriptor_fingerprint,
                "old_materialization_fingerprint": entry.old_materialization_fingerprint,
                "new_materialization_fingerprint": entry.new_materialization_fingerprint,
                "source_identity": identity_document(entry.source_identity),
                "target_identity": identity_document(entry.target_identity),
                "manifest": [
                    {"relative_path": item.relative_path, "mode": item.mode, "sha256": item.sha256}
                    for item in entry.manifest
                ],
                "phase": entry.phase.value,
                "result_code": entry.result_code,
            }
            for entry in journal.entries
        ],
        "blocking_error_codes": list(journal.blocking_error_codes),
    }


def _fingerprint(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def descriptor_fingerprint(descriptor: AgentDescriptor | None) -> str | None:
    if descriptor is None:
        return None
    return _fingerprint({
        "agent_id": descriptor.agent_id,
        "series_prefix": descriptor.series_prefix,
        "ordinal": descriptor.ordinal,
        "label": descriptor.label,
        "runner": descriptor.runner.value,
        "provider": descriptor.provider.value,
        "model": descriptor.model,
        "account_id": descriptor.account_id,
        "home": str(descriptor.home),
        "session": descriptor.session,
        "enabled": descriptor.enabled,
    })


def materialization_fingerprint(
    descriptor: AgentDescriptor,
    manifest: tuple[ArtifactDigest, ...],
) -> str:
    return _fingerprint({
        "agent_id": descriptor.agent_id,
        "series_prefix": descriptor.series_prefix,
        "ordinal": descriptor.ordinal,
        "runner": descriptor.runner.value,
        "provider": descriptor.provider.value,
        "model": descriptor.model,
        "manifest": [
            {"relative_path": item.relative_path, "mode": item.mode, "sha256": item.sha256}
            for item in manifest
        ],
    })


def classify_descriptor(
    authoritative: str | None,
    old: str | None,
    new: str | None,
) -> DescriptorState:
    if authoritative is None:
        return DescriptorState.ABSENT
    if old is not None and authoritative == old:
        return DescriptorState.OLD
    if new is not None and authoritative == new:
        return DescriptorState.NEW
    return DescriptorState.THIRD


_ACTION_MATRIX = {
    MutationKind.CREATED: {
        DescriptorState.ABSENT: RecoveryActionKind.QUARANTINE_CREATED,
        DescriptorState.OLD: RecoveryActionKind.QUARANTINE_CREATED,
        DescriptorState.NEW: RecoveryActionKind.VERIFY_CREATED,
        DescriptorState.THIRD: RecoveryActionKind.QUARANTINE_CREATED,
    },
    MutationKind.BACKUP: {
        DescriptorState.ABSENT: RecoveryActionKind.RETAIN_QUARANTINE,
        DescriptorState.OLD: RecoveryActionKind.RESTORE_BACKUP,
        DescriptorState.NEW: RecoveryActionKind.RETAIN_QUARANTINE,
        DescriptorState.THIRD: RecoveryActionKind.RETAIN_QUARANTINE,
    },
    MutationKind.TOMBSTONE: {
        DescriptorState.ABSENT: RecoveryActionKind.RETAIN_QUARANTINE,
        DescriptorState.OLD: RecoveryActionKind.RESTORE_TOMBSTONE,
        DescriptorState.NEW: RecoveryActionKind.RETAIN_QUARANTINE,
        DescriptorState.THIRD: RecoveryActionKind.RETAIN_QUARANTINE,
    },
    MutationKind.RESERVATION: {
        DescriptorState.ABSENT: RecoveryActionKind.RELEASE_RESERVATION,
        DescriptorState.OLD: RecoveryActionKind.RELEASE_RESERVATION,
        DescriptorState.NEW: RecoveryActionKind.RELEASE_RESERVATION,
        DescriptorState.THIRD: RecoveryActionKind.RELEASE_RESERVATION,
    },
}


def plan_reconciliation(
    journal: FleetRecoveryJournal,
    authoritative_fingerprints: dict[str, str | None],
) -> RecoveryPlan:
    actions: list[RecoveryAction] = []
    has_third = False
    for index, entry in enumerate(journal.entries):
        if entry.agent_id not in authoritative_fingerprints:
            _fail()
        state = classify_descriptor(
            authoritative_fingerprints[entry.agent_id],
            entry.old_descriptor_fingerprint,
            entry.new_descriptor_fingerprint,
        )
        has_third = has_third or state is DescriptorState.THIRD
        actions.append(RecoveryAction(
            _ACTION_MATRIX[entry.kind][state],
            index,
            entry.agent_id,
            state,
        ))
    return RecoveryPlan(tuple(actions), has_third)


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


def advance_recovery_phase(
    journal: FleetRecoveryJournal,
    target: RecoveryPhase,
    *,
    authoritative_generation: int | None = None,
    blocking_error_codes: tuple[str, ...] = (),
) -> FleetRecoveryJournal:
    if target not in _TRANSITIONS[journal.phase]:
        _fail()
    generation = journal.authoritative_generation
    if authoritative_generation is not None:
        generation = _integer(authoritative_generation, minimum=1, maximum=2**63 - 1)
    if target in {
        RecoveryPhase.RECONCILING,
        RecoveryPhase.VERIFIED,
        RecoveryPhase.PUBLISHED,
        RecoveryPhase.COMPLETE,
    } and generation is None:
        _fail()
    if any(not isinstance(code, str) or code not in RESULT_CODES for code in blocking_error_codes):
        _fail()
    normalized_errors = tuple(sorted(set(blocking_error_codes)))
    if target in {RecoveryPhase.VERIFIED, RecoveryPhase.PUBLISHED, RecoveryPhase.COMPLETE} and normalized_errors:
        _fail()
    return replace(
        journal,
        phase=target,
        authoritative_generation=generation,
        blocking_error_codes=tuple(normalized_errors),
    )
