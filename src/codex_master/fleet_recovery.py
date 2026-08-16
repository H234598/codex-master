from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from dataclasses import field as _field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, TypeVar

from .fleet_registry import AgentDescriptor
from .fleet_migration_materialization import MemberIdAllocation


MAX_RECOVERY_DOCUMENT_BYTES = 1024 * 1024
MAX_RECOVERY_ENTRIES = 1000
RECOVERY_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_JOURNAL_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
# Registry series may use an explicit separator in a multi-part prefix, for
# example ``o-a1``.  Keep the legacy one-letter form strict so ambiguous
# identifiers such as ``aa1`` remain rejected.
_AGENT_ID_RE = re.compile(
    r"[a-z](?:[a-z0-9_-]*[-_][a-z0-9_-]*)?(?:[1-9]|[1-9][0-9]|100)\Z"
)
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
    VERIFY_UNCHANGED = "verify_unchanged"
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


class GMigrationRecoveryError(ValueError):
    def __init__(self, code: str = "migration_journal_invalid") -> None:
        self.code = code
        super().__init__(code)


class GMigrationPhase(str, Enum):
    PREPARED = "prepared"
    HOMES_STAGED = "homes_staged"
    ALIASES_STAGED = "aliases_staged"
    CAS_PENDING = "cas_pending"
    CAS_COMMITTED = "cas_committed"
    VERIFIED = "verified"
    PUBLISHED = "published"
    COMPLETE = "complete"
    ROLLED_BACK = "rolled_back"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class GMigrationHomeIdentity:
    agent_id: str
    identity: FileIdentity
    rollback_name: str


@dataclass(frozen=True, slots=True)
class GMigrationAlias:
    old_agent_id: str
    current_agent_id: str
    member_id: str = _field(repr=False)
    expected_generation: int
    migration_id: str


@dataclass(frozen=True, slots=True)
class GMigrationJournal:
    schema_version: int
    migration_id: str
    manifest_version: int
    expected_registry_generation: int
    source_projection_digest: str
    source_snapshot_digest: str
    plan_digest: str
    candidate_digest: str
    binding_evidence_digest: str = _field(repr=False)
    allocations: tuple[MemberIdAllocation, ...] = _field(repr=False)
    source_ids: tuple[str, ...]
    home_identities: tuple[GMigrationHomeIdentity, ...]
    aliases: tuple[GMigrationAlias, ...]
    phase: GMigrationPhase
    authoritative_generation: int | None
    blocking_error_codes: tuple[str, ...]

    def __repr__(self) -> str:
        return "GMigrationJournal(<redacted>)"


_G_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_G_UUID4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_G_ROLLBACK_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_G_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _g_fail() -> None:
    raise GMigrationRecoveryError()


def _g_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _g_fail()
    try:
        if any(type(key) is not str for key in value):
            _g_fail()
    except Exception:
        _g_fail()
    return value


def _g_exact_fields(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    raw = _g_mapping(value)
    try:
        if set(raw) != fields:
            _g_fail()
    except Exception:
        _g_fail()
    return raw


def _g_text(value: object, *, minimum: int, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _g_fail()
    return value


def _g_integer(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _g_fail()
    return value


def _g_digest(value: object) -> str:
    if type(value) is not str or not _G_DIGEST_RE.fullmatch(value):
        _g_fail()
    return value


def _g_canonical_member_id(value: object) -> str:
    if type(value) is not str or not _G_UUID4_RE.fullmatch(value):
        _g_fail()
    return value


def _g_agent_id(value: object) -> str:
    if type(value) is not str or not _AGENT_ID_RE.fullmatch(value):
        _g_fail()
    return value


def _g_migration_identity(value: object) -> str:
    value = _g_text(value, minimum=1, maximum=512)
    if any(char in value for char in "\\/\x00"):
        _g_fail()
    return value


def _g_rollback_name(value: object) -> str:
    value = _g_text(value, minimum=1, maximum=128)
    if value in {".", ".."} or not _G_ROLLBACK_NAME_RE.fullmatch(value):
        _g_fail()
    return value


def _g_file_identity(value: object) -> FileIdentity:
    if type(value) is not FileIdentity:
        _g_fail()
    _g_integer(value.dev, minimum=0, maximum=2**63 - 1)
    _g_integer(value.ino, minimum=1, maximum=2**63 - 1)
    _g_integer(value.mode, minimum=0, maximum=0o177777)
    _g_integer(value.uid, minimum=0, maximum=2**32 - 1)
    _g_integer(value.gid, minimum=0, maximum=2**32 - 1)
    _g_integer(value.nlink, minimum=1, maximum=2**31 - 1)
    return value


def _g_identity_document(value: object) -> FileIdentity:
    raw = _g_exact_fields(value, IDENTITY_FIELDS)
    return FileIdentity(
        _g_integer(raw["dev"], minimum=0, maximum=2**63 - 1),
        _g_integer(raw["ino"], minimum=1, maximum=2**63 - 1),
        _g_integer(raw["mode"], minimum=0, maximum=0o177777),
        _g_integer(raw["uid"], minimum=0, maximum=2**32 - 1),
        _g_integer(raw["gid"], minimum=0, maximum=2**32 - 1),
        _g_integer(raw["nlink"], minimum=1, maximum=2**31 - 1),
    )


def _g_allocation(value: object) -> MemberIdAllocation:
    raw = _g_exact_fields(value, frozenset({"migration_identity", "member_id"}))
    return MemberIdAllocation(
        _g_migration_identity(raw["migration_identity"]),
        _g_canonical_member_id(raw["member_id"]),
    )


def _g_home_identity(value: object) -> GMigrationHomeIdentity:
    raw = _g_exact_fields(value, frozenset({"agent_id", "identity", "rollback_name"}))
    return GMigrationHomeIdentity(
        _g_agent_id(raw["agent_id"]),
        _g_identity_document(raw["identity"]),
        _g_rollback_name(raw["rollback_name"]),
    )


def _g_alias(value: object, migration_id: str, expected_generation: int) -> GMigrationAlias:
    raw = _g_exact_fields(
        value,
        frozenset({"old_agent_id", "current_agent_id", "member_id", "expected_generation", "migration_id"}),
    )
    alias = GMigrationAlias(
        _g_agent_id(raw["old_agent_id"]),
        _g_agent_id(raw["current_agent_id"]),
        _g_canonical_member_id(raw["member_id"]),
        _g_integer(raw["expected_generation"], minimum=1, maximum=2**63 - 1),
        _g_text(raw["migration_id"], minimum=32, maximum=32),
    )
    if (
        alias.old_agent_id == alias.current_agent_id
        or alias.migration_id != migration_id
        or alias.expected_generation != expected_generation
    ):
        _g_fail()
    if not _JOURNAL_ID_RE.fullmatch(alias.migration_id):
        _g_fail()
    return alias


def _g_sorted_unique(values: tuple[str, ...]) -> bool:
    return values == tuple(sorted(values)) and len(values) == len(set(values))


def _g_validate_aliases(
    aliases: tuple[GMigrationAlias, ...],
    *,
    migration_id: str,
    expected_generation: int,
) -> None:
    if len(aliases) > MAX_RECOVERY_ENTRIES:
        _g_fail()
    old_ids: set[str] = set()
    current_ids: set[str] = set()
    mapping: dict[str, str] = {}
    for alias in aliases:
        if type(alias) is not GMigrationAlias:
            _g_fail()
        checked = _g_alias_document(alias)
        if (
            checked.migration_id != migration_id
            or checked.expected_generation != expected_generation
            or checked.old_agent_id == checked.current_agent_id
            or checked.old_agent_id in old_ids
            or checked.current_agent_id in current_ids
        ):
            _g_fail()
        old_ids.add(checked.old_agent_id)
        current_ids.add(checked.current_agent_id)
        mapping[checked.old_agent_id] = checked.current_agent_id
    if old_ids.intersection(current_ids):
        _g_fail()
    if tuple(alias.old_agent_id for alias in aliases) != tuple(sorted(old_ids)):
        _g_fail()
    for source in mapping:
        seen: set[str] = set()
        current = source
        while current in mapping:
            if current in seen:
                _g_fail()
            seen.add(current)
            current = mapping[current]


def _g_alias_document(alias: GMigrationAlias) -> GMigrationAlias:
    if type(alias) is not GMigrationAlias:
        _g_fail()
    return GMigrationAlias(
        _g_agent_id(alias.old_agent_id),
        _g_agent_id(alias.current_agent_id),
        _g_canonical_member_id(alias.member_id),
        _g_integer(alias.expected_generation, minimum=1, maximum=2**63 - 1),
        _g_text(alias.migration_id, minimum=32, maximum=32),
    )


def _g_validate_journal(journal: object) -> GMigrationJournal:
    if type(journal) is not GMigrationJournal:
        _g_fail()
    if (
        _g_integer(journal.schema_version, minimum=1, maximum=1) != 1
        or _g_text(journal.migration_id, minimum=32, maximum=32) != journal.migration_id
        or not _JOURNAL_ID_RE.fullmatch(journal.migration_id)
        or _g_integer(journal.manifest_version, minimum=1, maximum=1) != 1
    ):
        _g_fail()
    expected_generation = _g_integer(
        journal.expected_registry_generation,
        minimum=1,
        maximum=2**63 - 2,
    )
    for digest in (
        journal.source_projection_digest,
        journal.source_snapshot_digest,
        journal.plan_digest,
        journal.candidate_digest,
        journal.binding_evidence_digest,
    ):
        _g_digest(digest)
    if type(journal.allocations) is not tuple:
        _g_fail()
    allocations = tuple(
        MemberIdAllocation(
            _g_migration_identity(item.migration_identity),
            _g_canonical_member_id(item.member_id),
        )
        if type(item) is MemberIdAllocation
        else _g_fail()
        for item in journal.allocations
    )
    allocation_identities = tuple(item.migration_identity for item in allocations)
    allocation_member_ids = tuple(item.member_id for item in allocations)
    if (
        len(allocations) > MAX_RECOVERY_ENTRIES
        or not _g_sorted_unique(allocation_identities)
        or len(set(allocation_member_ids)) != len(allocation_member_ids)
    ):
        _g_fail()
    if type(journal.source_ids) is not tuple:
        _g_fail()
    source_ids = tuple(_g_agent_id(value) for value in journal.source_ids)
    if not _g_sorted_unique(source_ids):
        _g_fail()
    if len(source_ids) > MAX_RECOVERY_ENTRIES:
        _g_fail()
    if type(journal.home_identities) is not tuple:
        _g_fail()
    homes = tuple(
        GMigrationHomeIdentity(
            _g_agent_id(item.agent_id),
            _g_file_identity(item.identity),
            _g_rollback_name(item.rollback_name),
        )
        if type(item) is GMigrationHomeIdentity
        else _g_fail()
        for item in journal.home_identities
    )
    home_ids = tuple(item.agent_id for item in homes)
    if (
        len(homes) > MAX_RECOVERY_ENTRIES
        or not _g_sorted_unique(home_ids)
        or not set(home_ids).issubset(source_ids)
    ):
        _g_fail()
    target_generation = expected_generation + 1
    if type(journal.aliases) is not tuple:
        _g_fail()
    aliases = tuple(
        GMigrationAlias(
            _g_agent_id(item.old_agent_id),
            _g_agent_id(item.current_agent_id),
            _g_canonical_member_id(item.member_id),
            _g_integer(item.expected_generation, minimum=1, maximum=2**63 - 1),
            _g_text(item.migration_id, minimum=32, maximum=32),
        )
        if type(item) is GMigrationAlias
        else _g_fail()
        for item in journal.aliases
    )
    _g_validate_aliases(
        aliases,
        migration_id=journal.migration_id,
        expected_generation=target_generation,
    )
    if not set(alias.old_agent_id for alias in aliases).issubset(source_ids):
        _g_fail()
    if type(journal.phase) is not GMigrationPhase:
        _g_fail()
    authoritative = journal.authoritative_generation
    if authoritative is not None:
        _g_integer(authoritative, minimum=1, maximum=2**63 - 1)
        if authoritative != target_generation:
            _g_fail()
    if type(journal.blocking_error_codes) is not tuple or len(journal.blocking_error_codes) > 32:
        _g_fail()
    errors = tuple(
        _g_text(code, minimum=1, maximum=64)
        if _G_CODE_RE.fullmatch(code)
        else _g_fail()
        for code in journal.blocking_error_codes
    )
    if not _g_sorted_unique(errors):
        _g_fail()
    return GMigrationJournal(
        1,
        journal.migration_id,
        1,
        expected_generation,
        journal.source_projection_digest,
        journal.source_snapshot_digest,
        journal.plan_digest,
        journal.candidate_digest,
        journal.binding_evidence_digest,
        allocations,
        source_ids,
        homes,
        aliases,
        journal.phase,
        authoritative,
        errors,
    )


def _g_allocation_document(allocation: MemberIdAllocation) -> dict[str, str]:
    if type(allocation) is not MemberIdAllocation:
        _g_fail()
    return {
        "migration_identity": _g_migration_identity(allocation.migration_identity),
        "member_id": _g_canonical_member_id(allocation.member_id),
    }


def _g_home_document(home: GMigrationHomeIdentity) -> dict[str, object]:
    if type(home) is not GMigrationHomeIdentity:
        _g_fail()
    identity = _g_file_identity(home.identity)
    return {
        "agent_id": _g_agent_id(home.agent_id),
        "identity": {
            "dev": identity.dev,
            "ino": identity.ino,
            "mode": identity.mode,
            "uid": identity.uid,
            "gid": identity.gid,
            "nlink": identity.nlink,
        },
        "rollback_name": _g_rollback_name(home.rollback_name),
    }


def _g_alias_output(alias: GMigrationAlias) -> dict[str, object]:
    alias = _g_alias_document(alias)
    return {
        "old_agent_id": alias.old_agent_id,
        "current_agent_id": alias.current_agent_id,
        "member_id": alias.member_id,
        "expected_generation": alias.expected_generation,
        "migration_id": alias.migration_id,
    }


def normalize_g_migration_journal(value: object) -> GMigrationJournal:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > MAX_RECOVERY_DOCUMENT_BYTES:
            _g_fail()
        raw = _g_exact_fields(
            value,
            frozenset({
                "schema_version",
                "migration_id",
                "manifest_version",
                "expected_registry_generation",
                "source_projection_digest",
                "source_snapshot_digest",
                "plan_digest",
                "candidate_digest",
                "binding_evidence_digest",
                "allocations",
                "source_ids",
                "home_identities",
                "aliases",
                "phase",
                "authoritative_generation",
                "blocking_error_codes",
            }),
        )
        if (
            type(raw["allocations"]) is not list
            or type(raw["source_ids"]) is not list
            or type(raw["home_identities"]) is not list
            or type(raw["aliases"]) is not list
            or type(raw["blocking_error_codes"]) is not list
        ):
            _g_fail()
        journal = GMigrationJournal(
            _g_integer(raw["schema_version"], minimum=1, maximum=1),
            _g_text(raw["migration_id"], minimum=32, maximum=32),
            _g_integer(raw["manifest_version"], minimum=1, maximum=1),
            _g_integer(raw["expected_registry_generation"], minimum=1, maximum=2**63 - 2),
            _g_digest(raw["source_projection_digest"]),
            _g_digest(raw["source_snapshot_digest"]),
            _g_digest(raw["plan_digest"]),
            _g_digest(raw["candidate_digest"]),
            _g_digest(raw["binding_evidence_digest"]),
            tuple(_g_allocation(item) for item in raw["allocations"]),
            tuple(_g_agent_id(item) for item in raw["source_ids"]),
            tuple(_g_home_identity(item) for item in raw["home_identities"]),
            tuple(
                _g_alias(
                    item,
                    _g_text(raw["migration_id"], minimum=32, maximum=32),
                    _g_integer(raw["expected_registry_generation"], minimum=1, maximum=2**63 - 2) + 1,
                )
                for item in raw["aliases"]
            ),
            GMigrationPhase(raw["phase"])
            if type(raw["phase"]) is str
            else _g_fail(),
            None
            if raw["authoritative_generation"] is None
            else _g_integer(raw["authoritative_generation"], minimum=1, maximum=2**63 - 1),
            tuple(_g_text(code, minimum=1, maximum=64) for code in raw["blocking_error_codes"]),
        )
        return _g_validate_journal(journal)
    except GMigrationRecoveryError:
        raise
    except Exception:
        _g_fail()


def g_migration_journal_document(journal: GMigrationJournal) -> dict[str, object]:
    try:
        journal = _g_validate_journal(journal)
        document = {
            "schema_version": journal.schema_version,
            "migration_id": journal.migration_id,
            "manifest_version": journal.manifest_version,
            "expected_registry_generation": journal.expected_registry_generation,
            "source_projection_digest": journal.source_projection_digest,
            "source_snapshot_digest": journal.source_snapshot_digest,
            "plan_digest": journal.plan_digest,
            "candidate_digest": journal.candidate_digest,
            "binding_evidence_digest": journal.binding_evidence_digest,
            "allocations": [_g_allocation_document(item) for item in journal.allocations],
            "source_ids": list(journal.source_ids),
            "home_identities": [_g_home_document(item) for item in journal.home_identities],
            "aliases": [_g_alias_output(item) for item in journal.aliases],
            "phase": journal.phase.value,
            "authoritative_generation": journal.authoritative_generation,
            "blocking_error_codes": list(journal.blocking_error_codes),
        }
        normalize_g_migration_journal(document)
        return document
    except GMigrationRecoveryError:
        raise
    except Exception:
        _g_fail()


def g_migration_alias_view(journal: GMigrationJournal) -> Mapping[str, str]:
    journal = _g_validate_journal(journal)
    return MappingProxyType({alias.old_agent_id: alias.current_agent_id for alias in journal.aliases})


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
    try:
        raw_payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail()
    if len(raw_payload) > MAX_RECOVERY_DOCUMENT_BYTES:
        _fail()

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
        or any(not isinstance(error, str) or error not in RESULT_CODES for error in errors_raw)
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


def _recovery_document(journal: FleetRecoveryJournal) -> dict[str, object]:
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


def recovery_document(journal: FleetRecoveryJournal) -> dict[str, object]:
    if not isinstance(journal, FleetRecoveryJournal):
        _fail()
    try:
        raw = _recovery_document(journal)
    except (AttributeError, TypeError, ValueError):
        _fail()
    return _recovery_document(normalize_recovery_document(raw))


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
        "skill_profile": descriptor.skill_profile,
        "task_profile": descriptor.task_profile,
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
        "skill_profile": descriptor.skill_profile,
        "task_profile": descriptor.task_profile,
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
        if (
            entry.phase is EntryPhase.INTENT
            and entry.kind in {MutationKind.CREATED, MutationKind.BACKUP}
            and entry.source_identity is None
            and entry.target_identity is None
            and state in {DescriptorState.ABSENT, DescriptorState.OLD}
        ):
            actions.append(RecoveryAction(
                RecoveryActionKind.VERIFY_UNCHANGED,
                index,
                entry.agent_id,
                state,
            ))
            continue
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
