from __future__ import annotations

import contextlib
import ctypes
from dataclasses import dataclass, replace
from enum import Enum
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Callable


FLEET_HOME_RECOVERY_SCHEMA_VERSION = 2
MAX_FLEET_HOME_RECOVERY_BYTES = 256 * 1024
MAX_FLEET_HOME_RECOVERY_HOMES = 256
MAX_FLEET_HOME_RECOVERY_ENTRIES = 256
MAX_FLEET_HOME_RECOVERY_RECORDS = 16
MAX_FLEET_HOME_RECOVERY_PATH = 512
MAX_FLEET_HOME_RECOVERY_RETRIES = 3

_NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CHAIN_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MEMBER_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_PATH_PART_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


class FleetHomeRecoveryValidationError(ValueError):
    def __init__(self, code: str = "fleet_home_recovery_v2_invalid") -> None:
        self.code = code
        super().__init__(code)


class FleetHomeEntryKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"


class FleetHomeRecoveryPhase(str, Enum):
    PREPARE_PENDING = "prepare_pending"
    PREPARED = "prepared"
    SWITCH_PENDING = "switch_pending"
    SWITCHED = "switched"
    CAS_PENDING = "cas_pending"
    COMMIT_PENDING = "commit_pending"
    ROLLBACK_PENDING = "rollback_pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"


class FleetHomeRecoveryAction(str, Enum):
    PERSIST = "persist"
    PREPARE = "prepare"
    SWITCH = "switch"
    CAS = "cas"
    COMMIT = "commit"
    ROLLBACK = "rollback"
    BLOCK = "block"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class FleetIdentityJournalSlot:
    entry: str
    old: str | None
    replacement: str | None


@dataclass(frozen=True, slots=True)
class FleetIdentityJournalPlan:
    nonce: str
    staging_name: str
    journal_name: str
    slots: tuple[FleetIdentityJournalSlot, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryStat:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryObjectSnapshot:
    stat: FleetHomeRecoveryStat
    sha256: str | None


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryParentV2:
    path: str
    before: FleetHomeRecoveryStat


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryEntryV2:
    name: str
    before_kind: FleetHomeEntryKind | None
    before: FleetHomeRecoveryObjectSnapshot | None
    replacement_kind: FleetHomeEntryKind | None
    replacement_mode: int | None
    replacement_sha256: str | None


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryHomeV2:
    membership_index: int
    member_id: str
    home_root_before: FleetHomeRecoveryStat
    parents: tuple[FleetHomeRecoveryParentV2, ...]
    journal_plan: FleetIdentityJournalPlan
    entries: tuple[FleetHomeRecoveryEntryV2, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeRecoverySnapshotIdentity:
    generation: int
    digest: str


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryParentObservationV2:
    path: str
    stat: FleetHomeRecoveryStat


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryEntryObservationV2:
    name: str
    live: FleetHomeRecoveryObjectSnapshot | None
    old_slot: FleetHomeRecoveryObjectSnapshot | None
    replacement_slot: FleetHomeRecoveryObjectSnapshot | None


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryHomeObservationV2:
    membership_index: int
    member_id: str
    home_root: FleetHomeRecoveryStat
    parents: tuple[FleetHomeRecoveryParentObservationV2, ...]
    staging_identity: FleetHomeRecoveryObjectSnapshot | None
    journal_identity: FleetHomeRecoveryObjectSnapshot | None
    unexpected_slots: tuple[str, ...]
    entries: tuple[FleetHomeRecoveryEntryObservationV2, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryTransactionObservationV2:
    pool_parent: FleetHomeRecoveryStat
    homes: tuple[FleetHomeRecoveryHomeObservationV2, ...]


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryPhaseRecordV2:
    index: int
    phase: FleetHomeRecoveryPhase
    retry_count: int
    previous_digest: str | None
    observation: FleetHomeRecoveryTransactionObservationV2
    authoritative_readable: bool | None
    authoritative_snapshot: FleetHomeRecoverySnapshotIdentity | None
    explicit_conflict: bool


@dataclass(frozen=True, slots=True)
class FleetHomeRecoveryTransactionV2:
    schema_version: int
    nonce: str
    pool_parent_before: FleetHomeRecoveryStat
    current_snapshot: FleetHomeRecoverySnapshotIdentity
    planned_snapshot: FleetHomeRecoverySnapshotIdentity
    homes: tuple[FleetHomeRecoveryHomeV2, ...]
    records: tuple[FleetHomeRecoveryPhaseRecordV2, ...]

    @property
    def phase(self) -> FleetHomeRecoveryPhase:
        return self.records[-1].phase

    @property
    def retry_count(self) -> int:
        return self.records[-1].retry_count


def _fail(code: str = "fleet_home_recovery_v2_invalid") -> None:
    raise FleetHomeRecoveryValidationError(code)


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        _fail()
    return value


def _chain_digest(value: object) -> str:
    if type(value) is not str or _CHAIN_DIGEST_RE.fullmatch(value) is None:
        _fail()
    return value


def _relative_path(value: object, *, root_allowed: bool = False) -> str:
    if type(value) is not str or len(value.encode()) > MAX_FLEET_HOME_RECOVERY_PATH:
        _fail()
    if root_allowed and value == "":
        return value
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or any(
            part in {"", ".", ".."} or _PATH_PART_RE.fullmatch(part) is None
            for part in path.parts
        )
    ):
        _fail()
    return value


def _exact_dict(value: object, fields: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        _fail()
    if set(value) != fields:
        _fail()
    return value


def _validate_presence(entries: object) -> tuple[tuple[str, bool, bool], ...]:
    if type(entries) is not tuple or len(entries) > MAX_FLEET_HOME_RECOVERY_ENTRIES:
        _fail()
    result: list[tuple[str, bool, bool]] = []
    names: set[str] = set()
    for item in entries:
        if type(item) is not tuple or len(item) != 3:
            _fail()
        name, has_old, has_replacement = item
        name = _relative_path(name)
        if (
            type(has_old) is not bool
            or type(has_replacement) is not bool
            or name in names
        ):
            _fail()
        names.add(name)
        result.append((name, has_old, has_replacement))
    return tuple(result)


def make_fleet_identity_journal_plan(
    nonce: str,
    entries: tuple[tuple[str, bool, bool], ...],
) -> FleetIdentityJournalPlan:
    if type(nonce) is not str or _NONCE_RE.fullmatch(nonce) is None:
        _fail()
    presence = _validate_presence(entries)
    plan = FleetIdentityJournalPlan(
        nonce,
        f".fleet-identity-staging-{nonce}",
        f".fleet-identity-journal-{nonce}",
        tuple(
            FleetIdentityJournalSlot(
                name,
                f"old-{index:04d}" if has_old else None,
                f"replacement-{index:04d}" if has_replacement else None,
            )
            for index, (name, has_old, has_replacement) in enumerate(presence)
        ),
    )
    return validate_fleet_identity_journal_plan(plan, presence)


def validate_fleet_identity_journal_plan(
    plan: object,
    entries: tuple[tuple[str, bool, bool], ...],
) -> FleetIdentityJournalPlan:
    presence = _validate_presence(entries)
    if type(plan) is not FleetIdentityJournalPlan:
        _fail()
    if (
        type(plan.nonce) is not str
        or _NONCE_RE.fullmatch(plan.nonce) is None
        or plan.staging_name != f".fleet-identity-staging-{plan.nonce}"
        or plan.journal_name != f".fleet-identity-journal-{plan.nonce}"
        or type(plan.slots) is not tuple
        or len(plan.slots) != len(presence)
    ):
        _fail()
    expected_slots = tuple(
        FleetIdentityJournalSlot(
            name,
            f"old-{index:04d}" if has_old else None,
            f"replacement-{index:04d}" if has_replacement else None,
        )
        for index, (name, has_old, has_replacement) in enumerate(presence)
    )
    if plan.slots != expected_slots or any(
        type(slot) is not FleetIdentityJournalSlot for slot in plan.slots
    ):
        _fail()
    return plan


def _stat_kind(value: FleetHomeRecoveryStat) -> FleetHomeEntryKind:
    if stat.S_ISREG(value.mode):
        return FleetHomeEntryKind.FILE
    if stat.S_ISDIR(value.mode):
        return FleetHomeEntryKind.DIRECTORY
    _fail()


def _validate_stat(
    value: object,
    kind: FleetHomeEntryKind | None = None,
) -> FleetHomeRecoveryStat:
    if type(value) is not FleetHomeRecoveryStat:
        _fail()
    current = value
    _integer(current.dev, 0, 2**63 - 1)
    _integer(current.ino, 1, 2**63 - 1)
    _integer(current.mode, 0, 0o177777)
    _integer(current.uid, 0, 2**32 - 1)
    _integer(current.gid, 0, 2**32 - 1)
    _integer(current.nlink, 1, 2**31 - 1)
    _integer(current.size, 0, MAX_FLEET_HOME_RECOVERY_BYTES)
    _integer(current.mtime_ns, 0, 2**63 - 1)
    actual = _stat_kind(current)
    if kind is not None and actual is not kind:
        _fail()
    permissions = stat.S_IMODE(current.mode)
    if actual is FleetHomeEntryKind.DIRECTORY:
        if permissions != 0o700 or current.uid != os.geteuid():
            _fail()
    elif (
        permissions not in {0o600, 0o700}
        or current.uid != os.geteuid()
        or current.nlink != 1
    ):
        _fail()
    return current


def _validate_object(
    value: object,
    kind: FleetHomeEntryKind | None = None,
) -> FleetHomeRecoveryObjectSnapshot:
    if type(value) is not FleetHomeRecoveryObjectSnapshot:
        _fail()
    actual = _stat_kind(_validate_stat(value.stat, kind))
    if actual is FleetHomeEntryKind.FILE:
        _digest(value.sha256)
    elif value.sha256 is not None:
        _fail()
    return value


def _same_identity(left: FleetHomeRecoveryStat, right: FleetHomeRecoveryStat) -> bool:
    return (left.dev, left.ino, left.mode, left.uid, left.gid) == (
        right.dev,
        right.ino,
        right.mode,
        right.uid,
        right.gid,
    )


def _validate_snapshot_identity(value: object) -> FleetHomeRecoverySnapshotIdentity:
    if type(value) is not FleetHomeRecoverySnapshotIdentity:
        _fail()
    _integer(value.generation, 1, 2**63 - 1)
    _digest(value.digest)
    return value


def _validate_entry(entry: object) -> FleetHomeRecoveryEntryV2:
    if type(entry) is not FleetHomeRecoveryEntryV2:
        _fail()
    _relative_path(entry.name)
    if entry.before_kind is None:
        if entry.before is not None:
            _fail()
    elif type(entry.before_kind) is not FleetHomeEntryKind:
        _fail()
    else:
        _validate_object(entry.before, entry.before_kind)
    if entry.replacement_kind is None:
        if entry.replacement_mode is not None or entry.replacement_sha256 is not None:
            _fail()
    elif type(entry.replacement_kind) is not FleetHomeEntryKind:
        _fail()
    elif entry.replacement_kind is FleetHomeEntryKind.FILE:
        if type(entry.replacement_mode) is not int or entry.replacement_mode not in {
            0o600,
            0o700,
        }:
            _fail()
        _digest(entry.replacement_sha256)
    elif entry.replacement_mode != 0o700 or entry.replacement_sha256 is not None:
        _fail()
    if entry.before_kind is None and entry.replacement_kind is None:
        _fail()
    return entry


def _validate_home(home: object) -> FleetHomeRecoveryHomeV2:
    if type(home) is not FleetHomeRecoveryHomeV2:
        _fail()
    _integer(home.membership_index, 0, MAX_FLEET_HOME_RECOVERY_HOMES - 1)
    if type(home.member_id) is not str or _MEMBER_RE.fullmatch(home.member_id) is None:
        _fail()
    _validate_stat(home.home_root_before, FleetHomeEntryKind.DIRECTORY)
    if (
        type(home.parents) is not tuple
        or len(home.parents) > MAX_FLEET_HOME_RECOVERY_ENTRIES
    ):
        _fail()
    parent_paths: list[str] = []
    for parent in home.parents:
        if type(parent) is not FleetHomeRecoveryParentV2:
            _fail()
        parent_paths.append(_relative_path(parent.path))
        _validate_stat(parent.before, FleetHomeEntryKind.DIRECTORY)
    if parent_paths != sorted(set(parent_paths)) or "" in parent_paths:
        _fail()
    if (
        type(home.entries) is not tuple
        or not home.entries
        or len(home.entries) > MAX_FLEET_HOME_RECOVERY_ENTRIES
    ):
        _fail()
    names: list[str] = []
    future_directories: set[str] = set()
    for entry in home.entries:
        _validate_entry(entry)
        names.append(entry.name)
        parent_name = PurePosixPath(entry.name).parent.as_posix()
        parent_name = "" if parent_name == "." else parent_name
        if (
            parent_name
            and parent_name not in parent_paths
            and not any(
                parent_name == candidate or parent_name.startswith(f"{candidate}/")
                for candidate in future_directories
            )
        ):
            _fail()
        if (
            entry.before_kind is None
            and entry.replacement_kind is FleetHomeEntryKind.DIRECTORY
        ):
            future_directories.add(entry.name)
    if len(names) != len(set(names)):
        _fail()
    validate_fleet_identity_journal_plan(
        home.journal_plan,
        tuple(
            (
                entry.name,
                entry.before_kind is not None,
                entry.replacement_kind is not None,
            )
            for entry in home.entries
        ),
    )
    return home


def _before_observation(
    pool_parent: FleetHomeRecoveryStat,
    homes: tuple[FleetHomeRecoveryHomeV2, ...],
) -> FleetHomeRecoveryTransactionObservationV2:
    return FleetHomeRecoveryTransactionObservationV2(
        pool_parent,
        tuple(
            FleetHomeRecoveryHomeObservationV2(
                home.membership_index,
                home.member_id,
                home.home_root_before,
                tuple(
                    FleetHomeRecoveryParentObservationV2(parent.path, parent.before)
                    for parent in home.parents
                ),
                None,
                None,
                (),
                tuple(
                    FleetHomeRecoveryEntryObservationV2(
                        entry.name, entry.before, None, None
                    )
                    for entry in home.entries
                ),
            )
            for home in homes
        ),
    )


def _validate_observation(
    transaction: FleetHomeRecoveryTransactionV2,
    observation: object,
) -> FleetHomeRecoveryTransactionObservationV2:
    if type(observation) is not FleetHomeRecoveryTransactionObservationV2:
        _fail()
    _validate_stat(observation.pool_parent, FleetHomeEntryKind.DIRECTORY)
    if not _same_identity(observation.pool_parent, transaction.pool_parent_before):
        _fail()
    if type(observation.homes) is not tuple or len(observation.homes) != len(
        transaction.homes
    ):
        _fail()
    for home, current in zip(transaction.homes, observation.homes, strict=True):
        if (
            type(current) is not FleetHomeRecoveryHomeObservationV2
            or current.membership_index != home.membership_index
            or current.member_id != home.member_id
        ):
            _fail()
        _validate_stat(current.home_root, FleetHomeEntryKind.DIRECTORY)
        if not _same_identity(current.home_root, home.home_root_before):
            _fail()
        if type(current.parents) is not tuple or len(current.parents) != len(
            home.parents
        ):
            _fail()
        for parent, actual in zip(home.parents, current.parents, strict=True):
            if (
                type(actual) is not FleetHomeRecoveryParentObservationV2
                or actual.path != parent.path
            ):
                _fail()
            _validate_stat(actual.stat, FleetHomeEntryKind.DIRECTORY)
            if not _same_identity(actual.stat, parent.before):
                _fail()
        for journal in (current.staging_identity, current.journal_identity):
            if journal is not None:
                _validate_object(journal, FleetHomeEntryKind.DIRECTORY)
        if (
            type(current.unexpected_slots) is not tuple
            or len(current.unexpected_slots) > MAX_FLEET_HOME_RECOVERY_ENTRIES * 2
            or len(current.unexpected_slots) != len(set(current.unexpected_slots))
        ):
            _fail()
        for slot in current.unexpected_slots:
            _relative_path(slot)
        if type(current.entries) is not tuple or len(current.entries) != len(
            home.entries
        ):
            _fail()
        for entry, actual in zip(home.entries, current.entries, strict=True):
            if (
                type(actual) is not FleetHomeRecoveryEntryObservationV2
                or actual.name != entry.name
            ):
                _fail()
            for snapshot in (actual.live, actual.old_slot, actual.replacement_slot):
                if snapshot is not None:
                    _validate_object(snapshot)
    return observation


def _replacement_matches(
    entry: FleetHomeRecoveryEntryV2,
    snapshot: FleetHomeRecoveryObjectSnapshot | None,
) -> bool:
    if entry.replacement_kind is None:
        return snapshot is None
    if snapshot is None:
        return False
    try:
        _validate_object(snapshot, entry.replacement_kind)
    except FleetHomeRecoveryValidationError:
        return False
    return (
        stat.S_IMODE(snapshot.stat.mode) == entry.replacement_mode
        and snapshot.sha256 == entry.replacement_sha256
    )


def _prepared_observation_valid(
    transaction: FleetHomeRecoveryTransactionV2,
    observation: FleetHomeRecoveryTransactionObservationV2,
) -> bool:
    try:
        _validate_observation(transaction, observation)
    except FleetHomeRecoveryValidationError:
        return False
    if not _same_identity(observation.pool_parent, transaction.pool_parent_before):
        return False
    for home, current in zip(transaction.homes, observation.homes, strict=True):
        if (
            current.home_root != home.home_root_before
            or current.staging_identity is not None
            or current.journal_identity is None
            or current.unexpected_slots
            or any(
                actual.path != parent.path or actual.stat != parent.before
                for parent, actual in zip(home.parents, current.parents, strict=True)
            )
        ):
            return False
        for entry, actual in zip(home.entries, current.entries, strict=True):
            if (
                actual.live != entry.before
                or actual.old_slot is not None
                or not _replacement_matches(entry, actual.replacement_slot)
            ):
                return False
    return True


def _prepared_record(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryPhaseRecordV2 | None:
    return next(
        (
            record
            for record in transaction.records
            if record.phase is FleetHomeRecoveryPhase.PREPARED
        ),
        None,
    )


def _switch_rank(
    entry: FleetHomeRecoveryEntryV2,
    actual: FleetHomeRecoveryEntryObservationV2,
    replacement_snapshot: FleetHomeRecoveryObjectSnapshot | None,
) -> int | None:
    prepared = (entry.before, None, replacement_snapshot)
    switched = (replacement_snapshot, entry.before, None)
    current = (actual.live, actual.old_slot, actual.replacement_slot)
    if current == switched:
        return 2
    if entry.before is not None and current == (
        None,
        entry.before,
        replacement_snapshot,
    ):
        return 1
    if current == prepared:
        return 0
    return None


def _changed_parent_paths(
    home: FleetHomeRecoveryHomeV2,
    previous: FleetHomeRecoveryHomeObservationV2,
    current: FleetHomeRecoveryHomeObservationV2,
    ranks: tuple[tuple[int, int], ...],
) -> set[str]:
    return {
        ""
        if PurePosixPath(entry.name).parent.as_posix() == "."
        else PurePosixPath(entry.name).parent.as_posix()
        for entry, (before_rank, current_rank) in zip(home.entries, ranks, strict=True)
        if current_rank > before_rank
    }


def _parents_progress_valid(
    home: FleetHomeRecoveryHomeV2,
    previous: FleetHomeRecoveryHomeObservationV2,
    current: FleetHomeRecoveryHomeObservationV2,
    changed: set[str],
) -> bool:
    if not _same_identity(previous.home_root, current.home_root):
        return False
    if "" not in changed and previous.home_root != current.home_root:
        return False
    for before_parent, current_parent in zip(
        previous.parents, current.parents, strict=True
    ):
        if not _same_identity(before_parent.stat, current_parent.stat):
            return False
        if (
            current_parent.path not in changed
            and before_parent.stat != current_parent.stat
        ):
            return False
    return True


def _switch_progress(
    transaction: FleetHomeRecoveryTransactionV2,
    previous: FleetHomeRecoveryTransactionObservationV2,
    current: FleetHomeRecoveryTransactionObservationV2,
) -> str:
    prepared = _prepared_record(transaction)
    if prepared is None:
        return "drift"
    try:
        _validate_observation(transaction, current)
    except FleetHomeRecoveryValidationError:
        return "drift"
    if current.pool_parent != previous.pool_parent:
        return "drift"
    all_switched = True
    any_progress = False
    for home, prepared_home, before_home, current_home in zip(
        transaction.homes,
        prepared.observation.homes,
        previous.homes,
        current.homes,
        strict=True,
    ):
        if (
            current_home.staging_identity is not None
            or current_home.journal_identity is None
            or before_home.journal_identity is None
            or current_home.unexpected_slots
            or not _same_identity(
                before_home.journal_identity.stat,
                current_home.journal_identity.stat,
            )
        ):
            return "drift"
        ranks: list[tuple[int, int]] = []
        for entry, replacement_observed, before_entry, current_entry in zip(
            home.entries,
            prepared_home.entries,
            before_home.entries,
            current_home.entries,
            strict=True,
        ):
            before_rank = _switch_rank(
                entry, before_entry, replacement_observed.replacement_slot
            )
            current_rank = _switch_rank(
                entry, current_entry, replacement_observed.replacement_slot
            )
            if (
                before_rank is None
                or current_rank is None
                or current_rank < before_rank
            ):
                return "drift"
            ranks.append((before_rank, current_rank))
            any_progress |= current_rank > before_rank
            all_switched &= current_rank == 2
        changed = _changed_parent_paths(home, before_home, current_home, tuple(ranks))
        if not _parents_progress_valid(home, before_home, current_home, changed):
            return "drift"
        if not any(after > before for before, after in ranks) and (
            current_home.journal_identity != before_home.journal_identity
        ):
            return "drift"
    if all_switched:
        return "success"
    if current == previous:
        return "same"
    return "partial" if any_progress else "drift"


def _switched_entry(
    entry: FleetHomeRecoveryEntryV2,
    prepared: FleetHomeRecoveryEntryObservationV2,
    current: FleetHomeRecoveryEntryObservationV2,
) -> bool:
    return (current.live, current.old_slot, current.replacement_slot) == (
        prepared.replacement_slot,
        entry.before,
        None,
    )


def _commit_progress(
    transaction: FleetHomeRecoveryTransactionV2,
    previous: FleetHomeRecoveryTransactionObservationV2,
    current: FleetHomeRecoveryTransactionObservationV2,
) -> str:
    prepared = _prepared_record(transaction)
    if prepared is None:
        return "drift"
    try:
        _validate_observation(transaction, current)
    except FleetHomeRecoveryValidationError:
        return "drift"
    progressed = False
    for home, prepared_home, before_home, current_home in zip(
        transaction.homes,
        prepared.observation.homes,
        previous.homes,
        current.homes,
        strict=True,
    ):
        if (
            current_home.home_root != before_home.home_root
            or current_home.parents != before_home.parents
            or current_home.staging_identity is not None
            or current_home.unexpected_slots
        ):
            return "drift"
        for entry, prepared_entry, before_entry, current_entry in zip(
            home.entries,
            prepared_home.entries,
            before_home.entries,
            current_home.entries,
            strict=True,
        ):
            if (
                current_entry.live != prepared_entry.replacement_slot
                or current_entry.replacement_slot is not None
            ):
                return "drift"
            if before_entry.old_slot is None:
                if current_entry.old_slot is not None:
                    return "drift"
            elif current_entry.old_slot not in {before_entry.old_slot, None}:
                return "drift"
            progressed |= (
                before_entry.old_slot is not None and current_entry.old_slot is None
            )
        if current_home.journal_identity is None:
            if any(entry.old_slot is not None for entry in current_home.entries):
                return "drift"
        elif before_home.journal_identity is None or not _same_identity(
            before_home.journal_identity.stat,
            current_home.journal_identity.stat,
        ):
            return "drift"
    journals_absent = all(home.journal_identity is None for home in current.homes)
    slots_absent = all(
        entry.old_slot is None and entry.replacement_slot is None
        for home in current.homes
        for entry in home.entries
    )
    if journals_absent and slots_absent:
        if current.pool_parent == transaction.pool_parent_before:
            return "success"
        return "drift"
    if current.pool_parent != previous.pool_parent:
        return "drift"
    if current == previous:
        return "same"
    return "partial" if progressed else "drift"


def _rollback_rank(
    entry: FleetHomeRecoveryEntryV2,
    actual: FleetHomeRecoveryEntryObservationV2,
    replacement_snapshot: FleetHomeRecoveryObjectSnapshot | None,
) -> int | None:
    current = (actual.live, actual.old_slot, actual.replacement_slot)
    if current == (replacement_snapshot, entry.before, None):
        return 0
    if replacement_snapshot is not None and current == (
        None,
        entry.before,
        replacement_snapshot,
    ):
        return 1
    if replacement_snapshot is not None and current == (
        entry.before,
        None,
        replacement_snapshot,
    ):
        return 2
    if current == (entry.before, None, None):
        return 3
    return None


def _rollback_progress(
    transaction: FleetHomeRecoveryTransactionV2,
    previous: FleetHomeRecoveryTransactionObservationV2,
    current: FleetHomeRecoveryTransactionObservationV2,
) -> str:
    prepared = _prepared_record(transaction)
    if prepared is None:
        return "drift"
    try:
        _validate_observation(transaction, current)
    except FleetHomeRecoveryValidationError:
        return "drift"
    any_progress = False
    all_restored = True
    for home, prepared_home, before_home, current_home in zip(
        transaction.homes,
        prepared.observation.homes,
        previous.homes,
        current.homes,
        strict=True,
    ):
        if current_home.staging_identity is not None or current_home.unexpected_slots:
            return "drift"
        ranks: list[tuple[int, int]] = []
        for entry, prepared_entry, before_entry, current_entry in zip(
            home.entries,
            prepared_home.entries,
            before_home.entries,
            current_home.entries,
            strict=True,
        ):
            before_rank = _rollback_rank(
                entry, before_entry, prepared_entry.replacement_slot
            )
            current_rank = _rollback_rank(
                entry, current_entry, prepared_entry.replacement_slot
            )
            if (
                before_rank is None
                or current_rank is None
                or current_rank < before_rank
            ):
                return "drift"
            ranks.append((before_rank, current_rank))
            any_progress |= current_rank > before_rank
            all_restored &= current_rank == 3
        changed = _changed_parent_paths(home, before_home, current_home, tuple(ranks))
        if not _parents_progress_valid(home, before_home, current_home, changed):
            return "drift"
        if current_home.journal_identity is None:
            if not all(rank == 3 for _, rank in ranks):
                return "drift"
        elif before_home.journal_identity is None or not _same_identity(
            before_home.journal_identity.stat,
            current_home.journal_identity.stat,
        ):
            return "drift"
    journals_absent = all(home.journal_identity is None for home in current.homes)
    if journals_absent and all_restored:
        before = _before_observation(transaction.pool_parent_before, transaction.homes)
        if current == before:
            return "success"
        return "drift"
    if current.pool_parent != previous.pool_parent:
        return "drift"
    if current == previous:
        return "same"
    return "partial" if any_progress else "drift"


_ALLOWED_TRANSITIONS = {
    FleetHomeRecoveryPhase.PREPARE_PENDING: {
        FleetHomeRecoveryPhase.PREPARED,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.PREPARED: {
        FleetHomeRecoveryPhase.SWITCH_PENDING,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.SWITCH_PENDING: {
        FleetHomeRecoveryPhase.SWITCH_PENDING,
        FleetHomeRecoveryPhase.SWITCHED,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.SWITCHED: {
        FleetHomeRecoveryPhase.CAS_PENDING,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.CAS_PENDING: {
        FleetHomeRecoveryPhase.CAS_PENDING,
        FleetHomeRecoveryPhase.COMMIT_PENDING,
        FleetHomeRecoveryPhase.ROLLBACK_PENDING,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.COMMIT_PENDING: {
        FleetHomeRecoveryPhase.COMMIT_PENDING,
        FleetHomeRecoveryPhase.COMMITTED,
        FleetHomeRecoveryPhase.BLOCKED,
    },
    FleetHomeRecoveryPhase.ROLLBACK_PENDING: {
        FleetHomeRecoveryPhase.ROLLBACK_PENDING,
        FleetHomeRecoveryPhase.ROLLED_BACK,
        FleetHomeRecoveryPhase.BLOCKED,
    },
}


def _validate_authoritative(record: FleetHomeRecoveryPhaseRecordV2) -> None:
    if record.authoritative_readable is None:
        if record.authoritative_snapshot is not None or record.explicit_conflict:
            _fail()
    elif type(record.authoritative_readable) is not bool:
        _fail()
    elif record.authoritative_readable:
        _validate_snapshot_identity(record.authoritative_snapshot)
    elif record.authoritative_snapshot is not None:
        _fail()
    if type(record.explicit_conflict) is not bool:
        _fail()


def _validate_basis(transaction: FleetHomeRecoveryTransactionV2) -> None:
    if transaction.schema_version != FLEET_HOME_RECOVERY_SCHEMA_VERSION:
        _fail()
    if (
        type(transaction.nonce) is not str
        or _NONCE_RE.fullmatch(transaction.nonce) is None
    ):
        _fail()
    _validate_stat(transaction.pool_parent_before, FleetHomeEntryKind.DIRECTORY)
    _validate_snapshot_identity(transaction.current_snapshot)
    _validate_snapshot_identity(transaction.planned_snapshot)
    if transaction.current_snapshot == transaction.planned_snapshot:
        _fail()
    if (
        type(transaction.homes) is not tuple
        or not transaction.homes
        or len(transaction.homes) > MAX_FLEET_HOME_RECOVERY_HOMES
    ):
        _fail()
    for index, home in enumerate(transaction.homes):
        _validate_home(home)
        if home.membership_index != index:
            _fail()
    if len({home.member_id for home in transaction.homes}) != len(transaction.homes):
        _fail()


def _canonical(document: object) -> bytes:
    try:
        raw = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FleetHomeRecoveryValidationError() from exc
    if len(raw) > MAX_FLEET_HOME_RECOVERY_BYTES:
        _fail()
    return raw


def _full_record_digest(transaction: FleetHomeRecoveryTransactionV2, index: int) -> str:
    return (
        "sha256:"
        + hashlib.sha256(_record_file_bytes_unchecked(transaction, index)).hexdigest()
    )


def _validate_transaction(value: object) -> FleetHomeRecoveryTransactionV2:
    if type(value) is not FleetHomeRecoveryTransactionV2:
        _fail()
    transaction = value
    _validate_basis(transaction)
    if (
        type(transaction.records) is not tuple
        or not transaction.records
        or len(transaction.records) > MAX_FLEET_HOME_RECOVERY_RECORDS
    ):
        _fail()
    for index, record in enumerate(transaction.records):
        if (
            type(record) is not FleetHomeRecoveryPhaseRecordV2
            or record.index != index
            or type(record.phase) is not FleetHomeRecoveryPhase
        ):
            _fail()
        _integer(record.retry_count, 0, MAX_FLEET_HOME_RECOVERY_RETRIES)
        _validate_observation(transaction, record.observation)
        _validate_authoritative(record)
        if index == 0:
            if (
                record.phase is not FleetHomeRecoveryPhase.PREPARE_PENDING
                or record.retry_count != 0
                or record.previous_digest is not None
                or record.observation
                != _before_observation(
                    transaction.pool_parent_before, transaction.homes
                )
            ):
                _fail()
            continue
        previous = transaction.records[index - 1]
        if record.previous_digest != _full_record_digest(transaction, index - 1):
            _fail()
        if record.phase not in _ALLOWED_TRANSITIONS.get(previous.phase, set()):
            _fail()
        if record.phase is previous.phase:
            if record.retry_count != previous.retry_count + 1:
                _fail()
        elif record.retry_count != 0:
            _fail()
        if (
            record.phase
            not in {
                FleetHomeRecoveryPhase.CAS_PENDING,
                FleetHomeRecoveryPhase.COMMIT_PENDING,
                FleetHomeRecoveryPhase.ROLLBACK_PENDING,
                FleetHomeRecoveryPhase.COMMITTED,
                FleetHomeRecoveryPhase.ROLLED_BACK,
                FleetHomeRecoveryPhase.BLOCKED,
            }
            and record.authoritative_readable is not None
        ):
            _fail()
        if (
            record.phase is FleetHomeRecoveryPhase.PREPARED
            and not _prepared_observation_valid(
                replace(transaction, records=transaction.records[:index]),
                record.observation,
            )
        ):
            _fail()
        if record.phase is FleetHomeRecoveryPhase.SWITCH_PENDING:
            if previous.phase is FleetHomeRecoveryPhase.PREPARED:
                if record.observation != previous.observation:
                    _fail()
            elif previous.phase is FleetHomeRecoveryPhase.SWITCH_PENDING:
                prefix = replace(transaction, records=transaction.records[:index])
                if (
                    _switch_progress(prefix, previous.observation, record.observation)
                    != "partial"
                ):
                    _fail()
        if record.phase is FleetHomeRecoveryPhase.SWITCHED:
            prefix = replace(transaction, records=transaction.records[:index])
            if (
                _switch_progress(prefix, previous.observation, record.observation)
                != "success"
            ):
                _fail()
        if (
            record.phase is FleetHomeRecoveryPhase.CAS_PENDING
            and previous.phase is FleetHomeRecoveryPhase.SWITCHED
        ):
            if (
                record.observation != previous.observation
                or record.authoritative_readable is not None
            ):
                _fail()
        if (
            record.phase is FleetHomeRecoveryPhase.CAS_PENDING
            and previous.phase is FleetHomeRecoveryPhase.CAS_PENDING
        ):
            if (
                record.observation != previous.observation
                or previous.authoritative_readable is not None
                or record.authoritative_readable is None
            ):
                _fail()
        if record.phase is FleetHomeRecoveryPhase.COMMIT_PENDING:
            if previous.phase is FleetHomeRecoveryPhase.CAS_PENDING:
                if (
                    previous.authoritative_readable is not True
                    or previous.authoritative_snapshot != transaction.planned_snapshot
                    or record.observation != previous.observation
                ):
                    _fail()
            elif previous.phase is FleetHomeRecoveryPhase.COMMIT_PENDING:
                prefix = replace(transaction, records=transaction.records[:index])
                if (
                    _commit_progress(prefix, previous.observation, record.observation)
                    != "partial"
                ):
                    _fail()
            if (
                record.authoritative_snapshot != previous.authoritative_snapshot
                or record.authoritative_readable != previous.authoritative_readable
                or record.explicit_conflict != previous.explicit_conflict
            ):
                _fail()
        if record.phase is FleetHomeRecoveryPhase.ROLLBACK_PENDING:
            if previous.phase is FleetHomeRecoveryPhase.CAS_PENDING:
                if (
                    previous.authoritative_readable is not True
                    or previous.authoritative_snapshot != transaction.current_snapshot
                    or record.observation != previous.observation
                ):
                    _fail()
            elif previous.phase is FleetHomeRecoveryPhase.ROLLBACK_PENDING:
                prefix = replace(transaction, records=transaction.records[:index])
                if (
                    _rollback_progress(prefix, previous.observation, record.observation)
                    != "partial"
                ):
                    _fail()
            if (
                record.authoritative_snapshot != previous.authoritative_snapshot
                or record.authoritative_readable != previous.authoritative_readable
                or record.explicit_conflict != previous.explicit_conflict
            ):
                _fail()
        if record.phase is FleetHomeRecoveryPhase.COMMITTED:
            prefix = replace(transaction, records=transaction.records[:index])
            if (
                _commit_progress(prefix, previous.observation, record.observation)
                != "success"
                or record.authoritative_readable != previous.authoritative_readable
                or record.authoritative_snapshot != previous.authoritative_snapshot
                or record.explicit_conflict != previous.explicit_conflict
            ):
                _fail()
        if record.phase is FleetHomeRecoveryPhase.ROLLED_BACK:
            prefix = replace(transaction, records=transaction.records[:index])
            if (
                _rollback_progress(prefix, previous.observation, record.observation)
                != "success"
                or record.authoritative_readable != previous.authoritative_readable
                or record.authoritative_snapshot != previous.authoritative_snapshot
                or record.explicit_conflict != previous.explicit_conflict
            ):
                _fail()
    return transaction


def make_fleet_home_recovery_transaction_v2(
    *,
    nonce: str,
    pool_parent_before: FleetHomeRecoveryStat,
    current_snapshot: FleetHomeRecoverySnapshotIdentity,
    planned_snapshot: FleetHomeRecoverySnapshotIdentity,
    homes: tuple[FleetHomeRecoveryHomeV2, ...],
) -> FleetHomeRecoveryTransactionV2:
    observation = _before_observation(pool_parent_before, homes)
    transaction = FleetHomeRecoveryTransactionV2(
        FLEET_HOME_RECOVERY_SCHEMA_VERSION,
        nonce,
        pool_parent_before,
        current_snapshot,
        planned_snapshot,
        homes,
        (
            FleetHomeRecoveryPhaseRecordV2(
                0,
                FleetHomeRecoveryPhase.PREPARE_PENDING,
                0,
                None,
                observation,
                None,
                None,
                False,
            ),
        ),
    )
    _validate_transaction(transaction)
    if (
        len(_record_file_bytes_unchecked(transaction, 0))
        > MAX_FLEET_HOME_RECOVERY_BYTES
    ):
        _fail()
    return transaction


def advance_fleet_home_recovery_v2(
    transaction: FleetHomeRecoveryTransactionV2,
    target: FleetHomeRecoveryPhase,
    observation: FleetHomeRecoveryTransactionObservationV2,
    *,
    authoritative_readable: bool | None = None,
    authoritative_snapshot: FleetHomeRecoverySnapshotIdentity | None = None,
    explicit_conflict: bool = False,
) -> FleetHomeRecoveryTransactionV2:
    _validate_transaction(transaction)
    if type(target) is not FleetHomeRecoveryPhase:
        _fail()
    previous = transaction.records[-1]
    retry = previous.retry_count + 1 if target is previous.phase else 0
    record = FleetHomeRecoveryPhaseRecordV2(
        len(transaction.records),
        target,
        retry,
        _full_record_digest(transaction, len(transaction.records) - 1),
        observation,
        authoritative_readable,
        authoritative_snapshot,
        explicit_conflict,
    )
    return _validate_transaction(
        replace(transaction, records=(*transaction.records, record))
    )


def _block(
    transaction: FleetHomeRecoveryTransactionV2,
    observation: FleetHomeRecoveryTransactionObservationV2,
    *,
    authoritative_readable: bool | None = None,
    authoritative_snapshot: FleetHomeRecoverySnapshotIdentity | None = None,
    explicit_conflict: bool = False,
) -> tuple[FleetHomeRecoveryAction, FleetHomeRecoveryTransactionV2]:
    return FleetHomeRecoveryAction.BLOCK, advance_fleet_home_recovery_v2(
        transaction,
        FleetHomeRecoveryPhase.BLOCKED,
        observation,
        authoritative_readable=authoritative_readable,
        authoritative_snapshot=authoritative_snapshot,
        explicit_conflict=explicit_conflict,
    )


def _checkpoint_pending(
    transaction: FleetHomeRecoveryTransactionV2,
    observation: FleetHomeRecoveryTransactionObservationV2,
) -> tuple[FleetHomeRecoveryAction, FleetHomeRecoveryTransactionV2]:
    if transaction.retry_count >= MAX_FLEET_HOME_RECOVERY_RETRIES:
        return _block(transaction, observation)
    previous = transaction.records[-1]
    return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
        transaction,
        previous.phase,
        observation,
        authoritative_readable=previous.authoritative_readable,
        authoritative_snapshot=previous.authoritative_snapshot,
        explicit_conflict=previous.explicit_conflict,
    )


def plan_fleet_home_recovery_v2(
    transaction: FleetHomeRecoveryTransactionV2,
    observation: FleetHomeRecoveryTransactionObservationV2,
    *,
    authoritative_readable: bool | None,
    authoritative_snapshot: FleetHomeRecoverySnapshotIdentity | None,
    explicit_conflict: bool,
) -> tuple[FleetHomeRecoveryAction, FleetHomeRecoveryTransactionV2]:
    _validate_transaction(transaction)
    try:
        _validate_observation(transaction, observation)
    except FleetHomeRecoveryValidationError:
        raise
    if authoritative_readable is not None and type(authoritative_readable) is not bool:
        _fail()
    if type(explicit_conflict) is not bool:
        _fail()
    phase = transaction.phase
    previous = transaction.records[-1]
    no_result = (
        authoritative_readable is None
        and authoritative_snapshot is None
        and not explicit_conflict
    )
    if phase in {FleetHomeRecoveryPhase.COMMITTED, FleetHomeRecoveryPhase.ROLLED_BACK}:
        return (
            (FleetHomeRecoveryAction.COMPLETE, transaction)
            if observation == previous.observation
            else (FleetHomeRecoveryAction.BLOCK, transaction)
        )
    if phase is FleetHomeRecoveryPhase.BLOCKED:
        return FleetHomeRecoveryAction.BLOCK, transaction
    if phase is not FleetHomeRecoveryPhase.CAS_PENDING and not no_result:
        _fail()
    if phase is FleetHomeRecoveryPhase.PREPARE_PENDING:
        if observation == previous.observation:
            return FleetHomeRecoveryAction.PREPARE, transaction
        if _prepared_observation_valid(transaction, observation):
            return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
                transaction,
                FleetHomeRecoveryPhase.PREPARED,
                observation,
            )
        return _block(transaction, observation)
    if phase is FleetHomeRecoveryPhase.PREPARED:
        if observation != previous.observation:
            return _block(transaction, observation)
        return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
            transaction,
            FleetHomeRecoveryPhase.SWITCH_PENDING,
            observation,
        )
    if phase is FleetHomeRecoveryPhase.SWITCH_PENDING:
        state = _switch_progress(transaction, previous.observation, observation)
        if state == "same":
            return FleetHomeRecoveryAction.SWITCH, transaction
        if state == "partial":
            return _checkpoint_pending(transaction, observation)
        if state == "success":
            return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
                transaction,
                FleetHomeRecoveryPhase.SWITCHED,
                observation,
            )
        return _block(transaction, observation)
    if phase is FleetHomeRecoveryPhase.SWITCHED:
        if observation != previous.observation:
            return _block(transaction, observation)
        return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
            transaction,
            FleetHomeRecoveryPhase.CAS_PENDING,
            observation,
        )
    if phase is FleetHomeRecoveryPhase.CAS_PENDING:
        if observation != previous.observation:
            return _block(transaction, observation)
        if previous.authoritative_readable is None:
            if no_result:
                return FleetHomeRecoveryAction.CAS, transaction
            if authoritative_readable is True:
                _validate_snapshot_identity(authoritative_snapshot)
            elif authoritative_readable is False:
                if authoritative_snapshot is not None:
                    _fail()
            else:
                _fail()
            return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
                transaction,
                FleetHomeRecoveryPhase.CAS_PENDING,
                observation,
                authoritative_readable=authoritative_readable,
                authoritative_snapshot=authoritative_snapshot,
                explicit_conflict=explicit_conflict,
            )
        if not no_result:
            _fail()
        if previous.authoritative_readable is not True:
            return _block(
                transaction,
                observation,
                authoritative_readable=previous.authoritative_readable,
                authoritative_snapshot=previous.authoritative_snapshot,
                explicit_conflict=previous.explicit_conflict,
            )
        if previous.authoritative_snapshot == transaction.planned_snapshot:
            target = FleetHomeRecoveryPhase.COMMIT_PENDING
        elif previous.authoritative_snapshot == transaction.current_snapshot:
            target = FleetHomeRecoveryPhase.ROLLBACK_PENDING
        else:
            return _block(
                transaction,
                observation,
                authoritative_readable=True,
                authoritative_snapshot=previous.authoritative_snapshot,
                explicit_conflict=previous.explicit_conflict,
            )
        return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
            transaction,
            target,
            observation,
            authoritative_readable=True,
            authoritative_snapshot=previous.authoritative_snapshot,
            explicit_conflict=previous.explicit_conflict,
        )
    if phase is FleetHomeRecoveryPhase.COMMIT_PENDING:
        state = _commit_progress(transaction, previous.observation, observation)
        if state == "same":
            return FleetHomeRecoveryAction.COMMIT, transaction
        if state == "partial":
            return _checkpoint_pending(transaction, observation)
        if state == "success":
            return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
                transaction,
                FleetHomeRecoveryPhase.COMMITTED,
                observation,
                authoritative_readable=True,
                authoritative_snapshot=previous.authoritative_snapshot,
                explicit_conflict=previous.explicit_conflict,
            )
        return _block(transaction, observation)
    if phase is FleetHomeRecoveryPhase.ROLLBACK_PENDING:
        state = _rollback_progress(transaction, previous.observation, observation)
        if state == "same":
            return FleetHomeRecoveryAction.ROLLBACK, transaction
        if state == "partial":
            return _checkpoint_pending(transaction, observation)
        if state == "success":
            return FleetHomeRecoveryAction.PERSIST, advance_fleet_home_recovery_v2(
                transaction,
                FleetHomeRecoveryPhase.ROLLED_BACK,
                observation,
                authoritative_readable=True,
                authoritative_snapshot=previous.authoritative_snapshot,
                explicit_conflict=previous.explicit_conflict,
            )
        return _block(transaction, observation)
    _fail()


_STAT_FIELDS = frozenset(
    {"dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns"}
)
_OBJECT_FIELDS = frozenset({"stat", "sha256"})
_PARENT_FIELDS = frozenset({"path", "before"})
_PARENT_OBSERVATION_FIELDS = frozenset({"path", "stat"})
_SLOT_FIELDS = frozenset({"entry", "old", "replacement"})
_PLAN_FIELDS = frozenset({"nonce", "staging_name", "journal_name", "slot_map"})
_ENTRY_FIELDS = frozenset(
    {
        "name",
        "before_kind",
        "before",
        "replacement_kind",
        "replacement_mode",
        "replacement_sha256",
    }
)
_HOME_FIELDS = frozenset(
    {
        "membership_index",
        "member_id",
        "home_root_before",
        "parents",
        "journal_plan",
        "entries",
    }
)
_ENTRY_OBSERVATION_FIELDS = frozenset({"name", "live", "old_slot", "replacement_slot"})
_HOME_OBSERVATION_FIELDS = frozenset(
    {
        "membership_index",
        "member_id",
        "home_root",
        "parents",
        "staging_identity",
        "journal_identity",
        "unexpected_slots",
        "entries",
    }
)
_OBSERVATION_FIELDS = frozenset({"pool_parent", "homes"})
_SNAPSHOT_IDENTITY_FIELDS = frozenset({"generation", "digest"})
_RECORD_FIELDS = frozenset(
    {
        "index",
        "phase",
        "retry_count",
        "previous_digest",
        "current_observation",
        "authoritative_readable",
        "authoritative_snapshot",
        "explicit_conflict",
    }
)
_RECORD0_FIELDS = _RECORD_FIELDS - {"current_observation"}
_BASIS_FIELDS = frozenset(
    {"pool_parent_before", "current_snapshot", "planned_snapshot", "homes"}
)
_TRANSACTION_FIELDS = frozenset({"schema_version", "nonce", "basis", "records"})
_RECORD0_FILE_FIELDS = frozenset({"schema_version", "nonce", "basis", "record"})
_LATER_FILE_FIELDS = frozenset(
    {
        "schema_version",
        "nonce",
        "index",
        "phase",
        "retry_count",
        "previous_digest",
        "current_observation",
        "authoritative_readable",
        "authoritative_snapshot",
        "explicit_conflict",
    }
)


def _stat_document(value: FleetHomeRecoveryStat) -> dict[str, int]:
    return {
        "dev": value.dev,
        "ino": value.ino,
        "mode": value.mode,
        "uid": value.uid,
        "gid": value.gid,
        "nlink": value.nlink,
        "size": value.size,
        "mtime_ns": value.mtime_ns,
    }


def _stat_from_document(value: object) -> FleetHomeRecoveryStat:
    raw = _exact_dict(value, _STAT_FIELDS)
    return FleetHomeRecoveryStat(
        _integer(raw["dev"], 0, 2**63 - 1),
        _integer(raw["ino"], 1, 2**63 - 1),
        _integer(raw["mode"], 0, 0o177777),
        _integer(raw["uid"], 0, 2**32 - 1),
        _integer(raw["gid"], 0, 2**32 - 1),
        _integer(raw["nlink"], 1, 2**31 - 1),
        _integer(raw["size"], 0, MAX_FLEET_HOME_RECOVERY_BYTES),
        _integer(raw["mtime_ns"], 0, 2**63 - 1),
    )


def _object_document(value: FleetHomeRecoveryObjectSnapshot | None) -> object:
    return (
        None
        if value is None
        else {"stat": _stat_document(value.stat), "sha256": value.sha256}
    )


def _object_from_document(value: object) -> FleetHomeRecoveryObjectSnapshot | None:
    if value is None:
        return None
    raw = _exact_dict(value, _OBJECT_FIELDS)
    digest = raw["sha256"]
    if digest is not None and type(digest) is not str:
        _fail()
    return FleetHomeRecoveryObjectSnapshot(_stat_from_document(raw["stat"]), digest)


def _snapshot_identity_document(
    value: FleetHomeRecoverySnapshotIdentity,
) -> dict[str, object]:
    return {"generation": value.generation, "digest": value.digest}


def _snapshot_identity_from_document(
    value: object,
) -> FleetHomeRecoverySnapshotIdentity:
    raw = _exact_dict(value, _SNAPSHOT_IDENTITY_FIELDS)
    return FleetHomeRecoverySnapshotIdentity(
        _integer(raw["generation"], 1, 2**63 - 1),
        _digest(raw["digest"]),
    )


def _plan_document(plan: FleetIdentityJournalPlan) -> dict[str, object]:
    return {
        "nonce": plan.nonce,
        "staging_name": plan.staging_name,
        "journal_name": plan.journal_name,
        "slot_map": [
            {"entry": slot.entry, "old": slot.old, "replacement": slot.replacement}
            for slot in plan.slots
        ],
    }


def _plan_from_document(value: object) -> FleetIdentityJournalPlan:
    raw = _exact_dict(value, _PLAN_FIELDS)
    slots_raw = raw["slot_map"]
    if (
        type(slots_raw) is not list
        or not slots_raw
        or len(slots_raw) > MAX_FLEET_HOME_RECOVERY_ENTRIES
    ):
        _fail()
    presence: list[tuple[str, bool, bool]] = []
    slots: list[FleetIdentityJournalSlot] = []
    for item in slots_raw:
        slot = _exact_dict(item, _SLOT_FIELDS)
        name = _relative_path(slot["entry"])
        old = slot["old"]
        replacement_name = slot["replacement"]
        if old is not None and type(old) is not str:
            _fail()
        if replacement_name is not None and type(replacement_name) is not str:
            _fail()
        slots.append(FleetIdentityJournalSlot(name, old, replacement_name))
        presence.append((name, old is not None, replacement_name is not None))
    plan = make_fleet_identity_journal_plan(raw["nonce"], tuple(presence))
    if (
        tuple(slots) != plan.slots
        or raw["staging_name"] != plan.staging_name
        or raw["journal_name"] != plan.journal_name
    ):
        _fail()
    return plan


def _kind_document(value: FleetHomeEntryKind | None) -> str | None:
    return None if value is None else value.value


def _kind_from_document(value: object) -> FleetHomeEntryKind | None:
    if value is None:
        return None
    if type(value) is not str:
        _fail()
    try:
        return FleetHomeEntryKind(value)
    except ValueError:
        _fail()


def _entry_document(entry: FleetHomeRecoveryEntryV2) -> dict[str, object]:
    return {
        "name": entry.name,
        "before_kind": _kind_document(entry.before_kind),
        "before": _object_document(entry.before),
        "replacement_kind": _kind_document(entry.replacement_kind),
        "replacement_mode": entry.replacement_mode,
        "replacement_sha256": entry.replacement_sha256,
    }


def _entry_from_document(value: object) -> FleetHomeRecoveryEntryV2:
    raw = _exact_dict(value, _ENTRY_FIELDS)
    mode = raw["replacement_mode"]
    digest = raw["replacement_sha256"]
    if mode is not None and type(mode) is not int:
        _fail()
    if digest is not None and type(digest) is not str:
        _fail()
    return FleetHomeRecoveryEntryV2(
        _relative_path(raw["name"]),
        _kind_from_document(raw["before_kind"]),
        _object_from_document(raw["before"]),
        _kind_from_document(raw["replacement_kind"]),
        mode,
        digest,
    )


def _home_document(home: FleetHomeRecoveryHomeV2) -> dict[str, object]:
    return {
        "membership_index": home.membership_index,
        "member_id": home.member_id,
        "home_root_before": _stat_document(home.home_root_before),
        "parents": [
            {"path": parent.path, "before": _stat_document(parent.before)}
            for parent in home.parents
        ],
        "journal_plan": _plan_document(home.journal_plan),
        "entries": [_entry_document(entry) for entry in home.entries],
    }


def _home_from_document(value: object) -> FleetHomeRecoveryHomeV2:
    raw = _exact_dict(value, _HOME_FIELDS)
    parents_raw = raw["parents"]
    entries_raw = raw["entries"]
    if (
        type(parents_raw) is not list
        or len(parents_raw) > MAX_FLEET_HOME_RECOVERY_ENTRIES
        or type(entries_raw) is not list
        or not entries_raw
        or len(entries_raw) > MAX_FLEET_HOME_RECOVERY_ENTRIES
    ):
        _fail()
    return FleetHomeRecoveryHomeV2(
        _integer(raw["membership_index"], 0, MAX_FLEET_HOME_RECOVERY_HOMES - 1),
        raw["member_id"],
        _stat_from_document(raw["home_root_before"]),
        tuple(
            FleetHomeRecoveryParentV2(
                _relative_path(parent["path"]),
                _stat_from_document(parent["before"]),
            )
            for item in parents_raw
            for parent in (_exact_dict(item, _PARENT_FIELDS),)
        ),
        _plan_from_document(raw["journal_plan"]),
        tuple(_entry_from_document(entry) for entry in entries_raw),
    )


def _basis_document(transaction: FleetHomeRecoveryTransactionV2) -> dict[str, object]:
    return {
        "pool_parent_before": _stat_document(transaction.pool_parent_before),
        "current_snapshot": _snapshot_identity_document(transaction.current_snapshot),
        "planned_snapshot": _snapshot_identity_document(transaction.planned_snapshot),
        "homes": [_home_document(home) for home in transaction.homes],
    }


def _basis_from_document(
    value: object,
) -> tuple[
    FleetHomeRecoveryStat,
    FleetHomeRecoverySnapshotIdentity,
    FleetHomeRecoverySnapshotIdentity,
    tuple[FleetHomeRecoveryHomeV2, ...],
]:
    raw = _exact_dict(value, _BASIS_FIELDS)
    homes_raw = raw["homes"]
    if (
        type(homes_raw) is not list
        or not homes_raw
        or len(homes_raw) > MAX_FLEET_HOME_RECOVERY_HOMES
    ):
        _fail()
    return (
        _stat_from_document(raw["pool_parent_before"]),
        _snapshot_identity_from_document(raw["current_snapshot"]),
        _snapshot_identity_from_document(raw["planned_snapshot"]),
        tuple(_home_from_document(home) for home in homes_raw),
    )


def _observation_document(
    observation: FleetHomeRecoveryTransactionObservationV2,
) -> dict[str, object]:
    return {
        "pool_parent": _stat_document(observation.pool_parent),
        "homes": [
            {
                "membership_index": home.membership_index,
                "member_id": home.member_id,
                "home_root": _stat_document(home.home_root),
                "parents": [
                    {"path": parent.path, "stat": _stat_document(parent.stat)}
                    for parent in home.parents
                ],
                "staging_identity": _object_document(home.staging_identity),
                "journal_identity": _object_document(home.journal_identity),
                "unexpected_slots": list(home.unexpected_slots),
                "entries": [
                    {
                        "name": entry.name,
                        "live": _object_document(entry.live),
                        "old_slot": _object_document(entry.old_slot),
                        "replacement_slot": _object_document(entry.replacement_slot),
                    }
                    for entry in home.entries
                ],
            }
            for home in observation.homes
        ],
    }


def _observation_from_document(
    value: object,
) -> FleetHomeRecoveryTransactionObservationV2:
    raw = _exact_dict(value, _OBSERVATION_FIELDS)
    homes_raw = raw["homes"]
    if (
        type(homes_raw) is not list
        or not homes_raw
        or len(homes_raw) > MAX_FLEET_HOME_RECOVERY_HOMES
    ):
        _fail()
    homes: list[FleetHomeRecoveryHomeObservationV2] = []
    for item in homes_raw:
        home = _exact_dict(item, _HOME_OBSERVATION_FIELDS)
        parents_raw = home["parents"]
        entries_raw = home["entries"]
        unexpected = home["unexpected_slots"]
        if (
            type(parents_raw) is not list
            or len(parents_raw) > MAX_FLEET_HOME_RECOVERY_ENTRIES
            or type(entries_raw) is not list
            or len(entries_raw) > MAX_FLEET_HOME_RECOVERY_ENTRIES
            or type(unexpected) is not list
            or len(unexpected) > MAX_FLEET_HOME_RECOVERY_ENTRIES * 2
        ):
            _fail()
        homes.append(
            FleetHomeRecoveryHomeObservationV2(
                _integer(
                    home["membership_index"], 0, MAX_FLEET_HOME_RECOVERY_HOMES - 1
                ),
                home["member_id"],
                _stat_from_document(home["home_root"]),
                tuple(
                    FleetHomeRecoveryParentObservationV2(
                        _relative_path(parent["path"]),
                        _stat_from_document(parent["stat"]),
                    )
                    for parent_item in parents_raw
                    for parent in (
                        _exact_dict(parent_item, _PARENT_OBSERVATION_FIELDS),
                    )
                ),
                _object_from_document(home["staging_identity"]),
                _object_from_document(home["journal_identity"]),
                tuple(_relative_path(slot) for slot in unexpected),
                tuple(
                    FleetHomeRecoveryEntryObservationV2(
                        _relative_path(entry["name"]),
                        _object_from_document(entry["live"]),
                        _object_from_document(entry["old_slot"]),
                        _object_from_document(entry["replacement_slot"]),
                    )
                    for entry_item in entries_raw
                    for entry in (_exact_dict(entry_item, _ENTRY_OBSERVATION_FIELDS),)
                ),
            )
        )
    return FleetHomeRecoveryTransactionObservationV2(
        _stat_from_document(raw["pool_parent"]),
        tuple(homes),
    )


def _record_document(
    record: FleetHomeRecoveryPhaseRecordV2,
    *,
    include_observation: bool = True,
) -> dict[str, object]:
    document: dict[str, object] = {
        "index": record.index,
        "phase": record.phase.value,
        "retry_count": record.retry_count,
        "previous_digest": record.previous_digest,
        "authoritative_readable": record.authoritative_readable,
        "authoritative_snapshot": (
            None
            if record.authoritative_snapshot is None
            else _snapshot_identity_document(record.authoritative_snapshot)
        ),
        "explicit_conflict": record.explicit_conflict,
    }
    if include_observation:
        document["current_observation"] = _observation_document(record.observation)
    return document


def _record_from_document(
    value: object,
    *,
    observation: FleetHomeRecoveryTransactionObservationV2 | None = None,
) -> FleetHomeRecoveryPhaseRecordV2:
    raw = _exact_dict(
        value, _RECORD0_FIELDS if observation is not None else _RECORD_FIELDS
    )
    phase_raw = raw["phase"]
    if type(phase_raw) is not str:
        _fail()
    try:
        phase = FleetHomeRecoveryPhase(phase_raw)
    except ValueError:
        _fail()
    previous = raw["previous_digest"]
    if previous is not None:
        previous = _chain_digest(previous)
    readable = raw["authoritative_readable"]
    if readable is not None and type(readable) is not bool:
        _fail()
    conflict = raw["explicit_conflict"]
    if type(conflict) is not bool:
        _fail()
    authoritative = raw["authoritative_snapshot"]
    return FleetHomeRecoveryPhaseRecordV2(
        _integer(raw["index"], 0, MAX_FLEET_HOME_RECOVERY_RECORDS - 1),
        phase,
        _integer(raw["retry_count"], 0, MAX_FLEET_HOME_RECOVERY_RETRIES),
        previous,
        observation
        if observation is not None
        else _observation_from_document(raw["current_observation"]),
        readable,
        None
        if authoritative is None
        else _snapshot_identity_from_document(authoritative),
        conflict,
    )


def _transaction_document(
    transaction: FleetHomeRecoveryTransactionV2,
) -> dict[str, object]:
    _validate_transaction(transaction)
    return {
        "schema_version": transaction.schema_version,
        "nonce": transaction.nonce,
        "basis": _basis_document(transaction),
        "records": [_record_document(record) for record in transaction.records],
    }


def encode_fleet_home_recovery_transaction_v2(
    transaction: FleetHomeRecoveryTransactionV2,
) -> bytes:
    return _canonical(_transaction_document(transaction))


def decode_fleet_home_recovery_transaction_v2(
    raw: bytes,
) -> FleetHomeRecoveryTransactionV2:
    if type(raw) is not bytes or not raw or len(raw) > MAX_FLEET_HOME_RECOVERY_BYTES:
        _fail()
    try:
        document = _exact_dict(json.loads(raw.decode()), _TRANSACTION_FIELDS)
        records_raw = document["records"]
        if (
            type(records_raw) is not list
            or not records_raw
            or len(records_raw) > MAX_FLEET_HOME_RECOVERY_RECORDS
        ):
            _fail()
        pool_parent, current, planned, homes = _basis_from_document(document["basis"])
        transaction = FleetHomeRecoveryTransactionV2(
            _integer(document["schema_version"], 2, 2),
            document["nonce"],
            pool_parent,
            current,
            planned,
            homes,
            tuple(_record_from_document(record) for record in records_raw),
        )
        _validate_transaction(transaction)
        if encode_fleet_home_recovery_transaction_v2(transaction) != raw:
            _fail()
        return transaction
    except FleetHomeRecoveryValidationError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, KeyError) as exc:
        raise FleetHomeRecoveryValidationError() from exc


def _record_file_document(
    transaction: FleetHomeRecoveryTransactionV2, index: int
) -> dict[str, object]:
    record = transaction.records[index]
    if index == 0:
        return {
            "schema_version": transaction.schema_version,
            "nonce": transaction.nonce,
            "basis": _basis_document(transaction),
            "record": _record_document(record, include_observation=False),
        }
    return {
        "schema_version": transaction.schema_version,
        "nonce": transaction.nonce,
        **_record_document(record),
    }


def _record_file_bytes_unchecked(
    transaction: FleetHomeRecoveryTransactionV2, index: int
) -> bytes:
    return _canonical(_record_file_document(transaction, index))


def _record_name(nonce: str, index: int) -> str:
    return f".fleet-home-recovery-v2-{nonce}-{index:04d}.json"


def _metadata(current: os.stat_result) -> tuple[int, ...]:
    return (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
    )


def _private_parent_stat(parent_fd: int) -> os.stat_result:
    try:
        current = os.fstat(parent_fd)
    except OSError as exc:
        raise FleetHomeRecoveryValidationError() from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o700
        or current.st_uid != os.geteuid()
    ):
        _fail()
    return current


def _read_fd_bytes(fd: int, expected: os.stat_result) -> bytes:
    if expected.st_size > MAX_FLEET_HOME_RECOVERY_BYTES:
        _fail()
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = expected.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                _fail()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1) or _metadata(os.fstat(fd)) != _metadata(expected):
            _fail()
        return b"".join(chunks)
    except FleetHomeRecoveryValidationError:
        raise
    except OSError as exc:
        raise FleetHomeRecoveryValidationError() from exc


def _rename_noreplace(parent_fd: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        _fail("fleet_home_recovery_v2_noreplace_unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1)
        != 0
    ):
        current_errno = ctypes.get_errno()
        if current_errno == errno.EEXIST:
            _fail("fleet_home_recovery_v2_collision")
        raise FleetHomeRecoveryValidationError() from OSError(
            current_errno, os.strerror(current_errno)
        )


def _preflight_absent(parent_fd: int, names: tuple[str, ...]) -> None:
    for name in names:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FleetHomeRecoveryValidationError() from exc
        _fail("fleet_home_recovery_v2_collision")


def _decode_record0(raw: bytes) -> FleetHomeRecoveryTransactionV2:
    try:
        document = _exact_dict(json.loads(raw.decode()), _RECORD0_FILE_FIELDS)
        pool, current, planned, homes = _basis_from_document(document["basis"])
        observation = _before_observation(pool, homes)
        record = _record_from_document(document["record"], observation=observation)
        transaction = FleetHomeRecoveryTransactionV2(
            _integer(document["schema_version"], 2, 2),
            document["nonce"],
            pool,
            current,
            planned,
            homes,
            (record,),
        )
        _validate_transaction(transaction)
        if _record_file_bytes_unchecked(transaction, 0) != raw:
            _fail()
        return transaction
    except FleetHomeRecoveryValidationError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, KeyError) as exc:
        raise FleetHomeRecoveryValidationError() from exc


def _decode_later_record(
    raw: bytes,
    transaction: FleetHomeRecoveryTransactionV2,
    index: int,
) -> FleetHomeRecoveryTransactionV2:
    try:
        document = _exact_dict(json.loads(raw.decode()), _LATER_FILE_FIELDS)
        if document["schema_version"] != 2 or document["nonce"] != transaction.nonce:
            _fail()
        record = _record_from_document(
            {
                key: value
                for key, value in document.items()
                if key not in {"schema_version", "nonce"}
            }
        )
        if record.index != index:
            _fail()
        result = _validate_transaction(
            replace(transaction, records=(*transaction.records, record))
        )
        if _record_file_bytes_unchecked(result, index) != raw:
            _fail()
        return result
    except FleetHomeRecoveryValidationError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, KeyError) as exc:
        raise FleetHomeRecoveryValidationError() from exc


def persist_fleet_home_recovery_transaction_v2(
    parent_fd: int,
    transaction: FleetHomeRecoveryTransactionV2,
    *,
    faultpoint: Callable[[str], None] | None = None,
) -> None:
    _validate_transaction(transaction)
    index = len(transaction.records) - 1
    _private_parent_stat(parent_fd)
    if index == 0:
        names = tuple(
            name
            for candidate in range(MAX_FLEET_HOME_RECOVERY_RECORDS)
            for final in (_record_name(transaction.nonce, candidate),)
            for name in (final, f".{final}.tmp")
        )
        _preflight_absent(parent_fd, names)
    else:
        current = load_fleet_home_recovery_transaction_v2(parent_fd, transaction.nonce)
        if current == transaction:
            _fail("fleet_home_recovery_v2_collision")
        if (
            current.records != transaction.records[:-1]
            or current.pool_parent_before != transaction.pool_parent_before
            or current.current_snapshot != transaction.current_snapshot
            or current.planned_snapshot != transaction.planned_snapshot
            or current.homes != transaction.homes
        ):
            _fail()
    encoded = _record_file_bytes_unchecked(transaction, index)
    final_name = _record_name(transaction.nonce, index)
    temp_name = f".{final_name}.tmp"
    if index:
        _preflight_absent(parent_fd, (final_name, temp_name))
    parent_identity = _metadata(_private_parent_stat(parent_fd))[:6]
    temp_fd = -1
    trusted_stat: os.stat_result | None = None
    trusted_bytes: bytes | None = None
    trusted_digest: str | None = None
    parent_with_temp: tuple[int, ...] | None = None
    pinned_previous: list[tuple[str, int, os.stat_result, bytes, str]] = []
    published = False
    try:
        try:
            temp_fd = os.open(
                temp_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise FleetHomeRecoveryValidationError() from exc
        opened = os.fstat(temp_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or _metadata(os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False))
            != _metadata(opened)
        ):
            _fail()
        trusted_stat = opened
        trusted_bytes = _read_fd_bytes(temp_fd, opened)
        trusted_digest = hashlib.sha256(trusted_bytes).hexdigest()
        parent_with_temp = _metadata(_private_parent_stat(parent_fd))
        if faultpoint is not None:
            faultpoint("after_recovery_temp_open")
        offset = 0
        while offset < len(encoded):
            written = os.write(temp_fd, encoded[offset:])
            if written <= 0:
                _fail()
            offset += written
        written_stat = os.fstat(temp_fd)
        written_bytes = _read_fd_bytes(temp_fd, written_stat)
        if written_bytes != encoded or _metadata(
            os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        ) != _metadata(written_stat):
            _fail()
        trusted_stat = written_stat
        trusted_bytes = written_bytes
        trusted_digest = hashlib.sha256(trusted_bytes).hexdigest()
        os.fsync(temp_fd)
        if (
            _metadata(os.fstat(temp_fd)) != _metadata(trusted_stat)
            or _read_fd_bytes(temp_fd, trusted_stat) != trusted_bytes
        ):
            _fail()
        if faultpoint is not None:
            faultpoint("after_recovery_file_fsync")
        for candidate in range(index):
            previous_name = _record_name(transaction.nonce, candidate)
            try:
                previous_target = os.stat(
                    previous_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(previous_target.st_mode)
                    or stat.S_IMODE(previous_target.st_mode) != 0o600
                    or previous_target.st_uid != os.geteuid()
                    or previous_target.st_nlink != 1
                    or previous_target.st_size > MAX_FLEET_HOME_RECOVERY_BYTES
                ):
                    _fail()
                previous_fd = os.open(
                    previous_name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise FleetHomeRecoveryValidationError() from exc
            pinned_previous.append(
                (previous_name, previous_fd, previous_target, b"", "")
            )
            if _metadata(os.fstat(previous_fd)) != _metadata(previous_target):
                _fail()
            previous_bytes = _read_fd_bytes(previous_fd, previous_target)
            previous_digest = hashlib.sha256(previous_bytes).hexdigest()
            if previous_bytes != _record_file_bytes_unchecked(
                transaction, candidate
            ) or _metadata(
                os.stat(
                    previous_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            ) != _metadata(previous_target):
                _fail()
            pinned_previous[-1] = (
                previous_name,
                previous_fd,
                previous_target,
                previous_bytes,
                previous_digest,
            )
        if faultpoint is not None:
            faultpoint("before_recovery_record_publish")
        reserved_absences = tuple(
            name
            for candidate in range(MAX_FLEET_HOME_RECOVERY_RECORDS)
            for candidate_final in (_record_name(transaction.nonce, candidate),)
            for name in (candidate_final, f".{candidate_final}.tmp")
            if (name == candidate_final and candidate >= index)
            or (name != candidate_final and candidate != index)
        )
        _preflight_absent(parent_fd, reserved_absences)
        for (
            previous_name,
            previous_fd,
            previous_target,
            previous_bytes,
            previous_digest,
        ) in pinned_previous:
            previous_current = os.fstat(previous_fd)
            previous_current_bytes = _read_fd_bytes(previous_fd, previous_current)
            if (
                _metadata(previous_current) != _metadata(previous_target)
                or previous_current_bytes != previous_bytes
                or hashlib.sha256(previous_current_bytes).hexdigest() != previous_digest
                or _metadata(
                    os.stat(
                        previous_name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                )
                != _metadata(previous_target)
            ):
                _fail()
        current_stat = os.fstat(temp_fd)
        current_bytes = _read_fd_bytes(temp_fd, current_stat)
        if (
            _metadata(current_stat) != _metadata(trusted_stat)
            or current_bytes != trusted_bytes
            or hashlib.sha256(current_bytes).hexdigest() != trusted_digest
            or _metadata(os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False))
            != _metadata(trusted_stat)
            or parent_with_temp is None
            or _metadata(_private_parent_stat(parent_fd)) != parent_with_temp
        ):
            _fail()
        _rename_noreplace(parent_fd, temp_name, final_name)
        published = True
        if faultpoint is not None:
            faultpoint("after_recovery_record_publish")
        if (
            _metadata(os.fstat(temp_fd)) != _metadata(trusted_stat)
            or _metadata(os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False))
            != _metadata(trusted_stat)
            or _metadata(_private_parent_stat(parent_fd))[:6] != parent_identity
        ):
            _fail()
        os.fsync(parent_fd)
        if faultpoint is not None:
            faultpoint("after_recovery_parent_fsync")
    finally:
        cleanup_diverged = False
        if not published and temp_fd >= 0 and trusted_stat is not None:
            try:
                current_stat = os.fstat(temp_fd)
                path_stat = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
                current_bytes = _read_fd_bytes(temp_fd, current_stat)
                if (
                    _metadata(current_stat) == _metadata(trusted_stat)
                    and _metadata(path_stat) == _metadata(trusted_stat)
                    and current_bytes == trusted_bytes
                    and hashlib.sha256(current_bytes).hexdigest() == trusted_digest
                ):
                    os.unlink(temp_name, dir_fd=parent_fd)
                    with contextlib.suppress(OSError):
                        os.fsync(parent_fd)
                else:
                    cleanup_diverged = True
            except (FileNotFoundError, OSError, FleetHomeRecoveryValidationError):
                cleanup_diverged = True
        if temp_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(temp_fd)
        for _, previous_fd, _, _, _ in pinned_previous:
            with contextlib.suppress(OSError):
                os.close(previous_fd)
        if cleanup_diverged:
            raise FleetHomeRecoveryValidationError(
                "fleet_home_recovery_v2_cleanup_diverged"
            )
    if (
        load_fleet_home_recovery_transaction_v2(parent_fd, transaction.nonce)
        != transaction
    ):
        _fail()


def load_fleet_home_recovery_transaction_v2(
    parent_fd: int,
    nonce: str,
    *,
    faultpoint: Callable[[str], None] | None = None,
) -> FleetHomeRecoveryTransactionV2:
    if type(nonce) is not str or _NONCE_RE.fullmatch(nonce) is None:
        _fail()
    parent_before = _private_parent_stat(parent_fd)
    opened: list[tuple[str, int, os.stat_result, bytes, str]] = []
    transaction: FleetHomeRecoveryTransactionV2 | None = None
    missing_seen = False
    try:
        for index in range(MAX_FLEET_HOME_RECOVERY_RECORDS):
            name = _record_name(nonce, index)
            try:
                target = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                missing_seen = True
                continue
            except OSError as exc:
                raise FleetHomeRecoveryValidationError() from exc
            if missing_seen:
                _fail()
            if (
                not stat.S_ISREG(target.st_mode)
                or stat.S_IMODE(target.st_mode) != 0o600
                or target.st_uid != os.geteuid()
                or target.st_nlink != 1
                or target.st_size > MAX_FLEET_HOME_RECOVERY_BYTES
            ):
                _fail()
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise FleetHomeRecoveryValidationError() from exc
            opened.append((name, fd, target, b"", ""))
            if _metadata(os.fstat(fd)) != _metadata(target):
                _fail()
            raw = _read_fd_bytes(fd, target)
            opened[-1] = (name, fd, target, raw, hashlib.sha256(raw).hexdigest())
            if index == 0:
                transaction = _decode_record0(raw)
                if transaction.nonce != nonce:
                    _fail()
            else:
                if transaction is None:
                    _fail()
                transaction = _decode_later_record(raw, transaction, index)
                if (
                    transaction.records[-1].previous_digest
                    != "sha256:" + hashlib.sha256(opened[-2][3]).hexdigest()
                ):
                    _fail()
        if transaction is None:
            _fail()
        if faultpoint is not None:
            faultpoint("before_recovery_final_identity_revalidation")
        if _metadata(_private_parent_stat(parent_fd)) != _metadata(parent_before):
            _fail()
        for name, fd, target, raw, raw_digest in opened:
            current = os.fstat(fd)
            current_raw = _read_fd_bytes(fd, current)
            if (
                _metadata(current) != _metadata(target)
                or current_raw != raw
                or hashlib.sha256(current_raw).hexdigest() != raw_digest
                or _metadata(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                != _metadata(target)
            ):
                _fail()
        return transaction
    except FleetHomeRecoveryValidationError:
        raise
    except OSError as exc:
        raise FleetHomeRecoveryValidationError() from exc
    finally:
        for _, fd, _, _, _ in opened:
            with contextlib.suppress(OSError):
                os.close(fd)
