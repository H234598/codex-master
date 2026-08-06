"""Fail-closed execution-admission records and a local reservation store.

This module is the small stateful boundary below the read-only selection
preview.  It deliberately owns no provider, lease, lifecycle, filesystem, or
network operation.  The store only provides an atomic in-process contract for
binding work, authority, scope, and a selected resource before a future
integration layer performs its own revalidation.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import RLock
from collections.abc import Callable, Mapping
from typing import Any


DEFAULT_RESERVATION_TTL_SECONDS = 30
MAX_RESERVATION_TTL_SECONDS = 120
MAX_ADMISSION_ID_LENGTH = 128
MAX_SCOPE_PATHS = 256
MAX_SCOPE_PATH_LENGTH = 512
MAX_RESOURCE_USAGE_MICRO = 10**18
MAX_ADMISSION_STATE_BYTES = 4 * 1024 * 1024
MAX_STORED_ADMISSIONS = 4096


class AdmissionError(ValueError):
    """Raised when an admission record or state transition is invalid."""


class AdmissionState(str, Enum):
    PLANNED = "planned"
    RESERVED = "reserved"
    REVALIDATING = "revalidating"
    ADMITTED = "admitted"
    EXECUTING = "executing"
    PAUSED = "paused"
    FINALIZED = "finalized"
    CONFLICT = "conflict"
    EXPIRED = "expired"
    DENIED = "denied"
    EXECUTION_FAILED = "execution_failed"
    COMPENSATING = "compensating"
    FAILED_FINAL = "failed_final"
    RECOVERED_AFTER_CRASH = "recovered_after_crash"
    CANCELLED = "cancelled"
    COMPENSATED = "compensated"


@dataclass(frozen=True, slots=True)
class ScopeBinding:
    """Repository-relative scope bound to a canonical digest."""

    mode: str
    paths: tuple[str, ...]
    canonical_digest: str

    def __post_init__(self) -> None:
        if self.mode not in {"read", "write"}:
            raise AdmissionError("invalid_scope_mode")
        if not isinstance(self.paths, tuple) or not 1 <= len(self.paths) <= MAX_SCOPE_PATHS:
            raise AdmissionError("invalid_scope_paths")
        for path in self.paths:
            if (
                not isinstance(path, str)
                or not 1 <= len(path) <= MAX_SCOPE_PATH_LENGTH
                or any(ord(char) < 32 for char in path)
                or path.startswith(("/", "~"))
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise AdmissionError("invalid_scope_paths")
        _bounded_text(self.canonical_digest, "invalid_scope_digest", 192)


@dataclass(frozen=True, slots=True)
class ResourceBinding:
    """Private account binding plus the public model/resource metadata."""

    agent_id: str
    account_key: str
    budget_key: str
    model_id: str
    expected_usage_micro: int

    def __post_init__(self) -> None:
        for value, code in (
            (self.agent_id, "invalid_resource_agent"),
            (self.account_key, "invalid_resource_account"),
            (self.budget_key, "invalid_resource_budget"),
            (self.model_id, "invalid_resource_model"),
        ):
            _bounded_text(value, code, 128)
        _bounded_int(self.expected_usage_micro, "invalid_resource_usage", 0, MAX_RESOURCE_USAGE_MICRO)


@dataclass(frozen=True, slots=True)
class LeaseBinding:
    """Expected lease metadata; lease ownership remains outside this module."""

    expected_state: str
    lease_id: str | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.expected_state, "invalid_lease_state", 64)
        if self.lease_id is not None:
            _bounded_text(self.lease_id, "invalid_lease_id", 128)


@dataclass(frozen=True, slots=True)
class AdmissionPriority:
    """Scheduling evidence carried into admission without re-running selection."""

    dispatch: str
    selection_reason: str

    def __post_init__(self) -> None:
        if self.dispatch not in {"DP0", "DP1", "DP2", "DP3"}:
            raise AdmissionError("invalid_dispatch_priority")
        _bounded_text(self.selection_reason, "invalid_selection_reason", 128)


@dataclass(frozen=True, slots=True)
class AdmissionRecord:
    """Immutable, versioned execution-admission record.

    The dataclass intentionally contains private bindings because the local
    reservation owner needs them for conflict checks.  Callers crossing a
    public boundary must use :meth:`public`, which omits account keys, scope
    paths, grant digests, principal identifiers, and lease identifiers.
    """

    schema_version: int
    admission_id: str
    request_id: str
    dispatch_id: str
    workpackage_id: str
    assignment_intent_id: str
    repo_id: str
    principal_id: str
    parent_principal_id: str
    grant_id: str
    grant_digest: str
    work_item_version: int
    scope: ScopeBinding
    resource: ResourceBinding
    lease_context: LeaseBinding
    priority: AdmissionPriority
    state: AdmissionState
    created_at_utc: datetime
    expires_at_utc: datetime
    revision: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise AdmissionError("unsupported_admission_schema")
        for value, code in (
            (self.admission_id, "invalid_admission_id"),
            (self.request_id, "invalid_request_id"),
            (self.dispatch_id, "invalid_dispatch_id"),
            (self.workpackage_id, "invalid_workpackage_id"),
            (self.assignment_intent_id, "invalid_assignment_intent_id"),
            (self.repo_id, "invalid_repo_id"),
            (self.principal_id, "invalid_principal_id"),
            (self.parent_principal_id, "invalid_parent_principal_id"),
            (self.grant_id, "invalid_grant_id"),
        ):
            _bounded_text(value, code, MAX_ADMISSION_ID_LENGTH)
        _bounded_text(self.grant_digest, "invalid_grant_digest", 192)
        _bounded_int(self.work_item_version, "invalid_work_item_version", 1, 10**12)
        if not isinstance(self.scope, ScopeBinding):
            raise AdmissionError("invalid_scope_binding")
        if not isinstance(self.resource, ResourceBinding):
            raise AdmissionError("invalid_resource_binding")
        if not isinstance(self.lease_context, LeaseBinding):
            raise AdmissionError("invalid_lease_binding")
        if not isinstance(self.priority, AdmissionPriority):
            raise AdmissionError("invalid_priority_binding")
        if not isinstance(self.state, AdmissionState):
            raise AdmissionError("invalid_admission_state")
        created = _aware(self.created_at_utc, "invalid_created_timestamp")
        expires = _aware(self.expires_at_utc, "invalid_expiry_timestamp")
        ttl = (expires - created).total_seconds()
        if ttl <= 0 or ttl > MAX_RESERVATION_TTL_SECONDS:
            raise AdmissionError("invalid_reservation_ttl")
        _bounded_int(self.revision, "invalid_admission_revision", 0, 10**12)

    @property
    def active(self) -> bool:
        return self.state in _ACTIVE_STATES

    def is_expired(self, now: datetime) -> bool:
        return _aware(now, "invalid_admission_time") >= self.expires_at_utc

    def advance(self, target: AdmissionState, *, now: datetime) -> "AdmissionRecord":
        """Return the next immutable state, enforcing the transition graph."""

        now = _aware(now, "invalid_admission_time")
        if not isinstance(target, AdmissionState):
            raise AdmissionError("invalid_admission_state")
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise AdmissionError(f"invalid_transition:{self.state.value}->{target.value}")
        if self.state in _EXPIRABLE_STATES and self.is_expired(now) and target not in {
            AdmissionState.EXPIRED,
            AdmissionState.COMPENSATED,
        }:
            raise AdmissionError("admission_expired")
        return replace(self, state=target, revision=self.revision + 1)

    def public(self) -> dict[str, Any]:
        """Return the bounded public representation without private bindings."""

        return {
            "schema_version": self.schema_version,
            "admission_id": self.admission_id,
            "request_id": self.request_id,
            "dispatch_id": self.dispatch_id,
            "workpackage_id": self.workpackage_id,
            "repo_id": self.repo_id,
            "work_item_version": self.work_item_version,
            "scope": {"mode": self.scope.mode, "path_count": len(self.scope.paths)},
            "resource": {
                "agent_id": self.resource.agent_id,
                "budget_key": self.resource.budget_key,
                "model_id": self.resource.model_id,
                "expected_usage_micro": self.resource.expected_usage_micro,
            },
            "lease_context": {"expected_state": self.lease_context.expected_state},
            "priority": {
                "dispatch": self.priority.dispatch,
                "selection_reason": self.priority.selection_reason,
            },
            "state": self.state.value,
            "created_at_utc": self.created_at_utc.isoformat(),
            "expires_at_utc": self.expires_at_utc.isoformat(),
            "revision": self.revision,
        }


def create_admission(
    *,
    admission_id: str,
    request_id: str,
    dispatch_id: str,
    workpackage_id: str,
    assignment_intent_id: str,
    repo_id: str,
    principal_id: str,
    parent_principal_id: str,
    grant_id: str,
    grant_digest: str,
    work_item_version: int,
    scope: ScopeBinding,
    resource: ResourceBinding,
    lease_context: LeaseBinding,
    priority: AdmissionPriority,
    now: datetime,
    ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
) -> AdmissionRecord:
    """Create a planned record with a bounded reservation lifetime."""

    now = _aware(now, "invalid_admission_time")
    _bounded_int(ttl_seconds, "invalid_reservation_ttl", 1, MAX_RESERVATION_TTL_SECONDS)
    return AdmissionRecord(
        1,
        admission_id,
        request_id,
        dispatch_id,
        workpackage_id,
        assignment_intent_id,
        repo_id,
        principal_id,
        parent_principal_id,
        grant_id,
        grant_digest,
        work_item_version,
        scope,
        resource,
        lease_context,
        priority,
        AdmissionState.PLANNED,
        now,
        now + timedelta(seconds=ttl_seconds),
        0,
    )


class AdmissionStore:
    """Atomic in-process reservation store with no external side effects.

    The lock protects record revision checks and exclusive resource keys.  No
    provider, filesystem, lease, or lifecycle callback is accepted, so a
    future executor must finish all external revalidation after leaving this
    short critical section and before calling its existing mutation path.
    """

    def __init__(
        self,
        *,
        agent_capacity: int = 1,
        account_capacity: int = 1,
        account_model_capacity: int = 1,
    ) -> None:
        _bounded_int(agent_capacity, "invalid_agent_capacity", 1, 256)
        _bounded_int(account_capacity, "invalid_account_capacity", 1, 256)
        _bounded_int(account_model_capacity, "invalid_account_model_capacity", 1, 256)
        self._records: dict[str, AdmissionRecord] = {}
        self._lock = RLock()
        self._agent_capacity = agent_capacity
        self._account_capacity = account_capacity
        self._account_model_capacity = account_model_capacity

    def reserve(self, record: AdmissionRecord, *, now: datetime) -> AdmissionRecord:
        """Reserve a planned record or fail closed on a duplicate/conflict."""

        now = _aware(now, "invalid_admission_time")
        if record.state is not AdmissionState.PLANNED:
            raise AdmissionError("record_must_be_planned")
        with self._lock:
            self._expire_locked(now)
            if record.admission_id in self._records:
                raise AdmissionError("duplicate_admission_id")
            conflict = self._reservation_conflict(record)
            if conflict is not None:
                raise AdmissionError(conflict)
            reserved = record.advance(AdmissionState.RESERVED, now=now)
            self._records[reserved.admission_id] = reserved
            return reserved

    def get(self, admission_id: str) -> AdmissionRecord:
        with self._lock:
            try:
                return self._records[admission_id]
            except KeyError as exc:
                raise AdmissionError("admission_not_found") from exc

    def begin_revalidation(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id,
            AdmissionState.REVALIDATING,
            expected_revision=expected_revision,
            now=now,
        )

    def complete_revalidation(
        self,
        admission_id: str,
        *,
        expected_revision: int,
        valid: bool,
        now: datetime,
    ) -> AdmissionRecord:
        if not isinstance(valid, bool):
            raise AdmissionError("invalid_revalidation_result")
        target = AdmissionState.ADMITTED if valid else AdmissionState.DENIED
        return self.transition(admission_id, target, expected_revision=expected_revision, now=now)

    def begin_execution(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id,
            AdmissionState.EXECUTING,
            expected_revision=expected_revision,
            now=now,
        )

    def finalize(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        record = self.get(admission_id)
        if record.state is AdmissionState.FINALIZED:
            return record
        return self.transition(
            admission_id,
            AdmissionState.FINALIZED,
            expected_revision=expected_revision,
            now=now,
        )

    def mark_execution_failed(
        self, admission_id: str, *, expected_revision: int, now: datetime
    ) -> AdmissionRecord:
        return self.transition(
            admission_id, AdmissionState.EXECUTION_FAILED, expected_revision=expected_revision, now=now
        )

    def begin_compensation(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id,
            AdmissionState.COMPENSATING,
            expected_revision=expected_revision,
            now=now,
        )

    def compensate(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id,
            AdmissionState.COMPENSATED,
            expected_revision=expected_revision,
            now=now,
        )

    def finish_compensation(
        self, admission_id: str, *, expected_revision: int, now: datetime
    ) -> AdmissionRecord:
        return self.transition(
            admission_id, AdmissionState.FAILED_FINAL, expected_revision=expected_revision, now=now
        )

    def cancel(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id,
            AdmissionState.CANCELLED,
            expected_revision=expected_revision,
            now=now,
        )

    def recover_after_crash(self, admission_id: str, *, expected_revision: int, now: datetime) -> AdmissionRecord:
        return self.transition(
            admission_id, AdmissionState.RECOVERED_AFTER_CRASH, expected_revision=expected_revision, now=now
        )

    def expire(self, *, now: datetime) -> tuple[AdmissionRecord, ...]:
        now = _aware(now, "invalid_admission_time")
        with self._lock:
            return self._expire_locked(now)

    def public_snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(record.public() for record in self._records.values())

    def records_snapshot(self) -> tuple[AdmissionRecord, ...]:
        """Return immutable internal records for a recovery coordinator."""

        with self._lock:
            return tuple(self._records.values())

    def transition(
        self,
        admission_id: str,
        target: AdmissionState,
        *,
        expected_revision: int,
        now: datetime,
    ) -> AdmissionRecord:
        """Apply one explicitly allowed state transition with a revision CAS."""

        return self._transition(admission_id, target, expected_revision=expected_revision, now=now)

    def _transition(
        self,
        admission_id: str,
        target: AdmissionState,
        *,
        expected_revision: int,
        now: datetime,
    ) -> AdmissionRecord:
        now = _aware(now, "invalid_admission_time")
        with self._lock:
            record = self._records.get(admission_id)
            if record is None:
                raise AdmissionError("admission_not_found")
            return self._transition_locked(record, target, expected_revision=expected_revision, now=now)

    def _transition_locked(
        self,
        record: AdmissionRecord,
        target: AdmissionState,
        *,
        expected_revision: int,
        now: datetime,
    ) -> AdmissionRecord:
        _bounded_int(expected_revision, "invalid_admission_revision", 0, 10**12)
        if record.revision != expected_revision:
            raise AdmissionError("stale_admission_revision")
        updated = record.advance(target, now=now)
        self._records[record.admission_id] = updated
        return updated

    def _expire_locked(self, now: datetime) -> tuple[AdmissionRecord, ...]:
        expired: list[AdmissionRecord] = []
        for record in tuple(self._records.values()):
            if record.state in _EXPIRABLE_STATES and record.is_expired(now):
                updated = record.advance(AdmissionState.EXPIRED, now=now)
                self._records[record.admission_id] = updated
                expired.append(updated)
        return tuple(expired)

    def _reservation_conflict(self, record: AdmissionRecord) -> str | None:
        active = tuple(current for current in self._records.values() if current.active)
        if any(current.resource.agent_id == record.resource.agent_id for current in active):
            return "agent_conflict"
        account_key = (record.resource.account_key, record.resource.budget_key)
        account_count = sum(
            (current.resource.account_key, current.resource.budget_key) == account_key for current in active
        )
        if account_count >= self._account_capacity:
            return "account_capacity_conflict"
        model_key = (*account_key, record.resource.model_id)
        model_count = sum(
            (current.resource.account_key, current.resource.budget_key, current.resource.model_id) == model_key
            for current in active
        )
        if model_count >= self._account_model_capacity:
            return "account_model_capacity_conflict"
        if any(_scope_conflicts(current, record) for current in active):
            return "scope_conflict"
        return None

    def prune_expired(self, *, now: datetime) -> tuple[str, ...]:
        """Expire reservations and return only their opaque admission IDs."""

        return tuple(record.admission_id for record in self.expire(now=now))


class FileAdmissionStore(AdmissionStore):
    """Cross-process store using one private lock and atomic state replacement.

    The file contains the complete internal record, including pseudonymous
    account bindings, and is never a public response.  Reads reject symlinks,
    malformed JSON, oversized documents, and unknown schema data instead of
    silently treating them as an empty store.
    """

    def __init__(
        self,
        state_path: Path,
        lock_path: Path,
        *,
        agent_capacity: int = 1,
        account_capacity: int = 1,
        account_model_capacity: int = 1,
    ) -> None:
        super().__init__(
            agent_capacity=agent_capacity,
            account_capacity=account_capacity,
            account_model_capacity=account_model_capacity,
        )
        self._state_path = _private_absolute_path(state_path, "invalid_admission_state_path")
        self._lock_path = _private_absolute_path(lock_path, "invalid_admission_lock_path")
        if self._state_path == self._lock_path:
            raise AdmissionError("admission_state_and_lock_must_differ")
        _ensure_private_parent(self._state_path.parent)
        _ensure_private_parent(self._lock_path.parent)

    def reserve(self, record: AdmissionRecord, *, now: datetime) -> AdmissionRecord:
        return self._mutate(lambda: AdmissionStore.reserve(self, record, now=now))

    def transition(
        self,
        admission_id: str,
        target: AdmissionState,
        *,
        expected_revision: int,
        now: datetime,
    ) -> AdmissionRecord:
        return self._mutate(
            lambda: AdmissionStore._transition(
                self,
                admission_id,
                target,
                expected_revision=expected_revision,
                now=now,
            )
        )

    def expire(self, *, now: datetime) -> tuple[AdmissionRecord, ...]:
        return self._mutate(lambda: AdmissionStore.expire(self, now=now))

    def get(self, admission_id: str) -> AdmissionRecord:
        with self._file_lock():
            self._records = self._load_records()
            return AdmissionStore.get(self, admission_id)

    def public_snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._file_lock():
            self._records = self._load_records()
            return AdmissionStore.public_snapshot(self)

    def records_snapshot(self) -> tuple[AdmissionRecord, ...]:
        with self._file_lock():
            self._records = self._load_records()
            return AdmissionStore.records_snapshot(self)

    def _mutate(self, operation: Callable[[], Any]) -> Any:
        with self._file_lock():
            self._records = self._load_records()
            result = operation()
            self._write_records()
            return result

    @contextlib.contextmanager
    def _file_lock(self) -> Any:
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise AdmissionError("could_not_open_admission_lock") from exc
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise AdmissionError("could_not_lock_admission_state") from exc
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_records(self) -> dict[str, AdmissionRecord]:
        try:
            current = self._state_path.lstat()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise AdmissionError("could_not_read_admission_state") from exc
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise AdmissionError("invalid_admission_state_file")
        if current.st_size > MAX_ADMISSION_STATE_BYTES:
            raise AdmissionError("admission_state_too_large")
        try:
            with self._state_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AdmissionError("invalid_admission_state") from exc
        if not isinstance(payload, Mapping) or payload.get("schema_version") != 1:
            raise AdmissionError("unsupported_admission_state_schema")
        raw_records = payload.get("records")
        if not isinstance(raw_records, list) or len(raw_records) > MAX_STORED_ADMISSIONS:
            raise AdmissionError("invalid_admission_state_records")
        records: dict[str, AdmissionRecord] = {}
        for raw_record in raw_records:
            record = _record_from_payload(raw_record)
            if record.admission_id in records:
                raise AdmissionError("duplicate_admission_id")
            records[record.admission_id] = record
        return records

    def _write_records(self) -> None:
        payload = {
            "schema_version": 1,
            "records": [_record_to_payload(record) for record in self._records.values()],
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        if len(encoded.encode("utf-8")) > MAX_ADMISSION_STATE_BYTES:
            raise AdmissionError("admission_state_too_large")
        descriptor: int | None = None
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=f".{self._state_path.name}.", dir=self._state_path.parent)
            temporary = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._state_path)
            temporary = None
        except OSError as exc:
            raise AdmissionError("could_not_write_admission_state") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


_ACTIVE_STATES = frozenset(
    {
        AdmissionState.PLANNED,
        AdmissionState.RESERVED,
        AdmissionState.REVALIDATING,
        AdmissionState.ADMITTED,
        AdmissionState.EXECUTING,
        AdmissionState.PAUSED,
    }
)

_EXPIRABLE_STATES = frozenset(
    {
        AdmissionState.PLANNED,
        AdmissionState.RESERVED,
        AdmissionState.REVALIDATING,
        AdmissionState.ADMITTED,
        AdmissionState.PAUSED,
    }
)

_ALLOWED_TRANSITIONS = {
    AdmissionState.PLANNED: frozenset({AdmissionState.RESERVED, AdmissionState.EXPIRED, AdmissionState.CANCELLED}),
    AdmissionState.RESERVED: frozenset(
        {AdmissionState.REVALIDATING, AdmissionState.CONFLICT, AdmissionState.EXPIRED, AdmissionState.CANCELLED}
    ),
    AdmissionState.REVALIDATING: frozenset(
        {AdmissionState.ADMITTED, AdmissionState.DENIED, AdmissionState.EXPIRED, AdmissionState.CANCELLED}
    ),
    AdmissionState.ADMITTED: frozenset(
        {AdmissionState.EXECUTING, AdmissionState.EXECUTION_FAILED, AdmissionState.EXPIRED, AdmissionState.CANCELLED}
    ),
    AdmissionState.EXECUTING: frozenset(
        {AdmissionState.PAUSED, AdmissionState.FINALIZED, AdmissionState.RECOVERED_AFTER_CRASH, AdmissionState.EXECUTION_FAILED}
    ),
    AdmissionState.PAUSED: frozenset(
        {AdmissionState.EXECUTING, AdmissionState.EXPIRED, AdmissionState.CANCELLED}
    ),
    AdmissionState.RECOVERED_AFTER_CRASH: frozenset({AdmissionState.FINALIZED}),
    AdmissionState.CONFLICT: frozenset({AdmissionState.COMPENSATED}),
    AdmissionState.EXPIRED: frozenset({AdmissionState.COMPENSATED}),
    AdmissionState.DENIED: frozenset({AdmissionState.COMPENSATED}),
    AdmissionState.CANCELLED: frozenset({AdmissionState.COMPENSATED}),
    AdmissionState.EXECUTION_FAILED: frozenset({AdmissionState.COMPENSATING}),
    AdmissionState.COMPENSATING: frozenset({AdmissionState.FAILED_FINAL}),
    AdmissionState.FINALIZED: frozenset(),
    AdmissionState.COMPENSATED: frozenset(),
    AdmissionState.FAILED_FINAL: frozenset(),
}


def _scope_conflicts(left: AdmissionRecord, right: AdmissionRecord) -> bool:
    """Apply the plan's repository-local read/write overlap policy."""

    if left.repo_id != right.repo_id:
        return False
    if left.scope.mode == "read" and right.scope.mode == "read":
        return False
    return any(_scope_paths_overlap(left_path, right_path) for left_path in left.scope.paths for right_path in right.scope.paths)


def _scope_paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(f"{right}/") or right.startswith(f"{left}/")


def _record_to_payload(record: AdmissionRecord) -> dict[str, Any]:
    return {
        "schema_version": record.schema_version,
        "admission_id": record.admission_id,
        "request_id": record.request_id,
        "dispatch_id": record.dispatch_id,
        "workpackage_id": record.workpackage_id,
        "assignment_intent_id": record.assignment_intent_id,
        "repo_id": record.repo_id,
        "principal_id": record.principal_id,
        "parent_principal_id": record.parent_principal_id,
        "grant_id": record.grant_id,
        "grant_digest": record.grant_digest,
        "work_item_version": record.work_item_version,
        "scope": {
            "mode": record.scope.mode,
            "paths": list(record.scope.paths),
            "canonical_digest": record.scope.canonical_digest,
        },
        "resource": {
            "agent_id": record.resource.agent_id,
            "account_key": record.resource.account_key,
            "budget_key": record.resource.budget_key,
            "model_id": record.resource.model_id,
            "expected_usage_micro": record.resource.expected_usage_micro,
        },
        "lease_context": {
            "expected_state": record.lease_context.expected_state,
            "lease_id": record.lease_context.lease_id,
        },
        "priority": {
            "dispatch": record.priority.dispatch,
            "selection_reason": record.priority.selection_reason,
        },
        "state": record.state.value,
        "created_at_utc": record.created_at_utc.isoformat(),
        "expires_at_utc": record.expires_at_utc.isoformat(),
        "revision": record.revision,
    }


def _record_from_payload(payload: object) -> AdmissionRecord:
    try:
        if not isinstance(payload, Mapping):
            raise AdmissionError("invalid_admission_state")
        scope = payload["scope"]
        resource = payload["resource"]
        lease_context = payload["lease_context"]
        priority = payload["priority"]
        if not all(isinstance(value, Mapping) for value in (scope, resource, lease_context, priority)):
            raise AdmissionError("invalid_admission_state")
        raw_paths = scope["paths"]
        if not isinstance(raw_paths, list):
            raise AdmissionError("invalid_admission_state")
        return AdmissionRecord(
            payload["schema_version"],
            payload["admission_id"],
            payload["request_id"],
            payload["dispatch_id"],
            payload["workpackage_id"],
            payload["assignment_intent_id"],
            payload["repo_id"],
            payload["principal_id"],
            payload["parent_principal_id"],
            payload["grant_id"],
            payload["grant_digest"],
            payload["work_item_version"],
            ScopeBinding(scope["mode"], tuple(raw_paths), scope["canonical_digest"]),
            ResourceBinding(
                resource["agent_id"],
                resource["account_key"],
                resource["budget_key"],
                resource["model_id"],
                resource["expected_usage_micro"],
            ),
            LeaseBinding(lease_context["expected_state"], lease_context.get("lease_id")),
            AdmissionPriority(priority["dispatch"], priority["selection_reason"]),
            AdmissionState(payload["state"]),
            _parse_timestamp(payload["created_at_utc"], "invalid_created_timestamp"),
            _parse_timestamp(payload["expires_at_utc"], "invalid_expiry_timestamp"),
            payload["revision"],
        )
    except (AdmissionError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionError) and str(exc) == "invalid_admission_state":
            raise
        raise AdmissionError("invalid_admission_state") from exc


def _parse_timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise AdmissionError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdmissionError(code) from exc
    return _aware(parsed, code)


def _private_absolute_path(value: Path, code: str) -> Path:
    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError) as exc:
        raise AdmissionError(code) from exc
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AdmissionError(code)
    return path


def _ensure_private_parent(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        current = path.lstat()
    except OSError as exc:
        raise AdmissionError("could_not_prepare_admission_state") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise AdmissionError("invalid_admission_state_directory")
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise AdmissionError("could_not_prepare_admission_state") from exc


def _bounded_text(value: object, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
        raise AdmissionError(code)
    return value


def _bounded_int(value: object, code: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AdmissionError(code)
    return value


def _aware(value: object, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AdmissionError(code)
    return value
