"""Durable host-agent master queue backed by private Hive state."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Literal, cast
import uuid

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
)
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_AGENT_OPERATION_RECORDS = 1024
MAX_AGENT_OPERATION_STATE_BYTES = 4 * 1024 * 1024
AGENT_OPERATION_LIFETIME = timedelta(minutes=15)
AGENT_OPERATION_LEASE = timedelta(seconds=30)
MAX_AGENT_OPERATION_ATTEMPTS = 8
MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL = 8

_DOCUMENT = PurePosixPath("operations.json")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_STATES = frozenset({"queued", "leased", "succeeded", "failed", "unknown", "cancelled"})
_TERMINAL_STATES = frozenset({"succeeded", "failed", "unknown", "cancelled"})
_ALLOWED_ACTIONS = {
    "host.probe": frozenset({"collect"}),
    "ollama.instance": frozenset({"plan", "apply", "probe", "stop"}),
}
_FORBIDDEN_KEY_PARTS = (
    "path",
    "command",
    "argv",
    "shell",
    "url",
    "certificate",
    "credential",
    "token",
    "cookie",
)


class AgentOperationError(ValueError):
    """Stable, path-free host operation error."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _raise(code: str) -> None:
    raise AgentOperationError(code)


def _token(value: object, code: str = "host.request_invalid") -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _raise(code)
    return cast(str, value)


def _digest(value: object, code: str = "host.request_invalid") -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _raise(code)
    return cast(str, value)


def _integer(value: object, code: str = "host.request_invalid", *, low: int = 0) -> int:
    if type(value) is not int or value < low:
        _raise(code)
    return cast(int, value)


def _utc(value: object, code: str = "host.request_invalid") -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        _raise(code)
    moment = cast(datetime, value).astimezone(UTC)
    if moment.microsecond != 0:
        _raise(code)
    return moment


def _wire_time(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: object) -> datetime:
    if type(value) is not str:
        _raise("host.operation_store_unavailable")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _raise("host.operation_store_unavailable")


def _check_kind_action(kind: object, action: object) -> tuple[str, str]:
    kind_value = _token(kind)
    action_value = _token(action)
    if action_value not in _ALLOWED_ACTIONS.get(kind_value, ()):
        _raise("host.request_invalid")
    return kind_value, action_value


def _check_key(name: str) -> None:
    lowered = name.lower()
    if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
        _raise("host.request_invalid")


def _freeze_json(value: object) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value < 0:
            _raise("host.request_invalid")
        return value
    if type(value) is str:
        if not value or any(ord(char) < 32 for char in value):
            _raise("host.request_invalid")
        return value
    if type(value) in {list, tuple}:
        return tuple(_freeze_json(item) for item in cast(list[object], value))
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str or not key:
                _raise("host.request_invalid")
            _check_key(key)
            result[key] = _freeze_json(item)
        return MappingProxyType(dict(sorted(result.items())))
    _raise("host.request_invalid")


def _public_json(value: object) -> object:
    if type(value) is tuple:
        return [_public_json(item) for item in cast(tuple[object, ...], value)]
    if type(value) is MappingProxyType:
        return {
            key: _public_json(item)
            for key, item in cast(Mapping[str, object], value).items()
        }
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _raise("host.request_invalid")


def _canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value).rstrip(b"\n")).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentPrincipalV1:
    host_ref: str
    registry_generation: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "host_ref", _token(self.host_ref))
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )


@dataclass(frozen=True, slots=True)
class AgentOperationRequestV1:
    key: str
    kind: Literal["host.probe", "ollama.instance"]
    action: Literal["collect", "plan", "apply", "probe", "stop"]
    registry_generation: int
    plan_digest: str
    arguments: Mapping[str, object]
    deadline: datetime
    target_host_ref: str | None = None

    def __post_init__(self) -> None:
        kind, action = _check_kind_action(self.kind, self.action)
        arguments = cast(Mapping[str, object], _freeze_json(dict(self.arguments)))
        object.__setattr__(self, "key", _token(self.key))
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(self, "deadline", _utc(self.deadline))
        if self.target_host_ref is not None:
            object.__setattr__(self, "target_host_ref", _token(self.target_host_ref))


@dataclass(frozen=True, slots=True)
class AgentOperationViewV1:
    operation_id: str
    state: Literal["queued", "leased", "succeeded", "failed", "unknown", "cancelled"]
    kind: str
    action: str
    registry_generation: int
    attempt: int
    plan_digest: str
    arguments_digest: str
    created_at: datetime
    deadline: datetime
    host_ref: str | None = None
    lease_id: str | None = None
    lease_epoch: int | None = None
    reason_codes: tuple[str, ...] = ()
    result_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _token(self.operation_id))
        state = _token(self.state)
        if state not in _STATES:
            _raise("host.operation_store_unavailable")
        object.__setattr__(self, "state", state)
        kind, action = _check_kind_action(self.kind, self.action)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )
        object.__setattr__(self, "attempt", _integer(self.attempt))
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(
            self, "arguments_digest", _digest(self.arguments_digest)
        )
        object.__setattr__(self, "created_at", _utc(self.created_at))
        object.__setattr__(self, "deadline", _utc(self.deadline))
        if self.host_ref is not None:
            object.__setattr__(self, "host_ref", _token(self.host_ref))
        if self.lease_id is not None:
            object.__setattr__(self, "lease_id", _token(self.lease_id))
        if self.lease_epoch is not None:
            object.__setattr__(
                self, "lease_epoch", _integer(self.lease_epoch)
            )
        object.__setattr__(
            self,
            "reason_codes",
            tuple(_token(reason) for reason in self.reason_codes),
        )
        if self.result_digest is not None:
            object.__setattr__(self, "result_digest", _digest(self.result_digest))


@dataclass(frozen=True, slots=True)
class AgentAttemptExhaustionV1:
    """Exact private context for a bounded terminal-exhaustion owner."""

    operation_id: str
    host_ref: str
    target_host_ref: str | None
    kind: str
    action: str
    registry_generation: int
    attempt: int
    plan_digest: str
    arguments_digest: str
    arguments: Mapping[str, object]
    lease_id: str
    lease_epoch: int
    deadline: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _token(self.operation_id))
        object.__setattr__(self, "host_ref", _token(self.host_ref))
        if self.target_host_ref is not None:
            object.__setattr__(
                self,
                "target_host_ref",
                _token(self.target_host_ref),
            )
        kind, action = _check_kind_action(self.kind, self.action)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "registry_generation",
            _integer(self.registry_generation),
        )
        object.__setattr__(self, "attempt", _integer(self.attempt, low=1))
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(
            self,
            "arguments_digest",
            _digest(self.arguments_digest),
        )
        object.__setattr__(
            self,
            "arguments",
            cast(Mapping[str, object], _freeze_json(dict(self.arguments))),
        )
        object.__setattr__(self, "lease_id", _token(self.lease_id))
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(self, "deadline", _utc(self.deadline))


@dataclass(frozen=True, slots=True)
class AgentOperationDeadlineExpiryV1:
    """Exact private context for a bounded operation-deadline owner."""

    operation_id: str
    host_ref: str
    target_host_ref: str | None
    kind: str
    action: str
    registry_generation: int
    attempt: int
    plan_digest: str
    arguments_digest: str
    arguments: Mapping[str, object]
    deadline: datetime
    lease_id: str | None
    lease_registry_generation: int | None
    lease_epoch: int | None
    lease_deadline: datetime | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _token(self.operation_id))
        object.__setattr__(self, "host_ref", _token(self.host_ref))
        if self.target_host_ref is not None:
            object.__setattr__(
                self,
                "target_host_ref",
                _token(self.target_host_ref),
            )
        kind, action = _check_kind_action(self.kind, self.action)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "registry_generation",
            _integer(self.registry_generation),
        )
        object.__setattr__(self, "attempt", _integer(self.attempt))
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(
            self,
            "arguments_digest",
            _digest(self.arguments_digest),
        )
        object.__setattr__(
            self,
            "arguments",
            cast(Mapping[str, object], _freeze_json(dict(self.arguments))),
        )
        object.__setattr__(self, "deadline", _utc(self.deadline))
        lease_values = (
            self.lease_id,
            self.lease_registry_generation,
            self.lease_epoch,
            self.lease_deadline,
        )
        if any(value is None for value in lease_values):
            if any(value is not None for value in lease_values):
                _raise("host.operation_store_unavailable")
            return
        object.__setattr__(self, "lease_id", _token(self.lease_id))
        object.__setattr__(
            self,
            "lease_registry_generation",
            _integer(self.lease_registry_generation),
        )
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(self, "lease_deadline", _utc(self.lease_deadline))


class AgentOperationStore:
    """One bounded durable master queue guarded by HiveStateStore."""

    def __init__(
        self,
        state_root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise AgentOperationError("host.operation_store_unavailable")
        self._clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))
        self._root = state_root / "agent-operations"
        self._active_lock = RLock()
        self._active_polls: set[str] = set()
        self._reconciled_attempt_exhaustions: set[str] = set()
        self._reconciled_operation_deadlines: set[str] = set()
        try:
            self._state = HiveStateStore(self._root)
            with self._state.locked():
                document = self._read_locked()
                self._write_locked(document)
        except (HiveStateError, AgentOperationError, OSError, ValueError):
            raise AgentOperationError("host.operation_store_unavailable") from None

    @classmethod
    def for_test(
        cls,
        state_root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> AgentOperationStore:
        return cls(state_root, clock=clock)

    def enqueue(self, request: AgentOperationRequestV1) -> AgentOperationViewV1:
        if type(request) is not AgentOperationRequestV1:
            _raise("host.request_invalid")
        now = self._now()
        if request.deadline <= now or request.deadline > now + AGENT_OPERATION_LIFETIME:
            _raise("host.deadline_invalid")

        with self._state.locked():
            document = self._read_locked()
            records = document["operations"]
            arguments = cast(dict[str, object], _public_json(request.arguments))
            arguments_digest = _canonical_digest(arguments)
            for record in records:
                if record["key"] != request.key:
                    continue
                if (
                    record["kind"] != request.kind
                    or record["action"] != request.action
                    or record["registry_generation"] != request.registry_generation
                    or record["plan_digest"] != request.plan_digest
                    or record["arguments_digest"] != arguments_digest
                ):
                    _raise("host.idempotency_conflict")
                return self._view(record)
            if len(records) >= MAX_AGENT_OPERATION_RECORDS:
                _raise("host.operation_limit")
            record: dict[str, Any] = {
                "operation_id": self._new_operation_id(records),
                "key": request.key,
                "state": "queued",
                "kind": request.kind,
                "action": request.action,
                "registry_generation": request.registry_generation,
                "attempt": 0,
                "plan_digest": request.plan_digest,
                "arguments_digest": arguments_digest,
                "arguments": arguments,
                "created_at": _wire_time(now),
                "deadline": _wire_time(request.deadline),
                "target_host_ref": request.target_host_ref,
                "lease": None,
                "completion": None,
            }
            records.append(record)
            self._write_locked(document)
            return self._view(record)

    def poll(
        self,
        principal: AgentPrincipalV1,
        poll: AgentPollV1,
        *,
        attempt_exhaustion_owner: Callable[[AgentAttemptExhaustionV1], bool]
        | None = None,
        operation_deadline_owner: Callable[[AgentOperationDeadlineExpiryV1], bool]
        | None = None,
        lifecycle_ack_owner: Callable[
            [AgentAttemptExhaustionV1 | AgentOperationDeadlineExpiryV1], None
        ]
        | None = None,
    ) -> AgentLeaseV1 | AgentNoWorkV1:
        if type(principal) is not AgentPrincipalV1 or type(poll) is not AgentPollV1:
            _raise("host.request_invalid")
        if attempt_exhaustion_owner is not None and not callable(
            attempt_exhaustion_owner
        ):
            _raise("host.request_invalid")
        if operation_deadline_owner is not None and not callable(
            operation_deadline_owner
        ):
            _raise("host.request_invalid")
        if lifecycle_ack_owner is not None and not callable(lifecycle_ack_owner):
            _raise("host.request_invalid")
        if principal.registry_generation != poll.registry_generation:
            _raise("host.registry_generation_stale")
        self._begin_poll(principal.host_ref)
        try:
            if (
                attempt_exhaustion_owner is None
                and operation_deadline_owner is None
            ):
                self.expire_leases()
            else:
                self.expire_leases(
                    attempt_exhaustion_owner=attempt_exhaustion_owner,
                    operation_deadline_owner=operation_deadline_owner,
                    lifecycle_ack_owner=lifecycle_ack_owner,
                    owner_host_ref=principal.host_ref,
                )
            with self._state.locked():
                document = self._read_locked()
                now = self._now()
                host_epochs = document["host_epochs"]
                previous = host_epochs.get(principal.host_ref)
                if previous is not None and poll.lease_epoch < previous:
                    _raise("host.lease_epoch_stale")
                if previous is None or poll.lease_epoch > previous:
                    host_epochs[principal.host_ref] = poll.lease_epoch
                for record in document["operations"]:
                    if record["state"] != "queued":
                        continue
                    if (
                        record["target_host_ref"] is not None
                        and record["target_host_ref"] != principal.host_ref
                    ):
                        continue
                    if record["registry_generation"] > poll.registry_generation:
                        _raise("host.registry_generation_stale")
                    operation_deadline = _parse_time(record["deadline"])
                    if now >= operation_deadline:
                        if operation_deadline_owner is None:
                            self._set_operation_deadline_expired(record)
                        continue
                    if record["attempt"] >= MAX_AGENT_OPERATION_ATTEMPTS:
                        record["state"] = "unknown"
                        record["completion"] = {
                            "reason_codes": ["host.attempts_exhausted"],
                            "result_digest": None,
                        }
                        continue
                    record["state"] = "leased"
                    record["attempt"] += 1
                    lease_id = self._new_lease_id()
                    deadline = min(
                        now + AGENT_OPERATION_LEASE,
                        operation_deadline,
                    )
                    record["lease"] = {
                        "lease_id": lease_id,
                        "host_ref": principal.host_ref,
                        "registry_generation": poll.registry_generation,
                        "lease_epoch": poll.lease_epoch,
                        "deadline": _wire_time(deadline),
                    }
                    self._write_locked(document)
                    return AgentLeaseV1(
                        operation_id=record["operation_id"],
                        lease_id=lease_id,
                        host_ref=principal.host_ref,
                        kind=record["kind"],
                        action=record["action"],
                        registry_generation=poll.registry_generation,
                        lease_epoch=poll.lease_epoch,
                        attempt=record["attempt"],
                        plan_digest=record["plan_digest"],
                        arguments_digest=record["arguments_digest"],
                        deadline=deadline,
                        arguments=record["arguments"],
                    )
                self._write_locked(document)
                return AgentNoWorkV1(
                    poll.registry_generation,
                    poll.lease_epoch,
                    poll.max_wait_seconds,
                )
        finally:
            self._end_poll(principal.host_ref)

    def complete(
        self, principal: AgentPrincipalV1, receipt: AgentReceiptV1
    ) -> AgentOperationViewV1:
        if type(principal) is not AgentPrincipalV1 or type(receipt) is not AgentReceiptV1:
            _raise("host.request_invalid")
        with self._state.locked():
            document = self._read_locked()
            record = self._find(document["operations"], receipt.operation_id)
            terminal = self._validate_completion_locked(principal, receipt, record)
            if terminal:
                return self._view(record)
            record["state"] = receipt.state
            record["completion"] = self._completion_doc(receipt)
            self._write_locked(document)
            return self._view(record)

    def validate_completion(
        self, principal: AgentPrincipalV1, receipt: AgentReceiptV1
    ) -> Mapping[str, object]:
        """Validate receipt fences and expose fixed owner context without mutation."""
        if type(principal) is not AgentPrincipalV1 or type(receipt) is not AgentReceiptV1:
            _raise("host.request_invalid")
        with self._state.locked():
            record = self._find(
                self._read_locked()["operations"], receipt.operation_id
            )
            self._validate_completion_locked(principal, receipt, record)
            return MappingProxyType(
                {
                    "target_host_ref": record["target_host_ref"],
                    "registry_generation": record["registry_generation"],
                    "arguments": MappingProxyType(dict(record["arguments"])),
                }
            )

    def cancel(self, operation_id: str) -> AgentOperationViewV1:
        operation_id = _token(operation_id, "host.operation_not_found")
        with self._state.locked():
            document = self._read_locked()
            record = self._find(document["operations"], operation_id)
            if record["state"] == "cancelled":
                return self._view(record)
            if record["state"] != "queued":
                _raise("host.cancel_conflict")
            record["state"] = "cancelled"
            record["completion"] = {
                "reason_codes": ["host.cancelled"],
                "result_digest": None,
            }
            self._write_locked(document)
            return self._view(record)

    def expire_leases(
        self,
        *,
        attempt_exhaustion_owner: Callable[[AgentAttemptExhaustionV1], bool]
        | None = None,
        operation_deadline_owner: Callable[[AgentOperationDeadlineExpiryV1], bool]
        | None = None,
        lifecycle_ack_owner: Callable[
            [AgentAttemptExhaustionV1 | AgentOperationDeadlineExpiryV1], None
        ]
        | None = None,
        owner_host_ref: str | None = None,
    ) -> tuple[str, ...]:
        has_owner = (
            attempt_exhaustion_owner is not None
            or operation_deadline_owner is not None
        )
        if has_owner:
            if (
                attempt_exhaustion_owner is not None
                and not callable(attempt_exhaustion_owner)
            ) or (
                operation_deadline_owner is not None
                and not callable(operation_deadline_owner)
            ) or (
                lifecycle_ack_owner is not None
                and not callable(lifecycle_ack_owner)
            ) or owner_host_ref is None:
                _raise("host.request_invalid")
            owner_host_ref = _token(owner_host_ref)
        elif owner_host_ref is not None or lifecycle_ack_owner is not None:
            _raise("host.request_invalid")
        now = self._now()
        with self._active_lock:
            reconciled_exhaustions = frozenset(
                self._reconciled_attempt_exhaustions
            )
            reconciled_deadlines = frozenset(
                self._reconciled_operation_deadlines
            )
        expired: list[str] = []
        exhaustions: list[AgentAttemptExhaustionV1] = []
        deadline_expiries: list[AgentOperationDeadlineExpiryV1] = []
        changed = False
        with self._state.locked():
            document = self._read_locked()
            for record in document["operations"]:
                reconciliation_count = len(exhaustions) + len(deadline_expiries)
                lease = record["lease"]
                if self._is_attempts_exhausted(record):
                    if (
                        attempt_exhaustion_owner is not None
                        and record["operation_id"] not in reconciled_exhaustions
                        and type(lease) is dict
                        and _parse_time(lease["deadline"]) <= now
                        and lease["host_ref"] == owner_host_ref
                        and reconciliation_count
                        < MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL
                    ):
                        exhaustions.append(self._attempt_exhaustion(record))
                    continue
                if self._is_operation_deadline_expired(record):
                    lease_host = (
                        lease["host_ref"]
                        if type(lease) is dict
                        else record["target_host_ref"]
                    )
                    if (
                        operation_deadline_owner is not None
                        and record["operation_id"] not in reconciled_deadlines
                        and lease_host == owner_host_ref
                        and reconciliation_count
                        < MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL
                    ):
                        deadline_expiries.append(
                            self._operation_deadline_expiry(
                                record,
                                host_ref=cast(str, owner_host_ref),
                            )
                        )
                    continue
                if record["state"] == "queued":
                    if _parse_time(record["deadline"]) > now:
                        continue
                    target = record["target_host_ref"]
                    if (
                        operation_deadline_owner is not None
                        and (target is None or target == owner_host_ref)
                        and reconciliation_count
                        < MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL
                    ):
                        deadline_expiries.append(
                            self._operation_deadline_expiry(
                                record,
                                host_ref=cast(str, owner_host_ref),
                            )
                        )
                    elif operation_deadline_owner is None:
                        self._set_operation_deadline_expired(record)
                        changed = True
                    continue
                if record["state"] != "leased" or type(lease) is not dict:
                    continue
                if _parse_time(record["deadline"]) <= now:
                    expired.append(record["operation_id"])
                    if (
                        operation_deadline_owner is not None
                        and lease["host_ref"] == owner_host_ref
                        and reconciliation_count
                        < MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL
                    ):
                        deadline_expiries.append(
                            self._operation_deadline_expiry(
                                record,
                                host_ref=lease["host_ref"],
                            )
                        )
                    elif operation_deadline_owner is None:
                        self._set_operation_deadline_expired(record)
                        changed = True
                    continue
                if _parse_time(lease["deadline"]) > now:
                    continue
                expired.append(record["operation_id"])
                if record["attempt"] >= MAX_AGENT_OPERATION_ATTEMPTS:
                    # An authenticated poll may reconcile only its own host.
                    # Other hosts retain their durable candidate for their poll.
                    if (
                        attempt_exhaustion_owner is not None
                        and lease["host_ref"] == owner_host_ref
                        and reconciliation_count
                        < MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL
                    ):
                        exhaustions.append(self._attempt_exhaustion(record))
                    elif attempt_exhaustion_owner is None:
                        self._set_attempts_exhausted(record)
                        changed = True
                else:
                    record["state"] = "queued"
                    record["lease"] = None
                    changed = True
            if changed:
                self._write_locked(document)
        if operation_deadline_owner is not None:
            for expiry in deadline_expiries:
                claimed = operation_deadline_owner(expiry)
                if type(claimed) is not bool:
                    _raise("host.operation_store_unavailable")
                self._finalize_operation_deadline(expiry)
                if claimed and lifecycle_ack_owner is not None:
                    lifecycle_ack_owner(expiry)
                with self._active_lock:
                    self._reconciled_operation_deadlines.add(
                        expiry.operation_id
                    )
        if attempt_exhaustion_owner is not None:
            for exhaustion in exhaustions:
                claimed = attempt_exhaustion_owner(exhaustion)
                if type(claimed) is not bool:
                    _raise("host.operation_store_unavailable")
                self._finalize_attempt_exhaustion(exhaustion)
                if claimed and lifecycle_ack_owner is not None:
                    lifecycle_ack_owner(exhaustion)
                with self._active_lock:
                    self._reconciled_attempt_exhaustions.add(
                        exhaustion.operation_id
                    )
        return tuple(expired)

    def get(self, operation_id: str) -> AgentOperationViewV1:
        operation_id = _token(operation_id, "host.operation_not_found")
        with self._state.locked():
            return self._view(self._find(self._read_locked()["operations"], operation_id))

    def context(self, operation_id: str) -> Mapping[str, object]:
        """Private owner context for the fixed host-probe completion path."""
        operation_id = _token(operation_id, "host.operation_not_found")
        with self._state.locked():
            record = self._find(self._read_locked()["operations"], operation_id)
            return MappingProxyType(
                {
                    "target_host_ref": record["target_host_ref"],
                    "registry_generation": record["registry_generation"],
                    "arguments": MappingProxyType(dict(record["arguments"])),
                }
            )

    def _host_probe_lifecycle_bindings(self) -> tuple[Mapping[str, object], ...]:
        """Return only exact fixed probe pairs for Admin owner migration."""

        with self._state.locked():
            bindings: list[Mapping[str, object]] = []
            for record in self._read_locked()["operations"]:
                lifecycle_unknown = (
                    record["state"] == "unknown"
                    and record["completion"]
                    in (
                        {
                            "reason_codes": ["host.attempts_exhausted"],
                            "result_digest": None,
                        },
                        {
                            "reason_codes": ["host.lease_expired"],
                            "result_digest": None,
                        },
                    )
                )
                if (
                    (record["kind"], record["action"])
                    != ("host.probe", "collect")
                    or not (
                        record["state"] in {"queued", "leased"}
                        or lifecycle_unknown
                    )
                    or type(record["target_host_ref"]) is not str
                    or set(record["arguments"])
                    != {"admin_operation_id", "probe_schema"}
                    or record["arguments"].get("probe_schema") != 1
                    or type(record["arguments"].get("admin_operation_id"))
                    is not str
                ):
                    continue
                bindings.append(
                    MappingProxyType(
                        {
                            "operation_id": record["operation_id"],
                            "admin_operation_id": record["arguments"][
                                "admin_operation_id"
                            ],
                            "target_host_ref": record["target_host_ref"],
                            "plan_digest": record["plan_digest"],
                        }
                    )
                )
            return tuple(bindings)

    def _attempt_exhaustion(
        self, record: Mapping[str, Any]
    ) -> AgentAttemptExhaustionV1:
        lease = record["lease"]
        if type(lease) is not dict:
            _raise("host.operation_store_unavailable")
        return AgentAttemptExhaustionV1(
            operation_id=record["operation_id"],
            host_ref=lease["host_ref"],
            target_host_ref=record["target_host_ref"],
            kind=record["kind"],
            action=record["action"],
            registry_generation=record["registry_generation"],
            attempt=record["attempt"],
            plan_digest=record["plan_digest"],
            arguments_digest=record["arguments_digest"],
            arguments=record["arguments"],
            lease_id=lease["lease_id"],
            lease_epoch=lease["lease_epoch"],
            deadline=_parse_time(lease["deadline"]),
        )

    def _operation_deadline_expiry(
        self,
        record: Mapping[str, Any],
        *,
        host_ref: str,
    ) -> AgentOperationDeadlineExpiryV1:
        lease = record["lease"]
        if type(lease) is dict:
            if lease["host_ref"] != host_ref:
                _raise("host.operation_store_unavailable")
            lease_id = lease["lease_id"]
            lease_registry_generation = lease["registry_generation"]
            lease_epoch = lease["lease_epoch"]
            lease_deadline = _parse_time(lease["deadline"])
        elif lease is None and record["state"] in {"queued", "unknown"}:
            lease_id = None
            lease_registry_generation = None
            lease_epoch = None
            lease_deadline = None
        else:
            _raise("host.operation_store_unavailable")
        return AgentOperationDeadlineExpiryV1(
            operation_id=record["operation_id"],
            host_ref=host_ref,
            target_host_ref=record["target_host_ref"],
            kind=record["kind"],
            action=record["action"],
            registry_generation=record["registry_generation"],
            attempt=record["attempt"],
            plan_digest=record["plan_digest"],
            arguments_digest=record["arguments_digest"],
            arguments=record["arguments"],
            deadline=_parse_time(record["deadline"]),
            lease_id=lease_id,
            lease_registry_generation=lease_registry_generation,
            lease_epoch=lease_epoch,
            lease_deadline=lease_deadline,
        )

    def _finalize_attempt_exhaustion(
        self, exhaustion: AgentAttemptExhaustionV1
    ) -> None:
        with self._state.locked():
            document = self._read_locked()
            now = self._now()
            record = self._find(document["operations"], exhaustion.operation_id)
            if record["state"] == "unknown" and record["completion"] == {
                "reason_codes": ["host.attempts_exhausted"],
                "result_digest": None,
            }:
                return
            if (
                record["state"] != "leased"
                or record["attempt"] < MAX_AGENT_OPERATION_ATTEMPTS
                or self._attempt_exhaustion(record) != exhaustion
                or exhaustion.deadline > now
            ):
                _raise("host.lease_stale")
            self._set_attempts_exhausted(record)
            self._write_locked(document)

    def _finalize_operation_deadline(
        self, expiry: AgentOperationDeadlineExpiryV1
    ) -> None:
        with self._state.locked():
            document = self._read_locked()
            now = self._now()
            record = self._find(document["operations"], expiry.operation_id)
            if record["state"] == "unknown" and record["completion"] == {
                "reason_codes": ["host.lease_expired"],
                "result_digest": None,
            }:
                return
            if (
                record["state"] not in {"queued", "leased"}
                or _parse_time(record["deadline"]) > now
                or self._operation_deadline_expiry(
                    record,
                    host_ref=expiry.host_ref,
                )
                != expiry
            ):
                _raise("host.lease_stale")
            self._set_operation_deadline_expired(record)
            self._write_locked(document)

    @staticmethod
    def _is_attempts_exhausted(record: Mapping[str, Any]) -> bool:
        return (
            record["state"] == "unknown"
            and record["attempt"] >= MAX_AGENT_OPERATION_ATTEMPTS
            and record["completion"]
            == {
                "reason_codes": ["host.attempts_exhausted"],
                "result_digest": None,
            }
        )

    @staticmethod
    def _is_operation_deadline_expired(record: Mapping[str, Any]) -> bool:
        return (
            record["state"] == "unknown"
            and record["completion"]
            == {
                "reason_codes": ["host.lease_expired"],
                "result_digest": None,
            }
        )

    @staticmethod
    def _set_attempts_exhausted(record: dict[str, Any]) -> None:
        record["state"] = "unknown"
        record["completion"] = {
            "reason_codes": ["host.attempts_exhausted"],
            "result_digest": None,
        }

    @staticmethod
    def _set_operation_deadline_expired(record: dict[str, Any]) -> None:
        record["state"] = "unknown"
        record["completion"] = {
            "reason_codes": ["host.lease_expired"],
            "result_digest": None,
        }

    def _begin_poll(self, host_ref: str) -> None:
        with self._active_lock:
            if host_ref in self._active_polls:
                _raise("host.poll_already_active")
            self._active_polls.add(host_ref)

    def _end_poll(self, host_ref: str) -> None:
        with self._active_lock:
            self._active_polls.discard(host_ref)

    def _now(self) -> datetime:
        return _utc(self._clock(), "host.operation_store_unavailable")

    def _read_locked(self) -> dict[str, Any]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_AGENT_OPERATION_STATE_BYTES
            )
        except HiveStateError as exc:
            if str(exc) != "state_not_found":
                raise
            return {"schema_version": 1, "operations": [], "host_epochs": {}}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _raise("host.operation_store_unavailable")
        return self._validate_document(payload)

    def _write_locked(self, document: Mapping[str, object]) -> None:
        encoded = _canonical_bytes(document)
        if len(encoded) > MAX_AGENT_OPERATION_STATE_BYTES:
            _raise("host.operation_store_unavailable")
        self._state.replace_private_bytes(_DOCUMENT, encoded)

    def _validate_document(self, payload: object) -> dict[str, Any]:
        if type(payload) is not dict or set(payload) != {
            "schema_version",
            "operations",
            "host_epochs",
        }:
            _raise("host.operation_store_unavailable")
        if payload["schema_version"] != 1:
            _raise("host.operation_store_unavailable")
        operations = payload["operations"]
        host_epochs = payload["host_epochs"]
        if type(operations) is not list or len(operations) > MAX_AGENT_OPERATION_RECORDS:
            _raise("host.operation_store_unavailable")
        if type(host_epochs) is not dict:
            _raise("host.operation_store_unavailable")
        validated = {
            "schema_version": 1,
            "operations": [self._record(record) for record in operations],
            "host_epochs": {
                _token(key, "host.operation_store_unavailable"): _integer(
                    value, "host.operation_store_unavailable"
                )
                for key, value in host_epochs.items()
            },
        }
        return validated

    def _record(self, value: object) -> dict[str, Any]:
        if type(value) is not dict or set(value) not in (
            {
            "operation_id",
            "key",
            "state",
            "kind",
            "action",
            "registry_generation",
            "attempt",
            "plan_digest",
            "arguments_digest",
            "arguments",
            "created_at",
            "deadline",
            "lease",
            "completion",
            },
            {
            "operation_id",
            "key",
            "state",
            "kind",
            "action",
            "registry_generation",
            "attempt",
            "plan_digest",
            "arguments_digest",
            "arguments",
            "created_at",
            "deadline",
            "target_host_ref",
            "lease",
            "completion",
            },
        ):
            _raise("host.operation_store_unavailable")
        record = cast(dict[str, object], value)
        state = _token(record["state"], "host.operation_store_unavailable")
        if state not in _STATES:
            _raise("host.operation_store_unavailable")
        kind, action = _check_kind_action(record["kind"], record["action"])
        arguments = cast(Mapping[str, object], _freeze_json(record["arguments"]))
        result: dict[str, Any] = {
            "operation_id": _token(
                record["operation_id"], "host.operation_store_unavailable"
            ),
            "key": _token(record["key"], "host.operation_store_unavailable"),
            "state": state,
            "kind": kind,
            "action": action,
            "registry_generation": _integer(
                record["registry_generation"], "host.operation_store_unavailable"
            ),
            "attempt": _integer(record["attempt"], "host.operation_store_unavailable"),
            "plan_digest": _digest(
                record["plan_digest"], "host.operation_store_unavailable"
            ),
            "arguments_digest": _digest(
                record["arguments_digest"], "host.operation_store_unavailable"
            ),
            "arguments": cast(dict[str, object], _public_json(arguments)),
            "created_at": _wire_time(_parse_time(record["created_at"])),
            "deadline": _wire_time(_parse_time(record["deadline"])),
            "target_host_ref": (
                None
                if record.get("target_host_ref") is None
                else _token(record["target_host_ref"], "host.operation_store_unavailable")
            ),
            "lease": self._lease_doc(
                record["lease"],
                operation_generation=cast(int, record["registry_generation"]),
            ),
            "completion": self._stored_completion_doc(record["completion"]),
        }
        if result["arguments_digest"] != _canonical_digest(result["arguments"]):
            _raise("host.operation_store_unavailable")
        return result

    def _lease_doc(
        self, value: object, *, operation_generation: int
    ) -> dict[str, object] | None:
        if value is None:
            return None
        if type(value) is not dict or set(value) not in (
            {"lease_id", "host_ref", "lease_epoch", "deadline"},
            {
                "lease_id",
                "host_ref",
                "registry_generation",
                "lease_epoch",
                "deadline",
            },
        ):
            _raise("host.operation_store_unavailable")
        doc = cast(dict[str, object], value)
        registry_generation = _integer(
            doc.get("registry_generation", operation_generation),
            "host.operation_store_unavailable",
        )
        if registry_generation < operation_generation:
            _raise("host.operation_store_unavailable")
        return {
            "lease_id": _token(doc["lease_id"], "host.operation_store_unavailable"),
            "host_ref": _token(doc["host_ref"], "host.operation_store_unavailable"),
            "registry_generation": registry_generation,
            "lease_epoch": _integer(
                doc["lease_epoch"], "host.operation_store_unavailable"
            ),
            "deadline": _wire_time(_parse_time(doc["deadline"])),
        }

    def _stored_completion_doc(self, value: object) -> dict[str, object] | None:
        if value is None:
            return None
        if type(value) is not dict or set(value) != {
            "reason_codes",
            "result_digest",
        }:
            _raise("host.operation_store_unavailable")
        doc = cast(dict[str, object], value)
        result_digest = doc["result_digest"]
        if result_digest is not None:
            result_digest = _digest(result_digest, "host.operation_store_unavailable")
        return {
            "reason_codes": [
                _token(reason, "host.operation_store_unavailable")
                for reason in self._list(doc["reason_codes"])
            ],
            "result_digest": result_digest,
        }

    @staticmethod
    def _list(value: object) -> list[object]:
        if type(value) is not list:
            _raise("host.operation_store_unavailable")
        return cast(list[object], value)

    def _validate_receipt_fences(
        self,
        principal: AgentPrincipalV1,
        receipt: AgentReceiptV1,
        record: Mapping[str, Any],
        lease: Mapping[str, object],
        *,
        check_deadline: bool,
        now: datetime,
    ) -> None:
        if principal.host_ref != lease["host_ref"]:
            _raise("host.identity_mismatch")
        # Redelivery issues a new lease at the resolver's current generation.
        # Terminal replay stays exact so an older identity document cannot complete it.
        if principal.registry_generation != lease["registry_generation"]:
            _raise("host.registry_generation_stale")
        if receipt.lease_id != lease["lease_id"]:
            _raise("host.lease_stale")
        if receipt.lease_epoch != lease["lease_epoch"]:
            _raise("host.lease_epoch_stale")
        if receipt.attempt != record["attempt"]:
            _raise("host.lease_stale")
        if receipt.plan_digest != record["plan_digest"]:
            _raise("host.plan_digest_mismatch")
        if receipt.arguments_digest != record["arguments_digest"]:
            _raise("host.arguments_digest_mismatch")
        if receipt.result.kind != record["kind"] or receipt.result.action != record["action"]:
            _raise("host.result_mismatch")
        if check_deadline:
            if _parse_time(record["deadline"]) <= now:
                _raise("host.lease_stale")
            if _parse_time(lease["deadline"]) <= now:
                _raise("host.lease_stale")

    def _validate_completion_locked(
        self,
        principal: AgentPrincipalV1,
        receipt: AgentReceiptV1,
        record: Mapping[str, Any],
    ) -> bool:
        now = self._now()
        existing = record["completion"]
        if record["state"] in _TERMINAL_STATES:
            if type(record["lease"]) is not dict:
                _raise("host.lease_stale")
            self._validate_receipt_fences(
                principal,
                receipt,
                record,
                record["lease"],
                check_deadline=False,
                now=now,
            )
            if (
                record["state"] != receipt.state
                or existing != self._completion_doc(receipt)
            ):
                _raise("host.completion_conflict")
            return True
        if record["state"] != "leased" or type(record["lease"]) is not dict:
            _raise("host.lease_stale")
        self._validate_receipt_fences(
            principal,
            receipt,
            record,
            record["lease"],
            check_deadline=True,
            now=now,
        )
        return False

    @staticmethod
    def _completion_doc(receipt: AgentReceiptV1) -> dict[str, object]:
        return {
            "reason_codes": list(receipt.reason_codes),
            "result_digest": receipt.result_digest,
        }

    def _view(self, record: Mapping[str, Any]) -> AgentOperationViewV1:
        lease = record["lease"] if type(record["lease"]) is dict else {}
        completion = record["completion"] if type(record["completion"]) is dict else {}
        return AgentOperationViewV1(
            operation_id=record["operation_id"],
            state=record["state"],
            kind=record["kind"],
            action=record["action"],
            registry_generation=record["registry_generation"],
            attempt=record["attempt"],
            plan_digest=record["plan_digest"],
            arguments_digest=record["arguments_digest"],
            created_at=_parse_time(record["created_at"]),
            deadline=_parse_time(record["deadline"]),
            host_ref=lease.get("host_ref"),
            lease_id=lease.get("lease_id"),
            lease_epoch=lease.get("lease_epoch"),
            reason_codes=tuple(completion.get("reason_codes", ())),
            result_digest=completion.get("result_digest"),
        )

    @staticmethod
    def _find(
        records: list[dict[str, Any]], operation_id: str
    ) -> dict[str, Any]:
        for record in records:
            if record["operation_id"] == operation_id:
                return record
        _raise("host.operation_not_found")

    @staticmethod
    def _new_lease_id() -> str:
        return "lease-" + uuid.uuid4().hex

    @staticmethod
    def _new_operation_id(records: list[dict[str, Any]]) -> str:
        existing = {record["operation_id"] for record in records}
        while True:
            candidate = "operation-" + uuid.uuid4().hex
            if candidate not in existing:
                return candidate

__all__ = [
    "AGENT_OPERATION_LEASE",
    "AGENT_OPERATION_LIFETIME",
    "MAX_AGENT_OPERATION_ATTEMPTS",
    "MAX_AGENT_OPERATION_RECORDS",
    "MAX_AGENT_EXHAUSTION_RECONCILIATIONS_PER_POLL",
    "AgentAttemptExhaustionV1",
    "AgentOperationDeadlineExpiryV1",
    "AgentOperationError",
    "AgentOperationRequestV1",
    "AgentOperationStore",
    "AgentOperationViewV1",
    "AgentPrincipalV1",
]
