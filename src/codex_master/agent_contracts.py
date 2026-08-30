"""Private, bounded wire contracts for the host-agent route."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import re
from types import MappingProxyType
from typing import Literal, cast


_MAX_INT = 2**63 - 1
_MAX_WAIT_SECONDS = 30
_MAX_REASON_CODES = 32
_MAX_RESULT_BYTES = 256 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_POLL_FIELDS = frozenset(
    {
        "schema_version",
        "registry_generation",
        "lease_epoch",
        "capabilities_digest",
        "max_wait_seconds",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "operation_id",
        "lease_id",
        "lease_epoch",
        "attempt",
        "plan_digest",
        "arguments_digest",
        "state",
        "reason_codes",
        "result_digest",
        "result",
    }
)
_RESULT_FIELDS = frozenset({"kind", "action", "payload"})
_RECEIPT_STATES = frozenset({"succeeded", "failed", "unknown"})
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


class AgentContractError(ValueError):
    """Fail-closed contract violation."""

    __slots__ = ("code",)
    code: str

    def __init__(self, code: str = "agent.request_invalid") -> None:
        self.code = code
        super().__init__(code)


def _invalid() -> None:
    raise AgentContractError("agent.request_invalid")


def _mapping(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        _invalid()
    return cast(Mapping[str, object], value)


def _integer(value: object, *, low: int = 0, high: int = _MAX_INT) -> int:
    if type(value) is not int or not low <= value <= high:
        _invalid()
    return cast(int, value)


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _invalid()
    return cast(str, value)


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _invalid()
    return cast(str, value)


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        _invalid()
    moment = cast(datetime, value).astimezone(UTC)
    if moment.microsecond != 0:
        _invalid()
    return moment


def _wire_time(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reason_codes(value: object) -> tuple[str, ...]:
    if type(value) not in {list, tuple}:
        _invalid()
    items = tuple(_token(item) for item in cast(list[object] | tuple[object, ...], value))
    if len(items) > _MAX_REASON_CODES or len(set(items)) != len(items):
        _invalid()
    return items


def _check_kind_action(kind: object, action: object) -> tuple[str, str]:
    kind_value = _token(kind)
    action_value = _token(action)
    if action_value not in _ALLOWED_ACTIONS.get(kind_value, ()):
        _invalid()
    return kind_value, action_value


def _check_key(name: str) -> None:
    lowered = name.lower()
    if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
        _invalid()


def _freeze_json(value: object) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return _integer(value)
    if type(value) is str:
        encoded = value.encode("utf-8")
        if not value or len(encoded) > _MAX_RESULT_BYTES or any(ord(char) < 32 for char in value):
            _invalid()
        if _UTC_TIMESTAMP.fullmatch(value) is not None:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
                _invalid()
        return value
    if type(value) in {list, tuple}:
        return tuple(_freeze_json(item) for item in cast(list[object] | tuple[object, ...], value))
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str or not key:
                _invalid()
            _check_key(key)
            result[key] = _freeze_json(item)
        return MappingProxyType(dict(sorted(result.items())))
    _invalid()


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
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        _invalid()


def _canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentPollV1:
    registry_generation: int
    lease_epoch: int
    capabilities_digest: str
    max_wait_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(
            self, "capabilities_digest", _digest(self.capabilities_digest)
        )
        object.__setattr__(
            self,
            "max_wait_seconds",
            _integer(self.max_wait_seconds, low=0, high=_MAX_WAIT_SECONDS),
        )


@dataclass(frozen=True, slots=True)
class AgentNoWorkV1:
    registry_generation: int
    lease_epoch: int
    max_wait_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(
            self,
            "max_wait_seconds",
            _integer(self.max_wait_seconds, low=0, high=_MAX_WAIT_SECONDS),
        )


@dataclass(frozen=True, slots=True)
class AgentResultV1:
    kind: Literal["host.probe", "ollama.instance"]
    action: Literal["collect", "plan", "apply", "probe", "stop"]
    payload: Mapping[str, object] = field(repr=False)

    def __post_init__(self) -> None:
        kind, action = _check_kind_action(self.kind, self.action)
        frozen_payload = _freeze_json(_mapping(self.payload))
        payload = cast(Mapping[str, object], frozen_payload)
        encoded = _canonical_bytes(
            {"kind": kind, "action": action, "payload": _public_json(payload)}
        )
        if len(encoded) > _MAX_RESULT_BYTES:
            _invalid()
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "payload", payload)


@dataclass(frozen=True, slots=True)
class AgentLeaseV1:
    operation_id: str
    lease_id: str
    host_ref: str
    kind: Literal["host.probe", "ollama.instance"]
    action: Literal["collect", "plan", "apply", "probe", "stop"]
    registry_generation: int
    lease_epoch: int
    attempt: int
    plan_digest: str
    arguments_digest: str
    deadline: datetime
    arguments: Mapping[str, object] = field(repr=False)

    def __post_init__(self) -> None:
        kind, action = _check_kind_action(self.kind, self.action)
        frozen_arguments = _freeze_json(_mapping(self.arguments))
        arguments = cast(Mapping[str, object], frozen_arguments)
        object.__setattr__(self, "operation_id", _token(self.operation_id))
        object.__setattr__(self, "lease_id", _token(self.lease_id))
        object.__setattr__(self, "host_ref", _token(self.host_ref))
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self, "registry_generation", _integer(self.registry_generation)
        )
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(self, "attempt", _integer(self.attempt, low=1))
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(
            self, "arguments_digest", _digest(self.arguments_digest)
        )
        if self.arguments_digest != _canonical_digest(_public_json(arguments)):
            _invalid()
        object.__setattr__(self, "deadline", _utc(self.deadline))
        object.__setattr__(self, "arguments", arguments)


@dataclass(frozen=True, slots=True)
class AgentReceiptV1:
    operation_id: str
    lease_id: str
    lease_epoch: int
    attempt: int
    plan_digest: str
    arguments_digest: str
    state: Literal["succeeded", "failed", "unknown"]
    reason_codes: tuple[str, ...]
    result_digest: str
    result: AgentResultV1

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _token(self.operation_id))
        object.__setattr__(self, "lease_id", _token(self.lease_id))
        object.__setattr__(self, "lease_epoch", _integer(self.lease_epoch))
        object.__setattr__(self, "attempt", _integer(self.attempt, low=1))
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        object.__setattr__(
            self, "arguments_digest", _digest(self.arguments_digest)
        )
        state = _token(self.state)
        if state not in _RECEIPT_STATES:
            _invalid()
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "reason_codes", _reason_codes(self.reason_codes))
        if type(self.result) is not AgentResultV1:
            _invalid()
        object.__setattr__(self, "result_digest", _digest(self.result_digest))
        if self.result_digest != _canonical_digest(serialize_agent_result(self.result)):
            _invalid()
        if self.state == "succeeded" and not self.reason_codes:
            _invalid()


def parse_agent_poll(value: object) -> AgentPollV1:
    payload = _mapping(value)
    if set(payload) != _POLL_FIELDS:
        _invalid()
    if _integer(payload.get("schema_version")) != 1:
        _invalid()
    return AgentPollV1(
        registry_generation=payload["registry_generation"],  # type: ignore[arg-type]
        lease_epoch=payload["lease_epoch"],  # type: ignore[arg-type]
        capabilities_digest=payload["capabilities_digest"],  # type: ignore[arg-type]
        max_wait_seconds=payload["max_wait_seconds"],  # type: ignore[arg-type]
    )


def parse_agent_receipt(value: object) -> AgentReceiptV1:
    payload = _mapping(value)
    if set(payload) != _RECEIPT_FIELDS:
        _invalid()
    if _integer(payload.get("schema_version")) != 1:
        _invalid()
    result = _mapping(payload["result"])
    if set(result) != _RESULT_FIELDS:
        _invalid()
    return AgentReceiptV1(
        operation_id=payload["operation_id"],  # type: ignore[arg-type]
        lease_id=payload["lease_id"],  # type: ignore[arg-type]
        lease_epoch=payload["lease_epoch"],  # type: ignore[arg-type]
        attempt=payload["attempt"],  # type: ignore[arg-type]
        plan_digest=payload["plan_digest"],  # type: ignore[arg-type]
        arguments_digest=payload["arguments_digest"],  # type: ignore[arg-type]
        state=payload["state"],  # type: ignore[arg-type]
        reason_codes=_reason_codes(payload["reason_codes"]),
        result_digest=payload["result_digest"],  # type: ignore[arg-type]
        result=AgentResultV1(
            kind=result["kind"],  # type: ignore[arg-type]
            action=result["action"],  # type: ignore[arg-type]
            payload=_mapping(result["payload"]),
        ),
    )


def serialize_agent_result(value: object) -> dict[str, object]:
    if type(value) is not AgentResultV1:
        _invalid()
    result = cast(AgentResultV1, value)
    return {
        "kind": result.kind,
        "action": result.action,
        "payload": cast(dict[str, object], _public_json(result.payload)),
    }


def serialize_agent_lease(value: object) -> dict[str, object]:
    if type(value) is not AgentLeaseV1:
        _invalid()
    lease = cast(AgentLeaseV1, value)
    return {
        "schema_version": 1,
        "operation_id": lease.operation_id,
        "lease_id": lease.lease_id,
        "host_ref": lease.host_ref,
        "kind": lease.kind,
        "action": lease.action,
        "registry_generation": lease.registry_generation,
        "lease_epoch": lease.lease_epoch,
        "attempt": lease.attempt,
        "plan_digest": lease.plan_digest,
        "arguments_digest": lease.arguments_digest,
        "deadline": _wire_time(lease.deadline),
        "arguments": cast(dict[str, object], _public_json(lease.arguments)),
    }


__all__ = [
    "AgentContractError",
    "AgentLeaseV1",
    "AgentNoWorkV1",
    "AgentPollV1",
    "AgentReceiptV1",
    "AgentResultV1",
    "parse_agent_poll",
    "parse_agent_receipt",
    "serialize_agent_lease",
    "serialize_agent_result",
]
