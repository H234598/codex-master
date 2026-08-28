"""Versioned, fail-closed public contracts for Masterjet administration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType


_OPERATIONS = frozenset({
    "openai.accounts.list", "google.accounts.list", "google.projects.list", "hosts.list",
    "operations.get", "openai.auth.plan", "openai.auth.apply", "google.oauth.begin",
    "google.provision.plan", "google.provision.apply", "google.billing.plan",
    "google.billing.apply",
})
_GLOBAL_LISTS = frozenset({"openai.accounts.list", "google.accounts.list", "google.projects.list", "hosts.list"})
_ACCOUNT_OPERATIONS = _OPERATIONS - _GLOBAL_LISTS - {"operations.get"}
_APPLY_OPERATIONS = frozenset(operation for operation in _OPERATIONS if operation.endswith(".apply"))
_REQUEST_FIELDS = frozenset({"schema_version", "operation", "arguments", "expected_generation", "idempotency_key", "plan_digest"})
_MAX_TEXT_BYTES = 4096
_MAX_KEY_BYTES = 128
_MAX_GENERATION = 2**63 - 1
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_PRIVATE_TEXT = re.compile(r"\bbearer\s+\S+|file://|\\\\[^\\\s]+\\|(?:^|[\s:=])/\S+|[A-Za-z]:[\\/]", re.IGNORECASE)


class AdminContractError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _invalid() -> None:
    raise AdminContractError("control.request_invalid")


def _private() -> None:
    raise AdminContractError("control.response_private")


def _text(value: object, *, private: bool = False) -> str:
    fail = _private if private else _invalid
    if type(value) is not str:
        fail()
    try:
        if not value or len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
            fail()
    except UnicodeError:
        fail()
    if private and _PRIVATE_TEXT.search(value):
        fail()
    return value


def _token(value: object, *, private: bool = False) -> str:
    text = _text(value, private=private)
    if _TOKEN.fullmatch(text) is None:
        (_private if private else _invalid)()
    return text


def _generation(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_GENERATION:
        _invalid()
    return value


def _public_generation(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_GENERATION:
        _private()
    return value


def _digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        _invalid()
    return text


def _mapping(value: object, *, private: bool = False) -> Mapping[str, object]:
    fail = _private if private else _invalid
    if not isinstance(value, Mapping) or len(value) > 32:
        fail()
    result: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str:
            fail()
        try:
            if not key or len(key.encode("utf-8")) > _MAX_KEY_BYTES:
                fail()
        except UnicodeError:
            fail()
        result[key] = item
    return result


def _account_arguments(value: object) -> Mapping[str, object]:
    arguments = _mapping(value)
    if set(arguments) != {"account_ref"}:
        _invalid()
    return MappingProxyType({"account_ref": _token(arguments["account_ref"])})


def _arguments(operation: str, value: object) -> Mapping[str, object]:
    arguments = _mapping(value)
    if operation in _GLOBAL_LISTS:
        if arguments:
            _invalid()
        return MappingProxyType({})
    if operation == "operations.get":
        if set(arguments) != {"operation_id"}:
            _invalid()
        return MappingProxyType({"operation_id": _token(arguments["operation_id"])})
    return _account_arguments(arguments)


def _reason_codes(value: object, *, private: bool = False) -> tuple[str, ...]:
    fail = _private if private else _invalid
    if type(value) not in {list, tuple} or len(value) > 32:
        fail()
    return tuple(_token(item, private=private) for item in value)


def _problem_details(value: object) -> Mapping[str, object]:
    details = _mapping(value, private=True)
    if set(details) - {"reason_codes"}:
        _private()
    result: dict[str, object] = {}
    if "reason_codes" in details:
        result["reason_codes"] = _reason_codes(details["reason_codes"], private=True)
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class AdminRequestV1:
    operation: str
    arguments: Mapping[str, object]
    expected_generation: int | None
    idempotency_key: str | None
    plan_digest: str | None

    def __post_init__(self) -> None:
        operation = _token(self.operation)
        if operation not in _OPERATIONS:
            _invalid()
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "arguments", _arguments(operation, self.arguments))
        if operation in _APPLY_OPERATIONS:
            object.__setattr__(self, "expected_generation", _generation(self.expected_generation))
            object.__setattr__(self, "idempotency_key", _token(self.idempotency_key))
            object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
        elif any(value is not None for value in (self.expected_generation, self.idempotency_key, self.plan_digest)):
            _invalid()


@dataclass(frozen=True, slots=True)
class AdminPrincipalV1:
    subject: str
    scopes: tuple[str, ...]
    authentication: str
    step_up: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", _token(self.subject, private=True))
        object.__setattr__(self, "scopes", _reason_codes(self.scopes, private=True))
        object.__setattr__(self, "authentication", _token(self.authentication, private=True))
        if type(self.step_up) is not bool:
            _private()


@dataclass(frozen=True, slots=True)
class OperationV1:
    operation_id: str
    kind: str
    state: str
    expected_generation: int
    resulting_generation: int | None
    plan_digest: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _token(self.operation_id, private=True))
        object.__setattr__(self, "kind", _token(self.kind, private=True))
        object.__setattr__(self, "state", _token(self.state, private=True))
        object.__setattr__(self, "expected_generation", _public_generation(self.expected_generation))
        if self.resulting_generation is not None:
            object.__setattr__(self, "resulting_generation", _public_generation(self.resulting_generation))
        digest = _text(self.plan_digest, private=True)
        if _DIGEST.fullmatch(digest) is None:
            _private()
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "reason_codes", _reason_codes(self.reason_codes, private=True))


@dataclass(frozen=True, slots=True)
class HiveProblemV1:
    code: str
    message: str
    details: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _token(self.code, private=True))
        object.__setattr__(self, "message", _text(self.message, private=True))
        object.__setattr__(self, "details", _problem_details(self.details))


def parse_admin_request(value: object) -> AdminRequestV1:
    request = _mapping(value)
    if set(request) - _REQUEST_FIELDS or type(request.get("schema_version")) is not int:
        _invalid()
    if request.get("schema_version") != 1:
        _invalid()
    return AdminRequestV1(
        request.get("operation"), request.get("arguments", {}), request.get("expected_generation"),
        request.get("idempotency_key"), request.get("plan_digest"),
    )


def public_admin_result(value: object) -> dict[str, object]:
    """Serialize only validated V1 DTOs into their explicit public wire forms."""
    if type(value) is HiveProblemV1:
        return {"schema_version": 1, "code": value.code, "message": value.message, "details": {
            key: list(item) if type(item) is tuple else item for key, item in value.details.items()
        }}
    if type(value) is OperationV1:
        return {
            "schema_version": 1, "operation_id": value.operation_id, "kind": value.kind,
            "state": value.state, "expected_generation": value.expected_generation,
            "resulting_generation": value.resulting_generation, "plan_digest": value.plan_digest,
            "reason_codes": list(value.reason_codes),
        }
    if type(value) is AdminPrincipalV1:
        return {
            "schema_version": 1, "subject": value.subject, "scopes": list(value.scopes),
            "authentication": value.authentication, "step_up": value.step_up,
        }
    if type(value) is AdminRequestV1:
        return {
            "schema_version": 1, "operation": value.operation, "arguments": dict(value.arguments),
            "expected_generation": value.expected_generation, "idempotency_key": value.idempotency_key,
            "plan_digest": value.plan_digest,
        }
    _private()
