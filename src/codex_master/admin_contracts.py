"""Versioned, secret-free contracts for Masterjet administration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re


_REQUEST_FIELDS = frozenset({"schema_version", "operation", "arguments", "expected_generation", "idempotency_key"})
_MUTATING_OPERATIONS = frozenset({
    "openai.auth.plan",
    "openai.auth.apply",
    "google.oauth.begin",
    "google.provision.plan",
    "google.provision.apply",
    "google.billing.plan",
    "google.billing.apply",
})
_PRIVATE_KEY_PARTS = frozenset({"token", "secret", "cookie", "authorization", "auth_json", "backend_account_id"})
_MAX_DEPTH = 8
_MAX_ITEMS = 128
_MAX_STRING_BYTES = 4096
_MAX_GENERATION = 2**63 - 1
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_WINDOWS_ABSOLUTE_PATH = re.compile(r"[A-Za-z]:[\\/]", re.ASCII)


class AdminContractError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AdminRequestV1:
    operation: str
    arguments: Mapping[str, object]
    expected_generation: int | None
    idempotency_key: str | None


@dataclass(frozen=True, slots=True)
class AdminPrincipalV1:
    subject: str
    scopes: tuple[str, ...]
    authentication: str
    step_up: bool


@dataclass(frozen=True, slots=True)
class OperationV1:
    operation_id: str
    kind: str
    state: str
    expected_generation: int
    resulting_generation: int | None
    plan_digest: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HiveProblemV1:
    code: str
    message: str
    details: Mapping[str, object]


def _request_invalid() -> None:
    raise AdminContractError("control.request_invalid")


def _response_private() -> None:
    raise AdminContractError("control.response_private")


def _bounded_text(value: object) -> str:
    if type(value) is not str:
        _request_invalid()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _request_invalid()
    if not value or size > _MAX_STRING_BYTES:
        _request_invalid()
    return value


def _request_value(value: object, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        _request_invalid()
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is str:
        return _bounded_text(value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            _request_invalid()
        result: dict[str, object] = {}
        for key, item in value.items():
            if (
                type(key) is not str
                or not key
                or len(key.encode("utf-8")) > 128
                or _private_key(key)
            ):
                _request_invalid()
            result[key] = _request_value(item, depth + 1)
        return result
    if type(value) in {list, tuple}:
        if len(value) > _MAX_ITEMS:
            _request_invalid()
        return tuple(_request_value(item, depth + 1) for item in value)
    _request_invalid()


def parse_admin_request(value: object) -> AdminRequestV1:
    if not isinstance(value, Mapping) or set(value) - _REQUEST_FIELDS:
        _request_invalid()
    if value.get("schema_version") != 1:
        _request_invalid()
    operation = _bounded_text(value.get("operation"))
    if _TOKEN.fullmatch(operation) is None:
        _request_invalid()
    arguments = _request_value(value.get("arguments", {}))
    if not isinstance(arguments, Mapping):
        _request_invalid()
    expected_generation = value.get("expected_generation")
    if expected_generation is not None and (
        type(expected_generation) is not int or not 0 <= expected_generation <= _MAX_GENERATION
    ):
        _request_invalid()
    idempotency_key = value.get("idempotency_key")
    if idempotency_key is not None:
        idempotency_key = _bounded_text(idempotency_key)
        if _TOKEN.fullmatch(idempotency_key) is None:
            _request_invalid()
    if operation in _MUTATING_OPERATIONS and (expected_generation is None or idempotency_key is None):
        _request_invalid()
    return AdminRequestV1(operation, arguments, expected_generation, idempotency_key)


def _private_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _PRIVATE_KEY_PARTS or any(
        part in _PRIVATE_KEY_PARTS for part in normalized.split("_")
    )


def _public_value(value: object, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        _response_private()
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is str:
        try:
            if len(value.encode("utf-8")) > _MAX_STRING_BYTES:
                _response_private()
        except UnicodeError:
            _response_private()
        if value.startswith("/") or _WINDOWS_ABSOLUTE_PATH.match(value):
            _response_private()
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            _response_private()
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or _private_key(key):
                _response_private()
            result[key] = _public_value(item, depth + 1)
        return result
    if type(value) in {list, tuple}:
        if len(value) > _MAX_ITEMS:
            _response_private()
        return [_public_value(item, depth + 1) for item in value]
    _response_private()


def public_admin_result(value: object) -> object:
    """Return detached JSON-safe public data, or reject private structures."""
    if isinstance(value, HiveProblemV1):
        value = {"code": value.code, "message": value.message, "details": value.details}
    return _public_value(value)
