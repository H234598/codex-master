"""Versioned, fail-closed public contracts for Masterjet administration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import re
from types import MappingProxyType
from typing import Never, cast
import unicodedata
from urllib.parse import unquote
import uuid


@dataclass(frozen=True, slots=True)
class AdminOperationMetadataV1:
    scope: str | None
    command: bool
    argument_fields: tuple[str, ...]
    optional_argument_fields: tuple[str, ...] = ()
    text_argument_fields: tuple[str, ...] = ()
    requires_idempotency: bool = False
    requires_digest: bool = False
    generation_domain: str | None = None


ADMIN_OPERATION_METADATA = MappingProxyType(
    {
        "control.operations.list": AdminOperationMetadataV1(None, False, ()),
        "hosts.list": AdminOperationMetadataV1("fleet.host.read", False, ()),
        "openai.accounts.list": AdminOperationMetadataV1("fleet.read", False, ()),
        "google.accounts.list": AdminOperationMetadataV1("fleet.read", False, ()),
        "google.projects.list": AdminOperationMetadataV1(
            "fleet.read", False, ("account_ref",)
        ),
        "operations.get": AdminOperationMetadataV1(
            "fleet.read", False, ("account_ref", "operation_id")
        ),
        "openai.accounts.add": AdminOperationMetadataV1(
            "fleet.openai.write",
            True,
            ("account_ref", "label"),
            text_argument_fields=("label",),
            requires_idempotency=True,
            generation_domain="account_registry.openai",
        ),
        "openai.accounts.disable": AdminOperationMetadataV1(
            "fleet.openai.write",
            True,
            ("account_ref",),
            requires_idempotency=True,
            generation_domain="account_registry.openai",
        ),
        "google.accounts.add": AdminOperationMetadataV1(
            "fleet.google.oauth",
            True,
            ("account_ref", "label"),
            text_argument_fields=("label",),
            requires_idempotency=True,
            generation_domain="account_registry.google",
        ),
        "openai.auth.plan": AdminOperationMetadataV1(
            "fleet.openai.write",
            True,
            ("account_ref",),
            requires_idempotency=True,
            generation_domain="openai",
        ),
        "openai.auth.apply": AdminOperationMetadataV1(
            "fleet.secrets.ingress",
            True,
            ("account_ref",),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="openai",
        ),
        "secret.ingress.create": AdminOperationMetadataV1(
            "fleet.secrets.ingress",
            True,
            ("account_ref", "credential_kind"),
            ("transaction_id",),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="credential",
        ),
        "google.oauth.begin": AdminOperationMetadataV1(
            "fleet.google.oauth",
            True,
            ("account_ref", "oauth_client_ref", "redirect_uri", "scope_profile"),
            text_argument_fields=("redirect_uri",),
            requires_idempotency=True,
            generation_domain="google_oauth",
        ),
        "google.oauth.complete": AdminOperationMetadataV1(
            "fleet.google.oauth",
            True,
            ("account_ref", "transaction_id", "redirect_uri", "state"),
            text_argument_fields=("redirect_uri",),
            generation_domain="google_oauth",
        ),
        "google.oauth-client-import.plan": AdminOperationMetadataV1(
            "fleet.google.oauth",
            True,
            ("account_ref",),
            requires_idempotency=True,
            generation_domain="google_oauth",
        ),
        "google.oauth-client-import.apply": AdminOperationMetadataV1(
            "fleet.google.oauth",
            True,
            ("account_ref",),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="google_oauth",
        ),
        "google.inventory.refresh": AdminOperationMetadataV1(
            "fleet.google.inventory.refresh",
            True,
            (),
            requires_idempotency=True,
            generation_domain="google",
        ),
        "google.provision.plan": AdminOperationMetadataV1(
            "fleet.google.provision",
            True,
            ("account_ref",),
            requires_idempotency=True,
            generation_domain="google",
        ),
        "google.provision.apply": AdminOperationMetadataV1(
            "fleet.google.provision",
            True,
            ("account_ref",),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="google",
        ),
        "google.billing.plan": AdminOperationMetadataV1(
            "fleet.google.billing.bind",
            True,
            ("account_ref", "project_ref", "billing_ref"),
            requires_idempotency=True,
            generation_domain="google",
        ),
        "google.billing.apply": AdminOperationMetadataV1(
            "fleet.google.billing.bind",
            True,
            ("account_ref", "project_ref", "billing_ref", "plan_id"),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="google",
        ),
    }
)
ADMIN_OPERATION_CATALOG = tuple(ADMIN_OPERATION_METADATA)
ADMIN_OPERATION_CATALOG_DIGEST = hashlib.sha256(
    "\0".join(ADMIN_OPERATION_CATALOG).encode("ascii")
).hexdigest()
_OPERATIONS = frozenset(ADMIN_OPERATION_METADATA)
_QUERY_OPERATIONS = frozenset(
    operation
    for operation, metadata in ADMIN_OPERATION_METADATA.items()
    if not metadata.command
)
_COMMAND_OPERATIONS = _OPERATIONS - _QUERY_OPERATIONS
_IDEMPOTENCY_OPERATIONS = frozenset(
    operation
    for operation, metadata in ADMIN_OPERATION_METADATA.items()
    if metadata.requires_idempotency
)
_DIGEST_OPERATIONS = frozenset(
    operation
    for operation, metadata in ADMIN_OPERATION_METADATA.items()
    if metadata.requires_digest
)
_OPERATION_ALIASES = {
    "openai.auth-sync.plan": "openai.auth.plan",
    "openai.auth-sync.apply": "openai.auth.apply",
}
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "arguments",
        "expected_generation",
        "idempotency_key",
        "plan_digest",
    }
)
_MAX_TEXT_BYTES = 4096
_MAX_KEY_BYTES = 128
_MAX_GENERATION = 2**63 - 1
_MAX_COUNT = 100_000
_MAX_OPERATION_LIFETIME = timedelta(days=1)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_PRIVATE_TEXT = re.compile(
    r"\b(?:bearer|basic|(?:access|refresh)[\s_.-]*token|client[\s_.-]*secret|api[\s_.-]*key|auth(?:entication|orization)?|token|cookie|credential|passphrase|password|session|secret|jwt)\b"
    r"|(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
    r"|file:|\\\\|\\[^\\\s]+|(?:^|[\s\"'=:(\[])/(?:[^\s]+)|[A-Za-z]:[\\/]"
    r"|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
    r"|\b(?:traceback|[A-Z][A-Z0-9_.]*(?:error|exception))\s*(?::|\()",
    re.IGNORECASE,
)
_OPERATION_STATES = frozenset(
    {"planned", "queued", "running", "partial", "succeeded", "failed", "blocked"}
)
_PROBLEM_SEVERITIES = frozenset({"info", "warning", "error", "critical"})
_PROBLEM_TEMPLATES = {
    "control.step_up_required": (
        "warning",
        "Step-up required",
        "Additional authentication is required.",
        "Operation is paused.",
        "Complete step-up authentication.",
    )
}


class AdminContractError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _invalid() -> Never:
    raise AdminContractError("control.request_invalid")


def _private() -> Never:
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
    return value


def _public_text(value: object) -> str:
    text = _text(value, private=True)
    candidate = text
    for _ in range(4):
        candidate = unicodedata.normalize("NFKC", candidate)
        if _PRIVATE_TEXT.search(candidate) or any(
            unicodedata.category(char).startswith("C") for char in candidate
        ):
            _private()
        try:
            decoded = unquote(candidate, errors="strict")
        except UnicodeError:
            _private()
        if decoded == candidate:
            return text
        candidate = decoded
    _private()


def _token(value: object, *, private: bool = False) -> str:
    text = _text(value, private=private)
    if _TOKEN.fullmatch(text) is None:
        (_private if private else _invalid)()
    return text


def public_admin_text(value: object) -> str:
    """Return one bounded public string or fail with a code-only error."""

    return _public_text(value)


def public_admin_ref(value: object) -> str:
    """Return one public ASCII reference after public-text classification."""

    return _token(_public_text(value), private=True)


def _utc_time(value: object) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _private()
    return value.astimezone(UTC)


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        _private()
    return value


def _wire_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


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


def _arguments(operation: str, value: object) -> Mapping[str, object]:
    arguments = _mapping(value)
    metadata = ADMIN_OPERATION_METADATA[operation]
    fields = metadata.argument_fields
    allowed = set(fields) | set(metadata.optional_argument_fields)
    if set(arguments) - allowed or not set(fields) <= set(arguments):
        _invalid()
    result = {
        field: _text(arguments[field])
        if field in metadata.text_argument_fields
        else _token(arguments[field])
        for field in arguments
    }
    if operation == "secret.ingress.create" and result["credential_kind"] not in {
        "openai.auth-json",
        "google.oauth-client",
        "google-oauth-code",
        "openai_auth_json",
        "google_oauth_client_json",
    }:
        _invalid()
    if operation == "secret.ingress.create":
        has_transaction = "transaction_id" in result
        if (result["credential_kind"] == "google-oauth-code") != has_transaction:
            _invalid()
    if operation == "secret.ingress.create":
        result["credential_kind"] = {
            "openai_auth_json": "openai.auth-json",
            "google_oauth_client_json": "google.oauth-client",
        }.get(result["credential_kind"], result["credential_kind"])
    return MappingProxyType(result)


def _reason_codes(value: object, *, private: bool = False) -> tuple[str, ...]:
    fail = _private if private else _invalid
    if type(value) not in {list, tuple}:
        fail()
    values = cast(list[object] | tuple[object, ...], value)
    if len(values) > 32:
        fail()
    return tuple(_token(item, private=private) for item in values)


@dataclass(frozen=True, slots=True)
class AdminRequestV1:
    operation: str
    arguments: Mapping[str, object]
    expected_generation: int | None
    idempotency_key: str | None
    plan_digest: str | None

    def __post_init__(self) -> None:
        operation = _token(self.operation)
        operation = _OPERATION_ALIASES.get(operation, operation)
        if operation not in _OPERATIONS:
            _invalid()
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "arguments", _arguments(operation, self.arguments))
        if operation in _COMMAND_OPERATIONS:
            object.__setattr__(
                self, "expected_generation", _generation(self.expected_generation)
            )
            if operation in _IDEMPOTENCY_OPERATIONS:
                object.__setattr__(
                    self, "idempotency_key", _token(self.idempotency_key)
                )
            elif self.idempotency_key is not None:
                _invalid()
            if operation in _DIGEST_OPERATIONS:
                object.__setattr__(self, "plan_digest", _digest(self.plan_digest))
            elif self.plan_digest is not None:
                _invalid()
        elif any(
            value is not None
            for value in (
                self.expected_generation,
                self.idempotency_key,
                self.plan_digest,
            )
        ):
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
        object.__setattr__(
            self, "authentication", _token(self.authentication, private=True)
        )
        if type(self.step_up) is not bool:
            _private()


@dataclass(frozen=True, slots=True)
class OperationV1:
    id: str
    kind: str
    state: str
    expected_generation: int
    resulting_generation: int | None
    plan_digest: str
    created_at: datetime
    expires_at: datetime
    completed_count: int
    failed_count: int
    not_attempted_count: int
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _token(self.id, private=True))
        object.__setattr__(self, "kind", _token(self.kind, private=True))
        state = _token(self.state, private=True)
        if state not in _OPERATION_STATES:
            _private()
        object.__setattr__(self, "state", state)
        object.__setattr__(
            self, "expected_generation", _public_generation(self.expected_generation)
        )
        if self.resulting_generation is not None:
            object.__setattr__(
                self,
                "resulting_generation",
                _public_generation(self.resulting_generation),
            )
        digest = _text(self.plan_digest, private=True)
        if _DIGEST.fullmatch(digest) is None:
            _private()
        object.__setattr__(self, "plan_digest", digest)
        created_at = _utc_time(self.created_at)
        expires_at = _utc_time(self.expires_at)
        if not created_at < expires_at <= created_at + _MAX_OPERATION_LIFETIME:
            _private()
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "completed_count", _count(self.completed_count))
        object.__setattr__(self, "failed_count", _count(self.failed_count))
        object.__setattr__(
            self, "not_attempted_count", _count(self.not_attempted_count)
        )
        object.__setattr__(
            self, "reason_codes", _reason_codes(self.reason_codes, private=True)
        )


@dataclass(frozen=True, slots=True)
class HiveProblemV1:
    code: str
    severity: str
    title: str
    detail: str
    effect: str
    action: str
    retryable: bool
    retry_after_seconds: int | None
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _token(self.code, private=True))
        severity = _token(self.severity, private=True)
        if severity not in _PROBLEM_SEVERITIES:
            _private()
        object.__setattr__(self, "severity", severity)
        template = _PROBLEM_TEMPLATES.get(self.code)
        if template is not None:
            if (
                self.severity,
                self.title,
                self.detail,
                self.effect,
                self.action,
            ) != template:
                _private()
        else:
            for field in ("title", "detail", "effect", "action"):
                object.__setattr__(self, field, _public_text(getattr(self, field)))
        if type(self.retryable) is not bool:
            _private()
        if self.retry_after_seconds is not None:
            if (
                type(self.retry_after_seconds) is not int
                or not 0 <= self.retry_after_seconds <= 86_400
            ):
                _private()
            if not self.retryable:
                _private()
        object.__setattr__(
            self, "correlation_id", _token(self.correlation_id, private=True)
        )
        object.__setattr__(self, "occurred_at", _utc_time(self.occurred_at))


def canonical_admin_problem(code: str) -> HiveProblemV1:
    """Build one redacted public problem for transport adapters."""

    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect="No action was started",
        action="Review access and retry",
        retryable=False,
        retry_after_seconds=None,
        correlation_id="corr-" + uuid.uuid4().hex,
        occurred_at=datetime.now(UTC),
    )


def parse_admin_request(value: object) -> AdminRequestV1:
    request = _mapping(value)
    if set(request) - _REQUEST_FIELDS or type(request.get("schema_version")) is not int:
        _invalid()
    if request.get("schema_version") != 1:
        _invalid()
    operation = cast(str, request.get("operation"))
    operation = _OPERATION_ALIASES.get(operation, operation)
    arguments = dict(cast(Mapping[str, object], request.get("arguments", {})))
    if operation == "secret.ingress.create" and "credential_type" in arguments:
        if "credential_kind" in arguments:
            _invalid()
        arguments["credential_kind"] = arguments.pop("credential_type")
    return AdminRequestV1(
        operation,
        arguments,
        cast(int | None, request.get("expected_generation")),
        cast(str | None, request.get("idempotency_key")),
        cast(str | None, request.get("plan_digest")),
    )


def public_admin_result(value: object) -> dict[str, object]:
    """Serialize only validated V1 DTOs into their explicit public wire forms."""
    if type(value) is HiveProblemV1:
        return {
            "schema_version": 1,
            "code": value.code,
            "severity": value.severity,
            "title": value.title,
            "detail": value.detail,
            "effect": value.effect,
            "action": value.action,
            "retryable": value.retryable,
            "retry_after_seconds": value.retry_after_seconds,
            "correlation_id": value.correlation_id,
            "occurred_at": _wire_time(value.occurred_at),
        }
    if type(value) is OperationV1:
        return {
            "schema_version": 1,
            "id": value.id,
            "kind": value.kind,
            "state": value.state,
            "expected_generation": value.expected_generation,
            "resulting_generation": value.resulting_generation,
            "plan_digest": value.plan_digest,
            "created_at": _wire_time(value.created_at),
            "expires_at": _wire_time(value.expires_at),
            "completed_count": value.completed_count,
            "failed_count": value.failed_count,
            "not_attempted_count": value.not_attempted_count,
            "reason_codes": list(value.reason_codes),
        }
    if type(value) is AdminPrincipalV1:
        return {
            "schema_version": 1,
            "subject": value.subject,
            "scopes": list(value.scopes),
            "authentication": value.authentication,
            "step_up": value.step_up,
        }
    if type(value) is AdminRequestV1:
        return {
            "schema_version": 1,
            "operation": value.operation,
            "arguments": dict(value.arguments),
            "expected_generation": value.expected_generation,
            "idempotency_key": value.idempotency_key,
            "plan_digest": value.plan_digest,
        }
    _private()
