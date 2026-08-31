"""Versioned, fail-closed public contracts for Masterjet administration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import re
from types import MappingProxyType
from typing import Never, cast
import unicodedata
from urllib.parse import unquote
import uuid


MAX_ADMIN_TEXT_UTF8_BYTES = 4096


@dataclass(frozen=True, slots=True)
class AdminOperationMetadataV1:
    scope: str | None
    command: bool
    argument_fields: tuple[str, ...]
    optional_argument_fields: tuple[str, ...] = ()
    text_argument_fields: tuple[str, ...] = ()
    integer_argument_fields: tuple[str, ...] = ()
    token_list_argument_fields: tuple[str, ...] = ()
    text_argument_max_utf8_bytes: int = MAX_ADMIN_TEXT_UTF8_BYTES
    requires_idempotency: bool = False
    requires_digest: bool = False
    generation_domain: str | None = None


ADMIN_OPERATION_METADATA = MappingProxyType(
    {
        "control.operations.list": AdminOperationMetadataV1(None, False, ()),
        "hosts.list": AdminOperationMetadataV1("fleet.host.read", False, ()),
        "hosts.probe": AdminOperationMetadataV1(
            "fleet.host.probe",
            True,
            ("host_ref",),
            requires_idempotency=True,
            generation_domain="host",
        ),
        "openai.accounts.list": AdminOperationMetadataV1("fleet.read", False, ()),
        "google.accounts.list": AdminOperationMetadataV1("fleet.read", False, ()),
        "google.projects.list": AdminOperationMetadataV1(
            "fleet.read", False, ("account_ref",)
        ),
        "operations.get": AdminOperationMetadataV1(
            "fleet.read", False, ("operation_id",)
        ),
        "ollama.models.list": AdminOperationMetadataV1("fleet.read", False, ()),
        "ollama.instances.list": AdminOperationMetadataV1("fleet.read", False, ()),
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
        "google.quota-evidence.sync": AdminOperationMetadataV1(
            "fleet.google.provision",
            True,
            (
                "account_ref",
                "remaining",
                "observed_at",
                "source",
                "inventory_fingerprint",
            ),
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
        "ollama.instance.plan": AdminOperationMetadataV1(
            "fleet.ollama.write",
            True,
            (
                "ref",
                "label",
                "host_ref",
                "ollama_executable",
                "models_directory",
                "selected_model_refs",
                "allowed_cpus",
                "cpu_quota_percent",
                "cpu_weight",
            ),
            text_argument_fields=(
                "label",
                "ollama_executable",
                "models_directory",
            ),
            integer_argument_fields=("cpu_quota_percent", "cpu_weight"),
            token_list_argument_fields=("selected_model_refs",),
            requires_idempotency=True,
            generation_domain="ollama",
        ),
        "ollama.instance.apply": AdminOperationMetadataV1(
            "fleet.ollama.write",
            True,
            ("plan_id",),
            requires_idempotency=True,
            requires_digest=True,
            generation_domain="ollama",
        ),
        "ollama.instance.probe": AdminOperationMetadataV1(
            "fleet.ollama.write",
            True,
            ("instance_ref",),
            requires_idempotency=True,
            generation_domain="ollama",
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
_MAX_KEY_BYTES = 128
_MAX_GENERATION = 2**63 - 1
_MAX_COUNT = 100_000
_MAX_OPERATION_LIFETIME = timedelta(days=1)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
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
PUBLIC_AGENT_REASON_CODES = frozenset(
    {
        "host.unreachable",
        "host.identity_mismatch",
        "host.generation_stale",
        "host.lease_expired",
        "host.capability_mismatch",
        "host.probe_failed",
        "host.operation_unknown",
        "resource.host_response_invalid",
        "resource.host_unreachable",
        "control.plan_stale",
    }
)
_AGENT_RESULT_KINDS = {
    ("host.probe", "collect"): "host.probe",
    ("ollama.instance", "plan"): "ollama.instance.plan",
    ("ollama.instance", "apply"): "ollama.instance.apply",
    ("ollama.instance", "probe"): "ollama.instance.probe",
    ("ollama.instance", "stop"): "ollama.instance.stop",
}
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


def _text(
    value: object,
    *,
    private: bool = False,
    max_utf8_bytes: int = MAX_ADMIN_TEXT_UTF8_BYTES,
) -> str:
    fail = _private if private else _invalid
    if type(value) is not str:
        fail()
    try:
        if not value or len(value.encode("utf-8")) > max_utf8_bytes:
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
    result = {}
    for field in arguments:
        if field in metadata.text_argument_fields:
            result[field] = _text(
                arguments[field],
                max_utf8_bytes=metadata.text_argument_max_utf8_bytes,
            )
        elif field in metadata.integer_argument_fields:
            integer = arguments[field]
            if type(integer) is not int or not 1 <= integer <= 10000:
                _invalid()
            result[field] = integer
        elif field in metadata.token_list_argument_fields:
            values = arguments[field]
            if (
                type(values) not in {list, tuple}
                or not 1 <= len(values) <= 64
            ):
                _invalid()
            tokens = tuple(_token(item) for item in values)
            if len(set(tokens)) != len(tokens):
                _invalid()
            result[field] = tokens
        else:
            result[field] = _token(arguments[field])
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


def public_operation_status(
    operation: object,
    *,
    result_kind: str | None = None,
    result: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Serialize one operation with the fixed asynchronous-result envelope."""

    public = public_admin_result(operation)
    if result_kind is None and result is None:
        return {**public, "result_kind": None, "result": None}
    if type(result_kind) is not str or result is None:
        raise AdminContractError("resource.host_response_invalid")
    return {
        **public,
        "result_kind": result_kind,
        "result": public_agent_result(result_kind, result),
    }


def public_agent_result(
    result_kind: object, value: object
) -> dict[str, object]:
    """Fail closed to the five result shapes that may cross the Admin boundary."""

    if type(result_kind) is not str or result_kind not in _AGENT_RESULT_KINDS.values():
        raise AdminContractError("resource.host_response_invalid")
    if not isinstance(value, Mapping):
        raise AdminContractError("resource.host_response_invalid")
    payload = dict(value)
    if result_kind == "host.probe":
        return _public_host_probe_result(payload)
    if result_kind == "ollama.instance.plan":
        _require_result_fields(payload, {"plan_ref"})
        return {"plan_ref": _result_token(payload["plan_ref"])}
    if result_kind == "ollama.instance.apply":
        _require_result_fields(payload, {"instance_ref", "generation"})
        return {
            "instance_ref": _result_token(payload["instance_ref"]),
            "generation": _result_generation(payload["generation"]),
        }
    if result_kind == "ollama.instance.probe":
        _require_result_fields(
            payload,
            {
                "ready",
                "reason_codes",
                "process_running",
                "cgroup_member",
                "loopback_endpoint_reachable",
                "available_model_ids",
            },
        )
        identifiers = payload["available_model_ids"]
        if type(identifiers) is not list or len(identifiers) > 64:
            raise AdminContractError("resource.host_response_invalid")
        model_ids = [_result_token(item) for item in identifiers]
        if len(set(model_ids)) != len(model_ids):
            raise AdminContractError("resource.host_response_invalid")
        return {
            "ready": _result_bool(payload["ready"]),
            "reason_codes": _public_agent_reason_codes(payload["reason_codes"]),
            "process_running": _result_bool(payload["process_running"]),
            "cgroup_member": _result_bool(payload["cgroup_member"]),
            "loopback_endpoint_reachable": _result_bool(
                payload["loopback_endpoint_reachable"]
            ),
            "available_model_ids": model_ids,
        }
    _require_result_fields(payload, {"stopped"})
    return {"stopped": _result_bool(payload["stopped"])}


def agent_result_kind(kind: object, action: object) -> str:
    result_kind = _AGENT_RESULT_KINDS.get((kind, action))
    if result_kind is None:
        raise AdminContractError("resource.host_response_invalid")
    return result_kind


def _require_result_fields(payload: Mapping[str, object], fields: set[str]) -> None:
    if set(payload) != fields:
        raise AdminContractError("resource.host_response_invalid")


def _result_token(value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AdminContractError("resource.host_response_invalid")
    return value


def _result_generation(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_GENERATION:
        raise AdminContractError("resource.host_response_invalid")
    return value


def _result_bool(value: object) -> bool:
    if type(value) is not bool:
        raise AdminContractError("resource.host_response_invalid")
    return value


def _public_agent_reason_codes(value: object) -> list[str]:
    if type(value) is not list or len(value) > 32:
        raise AdminContractError("resource.host_response_invalid")
    if any(type(code) is not str or code not in PUBLIC_AGENT_REASON_CODES for code in value):
        raise AdminContractError("resource.host_response_invalid")
    if len(set(value)) != len(value):
        raise AdminContractError("resource.host_response_invalid")
    return list(cast(list[str], value))


def _public_host_probe_result(payload: Mapping[str, object]) -> dict[str, object]:
    fields = {
        "kernel_class",
        "architecture_class",
        "cpu_count",
        "memory_class",
        "cgroup_v2",
        "systemd",
        "load_class",
        "pressure_class",
        "ollama_capability",
        "observed_at",
        "agent_generation",
        "evidence_digest",
    }
    _require_result_fields(payload, fields)
    if (
        payload["kernel_class"] not in {"linux", "other"}
        or payload["architecture_class"] not in {"x86_64", "arm64", "other"}
        or type(payload["cpu_count"]) is not int
        or not 1 <= cast(int, payload["cpu_count"]) <= 2**31 - 1
        or payload["memory_class"]
        not in {"under-8-gib", "8-31-gib", "32-127-gib", "128-plus-gib"}
        or payload["load_class"] not in {"idle", "busy", "saturated"}
        or payload["pressure_class"] not in {"none", "low", "elevated"}
        or any(
            type(payload[field]) is not bool
            for field in ("cgroup_v2", "systemd", "ollama_capability")
        )
        or type(payload["observed_at"]) is not str
        or _UTC_TIMESTAMP.fullmatch(cast(str, payload["observed_at"])) is None
        or type(payload["agent_generation"]) is not int
        or not 1 <= cast(int, payload["agent_generation"]) <= _MAX_GENERATION
        or type(payload["evidence_digest"]) is not str
        or _DIGEST.fullmatch(cast(str, payload["evidence_digest"])) is None
    ):
        raise AdminContractError("resource.host_response_invalid")
    evidence = {field: payload[field] for field in fields - {"evidence_digest"}}
    canonical = json.dumps(
        evidence, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if "sha256:" + hashlib.sha256(canonical).hexdigest() != payload["evidence_digest"]:
        raise AdminContractError("resource.host_response_invalid")
    return {field: payload[field] for field in fields}
