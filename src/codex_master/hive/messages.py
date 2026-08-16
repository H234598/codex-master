"""Bounded, typed Hive message envelopes.

Messages carry routing and provenance metadata only.  They intentionally do
not retain prompts, terminal output, credentials, or arbitrary filesystem
material.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from types import MappingProxyType

from codex_master.hive.types import DispatchPriority, HiveValidationError, validate_identifier, validate_utc_datetime


MESSAGE_TYPES = frozenset(
    {
        "user.intent",
        "request.classified",
        "dispatch.plan",
        "delegation.request",
        "repo.plan",
        "workpackage.assign",
        "assignment.intent",
        "admission.planned",
        "admission.result",
        "progress.report",
        "result.report",
        "decision.request",
        "decision.recorded",
        "escalation",
        "pause.request",
        "cancel.request",
        "completion",
        "heartbeat",
    }
)
MAX_MESSAGE_BYTES = 256 * 1024
MAX_TEXT = 4096
MAX_LIST = 128
REPORT_MESSAGE_TYPES = frozenset({"progress.report", "result.report", "decision.request", "escalation", "completion"})
REPORT_STATUSES = frozenset({
    "planned", "queued", "executing", "integrating", "completed", "blocked", "decision_required",
    "failed", "paused", "unknown",
})


class HiveMessageError(ValueError):
    """Raised for malformed or unsafe Hive messages."""


def _id(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError as exc:
        raise HiveMessageError(str(exc)) from exc


def _text(value: object, field: str, *, maximum: int = MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise HiveMessageError(f"invalid_{field}")
    return value


def _optional_id(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _id(value, field)


def _texts(values: object, field: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or not 0 <= len(values) <= MAX_LIST:
        raise HiveMessageError(f"invalid_{field}")
    return tuple(_text(value, field, maximum=1024) for value in values)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise HiveMessageError(f"invalid_{field}")
    try:
        encoded = json.dumps(dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HiveMessageError(f"invalid_{field}") from exc
    if len(encoded.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise HiveMessageError(f"oversize_{field}")
    if value.get("raw_output") not in {None, "not_returned"}:
        raise HiveMessageError("raw_output_not_allowed")
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class PrincipalReference:
    principal_id: str
    class_id: str

    def __post_init__(self) -> None:
        _id(self.principal_id, "principal")
        _id(self.class_id, "class")


@dataclass(frozen=True, slots=True)
class AuthorizationEvidence:
    grant_id: str
    scope_digest: str
    principal_version: int

    def __post_init__(self) -> None:
        _id(self.grant_id, "grant")
        _text(self.scope_digest, "scope_digest", maximum=192)
        if isinstance(self.principal_version, bool) or not isinstance(self.principal_version, int) or self.principal_version < 1:
            raise HiveMessageError("invalid_principal_version")


@dataclass(frozen=True, slots=True)
class HiveMessage:
    schema_version: int
    message_id: str
    correlation_id: str
    causation_id: str | None
    message_type: str
    sender: PrincipalReference
    recipient: PrincipalReference
    repo_id: str | None
    dispatch_id: str | None
    workpackage_id: str | None
    dispatch_priority: DispatchPriority
    created_at_utc: datetime
    expires_at_utc: datetime
    authorization: AuthorizationEvidence
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise HiveMessageError("unsupported_message_schema")
        _id(self.message_id, "message")
        _id(self.correlation_id, "correlation")
        _optional_id(self.causation_id, "causation")
        if self.causation_id == self.message_id:
            raise HiveMessageError("message_self_causation")
        if self.message_type not in MESSAGE_TYPES:
            raise HiveMessageError("unknown_message_type")
        if not isinstance(self.sender, PrincipalReference) or not isinstance(self.recipient, PrincipalReference):
            raise HiveMessageError("invalid_message_principal")
        _optional_id(self.repo_id, "repo")
        _optional_id(self.dispatch_id, "dispatch")
        _optional_id(self.workpackage_id, "workpackage")
        if not isinstance(self.dispatch_priority, DispatchPriority):
            raise HiveMessageError("invalid_dispatch_priority")
        created = validate_utc_datetime(self.created_at_utc, field="message_timestamp")
        expires = validate_utc_datetime(self.expires_at_utc, field="message_expiry")
        if expires <= created:
            raise HiveMessageError("invalid_message_expiry")
        if (expires - created).total_seconds() > 24 * 60 * 60:
            raise HiveMessageError("message_ttl_too_long")
        if not isinstance(self.authorization, AuthorizationEvidence):
            raise HiveMessageError("invalid_authorization")
        _mapping(self.payload, "payload")

    def public(self) -> dict[str, object]:
        """Return envelope metadata while excluding the message payload."""

        return {
            "schema_version": self.schema_version,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "message_type": self.message_type,
            "sender": {"principal_id": self.sender.principal_id, "class_id": self.sender.class_id},
            "recipient": {"principal_id": self.recipient.principal_id, "class_id": self.recipient.class_id},
            "repo_id": self.repo_id,
            "dispatch_id": self.dispatch_id,
            "workpackage_id": self.workpackage_id,
            "dispatch_priority": self.dispatch_priority.value,
            "created_at_utc": self.created_at_utc.isoformat(),
            "expires_at_utc": self.expires_at_utc.isoformat(),
            "authorization": {
                "grant_id": self.authorization.grant_id,
                "scope_digest": self.authorization.scope_digest,
                "principal_version": self.authorization.principal_version,
            },
            "raw_output": "not_returned",
        }


def validate_message(payload: Mapping[str, object]) -> HiveMessage:
    """Parse one strict wire payload into an immutable message."""

    if not isinstance(payload, Mapping):
        raise HiveMessageError("invalid_message")
    allowed = {
        "schema_version", "message_id", "correlation_id", "causation_id", "message_type", "sender", "recipient",
        "repo_id", "dispatch_id", "workpackage_id", "dispatch_priority", "created_at_utc", "expires_at_utc",
        "authorization", "payload", "raw_output",
    }
    if set(payload) - allowed or payload.get("raw_output") not in {None, "not_returned"}:
        raise HiveMessageError("invalid_message_fields")
    try:
        sender_raw = payload["sender"]
        recipient_raw = payload["recipient"]
        auth_raw = payload["authorization"]
        if not isinstance(sender_raw, Mapping) or set(sender_raw) != {"principal_id", "class_id"}:
            raise HiveMessageError("invalid_message_sender")
        if not isinstance(recipient_raw, Mapping) or set(recipient_raw) != {"principal_id", "class_id"}:
            raise HiveMessageError("invalid_message_recipient")
        if not isinstance(auth_raw, Mapping) or set(auth_raw) != {"grant_id", "scope_digest", "principal_version"}:
            raise HiveMessageError("invalid_authorization")
        created = _parse_time(payload["created_at_utc"], "message_timestamp")
        expires = _parse_time(payload["expires_at_utc"], "message_expiry")
        return HiveMessage(
            payload["schema_version"],
            payload["message_id"],
            payload["correlation_id"],
            payload.get("causation_id"),
            payload["message_type"],
            PrincipalReference(sender_raw["principal_id"], sender_raw["class_id"]),
            PrincipalReference(recipient_raw["principal_id"], recipient_raw["class_id"]),
            payload.get("repo_id"),
            payload.get("dispatch_id"),
            payload.get("workpackage_id"),
            DispatchPriority(payload["dispatch_priority"]),
            created,
            expires,
            AuthorizationEvidence(auth_raw["grant_id"], auth_raw["scope_digest"], auth_raw["principal_version"]),
            _mapping(payload.get("payload", {}), "payload"),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, HiveMessageError):
            raise
        raise HiveMessageError("invalid_message") from exc


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise HiveMessageError(f"invalid_{field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return validate_utc_datetime(parsed, field=field)
    except (HiveValidationError, TypeError, ValueError) as exc:
        raise HiveMessageError(f"invalid_{field}") from exc


def _report_status(message: HiveMessage) -> str:
    value = message.payload.get("status")
    if isinstance(value, str) and value in REPORT_STATUSES - {"unknown"}:
        return value
    if message.message_type == "escalation":
        return "blocked"
    if message.message_type == "decision.request":
        return "decision_required"
    if message.message_type in {"result.report", "completion"}:
        return "completed"
    if message.message_type == "progress.report":
        return "executing"
    return "unknown"


def record_child_report(message: HiveMessage) -> Mapping[str, object]:
    """Reduce one child report to bounded, payload-free parent metadata."""

    if not isinstance(message, HiveMessage) or message.message_type not in REPORT_MESSAGE_TYPES:
        raise HiveMessageError("invalid_child_report")
    encoded = json.dumps(dict(message.payload), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    status = _report_status(message)
    return {
        "message_id": message.message_id,
        "message_type": message.message_type,
        "report_kind": message.message_type.removesuffix(".report").replace(".", "_"),
        "correlation_id": message.correlation_id,
        "causation_id": message.causation_id,
        "sender_principal_id": message.sender.principal_id,
        "recipient_principal_id": message.recipient.principal_id,
        "repo_id": message.repo_id,
        "dispatch_id": message.dispatch_id,
        "workpackage_id": message.workpackage_id,
        "status": status,
        "blocked": status in {"blocked", "failed", "decision_required"} or message.message_type == "escalation",
        "payload_digest": "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "raw_output": "not_returned",
    }


__all__ = [
    "AuthorizationEvidence",
    "HiveMessage",
    "HiveMessageError",
    "MESSAGE_TYPES",
    "PrincipalReference",
    "REPORT_MESSAGE_TYPES",
    "REPORT_STATUSES",
    "record_child_report",
    "validate_message",
]
