"""Immutable, offline-only contracts for Hive Bus event envelopes.

This module deliberately has no broker, policy, store, transport, or runtime
dependency.  It accepts a producer request without broker-assigned fields and
returns the canonical immutable envelope a later broker can persist.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Final, NoReturn
import unicodedata


HIVE_BUS_SCHEMA_VERSION: Final = 1
_MAX_INT: Final = (2**63) - 1
MAX_ENVELOPE_BYTES: Final = 4 * 1024
MAX_INLINE_PAYLOAD_BYTES: Final = 2 * 1024
MAX_STANDARD_PAYLOAD_BYTES: Final = 256 * 1024
MAX_PAYLOAD_BYTES: Final = 1024 * 1024
# An artifact ref transports only metadata.  Its size is a non-negative signed
# 64-bit byte count for the external artifact, not a bus transport allocation.
MAX_ARTIFACT_SIZE_BYTES: Final = _MAX_INT
MAX_CAUSATION_IDS: Final = 16
MAX_CANONICAL_JSON_DEPTH: Final = 8
MAX_CANONICAL_JSON_ITEMS: Final = 128

_MAX_CANONICAL_STRING_BYTES: Final = 2 * 1024
_SEGMENT_RE: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z", re.ASCII)
_DIGEST_RE: Final = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_IDEMPOTENCY_KEY_RE: Final = re.compile(r"idempotency-v1-[0-9a-f]{32}\Z", re.ASCII)
_PRODUCER_PRINCIPAL_ID_RE: Final = re.compile(
    r"producer-principal-v1-[0-9a-f]{32}\Z", re.ASCII
)
_PRODUCER_SESSION_ID_RE: Final = re.compile(
    r"producer-session-v1-[0-9a-f]{32}\Z", re.ASCII
)
_CORRELATION_ID_RE: Final = re.compile(r"correlation-v1-[0-9a-f]{32}\Z", re.ASCII)
_AUTHORITY_GRANT_ID_RE: Final = re.compile(
    r"authority-grant-v1-[0-9a-f]{32}\Z", re.ASCII
)
_TIMESTAMP_RE: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z",
    re.ASCII,
)
_SENSITIVE_PAYLOAD_KEY_MARKER_RE: Final = re.compile(
    r"(?:^|[/:?&._-])key(?:[=:/?&._-]|$)", re.ASCII | re.IGNORECASE
)
_SENSITIVE_IDENTIFIER_MARKERS: Final = frozenset(
    {
        "apikey",
        "auth",
        "bearer",
        "credential",
        "password",
        "privatekey",
        "prompt",
        "rawprovider",
        "secret",
        "skproj",
        "stderr",
        "stdout",
        "terminal",
        "token",
    }
)
_SENSITIVE_PAYLOAD_REFERENCE_MARKERS: Final = frozenset(
    {
        "apikey",
        "auth",
        "bearer",
        "credential",
        "password",
        "privatekey",
        "secret",
        "skproj",
        "token",
    }
)
_CLASSIFICATIONS: Final = frozenset({"internal", "restricted", "security"})
_RETENTION_CLASSES: Final = frozenset({"transient", "work", "audit", "manifest"})
_PAYLOAD_KINDS: Final = frozenset({"inline", "blob", "artifact"})
_PUBLISH_FIELDS: Final = frozenset(
    {
        "schema_version",
        "event_type",
        "partition",
        "idempotency_key",
        "producer_principal_id",
        "producer_session_id",
        "producer_epoch",
        "producer_seq",
        "repo_id",
        "topic_id",
        "workpackage_id",
        "correlation_id",
        "causation_ids",
        "authority",
        "classification",
        "payload",
        "retention_class",
        "created_at_utc",
    }
)
_AUTHORITY_FIELDS: Final = frozenset({"grant_id", "scope_digest", "principal_version"})
_PAYLOAD_FIELDS: Final = frozenset({"kind", "digest", "ref", "size_bytes"})


class HiveBusContractError(ValueError):
    """Fail-closed BUS-S0 envelope violation with a stable bus error code."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> NoReturn:
    raise HiveBusContractError(code)


def _mapping(value: object, *, code: str = "BUS_E_SCHEMA") -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(code)
    return value


def _exact_keys(value: Mapping[str, object], expected: frozenset[str]) -> None:
    try:
        keys = set(value)
    except TypeError:
        _reject("BUS_E_SCHEMA")
    if keys != expected:
        _reject("BUS_E_SCHEMA")


def _int(value: object, *, low: int = 0, high: int = _MAX_INT) -> int:
    if type(value) is not int or not low <= value <= high:
        _reject("BUS_E_SCHEMA")
    return value


def _unicode(value: object, *, max_bytes: int = _MAX_CANONICAL_STRING_BYTES) -> str:
    if type(value) is not str:
        _reject("BUS_E_CANONICALIZATION")
    try:
        normalized = unicodedata.normalize("NFC", value)
        encoded = normalized.encode("utf-8")
    except (TypeError, UnicodeError):
        _reject("BUS_E_CANONICALIZATION")
    if not normalized or len(encoded) > max_bytes:
        _reject("BUS_E_CANONICALIZATION")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        _reject("BUS_E_CANONICALIZATION")
    return normalized


def _has_sensitive_identifier_marker(value: str) -> bool:
    compact = value.casefold().translate(str.maketrans("", "", ".:_-"))
    return any(marker in compact for marker in _SENSITIVE_IDENTIFIER_MARKERS)


def _has_sensitive_payload_reference_marker(value: str) -> bool:
    compact = value.casefold().translate(str.maketrans("", "", ".:_-"))
    return any(
        marker in compact for marker in _SENSITIVE_PAYLOAD_REFERENCE_MARKERS
    ) or bool(_SENSITIVE_PAYLOAD_KEY_MARKER_RE.search(value))


def _generated_identifier(value: object, pattern: re.Pattern[str]) -> str:
    """Validate one closed, generated 128-bit V1 header identifier namespace."""

    if type(value) is not str:
        _reject("BUS_E_SCHEMA")
    if pattern.fullmatch(value) is None:
        _reject("BUS_E_SCHEMA")
    return value


def _idempotency_key(value: object) -> str:
    return _generated_identifier(value, _IDEMPOTENCY_KEY_RE)


def _producer_principal_id(value: object) -> str:
    return _generated_identifier(value, _PRODUCER_PRINCIPAL_ID_RE)


def _producer_session_id(value: object) -> str:
    return _generated_identifier(value, _PRODUCER_SESSION_ID_RE)


def _correlation_id(value: object) -> str:
    return _generated_identifier(value, _CORRELATION_ID_RE)


def _authority_grant_id(value: object) -> str:
    return _generated_identifier(value, _AUTHORITY_GRANT_ID_RE)


def _segment(value: object, *, code: str = "BUS_E_SCHEMA") -> str:
    if type(value) is not str:
        _reject(code)
    if _has_sensitive_identifier_marker(value):
        _reject("BUS_E_SECRET_CLASSIFICATION")
    if _SEGMENT_RE.fullmatch(value) is None:
        _reject(code)
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        _reject("BUS_E_SCHEMA")
    return value


def _canonical_value(value: object, *, depth: int, count: list[int]) -> object:
    if depth > MAX_CANONICAL_JSON_DEPTH:
        _reject("BUS_E_CANONICALIZATION")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -_MAX_INT <= value <= _MAX_INT:
            _reject("BUS_E_CANONICALIZATION")
        return value
    if type(value) is str:
        return _unicode(value)
    if type(value) in {list, tuple}:
        count[0] += len(value)
        if count[0] > MAX_CANONICAL_JSON_ITEMS:
            _reject("BUS_E_CANONICALIZATION")
        return [_canonical_value(item, depth=depth + 1, count=count) for item in value]
    if isinstance(value, Mapping):
        count[0] += len(value)
        if count[0] > MAX_CANONICAL_JSON_ITEMS:
            _reject("BUS_E_CANONICALIZATION")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or not key or not key.isascii():
                _reject("BUS_E_CANONICALIZATION")
            normalized_key = _unicode(key)
            if normalized_key in normalized:
                _reject("BUS_E_CANONICALIZATION")
            normalized[normalized_key] = _canonical_value(
                item, depth=depth + 1, count=count
            )
        return dict(sorted(normalized.items()))
    _reject("BUS_E_CANONICALIZATION")


def canonical_json_bytes(value: object) -> bytes:
    """Return strict UTF-8/NFC canonical JSON for safe, bounded JSON data."""

    normalized = _canonical_value(value, depth=0, count=[0])
    try:
        return json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        _reject("BUS_E_CANONICALIZATION")


def validate_topic_partition(value: object) -> str:
    """Validate one concrete, safe event partition and return it unchanged."""

    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or len(value.encode()) > 512
    ):
        _reject("BUS_E_TOPIC_INVALID")
    parts = value.split("/")
    for part in parts:
        _segment(part, code="BUS_E_TOPIC_INVALID")

    if len(parts) == 2 and parts in (["fleet", "control"], ["security", "global"]):
        return value
    if len(parts) == 2 and parts[0] in {"repo", "policy", "incident"}:
        return value
    if len(parts) == 3 and (
        (parts[0] == "archive" and parts[1] == "repo")
        or (parts[0] == "fleet" and parts[1] == "resource")
        or (parts[0] == "provider" and parts[2] == "status")
        or (parts[0] == "account" and parts[2] == "usage")
        or (parts[0] == "security" and parts[1] == "repo")
        or (parts[0] == "user" and parts[1] == "notification")
    ):
        return value
    if (
        len(parts) == 4
        and parts[0] == "repo"
        and parts[2]
        in {
            "topic",
            "task",
            "artifact",
        }
    ):
        return value
    if (
        len(parts) == 5
        and parts[0:2] == ["coordination", "repo"]
        and parts[3] == "to"
        and parts[2] != parts[4]
    ):
        return value
    _reject("BUS_E_TOPIC_INVALID")


def partition_kind(value: object) -> str:
    """Return the closed partition family for one validated partition."""

    partition = validate_topic_partition(value)
    parts = partition.split("/")
    if parts[0] == "repo":
        if len(parts) == 2:
            return "repo"
        return parts[2]
    if parts[0] == "archive":
        return "archive"
    if parts[0] == "fleet":
        return "fleet_control" if parts[1] == "control" else "fleet_resource"
    if parts[0] == "provider":
        return "provider_status"
    if parts[0] == "account":
        return "account_usage"
    if parts[0] == "policy":
        return "policy"
    if parts[0] == "security":
        return "security_global" if len(parts) == 2 else "security_repo"
    if parts[0] == "incident":
        return "incident"
    if parts[0] == "coordination":
        return "coordination"
    return "notification"


def _partition_repo_id(partition: str) -> str | None:
    parts = partition.split("/")
    if parts[0] == "repo":
        return parts[1]
    if parts[0] == "archive":
        return parts[2]
    if parts[0] == "security" and len(parts) == 3:
        return parts[2]
    if parts[0] == "coordination":
        return parts[2]
    return None


def _subscription_prefix_matches_repo(prefix: str, repo_id: str | None) -> bool:
    """Return whether a generated manifest may subscribe within its repository.

    A coordination prefix has both a source and target repository.  A Queen
    may publish from its own source repository, but subscriptions are limited
    to headers addressed to its repository.  The explicitly closed policy,
    provider-status, and fleet header families are global metadata; they do
    not derive or widen repository scope.
    """

    kind = partition_kind(prefix)
    if kind in {"policy", "provider_status", "fleet_control", "fleet_resource"}:
        return True
    if kind != "coordination":
        return _partition_repo_id(prefix) == repo_id
    source_repo_id, target_repo_id = prefix.split("/")[2::2]
    return repo_id == target_repo_id


def _validate_partition_scope(
    partition: str,
    *,
    repo_id: str | None,
    topic_id: str | None,
    workpackage_id: str | None,
) -> None:
    """Require envelope scope metadata to be exactly derivable from its partition."""

    parts = partition.split("/")
    kind = partition_kind(partition)
    expected_repo_id: str | None = None
    expected_topic_id: str | None = None
    expected_workpackage_id: str | None = None
    if kind in {"repo", "topic", "task", "artifact"}:
        expected_repo_id = parts[1]
    elif kind == "archive":
        expected_repo_id = parts[2]
    elif kind == "security_repo":
        expected_repo_id = parts[2]
    elif kind == "coordination":
        expected_repo_id = parts[2]

    if kind == "topic":
        expected_topic_id = parts[3]
    elif kind == "task":
        expected_workpackage_id = parts[3]

    if (repo_id, topic_id, workpackage_id) != (
        expected_repo_id,
        expected_topic_id,
        expected_workpackage_id,
    ):
        _reject("BUS_E_REPO_SCOPE")


@dataclass(frozen=True, slots=True)
class EventTypeSpecV1:
    """Static BUS-S0 shape; payload limits apply to inline/blob transport only."""

    event_type: str
    producer_partition_pairs: frozenset[tuple[str, str]]
    payload_kinds: frozenset[str]
    retention_class: str
    urgent: bool
    max_payload_bytes: int = MAX_STANDARD_PAYLOAD_BYTES

    @property
    def producer_classes(self) -> frozenset[str]:
        """Return the declared producer classes without widening their pairs."""

        return frozenset(
            producer_class for producer_class, _ in self.producer_partition_pairs
        )

    @property
    def partition_kinds(self) -> frozenset[str]:
        """Return the declared families without widening their producer pairs."""

        return frozenset(partition for _, partition in self.producer_partition_pairs)


def _event_spec(
    event_type: str,
    producer_partition_pairs: frozenset[tuple[str, str]],
    payload_kinds: frozenset[str],
    retention_class: str,
    *,
    urgent: bool = False,
) -> EventTypeSpecV1:
    return EventTypeSpecV1(
        event_type=event_type,
        producer_partition_pairs=producer_partition_pairs,
        payload_kinds=payload_kinds,
        retention_class=retention_class,
        urgent=urgent,
    )


_INLINE: Final = frozenset({"inline"})
_RESULT_PAYLOAD: Final = frozenset({"inline", "blob", "artifact"})
_BROKER_DIGEST_PARTITIONS: Final = (
    "repo",
    "topic",
    "task",
    "artifact",
    "archive",
    "fleet_control",
    "fleet_resource",
    "provider_status",
    "account_usage",
    "policy",
    "security_repo",
    "security_global",
    "incident",
    "notification",
)


def _producer_partitions(
    producer_class: str, *partition_kinds: str
) -> frozenset[tuple[str, str]]:
    return frozenset(
        (producer_class, partition_kind) for partition_kind in partition_kinds
    )


def _pairs(*values: frozenset[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    return frozenset().union(*values)


EVENT_TYPE_MATRIX: Final[Mapping[str, EventTypeSpecV1]] = MappingProxyType(
    {
        "archive.evidence_missing": _event_spec(
            "archive.evidence_missing",
            _producer_partitions("archivist", "archive"),
            _INLINE,
            "audit",
        ),
        "artifact.accepted": _event_spec(
            "artifact.accepted",
            _pairs(
                _producer_partitions("queen", "artifact"),
                _producer_partitions("topic_queen", "artifact"),
            ),
            frozenset({"artifact"}),
            "audit",
            urgent=True,
        ),
        "artifact.archived": _event_spec(
            "artifact.archived",
            _producer_partitions("archivist", "artifact", "archive"),
            frozenset({"artifact"}),
            "audit",
        ),
        "artifact.ready": _event_spec(
            "artifact.ready",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            frozenset({"artifact"}),
            "work",
        ),
        "assignment.cancelled": _event_spec(
            "assignment.cancelled",
            _pairs(
                _producer_partitions("teamlead", "task"),
                _producer_partitions("queen", "task"),
                _producer_partitions("topic_queen", "task"),
            ),
            _INLINE,
            "work",
            urgent=True,
        ),
        "assignment.created": _event_spec(
            "assignment.created",
            _pairs(
                _producer_partitions("teamlead", "task"),
                _producer_partitions("queen", "task"),
                _producer_partitions("topic_queen", "task"),
            ),
            _INLINE,
            "work",
        ),
        "assignment.started": _event_spec(
            "assignment.started",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
                _producer_partitions("teamlead", "task"),
            ),
            _INLINE,
            "work",
        ),
        "authority.revoked": _event_spec(
            "authority.revoked",
            _pairs(
                _producer_partitions(
                    "queen", "repo", "topic", "task", "artifact", "security_repo"
                ),
                _producer_partitions(
                    "godbee", "security_global", "fleet_control", "policy"
                ),
                _producer_partitions(
                    "broker",
                    "security_repo",
                    "security_global",
                    "fleet_control",
                    "policy",
                ),
            ),
            _INLINE,
            "audit",
            urgent=True,
        ),
        "blocker.detected": _event_spec(
            "blocker.detected",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _INLINE,
            "work",
        ),
        "blocker.encountered": _event_spec(
            "blocker.encountered",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
                _producer_partitions("teamlead", "repo", "topic", "task"),
                _producer_partitions("queen", "repo", "topic", "task", "coordination"),
                _producer_partitions("topic_queen", "topic", "task"),
            ),
            _INLINE,
            "work",
        ),
        "bus.gemini_cooldown_notice_pending": _event_spec(
            "bus.gemini_cooldown_notice_pending",
            _pairs(
                _producer_partitions("broker", "fleet_control"),
                _producer_partitions("teamlead", "task"),
            ),
            _INLINE,
            "work",
        ),
        "coordination.attention_requested": _event_spec(
            "coordination.attention_requested",
            _producer_partitions("teamlead", "repo"),
            _INLINE,
            "work",
        ),
        "decision.changed": _event_spec(
            "decision.changed",
            _pairs(
                _producer_partitions("teamlead", "repo", "topic", "task"),
                _producer_partitions("queen", "repo", "topic", "task", "coordination"),
                _producer_partitions("topic_queen", "topic", "task"),
                _producer_partitions("godbee", "policy"),
            ),
            _INLINE,
            "audit",
        ),
        "dependency.requested": _event_spec(
            "dependency.requested",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _INLINE,
            "work",
        ),
        "dependency.satisfied": _event_spec(
            "dependency.satisfied",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _INLINE,
            "work",
        ),
        "digest.tick": _event_spec(
            "digest.tick",
            _producer_partitions("broker", *_BROKER_DIGEST_PARTITIONS),
            _INLINE,
            "transient",
        ),
        "gemini.cooldown.committed.v1": _event_spec(
            "gemini.cooldown.committed.v1",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
                _producer_partitions("teamlead", "task"),
            ),
            _INLINE,
            "work",
        ),
        "handoff.available": _event_spec(
            "handoff.available",
            _pairs(
                _producer_partitions("teamlead", "repo", "topic", "task"),
                _producer_partitions("queen", "repo", "topic", "task", "coordination"),
                _producer_partitions("topic_queen", "topic", "task"),
                _producer_partitions("godbee", "repo"),
            ),
            _INLINE,
            "work",
        ),
        "interface.changed": _event_spec(
            "interface.changed",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
                _producer_partitions("teamlead", "repo", "topic", "task"),
                _producer_partitions("queen", "repo", "topic", "task", "coordination"),
                _producer_partitions("topic_queen", "topic", "task"),
            ),
            _INLINE,
            "work",
        ),
        "policy.invalidated": _event_spec(
            "policy.invalidated",
            _pairs(
                _producer_partitions("godbee", "policy"),
                _producer_partitions("broker", "policy", "fleet_control"),
            ),
            _INLINE,
            "audit",
            urgent=True,
        ),
        "provider.hard_stopped": _event_spec(
            "provider.hard_stopped",
            _producer_partitions("broker", "provider_status"),
            _INLINE,
            "transient",
            urgent=True,
        ),
        "resource.emergency": _event_spec(
            "resource.emergency",
            _producer_partitions("broker", "fleet_resource"),
            _INLINE,
            "transient",
            urgent=True,
        ),
        "result.proposed": _event_spec(
            "result.proposed",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _RESULT_PAYLOAD,
            "work",
        ),
        "result.report": _event_spec(
            "result.report",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
                _producer_partitions("teamlead", "task"),
            ),
            _RESULT_PAYLOAD,
            "work",
        ),
        "review.completed": _event_spec(
            "review.completed",
            _pairs(
                _producer_partitions("teamlead", "task"),
                _producer_partitions("queen", "task"),
                _producer_partitions("topic_queen", "task"),
            ),
            _RESULT_PAYLOAD,
            "work",
        ),
        "scope.affected": _event_spec(
            "scope.affected",
            _pairs(
                _producer_partitions("teamlead", "repo", "topic", "task"),
                _producer_partitions("queen", "repo", "topic", "task", "coordination"),
                _producer_partitions("topic_queen", "topic", "task"),
                _producer_partitions("godbee", "repo", "policy"),
            ),
            _INLINE,
            "audit",
        ),
        "security.critical": _event_spec(
            "security.critical",
            _pairs(
                _producer_partitions("queen", "security_repo"),
                _producer_partitions("godbee", "security_global"),
                _producer_partitions("broker", "security_repo", "security_global"),
            ),
            _INLINE,
            "audit",
            urgent=True,
        ),
        "session.sleep_requested": _event_spec(
            "session.sleep_requested",
            _pairs(
                _producer_partitions("teamlead", "topic", "task"),
                _producer_partitions("queen", "topic", "task"),
                _producer_partitions("topic_queen", "topic", "task"),
            ),
            _INLINE,
            "work",
            urgent=True,
        ),
        "skill.requested": _event_spec(
            "skill.requested",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _INLINE,
            "work",
        ),
        "spawn.requested": _event_spec(
            "spawn.requested",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _INLINE,
            "work",
        ),
        "test.result": _event_spec(
            "test.result",
            _pairs(
                _producer_partitions("worker", "task"),
                _producer_partitions("specialist", "task"),
            ),
            _RESULT_PAYLOAD,
            "work",
        ),
        "user.decision_recorded": _event_spec(
            "user.decision_recorded",
            _producer_partitions("godbee", "policy", "repo"),
            _INLINE,
            "audit",
            urgent=True,
        ),
        "user.notification.requested": _event_spec(
            "user.notification.requested",
            _pairs(
                _producer_partitions("queen", "notification"),
                _producer_partitions("godbee", "notification"),
                _producer_partitions("broker", "notification"),
            ),
            _INLINE,
            "transient",
            urgent=True,
        ),
    }
)


def event_type_spec(event_type: object) -> EventTypeSpecV1:
    """Return the declared static shape for one versioned, known event type."""

    if type(event_type) is not str or event_type not in EVENT_TYPE_MATRIX:
        _reject("BUS_E_SCHEMA")
    return EVENT_TYPE_MATRIX[event_type]


def validate_event_type_producer_partition(
    event_type: object,
    producer_class: object,
    partition: object,
) -> str:
    """Validate one static producer-class/partition-family contract pair.

    This is intentionally separate from envelope creation: BUS-S0 carries an
    opaque principal ID, while BUS-S2 binds it to the active producer class.
    The static matrix nevertheless has no cartesian-product widening.
    """

    spec = event_type_spec(event_type)
    if type(producer_class) is not str:
        _reject("BUS_E_ACL_DENIED")
    partition_kind_value = partition_kind(partition)
    if (producer_class, partition_kind_value) not in spec.producer_partition_pairs:
        _reject("BUS_E_ACL_DENIED")
    return partition_kind_value


@dataclass(frozen=True, slots=True)
class _AuthorityV1:
    grant_id: str
    scope_digest: str
    principal_version: int


@dataclass(frozen=True, slots=True)
class _PayloadRefV1:
    kind: str
    digest: str
    ref: str
    size_bytes: int


@dataclass(frozen=True, slots=True, init=False)
class HiveBusEventV1:
    """A fully canonical event whose ID is derived, never caller supplied."""

    schema_version: int
    event_type: str
    partition: str
    partition_seq: int
    event_id: str
    idempotency_key: str
    producer_principal_id: str
    producer_session_id: str
    producer_epoch: int
    producer_seq: int
    repo_id: str | None
    topic_id: str | None
    workpackage_id: str | None
    correlation_id: str
    causation_ids: tuple[str, ...]
    authority: _AuthorityV1
    classification: str
    payload: _PayloadRefV1
    retention_class: str
    created_at_utc: str
    accepted_at_utc: str
    raw_output: str

    def __init__(self) -> None:
        raise TypeError("use create_hive_bus_event_v1")


def _timestamp(value: object) -> str:
    if type(value) is not str:
        _reject("BUS_E_CANONICALIZATION")
    normalized = _unicode(value)
    if _TIMESTAMP_RE.fullmatch(normalized) is None:
        _reject("BUS_E_CANONICALIZATION")
    try:
        moment = datetime.fromisoformat(normalized[:-1] + "+00:00")
    except ValueError:
        _reject("BUS_E_CANONICALIZATION")
    utc = moment.astimezone(timezone.utc)
    result = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        result += "." + f"{utc.microsecond:06d}".rstrip("0")
    return result + "Z"


def _optional_segment(value: object) -> str | None:
    if value is None:
        return None
    return _segment(value)


def _causation_ids(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_CAUSATION_IDS:
        _reject("BUS_E_SCHEMA")
    ids = tuple(_digest(item) for item in value)
    if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
        _reject("BUS_E_SCHEMA")
    return ids


def _authority(value: object) -> _AuthorityV1:
    source = _mapping(value)
    _exact_keys(source, _AUTHORITY_FIELDS)
    return _AuthorityV1(
        grant_id=_authority_grant_id(source["grant_id"]),
        scope_digest=_digest(source["scope_digest"]),
        principal_version=_int(source["principal_version"], low=1),
    )


def _payload_reference(kind: str, value: object, payload_digest: str) -> str:
    """Validate the closed, digest-bound reference form for one payload kind."""

    if type(value) is not str:
        _reject("BUS_E_SCHEMA")
    if kind in {"inline", "blob"}:
        if _has_sensitive_payload_reference_marker(value):
            _reject("BUS_E_SECRET_CLASSIFICATION")
        reference = f"{kind}:{payload_digest}"
        if value != reference:
            _reject("BUS_E_SCHEMA")
        return reference
    if kind == "artifact":
        prefix = "artifact:"
        if not value.startswith(prefix):
            _reject("BUS_E_SCHEMA")
        artifact_id, separator, reference_digest = value[len(prefix) :].partition("@")
        if (
            separator != "@"
            or _segment(artifact_id) != artifact_id
            or reference_digest != payload_digest
        ):
            _reject("BUS_E_SCHEMA")
        return f"artifact:{artifact_id}@{payload_digest}"
    _reject("BUS_E_SCHEMA")


def _payload(value: object, spec: EventTypeSpecV1) -> _PayloadRefV1:
    source = _mapping(value)
    _exact_keys(source, _PAYLOAD_FIELDS)
    kind = source["kind"]
    if (
        type(kind) is not str
        or kind not in _PAYLOAD_KINDS
        or kind not in spec.payload_kinds
    ):
        _reject("BUS_E_SCHEMA")
    size_bytes = source["size_bytes"]
    if type(size_bytes) is not int or size_bytes < 0:
        _reject("BUS_E_SCHEMA")
    if kind == "artifact":
        if size_bytes > MAX_ARTIFACT_SIZE_BYTES:
            _reject("BUS_E_EVENT_TOO_LARGE")
    elif size_bytes > MAX_PAYLOAD_BYTES or size_bytes > spec.max_payload_bytes:
        _reject("BUS_E_EVENT_TOO_LARGE")
    if kind == "inline" and size_bytes > MAX_INLINE_PAYLOAD_BYTES:
        _reject("BUS_E_EVENT_TOO_LARGE")
    digest = _digest(source["digest"])
    return _PayloadRefV1(
        kind=kind,
        digest=digest,
        ref=_payload_reference(kind, source["ref"], digest),
        size_bytes=size_bytes,
    )


def _event_wire(
    event: HiveBusEventV1, *, include_broker_fields: bool
) -> dict[str, object]:
    wire: dict[str, object] = {
        "schema_version": event.schema_version,
        "event_type": event.event_type,
        "partition": event.partition,
        "idempotency_key": event.idempotency_key,
        "producer_principal_id": event.producer_principal_id,
        "producer_session_id": event.producer_session_id,
        "producer_epoch": event.producer_epoch,
        "producer_seq": event.producer_seq,
        "repo_id": event.repo_id,
        "topic_id": event.topic_id,
        "workpackage_id": event.workpackage_id,
        "correlation_id": event.correlation_id,
        "causation_ids": list(event.causation_ids),
        "authority": {
            "grant_id": event.authority.grant_id,
            "scope_digest": event.authority.scope_digest,
            "principal_version": event.authority.principal_version,
        },
        "classification": event.classification,
        "payload": {
            "kind": event.payload.kind,
            "digest": event.payload.digest,
            "ref": event.payload.ref,
            "size_bytes": event.payload.size_bytes,
        },
        "retention_class": event.retention_class,
        "created_at_utc": event.created_at_utc,
        "raw_output": event.raw_output,
    }
    if include_broker_fields:
        wire.update(
            {
                "partition_seq": event.partition_seq,
                "event_id": event.event_id,
                "accepted_at_utc": event.accepted_at_utc,
            }
        )
    return wire


def _event_id(event: HiveBusEventV1) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(_event_wire(event, include_broker_fields=False))
        ).hexdigest()
    )


def _validate_pre_broker_envelope_size(event: HiveBusEventV1) -> None:
    if (
        len(canonical_json_bytes(_event_wire(event, include_broker_fields=False)))
        > MAX_ENVELOPE_BYTES
    ):
        _reject("BUS_E_EVENT_TOO_LARGE")


def _parse_publish_request(
    request: object,
) -> tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int,
    int,
    str | None,
    str | None,
    str | None,
    str,
    tuple[str, ...],
    _AuthorityV1,
    str,
    _PayloadRefV1,
    str,
    str,
]:
    source = _mapping(request)
    _exact_keys(source, _PUBLISH_FIELDS)
    if (
        _int(
            source["schema_version"],
            low=HIVE_BUS_SCHEMA_VERSION,
            high=HIVE_BUS_SCHEMA_VERSION,
        )
        != HIVE_BUS_SCHEMA_VERSION
    ):
        _reject("BUS_E_SCHEMA")
    spec = event_type_spec(source["event_type"])
    partition = validate_topic_partition(source["partition"])
    if partition_kind(partition) not in spec.partition_kinds:
        _reject("BUS_E_SCHEMA")
    repo_id = _optional_segment(source["repo_id"])
    topic_id = _optional_segment(source["topic_id"])
    workpackage_id = _optional_segment(source["workpackage_id"])
    _validate_partition_scope(
        partition,
        repo_id=repo_id,
        topic_id=topic_id,
        workpackage_id=workpackage_id,
    )
    classification = source["classification"]
    if type(classification) is not str:
        _reject("BUS_E_SCHEMA")
    if classification == "secret":
        _reject("BUS_E_SECRET_CLASSIFICATION")
    if classification not in _CLASSIFICATIONS:
        _reject("BUS_E_SCHEMA")
    retention_class = source["retention_class"]
    if type(retention_class) is not str or retention_class not in _RETENTION_CLASSES:
        _reject("BUS_E_SCHEMA")
    if retention_class != spec.retention_class:
        _reject("BUS_E_SCHEMA")
    return (
        HIVE_BUS_SCHEMA_VERSION,
        spec.event_type,
        partition,
        _idempotency_key(source["idempotency_key"]),
        _producer_principal_id(source["producer_principal_id"]),
        _producer_session_id(source["producer_session_id"]),
        _int(source["producer_epoch"], low=1),
        _int(source["producer_seq"], low=1),
        repo_id,
        topic_id,
        workpackage_id,
        _correlation_id(source["correlation_id"]),
        _causation_ids(source["causation_ids"]),
        _authority(source["authority"]),
        classification,
        _payload(source["payload"], spec),
        retention_class,
        _timestamp(source["created_at_utc"]),
    )


def _event_from_request(request: object) -> HiveBusEventV1:
    parsed = _parse_publish_request(request)
    event = object.__new__(HiveBusEventV1)
    fields = (
        "schema_version",
        "event_type",
        "partition",
        "idempotency_key",
        "producer_principal_id",
        "producer_session_id",
        "producer_epoch",
        "producer_seq",
        "repo_id",
        "topic_id",
        "workpackage_id",
        "correlation_id",
        "causation_ids",
        "authority",
        "classification",
        "payload",
        "retention_class",
        "created_at_utc",
    )
    for name, value in zip(fields, parsed, strict=True):
        object.__setattr__(event, name, value)
    object.__setattr__(event, "partition_seq", 0)
    object.__setattr__(event, "accepted_at_utc", "1970-01-01T00:00:00Z")
    object.__setattr__(event, "raw_output", "not_returned")
    _validate_pre_broker_envelope_size(event)
    object.__setattr__(event, "event_id", _event_id(event))
    return event


def event_id_for_publish_request(request: object) -> str:
    """Derive the stable ID for one valid producer request without broker fields."""

    return _event_from_request(request).event_id


def create_hive_bus_event_v1(
    request: object,
    *,
    partition_seq: object,
    accepted_at_utc: object,
) -> HiveBusEventV1:
    """Bind broker-assigned fields and return a bounded immutable V1 envelope."""

    event = _event_from_request(request)
    object.__setattr__(event, "partition_seq", _int(partition_seq, low=1))
    object.__setattr__(event, "accepted_at_utc", _timestamp(accepted_at_utc))
    encoded = canonical_json_bytes(_event_wire(event, include_broker_fields=True))
    if len(encoded) > MAX_ENVELOPE_BYTES:
        _reject("BUS_E_EVENT_TOO_LARGE")
    return event


def serialize_hive_bus_event_v1(event: object) -> dict[str, object]:
    """Return a detached canonical wire value for one immutable V1 event."""

    if type(event) is not HiveBusEventV1:
        _reject("BUS_E_SCHEMA")
    return _event_wire(event, include_broker_fields=True)


@dataclass(frozen=True, slots=True)
class BusSubscriptionSetV1:
    """Immutable generated manifest; BUS-S2 binds its class and authority."""

    principal_id: str
    repo_id: str | None
    topic_prefixes: tuple[str, ...]
    event_types: tuple[str, ...]
    schema_version: int = HIVE_BUS_SCHEMA_VERSION
    generation: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            _int(
                self.schema_version,
                low=HIVE_BUS_SCHEMA_VERSION,
                high=HIVE_BUS_SCHEMA_VERSION,
            )
            != HIVE_BUS_SCHEMA_VERSION
        ):
            _reject("BUS_E_SCHEMA")
        object.__setattr__(
            self, "principal_id", _producer_principal_id(self.principal_id)
        )
        if self.repo_id is not None:
            object.__setattr__(self, "repo_id", _segment(self.repo_id))
        if (
            type(self.topic_prefixes) is not tuple
            or not self.topic_prefixes
            or len(self.topic_prefixes) > 64
        ):
            _reject("BUS_E_SCHEMA")
        prefixes = tuple(
            validate_topic_partition(prefix) for prefix in self.topic_prefixes
        )
        if prefixes != tuple(sorted(prefixes)) or len(prefixes) != len(set(prefixes)):
            _reject("BUS_E_SCHEMA")
        for prefix in prefixes:
            if not _subscription_prefix_matches_repo(prefix, self.repo_id):
                _reject("BUS_E_REPO_SCOPE")
        if (
            type(self.event_types) is not tuple
            or not self.event_types
            or len(self.event_types) > 64
        ):
            _reject("BUS_E_SCHEMA")
        event_types = tuple(
            event_type_spec(event_type).event_type for event_type in self.event_types
        )
        if event_types != tuple(sorted(event_types)) or len(event_types) != len(
            set(event_types)
        ):
            _reject("BUS_E_SCHEMA")
        object.__setattr__(self, "topic_prefixes", prefixes)
        object.__setattr__(self, "event_types", event_types)
        manifest = {
            "schema_version": self.schema_version,
            "principal_id": self.principal_id,
            "repo_id": self.repo_id,
            "topic_prefixes": list(prefixes),
            "event_types": list(event_types),
        }
        object.__setattr__(
            self,
            "generation",
            "sha256:" + hashlib.sha256(canonical_json_bytes(manifest)).hexdigest(),
        )


def serialize_bus_subscription_set_v1(subscription: object) -> dict[str, object]:
    """Return a detached canonical wire value for a generated subscription set."""

    if type(subscription) is not BusSubscriptionSetV1:
        _reject("BUS_E_SCHEMA")
    return {
        "schema_version": subscription.schema_version,
        "principal_id": subscription.principal_id,
        "repo_id": subscription.repo_id,
        "topic_prefixes": list(subscription.topic_prefixes),
        "event_types": list(subscription.event_types),
        "generation": subscription.generation,
    }


__all__ = [
    "BusSubscriptionSetV1",
    "EVENT_TYPE_MATRIX",
    "EventTypeSpecV1",
    "HIVE_BUS_SCHEMA_VERSION",
    "HiveBusContractError",
    "HiveBusEventV1",
    "MAX_CAUSATION_IDS",
    "MAX_ARTIFACT_SIZE_BYTES",
    "MAX_ENVELOPE_BYTES",
    "MAX_INLINE_PAYLOAD_BYTES",
    "MAX_PAYLOAD_BYTES",
    "MAX_STANDARD_PAYLOAD_BYTES",
    "canonical_json_bytes",
    "create_hive_bus_event_v1",
    "event_id_for_publish_request",
    "event_type_spec",
    "partition_kind",
    "serialize_bus_subscription_set_v1",
    "serialize_hive_bus_event_v1",
    "validate_event_type_producer_partition",
    "validate_topic_partition",
]

