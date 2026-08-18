"""In-memory ResumeCapsuleV1 state machine for Spark capacity retries.

Public API:
- ResumeCapsuleV1: immutable capsule state container.
- normalize_resume_capsule: parse and validate untrusted input into V1 capsule.
- serialize_resume_capsule: return compact, non-sensitive V1 payload.
- apply_resume_event: deterministic capsule transition for one event.
- is_capacity_retry_code: canonical capacity-code check.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Final, Mapping

_SCHEMA_VERSION: Final = 1
_CAPACITY_RETRY_LIMIT: Final = 50
_ACTIVE_WINDOW_MS: Final = 300_000
_ACCOUNT_BINDING_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_SPARK_REQUIREMENT_TOKEN: Final = "explicit_spark"
_CAPACITY_RETRY_CODES: Final[frozenset[str]] = frozenset(
    {"at_capacity", "server_overloaded"}
)
_ACTIVE_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {"provider", "tool", "progress"}
)
_ZERO_DURATION_EVENTS: Final[frozenset[str]] = frozenset(
    {"wait", "backoff", "poll", "liveness"}
)
_KNOWN_EVENT_TYPES: Final[frozenset[str]] = _ACTIVE_EVENT_TYPES | _ZERO_DURATION_EVENTS | frozenset(
    {"capacity"}
)
_CAPSULE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "retry_count",
        "event_sequence",
        "active_window_ms",
        "bee_id",
        "session_id",
        "spark_requirement",
        "model",
        "provider",
        "effort",
        "account_binding",
    }
)
_BINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "bee_id",
        "session_id",
        "spark_requirement",
        "model",
        "provider",
        "effort",
        "account_binding",
    }
)


def is_capacity_retry_code(code: str) -> bool:
    """Return True only for canonical capacity retry trigger codes."""

    return code in _CAPACITY_RETRY_CODES


@dataclass(frozen=True, slots=True)
class ResumeCapsuleV1:
    """Minimal immutable state for capacity-retry resume accounting."""

    bee_id: str
    session_id: str
    spark_requirement: str
    model: str
    provider: str
    effort: str
    account_binding: str
    retry_count: int = 0
    event_sequence: int = 0
    active_window_ms: int = 0


def _require_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid {key}")
    return value


def _require_int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if type(value) is not int:
        raise ValueError(f"missing or invalid {key}")
    return value


def _require_non_negative_int(raw: Mapping[str, Any], key: str) -> int:
    value = _require_int(raw, key)
    if value < 0:
        raise ValueError(f"negative {key}")
    return value


def _require_account_binding(raw: Mapping[str, Any], key: str) -> str:
    value = _require_str(raw, key)
    if _ACCOUNT_BINDING_RE.fullmatch(value) is None:
        raise ValueError(f"invalid {key}")
    return value


def _require_explicit_spark_requirement(raw: Mapping[str, Any], key: str) -> str:
    value = _require_str(raw, key)
    if value != _SPARK_REQUIREMENT_TOKEN:
        raise ValueError(f"invalid {key}")
    return value


def _require_exact_keys(raw: Mapping[str, Any], allowed: frozenset[str]) -> None:
    if set(raw.keys()) != allowed:
        raise ValueError("unexpected fields present")


def _require_binding(raw: Mapping[str, Any]) -> Mapping[str, str]:
    if not isinstance(raw, Mapping):
        raise ValueError("binding must be mapping")
    _require_exact_keys(raw, _BINDING_KEYS)
    return {
        "bee_id": _require_str(raw, "bee_id"),
        "session_id": _require_str(raw, "session_id"),
        "spark_requirement": _require_explicit_spark_requirement(raw, "spark_requirement"),
        "model": _require_str(raw, "model"),
        "provider": _require_str(raw, "provider"),
        "effort": _require_str(raw, "effort"),
        "account_binding": _require_account_binding(raw, "account_binding"),
    }


def normalize_resume_capsule(raw: Mapping[str, Any]) -> ResumeCapsuleV1:
    """Normalize untrusted data into strict ResumeCapsuleV1 state."""

    if not isinstance(raw, Mapping):
        raise TypeError("capsule must be mapping")
    _require_exact_keys(raw, _CAPSULE_KEYS)

    if _require_int(raw, "schema_version") != _SCHEMA_VERSION:
        raise ValueError("unsupported schema_version")

    retry_count = _require_non_negative_int(raw, "retry_count")
    if retry_count > _CAPACITY_RETRY_LIMIT:
        raise ValueError("retry_count out of range")

    event_sequence = _require_non_negative_int(raw, "event_sequence")
    active_window_ms = _require_non_negative_int(raw, "active_window_ms")
    if active_window_ms >= _ACTIVE_WINDOW_MS:
        raise ValueError("active_window_ms out of range")

    return ResumeCapsuleV1(
        bee_id=_require_str(raw, "bee_id"),
        session_id=_require_str(raw, "session_id"),
        spark_requirement=_require_explicit_spark_requirement(raw, "spark_requirement"),
        model=_require_str(raw, "model"),
        provider=_require_str(raw, "provider"),
        effort=_require_str(raw, "effort"),
        account_binding=_require_account_binding(raw, "account_binding"),
        retry_count=retry_count,
        event_sequence=event_sequence,
        active_window_ms=active_window_ms,
    )


def _validate_capsule(capsule: ResumeCapsuleV1) -> None:
    validate = {
        "schema_version": _SCHEMA_VERSION,
        "retry_count": capsule.retry_count,
        "event_sequence": capsule.event_sequence,
        "active_window_ms": capsule.active_window_ms,
        "bee_id": capsule.bee_id,
        "session_id": capsule.session_id,
        "spark_requirement": capsule.spark_requirement,
        "model": capsule.model,
        "provider": capsule.provider,
        "effort": capsule.effort,
        "account_binding": capsule.account_binding,
    }
    normalize_resume_capsule(validate)


def serialize_resume_capsule(capsule: ResumeCapsuleV1 | Mapping[str, Any]) -> dict[str, Any]:
    """Serialize V1 capsule as data-minimal, non-sensitive dict."""

    if isinstance(capsule, Mapping):
        capsule = normalize_resume_capsule(capsule)
    elif isinstance(capsule, ResumeCapsuleV1):
        _validate_capsule(capsule)
    else:
        raise TypeError("capsule must be ResumeCapsuleV1 or mapping")

    return {
        "schema_version": _SCHEMA_VERSION,
        "bee_id": capsule.bee_id,
        "session_id": capsule.session_id,
        "spark_requirement": capsule.spark_requirement,
        "model": capsule.model,
        "provider": capsule.provider,
        "effort": capsule.effort,
        "account_binding": capsule.account_binding,
        "retry_count": capsule.retry_count,
        "event_sequence": capsule.event_sequence,
        "active_window_ms": capsule.active_window_ms,
    }


@dataclass(frozen=True, slots=True)
class _ResumeEvent:
    event_sequence: int
    event_type: str
    active_duration_ms: int
    error_code: str | None


def _normalize_event(payload: Mapping[str, Any]) -> _ResumeEvent:
    if not isinstance(payload, Mapping):
        raise TypeError("event must be mapping")

    event_type = _require_str(payload, "event_type")
    if event_type not in _KNOWN_EVENT_TYPES:
        raise ValueError("unknown event type")

    event_sequence = _require_non_negative_int(payload, "event_sequence")

    if event_type == "capacity":
        _require_exact_keys(payload, frozenset({"event_sequence", "event_type", "binding", "error_code"}))
        _require_str(payload, "error_code")
        _require_binding(payload["binding"])  # noqa: B018
        return _ResumeEvent(
            event_sequence=event_sequence,
            event_type=event_type,
            active_duration_ms=0,
            error_code=payload["error_code"],
        )

    if event_type in _ACTIVE_EVENT_TYPES:
        _require_exact_keys(payload, frozenset({"event_sequence", "event_type", "binding", "active_duration_ms"}))
        active_duration_ms = _require_non_negative_int(payload, "active_duration_ms")
        _require_binding(payload["binding"])  # noqa: B018
        return _ResumeEvent(
            event_sequence=event_sequence,
            event_type=event_type,
            active_duration_ms=active_duration_ms,
            error_code=None,
        )

    if event_type in _ZERO_DURATION_EVENTS:
        allowed_with_duration = {"event_sequence", "event_type", "binding", "active_duration_ms"}
        allowed_without_duration = {"event_sequence", "event_type", "binding"}
        if set(payload.keys()) not in (allowed_with_duration, allowed_without_duration):
            raise ValueError("unexpected fields present")
        if "active_duration_ms" in payload:
            active_duration_ms = _require_non_negative_int(payload, "active_duration_ms")
            if active_duration_ms < 0:
                raise ValueError("negative active_duration_ms")
        _require_binding(payload["binding"])  # noqa: B018
        return _ResumeEvent(
            event_sequence=event_sequence,
            event_type=event_type,
            active_duration_ms=0,
            error_code=None,
        )

    raise ValueError("unknown event type")


def _apply_active_window(
    active_window_ms: int,
    retry_count: int,
) -> tuple[int, int]:
    if active_window_ms < 0:
        raise ValueError("invalid active window")
    if active_window_ms < _ACTIVE_WINDOW_MS:
        return active_window_ms, retry_count
    return 0, 0


def _matching_binding(capsule: ResumeCapsuleV1, payload: Mapping[str, Any]) -> bool:
    try:
        source = _require_binding(payload["binding"])  # type: ignore[index]
        return (
            capsule.bee_id == source["bee_id"]
            and capsule.session_id == source["session_id"]
            and capsule.spark_requirement == source["spark_requirement"]
            and capsule.model == source["model"]
            and capsule.provider == source["provider"]
            and capsule.effort == source["effort"]
            and capsule.account_binding == source["account_binding"]
        )
    except (TypeError, ValueError, KeyError):
        return False


def apply_resume_event(
    capsule: ResumeCapsuleV1,
    event: Mapping[str, Any],
) -> ResumeCapsuleV1:
    """Apply one event and return new capsule state.

    Any malformed payload or binding mismatch causes fail-closed no-op.
    """

    try:
        _validate_capsule(capsule)
        event_state = _normalize_event(event)
        if not _matching_binding(capsule, event):
            return capsule
        if event_state.event_sequence <= capsule.event_sequence:
            return capsule
    except (TypeError, ValueError, KeyError):
        return capsule

    active_window_ms = capsule.active_window_ms
    retry_count = capsule.retry_count

    if event_state.event_type in _ACTIVE_EVENT_TYPES:
        active_window_ms += event_state.active_duration_ms
        active_window_ms, retry_count = _apply_active_window(active_window_ms, retry_count)

    if (
        event_state.event_type == "capacity"
        and is_capacity_retry_code(event_state.error_code or "")
    ):
        if retry_count < _CAPACITY_RETRY_LIMIT:
            retry_count += 1

    return ResumeCapsuleV1(
        bee_id=capsule.bee_id,
        session_id=capsule.session_id,
        spark_requirement=capsule.spark_requirement,
        model=capsule.model,
        provider=capsule.provider,
        effort=capsule.effort,
        account_binding=capsule.account_binding,
        retry_count=retry_count,
        event_sequence=event_state.event_sequence,
        active_window_ms=active_window_ms,
    )
