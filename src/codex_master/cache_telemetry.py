"""Strict, provider-neutral cache and context-reset telemetry contracts.

The module deliberately accepts only the native usage fields enumerated in the
Cache Usage Observability plan.  It does not send requests, calculate prices,
or retain raw provider payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
import re
from typing import Mapping


SCHEMA_VERSION = 1
PARSER_GENERATION = "cache-telemetry-v1"
MAX_NATIVE_MAPPING_FIELDS = 128
MAX_TOKEN_COUNT = 2**63 - 1

_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]*\Z")
_CACHE_PSEUDONYM = re.compile(r"(?:sha256|hmac-sha256):[a-f0-9]{64}\Z")
_PROVIDERS = frozenset({"openai", "gemini", "anthropic", "deepseek"})
_DATA_SOURCES = frozenset(
    {
        "openai_responses",
        "openai_chat_completions",
        "gemini_interactions",
        "gemini_generate_content",
        "anthropic_messages",
        "deepseek_chat_completions",
    }
)
_SOURCE_PROVIDERS = {
    "openai_responses": "openai",
    "openai_chat_completions": "openai",
    "gemini_interactions": "gemini",
    "gemini_generate_content": "gemini",
    "anthropic_messages": "anthropic",
    "deepseek_chat_completions": "deepseek",
}
_SOURCE_METRIC_PROVENANCE = {
    "openai_responses": {
        "input_tokens": "usage.input_tokens",
        "output_tokens": "usage.output_tokens",
        "reasoning_tokens": "usage.output_tokens_details.reasoning_tokens",
        "cache_read_tokens": "usage.input_tokens_details.cached_tokens",
        "cache_write_tokens": "usage.input_tokens_details.cache_write_tokens",
    },
    "openai_chat_completions": {
        "input_tokens": "usage.prompt_tokens",
        "output_tokens": "usage.completion_tokens",
        "reasoning_tokens": "usage.completion_tokens_details.reasoning_tokens",
        "cache_read_tokens": "usage.prompt_tokens_details.cached_tokens",
        "cache_write_tokens": "usage.prompt_tokens_details.cache_write_tokens",
    },
    "gemini_interactions": {
        "input_tokens": "usage.input_tokens",
        "output_tokens": "usage.output_tokens",
        "cache_read_tokens": "usage.total_cached_tokens",
    },
    "gemini_generate_content": {
        "input_tokens": "usage_metadata.prompt_token_count",
        "output_tokens": "usage_metadata.candidates_token_count",
        "reasoning_tokens": "usage_metadata.thoughts_token_count",
        "cache_read_tokens": "usage_metadata.cached_content_token_count",
    },
    "anthropic_messages": {
        "input_tokens": "usage.input_tokens",
        "output_tokens": "usage.output_tokens",
        "cache_read_tokens": "usage.cache_read_input_tokens",
        "cache_write_tokens": "usage.cache_creation_input_tokens",
    },
    "deepseek_chat_completions": {
        "input_tokens": "usage.prompt_tokens",
        "output_tokens": "usage.completion_tokens",
        "cache_read_tokens": "usage.prompt_cache_hit_tokens",
        "cache_miss_tokens": "usage.prompt_cache_miss_tokens",
    },
}
_PROVIDER_NATIVE_FIELDS = {
    provider: frozenset(
        field
        for source, source_provider in _SOURCE_PROVIDERS.items()
        if source_provider == provider
        for field in _SOURCE_METRIC_PROVENANCE[source].values()
    )
    for provider in _PROVIDERS
}
_COVERAGE = frozenset({"complete", "partial", "unknown"})
_FRESHNESS = frozenset({"fresh", "stale", "unknown"})
_RESET_KINDS = frozenset(
    {
        "automatic_compaction",
        "manual_compaction",
        "session_restart",
        "crash_recovery",
        "resume_rehydrate",
        "provider_model_switch",
        "unknown",
    }
)
_ALLOWED_NATIVE_FIELDS = frozenset(
    {
        "usage.input_tokens",
        "usage.output_tokens",
        "usage.output_tokens_details.reasoning_tokens",
        "usage.prompt_tokens",
        "usage.completion_tokens",
        "usage.completion_tokens_details.reasoning_tokens",
        "usage.input_tokens_details.cached_tokens",
        "usage.input_tokens_details.cache_write_tokens",
        "usage.prompt_tokens_details.cached_tokens",
        "usage.prompt_tokens_details.cache_write_tokens",
        "usage.total_cached_tokens",
        "usage.input_tokens",
        "usage.output_tokens",
        "usage_metadata.prompt_token_count",
        "usage_metadata.candidates_token_count",
        "usage_metadata.thoughts_token_count",
        "usage_metadata.cached_content_token_count",
        "usage.cache_read_input_tokens",
        "usage.cache_creation_input_tokens",
        "usage.prompt_cache_hit_tokens",
        "usage.prompt_cache_miss_tokens",
    }
)


class CacheTelemetryValidationError(ValueError):
    """A bounded cache-telemetry value was malformed or unsafe to retain."""


def _require_mapping(value: object, field: str, *, max_fields: int = MAX_NATIVE_MAPPING_FIELDS) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > max_fields:
        raise CacheTelemetryValidationError(f"invalid_{field}")
    if any(not isinstance(key, str) for key in value):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return value


def _safe_identifier(value: object, field: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return value


def _optional_identifier(value: object, field: str, *, maximum: int = 128) -> str | None:
    if value is None:
        return None
    return _safe_identifier(value, field, maximum=maximum)


def _utc_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CacheTelemetryValidationError(f"invalid_{field}") from exc
    return _utc_datetime(parsed, field)


def _token(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_TOKEN_COUNT:
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return value


def _decimal(value: object, field: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, str)):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise CacheTelemetryValidationError(f"invalid_{field}") from exc
    if (
        not parsed.is_finite()
        or parsed < 0
        or parsed > Decimal("1e15")
        or len(parsed.as_tuple().digits) > 18
        or parsed.as_tuple().exponent < -18
    ):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return parsed


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")


def _decimal_instance(value: object, field: str) -> Decimal | None:
    parsed = _decimal(value, field)
    if parsed is not None and not isinstance(value, Decimal):
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return parsed


def _ratio_decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise CacheTelemetryValidationError("invalid_cache_ratio")
    return value


def _ratio(numerator: int | None, input_tokens: int | None) -> Decimal | None:
    """Return a cache ratio only when a native, non-zero input denominator exists.

    Read, write, and miss ratios all use native ``input_tokens`` as denominator.
    A missing numerator, a missing input total, or a zero input total yields
    ``None``.  No zero or complement is inferred from another cache category.
    """

    if numerator is None or input_tokens is None or input_tokens == 0:
        return None
    return Decimal(numerator) / Decimal(input_tokens)


def _coverage(*, input_tokens: int | None, cache_read_tokens: int | None, cache_write_tokens: int | None, cache_miss_tokens: int | None, uncached_input_tokens: int | None) -> str:
    cache_values = (cache_read_tokens, cache_write_tokens, cache_miss_tokens, uncached_input_tokens)
    if input_tokens is None and all(value is None for value in cache_values):
        return "unknown"
    if input_tokens is not None and all(value is not None for value in cache_values):
        return "complete"
    return "partial"


def _reset_coverage(values: tuple[int | None, ...]) -> str:
    if all(value is None for value in values):
        return "unknown"
    return "complete" if all(value is not None for value in values) else "partial"


def _optional_pseudonym(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _CACHE_PSEUDONYM.fullmatch(value) is None:
        raise CacheTelemetryValidationError(f"invalid_{field}")
    return value


@dataclass(frozen=True, slots=True)
class CacheCostEstimateV1:
    """Provider-supplied or separately calculated costs; this core never calculates them."""

    pricing_generation: str | None
    normal_input_cost: Decimal | None
    cache_read_cost: Decimal | None
    cache_write_cost: Decimal | None
    output_cost: Decimal | None
    reasoning_cost: Decimal | None

    def __post_init__(self) -> None:
        _optional_identifier(self.pricing_generation, "pricing_generation")
        for field in (
            "normal_input_cost",
            "cache_read_cost",
            "cache_write_cost",
            "output_cost",
            "reasoning_cost",
        ):
            _decimal_instance(getattr(self, field), field)

    def to_dict(self) -> dict[str, object]:
        return {
            "pricing_generation": self.pricing_generation,
            "normal_input_cost": _decimal_text(self.normal_input_cost),
            "cache_read_cost": _decimal_text(self.cache_read_cost),
            "cache_write_cost": _decimal_text(self.cache_write_cost),
            "output_cost": _decimal_text(self.output_cost),
            "reasoning_cost": _decimal_text(self.reasoning_cost),
        }

    @classmethod
    def from_dict(cls, value: object) -> CacheCostEstimateV1:
        data = _require_mapping(value, "cost_estimates", max_fields=6)
        expected = {
            "pricing_generation", "normal_input_cost", "cache_read_cost",
            "cache_write_cost", "output_cost", "reasoning_cost",
        }
        if set(data) != expected:
            raise CacheTelemetryValidationError("invalid_cost_estimates")
        return cls(
            pricing_generation=_optional_identifier(data["pricing_generation"], "pricing_generation"),
            normal_input_cost=_decimal(data["normal_input_cost"], "normal_input_cost"),
            cache_read_cost=_decimal(data["cache_read_cost"], "cache_read_cost"),
            cache_write_cost=_decimal(data["cache_write_cost"], "cache_write_cost"),
            output_cost=_decimal(data["output_cost"], "output_cost"),
            reasoning_cost=_decimal(data["reasoning_cost"], "reasoning_cost"),
        )


@dataclass(frozen=True, slots=True)
class CacheTelemetryContextV1:
    """Redacted request metadata supplied by an adapter, never a raw request."""

    model: str
    account_ref: str
    request_id: str
    session_id: str
    observed_at: datetime
    requested_service_tier: str | None
    effective_service_tier: str | None
    context_class: str | None
    cache_mode: str | None
    cache_key_pseudonym: str | None
    breakpoint_count: int | None
    costs: CacheCostEstimateV1
    freshness: str = "fresh"

    def __post_init__(self) -> None:
        _safe_identifier(self.model, "model", maximum=192)
        for field in ("account_ref", "request_id", "session_id"):
            _safe_identifier(getattr(self, field), field)
        _utc_datetime(self.observed_at, "observed_at")
        for field in ("requested_service_tier", "effective_service_tier", "context_class", "cache_mode"):
            _optional_identifier(getattr(self, field), field, maximum=96)
        _optional_pseudonym(self.cache_key_pseudonym, "cache_key_pseudonym")
        if self.breakpoint_count is not None and (isinstance(self.breakpoint_count, bool) or not isinstance(self.breakpoint_count, int) or not 0 <= self.breakpoint_count <= 100_000):
            raise CacheTelemetryValidationError("invalid_breakpoint_count")
        if not isinstance(self.costs, CacheCostEstimateV1) or self.freshness not in _FRESHNESS:
            raise CacheTelemetryValidationError("invalid_cache_context")


@dataclass(frozen=True, slots=True)
class CacheTelemetryV1:
    """One validated request or stream-final cache usage observation."""

    provider: str
    model: str
    account_ref: str
    request_id: str
    session_id: str
    observed_at: datetime
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cache_read_tokens: int | None
    cache_write_tokens: int | None
    cache_miss_tokens: int | None
    uncached_input_tokens: int | None
    cache_read_ratio: Decimal | None
    cache_write_ratio: Decimal | None
    cache_miss_ratio: Decimal | None
    requested_service_tier: str | None
    effective_service_tier: str | None
    context_class: str | None
    cache_mode: str | None
    cache_key_pseudonym: str | None
    breakpoint_count: int | None
    native_field_names: tuple[str, ...]
    costs: CacheCostEstimateV1
    coverage: str
    data_source: str
    parser_generation: str = PARSER_GENERATION
    validation_status: str = "valid"
    freshness: str = "fresh"

    def __post_init__(self) -> None:
        if self.provider not in _PROVIDERS or self.data_source not in _DATA_SOURCES or _SOURCE_PROVIDERS[self.data_source] != self.provider:
            raise CacheTelemetryValidationError("invalid_provider_source")
        for field, maximum in (("model", 192), ("account_ref", 128), ("request_id", 128), ("session_id", 128)):
            _safe_identifier(getattr(self, field), field, maximum=maximum)
        _utc_datetime(self.observed_at, "observed_at")
        for field in (
            "input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens",
            "cache_write_tokens", "cache_miss_tokens", "uncached_input_tokens",
        ):
            _token(getattr(self, field), field)
        expected_ratios = (
            _ratio(self.cache_read_tokens, self.input_tokens),
            _ratio(self.cache_write_tokens, self.input_tokens),
            _ratio(self.cache_miss_tokens, self.input_tokens),
        )
        actual_ratios = (self.cache_read_ratio, self.cache_write_ratio, self.cache_miss_ratio)
        if any(_ratio_decimal(value) != expected for value, expected in zip(actual_ratios, expected_ratios, strict=True)):
            raise CacheTelemetryValidationError("invalid_cache_ratio")
        for field in ("requested_service_tier", "effective_service_tier", "context_class", "cache_mode"):
            _optional_identifier(getattr(self, field), field, maximum=96)
        _optional_pseudonym(self.cache_key_pseudonym, "cache_key_pseudonym")
        if self.breakpoint_count is not None and (isinstance(self.breakpoint_count, bool) or not isinstance(self.breakpoint_count, int) or not 0 <= self.breakpoint_count <= 100_000):
            raise CacheTelemetryValidationError("invalid_breakpoint_count")
        if not isinstance(self.native_field_names, tuple) or len(self.native_field_names) > 16 or tuple(sorted(set(self.native_field_names))) != self.native_field_names or not set(self.native_field_names) <= _ALLOWED_NATIVE_FIELDS or not set(self.native_field_names) <= _PROVIDER_NATIVE_FIELDS[self.provider]:
            raise CacheTelemetryValidationError("invalid_native_field_names")
        if self.uncached_input_tokens is not None:
            raise CacheTelemetryValidationError("unsupported_uncached_input_tokens")
        expected_provenance = tuple(sorted(
            provenance
            for metric, provenance in _SOURCE_METRIC_PROVENANCE[self.data_source].items()
            if getattr(self, metric) is not None
        ))
        if self.native_field_names != expected_provenance:
            raise CacheTelemetryValidationError("incoherent_native_provenance")
        if not isinstance(self.costs, CacheCostEstimateV1) or self.coverage not in _COVERAGE or self.coverage != _coverage(
            input_tokens=self.input_tokens,
            cache_read_tokens=self.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens,
            cache_miss_tokens=self.cache_miss_tokens,
            uncached_input_tokens=self.uncached_input_tokens,
        ):
            raise CacheTelemetryValidationError("invalid_cache_coverage")
        if self.parser_generation != PARSER_GENERATION or self.validation_status != "valid" or self.freshness not in _FRESHNESS:
            raise CacheTelemetryValidationError("invalid_cache_validation")

    @property
    def event_key(self) -> str:
        return f"cache:{self.provider}:{self.account_ref}:{self.request_id}"

    def to_dict(self) -> dict[str, object]:
        return {
            "record_kind": "cache_telemetry_v1", "schema_version": SCHEMA_VERSION,
            "provider": self.provider, "model": self.model, "account_ref": self.account_ref,
            "request_id": self.request_id, "session_id": self.session_id,
            "observed_at": _timestamp(self.observed_at), "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "reasoning_tokens": self.reasoning_tokens,
            "cache_read_tokens": self.cache_read_tokens, "cache_write_tokens": self.cache_write_tokens,
            "cache_miss_tokens": self.cache_miss_tokens, "uncached_input_tokens": self.uncached_input_tokens,
            "cache_read_ratio": _decimal_text(self.cache_read_ratio),
            "cache_write_ratio": _decimal_text(self.cache_write_ratio),
            "cache_miss_ratio": _decimal_text(self.cache_miss_ratio),
            "requested_service_tier": self.requested_service_tier,
            "effective_service_tier": self.effective_service_tier,
            "context_class": self.context_class, "cache_mode": self.cache_mode,
            "cache_key_pseudonym": self.cache_key_pseudonym, "breakpoint_count": self.breakpoint_count,
            "native_field_names": list(self.native_field_names), "costs": self.costs.to_dict(),
            "coverage": self.coverage, "data_source": self.data_source,
            "parser_generation": self.parser_generation, "validation_status": self.validation_status,
            "freshness": self.freshness,
        }

    @classmethod
    def from_dict(cls, value: object) -> CacheTelemetryV1:
        data = _require_mapping(value, "cache_record", max_fields=40)
        expected = set(cls.__dataclass_fields__) | {"record_kind", "schema_version"}
        if set(data) != expected or data["record_kind"] != "cache_telemetry_v1" or data["schema_version"] != SCHEMA_VERSION:
            raise CacheTelemetryValidationError("invalid_cache_record")
        field_names = data["native_field_names"]
        if not isinstance(field_names, list) or any(not isinstance(item, str) for item in field_names):
            raise CacheTelemetryValidationError("invalid_native_field_names")
        return cls(
            provider=data["provider"], model=data["model"], account_ref=data["account_ref"],
            request_id=data["request_id"], session_id=data["session_id"],
            observed_at=_parse_timestamp(data["observed_at"], "observed_at"),
            input_tokens=_token(data["input_tokens"], "input_tokens"), output_tokens=_token(data["output_tokens"], "output_tokens"),
            reasoning_tokens=_token(data["reasoning_tokens"], "reasoning_tokens"), cache_read_tokens=_token(data["cache_read_tokens"], "cache_read_tokens"),
            cache_write_tokens=_token(data["cache_write_tokens"], "cache_write_tokens"), cache_miss_tokens=_token(data["cache_miss_tokens"], "cache_miss_tokens"),
            uncached_input_tokens=_token(data["uncached_input_tokens"], "uncached_input_tokens"),
            cache_read_ratio=_decimal(data["cache_read_ratio"], "cache_read_ratio"), cache_write_ratio=_decimal(data["cache_write_ratio"], "cache_write_ratio"),
            cache_miss_ratio=_decimal(data["cache_miss_ratio"], "cache_miss_ratio"),
            requested_service_tier=_optional_identifier(data["requested_service_tier"], "requested_service_tier", maximum=96),
            effective_service_tier=_optional_identifier(data["effective_service_tier"], "effective_service_tier", maximum=96),
            context_class=_optional_identifier(data["context_class"], "context_class", maximum=96),
            cache_mode=_optional_identifier(data["cache_mode"], "cache_mode", maximum=96),
            cache_key_pseudonym=_optional_pseudonym(data["cache_key_pseudonym"], "cache_key_pseudonym"), breakpoint_count=data["breakpoint_count"],
            native_field_names=tuple(field_names), costs=CacheCostEstimateV1.from_dict(data["costs"]), coverage=data["coverage"],
            data_source=data["data_source"], parser_generation=data["parser_generation"], validation_status=data["validation_status"], freshness=data["freshness"],
        )


@dataclass(frozen=True, slots=True)
class ContextResetTelemetryV1:
    """A redacted reset/recovery observation; it is never an authorisation to reset."""

    event_id: str
    session_id: str
    assignment_ref: str
    occurred_at: datetime
    provider: str
    model: str
    account_ref: str
    context_class: str | None
    lifecycle: str | None
    reset_kind: str
    native_cause: str | None
    pre_reset_context_tokens: int | None
    preserved_tokens: int | None
    first_post_reset_input_tokens: int | None
    first_post_reset_cache_read_tokens: int | None
    first_post_reset_cache_write_tokens: int | None
    first_post_reset_cache_miss_tokens: int | None
    first_post_reset_reasoning_tokens: int | None
    first_post_reset_output_tokens: int | None
    recovery_reread_tokens: int | None
    recovery_replayed_tokens: int | None
    recovery_tool_calls: int | None
    recovery_duration_seconds: Decimal | None
    recovery_cost: Decimal | None
    recovery_checkpoint_reached: bool
    previous_cache_key_pseudonym: str | None
    next_cache_key_pseudonym: str | None
    resume_capsule_generation: int | None
    related_pre_reset_request_id: str | None
    related_post_reset_request_id: str | None
    native_field_names: tuple[str, ...]
    reset_coverage: str
    recovery_coverage: str
    parser_generation: str = PARSER_GENERATION
    freshness: str = "fresh"

    def __post_init__(self) -> None:
        for field, maximum in (("event_id", 128), ("session_id", 128), ("assignment_ref", 128), ("model", 192), ("account_ref", 128)):
            _safe_identifier(getattr(self, field), field, maximum=maximum)
        if self.provider not in _PROVIDERS or self.reset_kind not in _RESET_KINDS:
            raise CacheTelemetryValidationError("invalid_reset_kind")
        _utc_datetime(self.occurred_at, "occurred_at")
        for field in ("context_class", "lifecycle", "native_cause", "related_pre_reset_request_id", "related_post_reset_request_id"):
            _optional_identifier(getattr(self, field), field, maximum=128)
        for field in (
            "pre_reset_context_tokens", "preserved_tokens", "first_post_reset_input_tokens",
            "first_post_reset_cache_read_tokens", "first_post_reset_cache_write_tokens",
            "first_post_reset_cache_miss_tokens", "first_post_reset_reasoning_tokens",
            "first_post_reset_output_tokens", "recovery_reread_tokens", "recovery_replayed_tokens",
            "recovery_tool_calls",
        ):
            _token(getattr(self, field), field)
        _decimal_instance(self.recovery_duration_seconds, "recovery_duration_seconds")
        _decimal_instance(self.recovery_cost, "recovery_cost")
        if not isinstance(self.recovery_checkpoint_reached, bool):
            raise CacheTelemetryValidationError("invalid_recovery_checkpoint")
        if not self.recovery_checkpoint_reached and (self.recovery_duration_seconds is not None or self.recovery_cost is not None):
            raise CacheTelemetryValidationError("unproven_recovery_checkpoint")
        _optional_pseudonym(self.previous_cache_key_pseudonym, "previous_cache_key_pseudonym")
        _optional_pseudonym(self.next_cache_key_pseudonym, "next_cache_key_pseudonym")
        if self.resume_capsule_generation is not None and (isinstance(self.resume_capsule_generation, bool) or not isinstance(self.resume_capsule_generation, int) or not 1 <= self.resume_capsule_generation <= 2**31 - 1):
            raise CacheTelemetryValidationError("invalid_resume_capsule_generation")
        if not isinstance(self.native_field_names, tuple) or len(self.native_field_names) > 16 or tuple(sorted(set(self.native_field_names))) != self.native_field_names or not set(self.native_field_names) <= _ALLOWED_NATIVE_FIELDS or not set(self.native_field_names) <= _PROVIDER_NATIVE_FIELDS[self.provider]:
            raise CacheTelemetryValidationError("invalid_native_field_names")
        if self.related_pre_reset_request_id is None and self.related_post_reset_request_id is None:
            raise CacheTelemetryValidationError("unlinked_reset_telemetry")
        expected_reset_coverage = _reset_coverage((
            self.pre_reset_context_tokens, self.preserved_tokens,
            self.first_post_reset_input_tokens, self.first_post_reset_cache_read_tokens,
            self.first_post_reset_cache_write_tokens, self.first_post_reset_cache_miss_tokens,
            self.first_post_reset_reasoning_tokens, self.first_post_reset_output_tokens,
        ))
        expected_recovery_coverage = _reset_coverage((
            self.recovery_reread_tokens, self.recovery_replayed_tokens,
            self.recovery_tool_calls,
            None if self.recovery_duration_seconds is None else 0,
            None if self.recovery_cost is None else 0,
        ))
        if self.reset_coverage != expected_reset_coverage or self.recovery_coverage != expected_recovery_coverage or self.parser_generation != PARSER_GENERATION or self.freshness not in _FRESHNESS:
            raise CacheTelemetryValidationError("invalid_reset_telemetry")

    @property
    def event_key(self) -> str:
        return f"reset:{self.event_id}"

    def to_dict(self) -> dict[str, object]:
        values = {name: getattr(self, name) for name in self.__dataclass_fields__}
        values.update({
            "record_kind": "context_reset_telemetry_v1", "schema_version": SCHEMA_VERSION,
            "occurred_at": _timestamp(self.occurred_at),
            "recovery_duration_seconds": _decimal_text(self.recovery_duration_seconds),
            "recovery_cost": _decimal_text(self.recovery_cost),
            "native_field_names": list(self.native_field_names),
        })
        return values

    @classmethod
    def from_dict(cls, value: object) -> ContextResetTelemetryV1:
        data = _require_mapping(value, "reset_record", max_fields=48)
        expected = set(cls.__dataclass_fields__) | {"record_kind", "schema_version"}
        if set(data) != expected or data["record_kind"] != "context_reset_telemetry_v1" or data["schema_version"] != SCHEMA_VERSION:
            raise CacheTelemetryValidationError("invalid_reset_record")
        names = data["native_field_names"]
        if not isinstance(names, list) or any(not isinstance(item, str) for item in names):
            raise CacheTelemetryValidationError("invalid_native_field_names")
        fields = dict(data)
        fields.pop("record_kind")
        fields.pop("schema_version")
        fields["occurred_at"] = _parse_timestamp(fields["occurred_at"], "occurred_at")
        fields["recovery_duration_seconds"] = _decimal(fields["recovery_duration_seconds"], "recovery_duration_seconds")
        fields["recovery_cost"] = _decimal(fields["recovery_cost"], "recovery_cost")
        fields["native_field_names"] = tuple(names)
        return cls(**fields)  # type: ignore[arg-type]


def _usage(payload: object) -> Mapping[str, object] | None:
    root = _require_mapping(payload, "native_payload")
    usage = root.get("usage")
    if usage is None:
        return None
    return _require_mapping(usage, "native_usage")


def _nested(usage: Mapping[str, object] | None, name: str) -> Mapping[str, object] | None:
    if usage is None or usage.get(name) is None:
        return None
    return _require_mapping(usage[name], f"native_{name}", max_fields=32)


def _number(usage: Mapping[str, object] | None, name: str, provenance: str, fields: list[str]) -> int | None:
    if usage is None or name not in usage:
        return None
    fields.append(provenance)
    return _token(usage[name], provenance)


def _number_alias(
    usage: Mapping[str, object] | None,
    snake_name: str,
    camel_name: str,
    provenance: str,
    fields: list[str],
) -> int | None:
    """Read one documented Gemini SDK/API spelling, rejecting ambiguity."""

    if usage is None:
        return None
    present = [name for name in (snake_name, camel_name) if name in usage]
    if len(present) > 1:
        raise CacheTelemetryValidationError("ambiguous_native_usage")
    if not present:
        return None
    fields.append(provenance)
    return _token(usage[present[0]], provenance)


def _detail_number(usage: Mapping[str, object] | None, detail: str, name: str, provenance: str, fields: list[str]) -> int | None:
    details = _nested(usage, detail)
    if details is None or name not in details:
        return None
    fields.append(provenance)
    return _token(details[name], provenance)


def _build(context: CacheTelemetryContextV1, *, provider: str, data_source: str, input_tokens: int | None, output_tokens: int | None, reasoning_tokens: int | None, cache_read_tokens: int | None, cache_write_tokens: int | None, cache_miss_tokens: int | None, native_field_names: list[str]) -> CacheTelemetryV1:
    if not isinstance(context, CacheTelemetryContextV1):
        raise CacheTelemetryValidationError("invalid_cache_context")
    return CacheTelemetryV1(
        provider=provider, model=context.model, account_ref=context.account_ref,
        request_id=context.request_id, session_id=context.session_id, observed_at=context.observed_at,
        input_tokens=input_tokens, output_tokens=output_tokens, reasoning_tokens=reasoning_tokens,
        cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens,
        cache_miss_tokens=cache_miss_tokens, uncached_input_tokens=None,
        cache_read_ratio=_ratio(cache_read_tokens, input_tokens),
        cache_write_ratio=_ratio(cache_write_tokens, input_tokens),
        cache_miss_ratio=_ratio(cache_miss_tokens, input_tokens),
        requested_service_tier=context.requested_service_tier,
        effective_service_tier=context.effective_service_tier,
        context_class=context.context_class, cache_mode=context.cache_mode,
        cache_key_pseudonym=context.cache_key_pseudonym, breakpoint_count=context.breakpoint_count,
        native_field_names=tuple(sorted(set(native_field_names))), costs=context.costs,
        coverage=_coverage(input_tokens=input_tokens, cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens, cache_miss_tokens=cache_miss_tokens, uncached_input_tokens=None),
        data_source=data_source, freshness=context.freshness,
    )


def normalize_openai_responses(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    """Normalize a completed OpenAI Responses usage payload without retaining it."""

    usage = _usage(payload)
    fields: list[str] = []
    return _build(context, provider="openai", data_source="openai_responses",
        input_tokens=_number(usage, "input_tokens", "usage.input_tokens", fields),
        output_tokens=_number(usage, "output_tokens", "usage.output_tokens", fields),
        reasoning_tokens=_detail_number(usage, "output_tokens_details", "reasoning_tokens", "usage.output_tokens_details.reasoning_tokens", fields),
        cache_read_tokens=_detail_number(usage, "input_tokens_details", "cached_tokens", "usage.input_tokens_details.cached_tokens", fields),
        cache_write_tokens=_detail_number(usage, "input_tokens_details", "cache_write_tokens", "usage.input_tokens_details.cache_write_tokens", fields),
        cache_miss_tokens=None, native_field_names=fields)


def normalize_openai_chat_completions(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    """Normalize a non-streaming OpenAI Chat Completions usage payload."""

    usage = _usage(payload)
    fields: list[str] = []
    return _build(context, provider="openai", data_source="openai_chat_completions",
        input_tokens=_number(usage, "prompt_tokens", "usage.prompt_tokens", fields),
        output_tokens=_number(usage, "completion_tokens", "usage.completion_tokens", fields),
        reasoning_tokens=_detail_number(usage, "completion_tokens_details", "reasoning_tokens", "usage.completion_tokens_details.reasoning_tokens", fields),
        cache_read_tokens=_detail_number(usage, "prompt_tokens_details", "cached_tokens", "usage.prompt_tokens_details.cached_tokens", fields),
        cache_write_tokens=_detail_number(usage, "prompt_tokens_details", "cache_write_tokens", "usage.prompt_tokens_details.cache_write_tokens", fields),
        cache_miss_tokens=None, native_field_names=fields)


def normalize_openai_chat_stream_final(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    """Accept only the usage-bearing terminal Chat Completions stream chunk.

    Request construction is intentionally outside this module.  Callers must
    request ``stream_options.include_usage=true`` and pass only its final,
    empty-choices chunk here.
    """

    root = _require_mapping(payload, "native_payload")
    choices = root.get("choices")
    if not isinstance(choices, list) or choices or root.get("usage") is None:
        raise CacheTelemetryValidationError("not_openai_chat_stream_final")
    return normalize_openai_chat_completions(root, context)


def normalize_gemini_interactions(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    usage = _usage(payload)
    fields: list[str] = []
    return _build(context, provider="gemini", data_source="gemini_interactions",
        input_tokens=_number(usage, "input_tokens", "usage.input_tokens", fields),
        output_tokens=_number(usage, "output_tokens", "usage.output_tokens", fields),
        reasoning_tokens=None, cache_read_tokens=_number(usage, "total_cached_tokens", "usage.total_cached_tokens", fields),
        cache_write_tokens=None, cache_miss_tokens=None, native_field_names=fields)


def normalize_gemini_generate_content(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    root = _require_mapping(payload, "native_payload")
    containers = [name for name in ("usage_metadata", "usageMetadata") if name in root]
    if len(containers) > 1:
        raise CacheTelemetryValidationError("ambiguous_native_usage")
    usage_value = root.get(containers[0]) if containers else None
    usage = None if usage_value is None else _require_mapping(usage_value, "native_usage")
    fields: list[str] = []
    return _build(context, provider="gemini", data_source="gemini_generate_content",
        input_tokens=_number_alias(usage, "prompt_token_count", "promptTokenCount", "usage_metadata.prompt_token_count", fields),
        output_tokens=_number_alias(usage, "candidates_token_count", "candidatesTokenCount", "usage_metadata.candidates_token_count", fields),
        reasoning_tokens=_number_alias(usage, "thoughts_token_count", "thoughtsTokenCount", "usage_metadata.thoughts_token_count", fields),
        cache_read_tokens=_number_alias(usage, "cached_content_token_count", "cachedContentTokenCount", "usage_metadata.cached_content_token_count", fields),
        cache_write_tokens=None, cache_miss_tokens=None, native_field_names=fields)


def normalize_anthropic(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    usage = _usage(payload)
    fields: list[str] = []
    return _build(context, provider="anthropic", data_source="anthropic_messages",
        input_tokens=_number(usage, "input_tokens", "usage.input_tokens", fields),
        output_tokens=_number(usage, "output_tokens", "usage.output_tokens", fields),
        reasoning_tokens=None, cache_read_tokens=_number(usage, "cache_read_input_tokens", "usage.cache_read_input_tokens", fields),
        cache_write_tokens=_number(usage, "cache_creation_input_tokens", "usage.cache_creation_input_tokens", fields),
        cache_miss_tokens=None, native_field_names=fields)


def normalize_deepseek(payload: object, context: CacheTelemetryContextV1) -> CacheTelemetryV1:
    usage = _usage(payload)
    fields: list[str] = []
    return _build(context, provider="deepseek", data_source="deepseek_chat_completions",
        input_tokens=_number(usage, "prompt_tokens", "usage.prompt_tokens", fields),
        output_tokens=_number(usage, "completion_tokens", "usage.completion_tokens", fields),
        reasoning_tokens=None, cache_read_tokens=_number(usage, "prompt_cache_hit_tokens", "usage.prompt_cache_hit_tokens", fields),
        cache_write_tokens=None, cache_miss_tokens=_number(usage, "prompt_cache_miss_tokens", "usage.prompt_cache_miss_tokens", fields),
        native_field_names=fields)


__all__ = [
    "CacheCostEstimateV1", "CacheTelemetryContextV1", "CacheTelemetryV1",
    "CacheTelemetryValidationError", "ContextResetTelemetryV1", "MAX_NATIVE_MAPPING_FIELDS",
    "PARSER_GENERATION", "SCHEMA_VERSION", "normalize_anthropic", "normalize_deepseek",
    "normalize_gemini_generate_content", "normalize_gemini_interactions",
    "normalize_openai_chat_completions", "normalize_openai_chat_stream_final",
    "normalize_openai_responses",
]
