from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import json

import pytest

from the_hive.cache_telemetry import (
    CacheCostEstimateV1,
    CacheTelemetryContextV1,
    CacheTelemetryValidationError,
    ContextResetTelemetryV1,
    MAX_NATIVE_MAPPING_FIELDS,
    normalize_anthropic,
    normalize_deepseek,
    normalize_gemini_generate_content,
    normalize_gemini_interactions,
    normalize_openai_chat_completions,
    normalize_openai_chat_stream_final,
    normalize_openai_responses,
)
from the_hive.cache_telemetry_history import (
    CacheTelemetryHistoryError,
    CacheTelemetryHistoryV1,
    aggregate_cache_telemetry,
)


NOW = datetime(2026, 9, 14, 12, tzinfo=UTC)
PSEUDONYM = "sha256:" + "a" * 64


def costs() -> CacheCostEstimateV1:
    return CacheCostEstimateV1(
        pricing_generation=None,
        normal_input_cost=None,
        cache_read_cost=None,
        cache_write_cost=None,
        output_cost=None,
        reasoning_cost=None,
    )


def context(*, request_id: str = "request-1", observed_at: datetime = NOW) -> CacheTelemetryContextV1:
    return CacheTelemetryContextV1(
        model="gpt-5.6", account_ref="account-1", request_id=request_id,
        session_id="session-1", observed_at=observed_at,
        requested_service_tier="flex", effective_service_tier="flex",
        context_class="coding", cache_mode="enabled",
        cache_key_pseudonym=PSEUDONYM, breakpoint_count=2, costs=costs(),
    )


def reset(*, event_id: str = "reset-1", checkpoint: bool = False) -> ContextResetTelemetryV1:
    return ContextResetTelemetryV1(
        event_id=event_id, session_id="session-1", assignment_ref="task-1",
        occurred_at=NOW, provider="openai", model="gpt-5.6", account_ref="account-1",
        context_class="coding", lifecycle="persistent", reset_kind="crash_recovery",
        native_cause="process_exit", pre_reset_context_tokens=100,
        preserved_tokens=None, first_post_reset_input_tokens=None,
        first_post_reset_cache_read_tokens=None, first_post_reset_cache_write_tokens=None,
        first_post_reset_cache_miss_tokens=None, first_post_reset_reasoning_tokens=None,
        first_post_reset_output_tokens=None, recovery_reread_tokens=None, recovery_replayed_tokens=None,
        recovery_tool_calls=None, recovery_duration_seconds=None, recovery_cost=None,
        recovery_checkpoint_reached=checkpoint, previous_cache_key_pseudonym=PSEUDONYM,
        next_cache_key_pseudonym=None, resume_capsule_generation=1,
        related_pre_reset_request_id="request-0", related_post_reset_request_id=None,
        native_field_names=(), reset_coverage="partial", recovery_coverage="unknown",
    )


def test_openai_responses_traces_parser_contract_history_and_aggregate(tmp_path) -> None:
    raw = {
        "usage": {
            "input_tokens": 100,
            "output_tokens": 30,
            "input_tokens_details": {"cached_tokens": 25, "cache_write_tokens": 10},
            "output_tokens_details": {"reasoning_tokens": 4},
            "ignored_future_field": "prompt text must never be retained",
        },
        "unrecognized_secret": "sk-not-retained",
    }

    event = normalize_openai_responses(raw, context())
    history = CacheTelemetryHistoryV1(tmp_path / "cache-history.json")
    receipt = history.append(event, now=NOW)
    aggregate = history.aggregate(now=NOW)[0]

    assert receipt.appended is True
    assert event.cache_read_tokens == 25
    assert event.cache_write_tokens == 10
    assert event.cache_miss_tokens is None
    assert event.cache_read_ratio == Decimal("0.25")
    assert event.cache_write_ratio == Decimal("0.1")
    assert event.cache_miss_ratio is None
    assert event.coverage == "partial"
    assert aggregate.request_count == 1
    assert aggregate.cache_read_tokens == 25
    assert aggregate.cache_read_ratio == Decimal("0.25")
    persisted = (tmp_path / "cache-history.json").read_text(encoding="utf-8")
    assert "prompt text" not in persisted
    assert "sk-not-retained" not in persisted
    assert "ignored_future_field" not in persisted


def test_openai_chat_completion_and_only_usage_bearing_final_stream_chunk() -> None:
    raw = {
        "usage": {
            "prompt_tokens": 80,
            "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 8},
            "completion_tokens_details": {"reasoning_tokens": 3},
        }
    }
    event = normalize_openai_chat_completions(raw, context())

    assert event.data_source == "openai_chat_completions"
    assert event.input_tokens == 80
    assert event.output_tokens == 10
    assert event.reasoning_tokens == 3
    assert event.cache_read_tokens == 20
    with pytest.raises(CacheTelemetryValidationError, match="not_openai_chat_stream_final"):
        normalize_openai_chat_stream_final({"choices": [{"delta": {}}]}, context())
    final = normalize_openai_chat_stream_final({"choices": [], **raw}, context())
    assert final.to_dict() == event.to_dict()


@pytest.mark.parametrize(
    ("normalizer", "raw", "expected"),
    [
        (
            normalize_gemini_interactions,
            {"usage": {"input_tokens": 60, "output_tokens": 7, "total_cached_tokens": 12}},
            ("gemini", "gemini_interactions", 60, 7, 12, None, None),
        ),
        (
            normalize_gemini_generate_content,
            {"usageMetadata": {"promptTokenCount": 70, "candidatesTokenCount": 8, "thoughtsTokenCount": 2, "cachedContentTokenCount": 14}},
            ("gemini", "gemini_generate_content", 70, 8, 14, None, None),
        ),
        (
            normalize_anthropic,
            {"usage": {"input_tokens": 90, "output_tokens": 9, "cache_read_input_tokens": 40, "cache_creation_input_tokens": 11}},
            ("anthropic", "anthropic_messages", 90, 9, 40, 11, None),
        ),
        (
            normalize_deepseek,
            {"usage": {"prompt_tokens": 50, "completion_tokens": 5, "prompt_cache_hit_tokens": 21, "prompt_cache_miss_tokens": 29}},
            ("deepseek", "deepseek_chat_completions", 50, 5, 21, None, 29),
        ),
    ],
)
def test_provider_normalizers_use_only_the_documented_native_cache_fields(normalizer, raw, expected) -> None:
    event = normalizer(raw, context())

    assert (
        event.provider, event.data_source, event.input_tokens, event.output_tokens,
        event.cache_read_tokens, event.cache_write_tokens, event.cache_miss_tokens,
    ) == expected
    assert event.uncached_input_tokens is None
    assert event.cache_read_ratio is not None


def test_missing_native_usage_remains_null_not_zero() -> None:
    event = normalize_openai_responses({"response_id": "unrelated"}, context())

    assert event.input_tokens is None
    assert event.cache_read_tokens is None
    assert event.cache_read_ratio is None
    assert event.coverage == "unknown"


def test_malformed_and_oversized_native_payloads_fail_closed() -> None:
    with pytest.raises(CacheTelemetryValidationError, match="usage.input_tokens"):
        normalize_openai_responses({"usage": {"input_tokens": True}}, context())
    oversized = {f"field-{index}": index for index in range(MAX_NATIVE_MAPPING_FIELDS + 1)}
    with pytest.raises(CacheTelemetryValidationError, match="native_payload"):
        normalize_openai_responses(oversized, context())
    with pytest.raises(CacheTelemetryValidationError, match="ambiguous_native_usage"):
        normalize_gemini_generate_content(
            {"usage_metadata": {"cached_content_token_count": 1, "cachedContentTokenCount": 1}},
            context(),
        )


def test_contract_rejects_full_cache_key_and_bad_native_provenance() -> None:
    with pytest.raises(CacheTelemetryValidationError, match="cache_key_pseudonym"):
        CacheTelemetryContextV1(
            model="gpt-5.6", account_ref="account-1", request_id="request-1", session_id="session-1",
            observed_at=NOW, requested_service_tier=None, effective_service_tier=None,
            context_class=None, cache_mode=None, cache_key_pseudonym="actual-cache-key",
            breakpoint_count=None, costs=costs(),
        )
    event = normalize_openai_responses({"usage": {"input_tokens": 1}}, context())
    data = event.to_dict()
    data["native_field_names"] = ["usage.prompt"]
    with pytest.raises(CacheTelemetryValidationError, match="native_field_names"):
        event.from_dict(data)
    data = event.to_dict()
    data["native_field_names"] = ["usage.prompt_cache_hit_tokens"]
    with pytest.raises(CacheTelemetryValidationError, match="native_field_names"):
        event.from_dict(data)
    cached = normalize_openai_responses(
        {"usage": {"input_tokens": 1, "input_tokens_details": {"cached_tokens": 1}}},
        context(),
    )
    data = cached.to_dict()
    data["native_field_names"] = ["usage.input_tokens"]
    with pytest.raises(CacheTelemetryValidationError, match="incoherent_native_provenance"):
        cached.from_dict(data)


def test_reset_contract_cannot_persist_unproven_recovery_or_capsule_contents() -> None:
    event = reset()
    serialized = event.to_dict()

    assert serialized["recovery_duration_seconds"] is None
    assert serialized["recovery_cost"] is None
    assert "resume_capsule_content" not in serialized
    with pytest.raises(CacheTelemetryValidationError, match="unproven_recovery_checkpoint"):
        replace(event, recovery_duration_seconds=Decimal("4"))
    with pytest.raises(CacheTelemetryValidationError, match="unlinked_reset_telemetry"):
        replace(event, related_pre_reset_request_id=None)
    with pytest.raises(CacheTelemetryValidationError, match="invalid_reset_telemetry"):
        replace(event, reset_coverage="complete")
    with pytest.raises(CacheTelemetryValidationError, match="native_field_names"):
        replace(event, native_field_names=("usage.prompt_cache_hit_tokens",))


def test_gemini_generate_content_rejects_ambiguous_usage_containers() -> None:
    with pytest.raises(CacheTelemetryValidationError, match="ambiguous_native_usage"):
        normalize_gemini_generate_content(
            {"usage_metadata": {}, "usageMetadata": {}}, context()
        )


def test_history_is_idempotent_retained_and_crash_safe_before_replace(tmp_path, monkeypatch) -> None:
    history_path = tmp_path / "cache-history.json"
    history = CacheTelemetryHistoryV1(history_path, max_records=1, retention=timedelta(hours=1))
    first = normalize_openai_responses({"usage": {"input_tokens": 5}}, context(request_id="request-1"))
    duplicate = history.append(first, now=NOW)
    repeated = history.append(first, now=NOW)

    assert duplicate.appended is True
    assert repeated.appended is False
    conflicting = normalize_openai_responses({"usage": {"input_tokens": 7}}, context(request_id="request-1"))
    with pytest.raises(CacheTelemetryHistoryError, match="idempotency_conflict"):
        history.append(conflicting, now=NOW)
    before = history_path.read_bytes()
    second = normalize_openai_responses({"usage": {"input_tokens": 6}}, context(request_id="request-2"))

    def crash_before_replace(*_args: object) -> None:
        raise OSError("simulated crash")

    monkeypatch.setattr("the_hive.cache_telemetry_history.os.replace", crash_before_replace)
    with pytest.raises(CacheTelemetryHistoryError, match="history_replace_failed"):
        history.append(second, now=NOW)
    assert history_path.read_bytes() == before
    assert list(tmp_path.glob(".cache-history.json.*")) == [tmp_path / ".cache-history.json.lock"]


def test_history_prunes_retention_and_aggregate_never_fabricates_incomplete_ratio(tmp_path) -> None:
    history = CacheTelemetryHistoryV1(tmp_path / "cache-history.json", retention=timedelta(minutes=10))
    old = normalize_openai_responses({"usage": {"input_tokens": 20, "input_tokens_details": {"cached_tokens": 10}}}, context(request_id="old", observed_at=NOW - timedelta(minutes=11)))
    partial = normalize_openai_responses({"usage": {"input_tokens": 20, "input_tokens_details": {"cached_tokens": 10}}}, context(request_id="partial"))
    missing_read = normalize_openai_responses({"usage": {"input_tokens": 20}}, context(request_id="missing-read"))
    history.append(old, now=NOW - timedelta(minutes=10, seconds=30))
    history.append(partial, now=NOW)
    history.append(missing_read, now=NOW)

    records = history.read(now=NOW)
    aggregate = aggregate_cache_telemetry(records)[0]
    assert [record.request_id for record in records] == ["missing-read", "partial"]
    assert aggregate.cache_read_tokens == 10
    assert aggregate.cache_read_ratio is None
    assert aggregate.coverage == "partial"


def test_history_does_not_persist_directly_appended_expired_record(tmp_path) -> None:
    history_path = tmp_path / "cache-history.json"
    history = CacheTelemetryHistoryV1(history_path, retention=timedelta(minutes=10))
    expired = normalize_openai_responses(
        {"usage": {"input_tokens": 20}},
        context(request_id="expired", observed_at=NOW - timedelta(minutes=11)),
    )

    receipt = history.append(expired, now=NOW)

    assert receipt.appended is False
    assert receipt.retained_record_count == 0
    assert not history_path.exists()


def test_history_reports_nonretained_capacity_candidate_as_not_appended(tmp_path) -> None:
    history = CacheTelemetryHistoryV1(tmp_path / "cache-history.json", max_records=1)
    newest = normalize_openai_responses({"usage": {"input_tokens": 1}}, context(request_id="newest"))
    older = normalize_openai_responses(
        {"usage": {"input_tokens": 1}},
        context(request_id="older", observed_at=NOW - timedelta(seconds=1)),
    )
    history.append(newest, now=NOW)

    first = history.append(older, now=NOW)
    retry = history.append(older, now=NOW)

    assert first.appended is False
    assert retry.appended is False
    assert history.read(now=NOW) == (newest,)


def test_history_rejects_malformed_and_oversized_document(tmp_path) -> None:
    path = tmp_path / "cache-history.json"
    path.write_text("{not-json", encoding="utf-8")
    history = CacheTelemetryHistoryV1(path)
    with pytest.raises(CacheTelemetryHistoryError, match="invalid_history_document"):
        history.read(now=NOW)
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(CacheTelemetryHistoryError, match="invalid_history_document"):
        history.read(now=NOW)
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(CacheTelemetryHistoryError, match="history_too_large"):
        history.read(now=NOW)


def test_reset_and_cache_aggregation_is_deterministic_and_redacted() -> None:
    event = normalize_openai_responses({"usage": {"input_tokens": 8}}, context())
    aggregates = aggregate_cache_telemetry((reset(), event), window_seconds=3600)

    assert [item.to_dict() for item in aggregates] == [item.to_dict() for item in aggregate_cache_telemetry((event, reset()), window_seconds=3600)]
    reset_aggregate = next(item for item in aggregates if item.lifecycle == "persistent")
    assert reset_aggregate.reset_kind_counts == (("crash_recovery", 1),)
    assert reset_aggregate.reset_coverage == "partial"
    assert reset_aggregate.recovery_coverage == "unknown"
    assert reset_aggregate.coverage == "partial"
    assert "actual-cache-key" not in json.dumps([item.to_dict() for item in aggregates])


def test_reset_round_trips_through_the_same_history_without_capsule_content(tmp_path) -> None:
    history = CacheTelemetryHistoryV1(tmp_path / "cache-history.json")
    history.append(reset(), now=NOW)

    restored = history.read(now=NOW)

    assert restored == (reset(),)
    assert restored[0].to_dict()["resume_capsule_generation"] == 1
