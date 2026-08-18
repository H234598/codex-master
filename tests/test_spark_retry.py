from __future__ import annotations

from codex_master.spark_retry import (
    ResumeCapsuleV1,
    apply_resume_event,
    is_capacity_retry_code,
    normalize_resume_capsule,
    serialize_resume_capsule,
)


def base_capsule_payload() -> dict:
    return {
        "schema_version": 1,
        "retry_count": 7,
        "event_sequence": 0,
        "active_window_ms": 0,
        "bee_id": "bee-001",
        "session_id": "session-77",
        "spark_requirement": "explicit_spark",
        "model": "gpt-5.3",
        "provider": "gemini",
        "effort": "high",
        "account_binding": "sha256:" + ("ab" * 32),
    }


def base_event_payload() -> dict:
    return {
        "binding": {
            "bee_id": "bee-001",
            "session_id": "session-77",
            "spark_requirement": "explicit_spark",
            "model": "gpt-5.3",
            "provider": "gemini",
            "effort": "high",
            "account_binding": "sha256:" + ("ab" * 32),
        }
    }


def test_normalization_is_strict_roundtrip_and_rejects_unknown_fields() -> None:
    base_capsule = base_capsule_payload()
    capsule = normalize_resume_capsule(base_capsule)
    dumped = serialize_resume_capsule(capsule)
    assert dumped == {
        "schema_version": 1,
        "bee_id": "bee-001",
        "session_id": "session-77",
        "spark_requirement": "explicit_spark",
        "model": "gpt-5.3",
        "provider": "gemini",
        "effort": "high",
        "account_binding": "sha256:" + ("ab" * 32),
        "retry_count": 7,
        "event_sequence": 0,
        "active_window_ms": 0,
    }

    raw = base_capsule_payload() | {
        "prompt": "secret question",
        "response": "answer",
        "credentials": {"token": "x"},
        "account_id": "acct-personal",
    }
    try:
        normalize_resume_capsule(raw)
    except ValueError:
        return
    raise AssertionError("unknown fields were accepted")


def test_normalization_rejects_invalid_account_binding_spark_requirement_or_window_shape() -> None:
    raw = base_capsule_payload() | {"schema_version": True}
    try:
        normalize_resume_capsule(raw)
    except ValueError:
        pass
    else:
        raise AssertionError("schema_version true was accepted")

    raw = base_capsule_payload() | {"account_binding": "acct-plain-id"}
    try:
        normalize_resume_capsule(raw)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid account binding was accepted")

    raw = base_capsule_payload() | {"spark_requirement": "resume-work"}
    try:
        normalize_resume_capsule(raw)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid spark_requirement was accepted")

    raw = base_capsule_payload() | {"active_window_ms": 300_000}
    try:
        normalize_resume_capsule(raw)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid window was accepted")

    invalid_window_capsule = ResumeCapsuleV1(
        bee_id="bee-001",
        session_id="session-77",
        spark_requirement="explicit_spark",
        model="gpt-5.3",
        provider="gemini",
        effort="high",
        account_binding="sha256:" + ("ab" * 32),
        retry_count=7,
        active_window_ms=300_000,
    )
    try:
        serialize_resume_capsule(invalid_window_capsule)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid active window was serialized")

    no_change = apply_resume_event(
        invalid_window_capsule,
        base_event_payload()
        | {"event_sequence": 1, "event_type": "provider", "active_duration_ms": 10_000},
    )
    assert no_change is invalid_window_capsule


def test_binding_fields_are_immutable_and_mismatch_is_fail_closed() -> None:
    capsule = normalize_resume_capsule(base_capsule_payload())
    event = base_event_payload() | {
        "event_sequence": 1,
        "event_type": "provider",
        "active_duration_ms": 10000,
        "binding": {
            "bee_id": "bee-999",
            "session_id": "session-77",
            "spark_requirement": "resume-work",
            "model": "gpt-5.3",
            "provider": "gemini",
            "effort": "high",
            "account_binding": "sha256:" + ("ab" * 32),
        },
    }

    updated = apply_resume_event(capsule, event)
    assert updated == capsule
    assert updated.retry_count == 7


def test_event_sequence_dedup_and_out_of_order_events_are_ignored() -> None:
    capsule = normalize_resume_capsule(base_capsule_payload())
    first = apply_resume_event(
        capsule,
        base_event_payload()
        | {"event_sequence": 1, "event_type": "provider", "active_duration_ms": 1000},
    )
    duplicate = apply_resume_event(
        first,
        base_event_payload()
        | {"event_sequence": 1, "event_type": "provider", "active_duration_ms": 120000},
    )
    out_of_order = apply_resume_event(
        first,
        base_event_payload()
        | {"event_sequence": 0, "event_type": "provider", "active_duration_ms": 8000},
    )

    assert duplicate == first
    assert out_of_order == first


def test_capacity_event_codes_and_non_codes_are_distinct() -> None:
    capsule = normalize_resume_capsule(base_capsule_payload())
    cap_event = base_event_payload() | {
        "event_sequence": 1,
        "event_type": "capacity",
        "error_code": "at_capacity",
    }
    non_cap_event = base_event_payload() | {
        "event_sequence": 2,
        "event_type": "capacity",
        "error_code": "token_lost",
    }
    cap_event2 = base_event_payload() | {
        "event_sequence": 3,
        "event_type": "capacity",
        "error_code": "server_overloaded",
    }

    after_cap = apply_resume_event(capsule, cap_event)
    after_non_cap = apply_resume_event(after_cap, non_cap_event)
    after_cap2 = apply_resume_event(after_non_cap, cap_event2)

    assert is_capacity_retry_code("at_capacity")
    assert is_capacity_retry_code("server_overloaded")
    assert not is_capacity_retry_code("at capacity")
    assert not is_capacity_retry_code("token_lost")
    assert after_cap.retry_count == 8
    assert after_non_cap.retry_count == 8
    assert after_cap2.retry_count == 9
    assert after_cap2.event_sequence == 3


def test_retry_counter_caps_at_fifty_retries() -> None:
    base = normalize_resume_capsule(base_capsule_payload() | {"retry_count": 49})
    near_cap = apply_resume_event(
        base,
        base_event_payload()
        | {"event_sequence": 1, "event_type": "capacity", "error_code": "at_capacity"},
    )
    at_cap = apply_resume_event(
        near_cap,
        base_event_payload()
        | {"event_sequence": 2, "event_type": "capacity", "error_code": "server_overloaded"},
    )
    blocked = apply_resume_event(
        at_cap,
        base_event_payload()
        | {"event_sequence": 3, "event_type": "capacity", "error_code": "at_capacity"},
    )

    assert near_cap.retry_count == 50
    assert at_cap.retry_count == 50
    assert blocked.retry_count == 50
    assert blocked.event_sequence == 3


def test_active_events_count_and_inactive_events_are_zeroed() -> None:
    capsule = normalize_resume_capsule(base_capsule_payload())
    after_wait = apply_resume_event(
        capsule,
        base_event_payload() | {"event_sequence": 1, "event_type": "wait", "active_duration_ms": 120000},
    )
    after_backoff = apply_resume_event(
        after_wait,
        base_event_payload() | {"event_sequence": 2, "event_type": "backoff", "active_duration_ms": 120000},
    )
    after_poll = apply_resume_event(
        after_backoff,
        base_event_payload() | {"event_sequence": 3, "event_type": "poll", "active_duration_ms": 120000},
    )
    after_liveness = apply_resume_event(
        after_poll,
        base_event_payload() | {"event_sequence": 4, "event_type": "liveness", "active_duration_ms": 120000},
    )
    assert after_wait.active_window_ms == 0
    assert after_backoff.active_window_ms == 0
    assert after_poll.active_window_ms == 0
    assert after_liveness.active_window_ms == 0
    assert after_liveness.retry_count == 7

    after_provider = apply_resume_event(
        after_liveness,
        base_event_payload() | {"event_sequence": 5, "event_type": "provider", "active_duration_ms": 500},
    )
    assert after_provider.active_window_ms == 500


def test_active_window_reset_and_capacity_before_and_after_boundary() -> None:
    base = normalize_resume_capsule(base_capsule_payload() | {"retry_count": 12, "active_window_ms": 299_900})
    before_reset = apply_resume_event(
        base,
        base_event_payload() | {"event_sequence": 1, "event_type": "capacity", "error_code": "at_capacity"},
    )
    after_reset_boundary = apply_resume_event(
        normalize_resume_capsule(
            base_capsule_payload() | {"retry_count": 12, "active_window_ms": 299_500}
        ),
        base_event_payload() | {"event_sequence": 1, "event_type": "provider", "active_duration_ms": 500},
    )
    after_capacity = apply_resume_event(
        after_reset_boundary,
        base_event_payload() | {"event_sequence": 2, "event_type": "capacity", "error_code": "at_capacity"},
    )

    assert before_reset.retry_count == 13
    assert after_reset_boundary.retry_count == 0
    assert after_reset_boundary.active_window_ms == 0
    assert after_capacity.retry_count == 1


def test_invalid_payload_and_event_types_are_fail_closed() -> None:
    capsule = normalize_resume_capsule(base_capsule_payload())
    malformed_event = base_event_payload() | {
        "event_sequence": "not-an-int",
        "event_type": "provider",
        "active_duration_ms": 10_000,
    }
    no_change = apply_resume_event(capsule, malformed_event)
    invalid_binding = base_event_payload() | {
        "event_sequence": 1,
        "event_type": "provider",
        "active_duration_ms": 10_000,
        "binding": {"bee_id": object()},
    }

    no_change_again = apply_resume_event(no_change, invalid_binding)
    assert no_change_again == capsule

    non_mapping_binding = base_event_payload() | {
        "event_sequence": 1,
        "event_type": "provider",
        "active_duration_ms": 10_000,
        "binding": "invalid",
    }
    no_change_again = apply_resume_event(no_change, non_mapping_binding)
    assert no_change_again == capsule


def test_serialize_rejects_invalid_capsule_state_and_unknown_event_field() -> None:
    invalid_capsule = ResumeCapsuleV1(
        bee_id="bee-001",
        session_id="session-77",
        spark_requirement="resume-work",
        model="gpt-5.3",
        provider="gemini",
        effort="high",
        account_binding="acct-plain-id",
        retry_count=7,
    )
    try:
        serialize_resume_capsule(invalid_capsule)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid capsule state was serialized")

    invalid_event = base_event_payload() | {
        "event_sequence": 1,
        "event_type": "provider",
        "active_duration_ms": 120_000,
        "credential": "x",
    }
    capsule = normalize_resume_capsule(base_capsule_payload())
    after = apply_resume_event(capsule, invalid_event)
    assert after == capsule
