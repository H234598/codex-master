from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from codex_master.hive.messages import HiveMessageError, record_child_report, validate_message


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def message_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "message_id": "msg-one",
        "correlation_id": "req-one",
        "causation_id": None,
        "message_type": "workpackage.assign",
        "sender": {"principal_id": "queen-one", "class_id": "koenigin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "repo-one",
        "dispatch_id": "dispatch-one",
        "workpackage_id": "workpackage-one",
        "dispatch_priority": "DP1",
        "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": {"raw_output": "not_returned", "context_digest": "sha256:context"},
        "raw_output": "not_returned",
    }


def test_message_validation_is_typed_bounded_and_public_payload_free() -> None:
    message = validate_message(message_payload())
    assert message.public()["raw_output"] == "not_returned"
    assert "payload" not in message.public()


def test_message_preserves_distinct_non_null_causation_at_wire_and_direct_boundary() -> None:
    payload = message_payload()
    payload["causation_id"] = "msg-parent"

    wire = validate_message(payload)
    direct = replace(wire)

    assert (wire.message_id, wire.correlation_id, wire.causation_id) == (
        "msg-one",
        "req-one",
        "msg-parent",
    )
    assert direct == wire
    assert direct.public() == wire.public()


def test_hive_message_constructor_rejects_self_causation_without_value_leak() -> None:
    message = validate_message(message_payload())

    with pytest.raises(HiveMessageError, match=r"^message_self_causation$") as raised:
        replace(message, causation_id=message.message_id)

    assert str(raised.value) == "message_self_causation"
    assert message.message_id not in str(raised.value)


def test_message_wire_boundary_rejects_self_causation_without_value_leak() -> None:
    payload = message_payload()
    payload["causation_id"] = payload["message_id"]

    with pytest.raises(HiveMessageError, match=r"^message_self_causation$") as raised:
        validate_message(payload)

    assert str(raised.value) == "message_self_causation"
    assert payload["message_id"] not in str(raised.value)


@pytest.mark.parametrize(
    "field,value",
    [("message_type", "unknown.type"), ("dispatch_priority", "P0"), ("raw_output", "terminal text")],
)
def test_message_rejects_unknown_types_or_raw_output(field: str, value: object) -> None:
    payload = message_payload()
    payload[field] = value
    with pytest.raises(HiveMessageError):
        validate_message(payload)


def test_message_rejects_expired_or_oversized_payload() -> None:
    payload = message_payload()
    payload["expires_at_utc"] = NOW.isoformat()
    with pytest.raises(HiveMessageError, match="invalid_message_expiry"):
        validate_message(payload)
    payload = message_payload()
    payload["payload"] = {"data": "x" * (256 * 1024)}
    with pytest.raises(HiveMessageError, match="oversize_payload"):
        validate_message(payload)


@pytest.mark.parametrize(
    ("message_type", "status", "expected"),
    (("progress.report", "executing", "executing"), ("decision.request", None, "decision_required"), ("escalation", None, "blocked")),
)
def test_child_report_is_payload_free_and_normalizes_control_status(
    message_type: str, status: str | None, expected: str
) -> None:
    payload = message_payload()
    payload["message_type"] = message_type
    payload["payload"] = {"status": status, "raw_output": "not_returned", "terminal": "private"}
    message = validate_message(payload)
    reduced = record_child_report(message)
    assert reduced["status"] == expected
    assert reduced["blocked"] is (expected in {"blocked", "failed", "decision_required"})
    assert "payload" not in reduced
    assert reduced["payload_digest"].startswith("sha256:")
    assert reduced["raw_output"] == "not_returned"


def test_child_report_rejects_non_report_message_types() -> None:
    message = validate_message(message_payload())
    with pytest.raises(HiveMessageError, match="invalid_child_report"):
        record_child_report(message)
