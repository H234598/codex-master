from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest

from codex_master.hive.events import HiveEventError, HiveEventStore
from codex_master.hive.messages import validate_message


NOW = datetime(2026, 8, 16, 10, 5, tzinfo=UTC)


def hive_message(message_type: str, *, message_id: str, payload: dict[str, object]) -> object:
    return validate_message({
        "schema_version": 1,
        "message_id": message_id,
        "correlation_id": "request-one",
        "causation_id": None,
        "message_type": message_type,
        "sender": {"principal_id": "specialist-one", "class_id": "spezialistin"},
        "recipient": {"principal_id": "lead-one", "class_id": "teamleiterin"},
        "repo_id": "codex-master",
        "dispatch_id": "dispatch-one",
        "workpackage_id": "workpackage-one",
        "dispatch_priority": "DP1",
        "created_at_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
        "authorization": {"grant_id": "grant-one", "scope_digest": "sha256:scope", "principal_version": 1},
        "payload": payload,
        "raw_output": "not_returned",
    })


def test_hive_event_store_persists_assignment_and_completion_without_payload(tmp_path: Path) -> None:
    store = HiveEventStore(tmp_path / "hive")
    store.append_message(hive_message("workpackage.assign", message_id="assign-one", payload={"secret": "TOKEN"}))
    store.append_message(
        hive_message(
            "completion",
            message_id="complete-one",
            payload={"status": "completed", "response": "PRIVATE_RESULT", "raw_output": "not_returned"},
        )
    )

    assignments, events = store.read_report_sources()

    assert assignments == (
        {
            "assignment_id": "workpackage-one",
            "created_at_utc": NOW.isoformat(),
            "agent": "lead-one",
        },
    )
    assert events[0]["assignment_id"] == "workpackage-one"
    assert events[0]["status"] == "completed"
    assert events[0]["agent"] == "specialist-one"
    raw = (tmp_path / "hive" / "events.jsonl").read_text(encoding="utf-8")
    assert "TOKEN" not in raw
    assert "PRIVATE_RESULT" not in raw


def test_hive_event_store_records_queue_completion_for_reporter(tmp_path: Path) -> None:
    store = HiveEventStore(tmp_path / "hive")
    store.append_queue_transition(
        "workpackage-one",
        "queued",
        at_utc=NOW,
        dispatch_id="dispatch-one",
        repo_id="codex-master",
        agent_id="agent-one",
    )
    store.append_queue_transition(
        "workpackage-one",
        "completed",
        at_utc=NOW + timedelta(minutes=10),
        dispatch_id="dispatch-one",
        repo_id="codex-master",
        agent_id="agent-one",
    )

    assignments, events = store.read_report_sources()

    assert assignments == (
        {
            "assignment_id": "workpackage-one",
            "created_at_utc": NOW.isoformat(),
            "agent": "agent-one",
        },
    )
    assert [event["status"] for event in events] == ["queued", "completed"]
    records = [
        json.loads(line)
        for line in (tmp_path / "hive" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert all(record["raw_output"] == "not_returned" for record in records)


def test_hive_event_store_rejects_tampered_record_schema(tmp_path: Path) -> None:
    store = HiveEventStore(tmp_path / "hive")
    path = tmp_path / "hive" / "events.jsonl"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "record_kind": "event",
            "event_id": "event-one",
            "at_utc": NOW.isoformat(),
            "assignment_id": "workpackage-one",
            "agent": "agent-one",
            "status": "completed",
            "raw_output": "PRIVATE_RESULT",
        }) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(HiveEventError, match="hive_event_log_invalid"):
        store.read_report_sources()


def test_hive_event_store_is_idempotent_for_explicit_event_id(tmp_path: Path) -> None:
    store = HiveEventStore(tmp_path / "hive")
    for _ in range(2):
        store.append_queue_transition(
            "workpackage-one",
            "completed",
            at_utc=NOW,
            agent_id="agent-one",
            event_id="event-one",
        )

    _, events = store.read_report_sources()

    assert len(events) == 1
