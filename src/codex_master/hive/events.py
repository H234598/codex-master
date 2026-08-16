"""Private, bounded Hive queue and completion evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
from typing import Callable

from codex_master.hive.messages import (
    HiveMessage,
    HiveMessageError,
    REPORT_MESSAGE_TYPES,
    record_child_report,
)
from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.hive.types import HiveValidationError, validate_identifier, validate_utc_datetime


MAX_EVENT_RECORDS = 4096
MAX_EVENT_BYTES = 512 * 1024
_EVENTS_PATH = PurePosixPath("events.jsonl")
_ASSIGNMENT_MESSAGE_TYPES = frozenset({"workpackage.assign", "assignment.intent", "admission.planned"})
_EVENT_STATUSES = frozenset({
    "assigned", "planned", "ready", "queued", "admission_planned", "admitted", "executing", "integrating",
    "completed", "blocked", "decision_required", "failed", "compensating", "failed_final", "paused",
    "cancelled", "timeout", "rate_limited",
})


class HiveEventError(ValueError):
    """Raised when Hive event evidence is invalid or unavailable."""


class HiveEventStore:
    """Persist only sanitized queue and completion metadata."""

    def __init__(self, state: Path | HiveStateStore, *, now: Callable[[], datetime] | None = None) -> None:
        try:
            self._state = state if isinstance(state, HiveStateStore) else HiveStateStore(state)
        except (HiveStateError, TypeError) as exc:
            raise HiveEventError("invalid_hive_event_state") from exc
        self._now = now or (lambda: datetime.now(timezone.utc))

    def append_message(self, message: HiveMessage) -> None:
        if not isinstance(message, HiveMessage):
            raise HiveEventError("invalid_hive_event_message")
        if message.message_type in _ASSIGNMENT_MESSAGE_TYPES:
            record = {
                "schema_version": 1,
                "record_kind": "assignment",
                "event_id": message.message_id,
                "assignment_id": _task_id(message.workpackage_id, message.dispatch_id, message.correlation_id),
                "created_at_utc": _timestamp(message.created_at_utc),
                "agent": message.recipient.principal_id,
                "raw_output": "not_returned",
            }
        elif message.message_type in REPORT_MESSAGE_TYPES:
            try:
                report = record_child_report(message)
            except HiveMessageError as exc:
                raise HiveEventError("invalid_hive_event_report") from exc
            record = {
                "schema_version": 1,
                "record_kind": "event",
                "event_id": message.message_id,
                "at_utc": _timestamp(message.created_at_utc),
                "assignment_id": _task_id(message.workpackage_id, message.dispatch_id, message.correlation_id),
                "agent": message.sender.principal_id,
                "status": report["status"],
                "raw_output": "not_returned",
            }
        else:
            raise HiveEventError("unsupported_hive_event_message")
        self._append(record)

    def append_queue_transition(
        self,
        workpackage_id: str,
        status: str,
        *,
        at_utc: datetime | None = None,
        dispatch_id: str | None = None,
        repo_id: str | None = None,
        agent_id: str = "hive-queue",
        event_id: str | None = None,
    ) -> None:
        workpackage_id = _id(workpackage_id, "workpackage")
        if not isinstance(status, str) or status not in _EVENT_STATUSES:
            raise HiveEventError("invalid_hive_event_status")
        _optional_id(dispatch_id, "dispatch")
        _optional_id(repo_id, "repo")
        agent_id = _id(agent_id, "agent")
        moment = _timestamp(at_utc or self._now())
        event_id = event_id or "queue-" + hashlib.sha256(
            f"{workpackage_id}\0{status}\0{moment}".encode("utf-8")
        ).hexdigest()[:24]
        event_id = _id(event_id, "event")
        self._append({
            "schema_version": 1,
            "record_kind": "event",
            "event_id": event_id,
            "at_utc": moment,
            "assignment_id": workpackage_id,
            "agent": agent_id,
            "status": status,
            "raw_output": "not_returned",
        })

    def read_report_sources(self) -> tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
        try:
            records = self._state.read_bounded_jsonl(
                _EVENTS_PATH,
                max_records=MAX_EVENT_RECORDS,
                max_bytes=MAX_EVENT_BYTES,
            )
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return (), ()
            raise HiveEventError("hive_event_log_unavailable") from exc
        assignments: dict[str, dict[str, str]] = {}
        assignment_order: list[str] = []
        events: list[dict[str, str]] = []
        for raw in records:
            kind = raw.get("record_kind")
            if kind == "assignment":
                _validate_record(raw, {
                    "schema_version", "record_kind", "event_id", "assignment_id", "created_at_utc", "agent",
                    "raw_output",
                })
                assignment_id = _record_id(raw, "assignment_id")
                _record_id(raw, "event_id")
                created_at = _record_timestamp(raw, "created_at_utc")
                agent = _record_id(raw, "agent")
                if assignment_id not in assignments:
                    assignment_order.append(assignment_id)
                assignments[assignment_id] = {
                    "assignment_id": assignment_id,
                    "created_at_utc": created_at,
                    "agent": agent,
                }
            elif kind == "event":
                _validate_record(raw, {
                    "schema_version", "record_kind", "event_id", "at_utc", "assignment_id", "agent", "status",
                    "raw_output",
                })
                assignment_id = _record_id(raw, "assignment_id")
                _record_id(raw, "event_id")
                at_utc = _record_timestamp(raw, "at_utc")
                agent = _record_id(raw, "agent")
                status = raw["status"]
                if not isinstance(status, str) or status not in _EVENT_STATUSES:
                    raise HiveEventError("hive_event_log_invalid")
                events.append({
                    "assignment_id": assignment_id,
                    "at_utc": at_utc,
                    "agent": agent,
                    "status": status,
                })
                if assignment_id not in assignments:
                    assignment_order.append(assignment_id)
                    assignments[assignment_id] = {
                        "assignment_id": assignment_id,
                        "created_at_utc": at_utc,
                        "agent": agent,
                    }
            else:
                raise HiveEventError("hive_event_log_invalid")
        return tuple(assignments[item] for item in assignment_order), tuple(events)

    def _append(self, record: Mapping[str, object]) -> None:
        try:
            with self._state.locked():
                current = self._state.read_bounded_jsonl_locked(
                    _EVENTS_PATH,
                    max_records=MAX_EVENT_RECORDS,
                    max_bytes=MAX_EVENT_BYTES,
                )
                if any(item.get("event_id") == record.get("event_id") for item in current):
                    return
                self._state.append_bounded_jsonl(
                    _EVENTS_PATH,
                    record,
                    max_records=MAX_EVENT_RECORDS,
                    max_bytes=MAX_EVENT_BYTES,
                )
        except HiveStateError as exc:
            raise HiveEventError("hive_event_write_failed") from exc


def _task_id(workpackage_id: str | None, dispatch_id: str | None, correlation_id: str) -> str:
    return _id(workpackage_id or dispatch_id or correlation_id, "assignment")


def _id(value: object, field: str) -> str:
    try:
        return validate_identifier(value, field=field)
    except HiveValidationError as exc:
        raise HiveEventError(str(exc)) from exc


def _optional_id(value: object, field: str) -> str | None:
    return None if value is None else _id(value, field)


def _timestamp(value: datetime) -> str:
    try:
        return validate_utc_datetime(value, field="event_timestamp").isoformat()
    except HiveValidationError as exc:
        raise HiveEventError(str(exc)) from exc


def _validate_record(record: Mapping[str, object], fields: set[str]) -> None:
    if record.keys() != fields or record.get("schema_version") != 1 or record.get("raw_output") != "not_returned":
        raise HiveEventError("hive_event_log_invalid")


def _record_id(record: Mapping[str, object], field: str) -> str:
    try:
        return _id(record.get(field), field)
    except HiveEventError as exc:
        raise HiveEventError("hive_event_log_invalid") from exc


def _record_timestamp(record: Mapping[str, object], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise HiveEventError("hive_event_log_invalid")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return validate_utc_datetime(moment, field="event_timestamp").isoformat()
    except (TypeError, ValueError, OverflowError):
        raise HiveEventError("hive_event_log_invalid") from None


__all__ = ["HiveEventError", "HiveEventStore", "MAX_EVENT_BYTES", "MAX_EVENT_RECORDS"]
