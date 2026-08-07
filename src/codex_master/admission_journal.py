"""Private, bounded completion evidence for cross-process admission recovery.

The journal records only opaque admission metadata, a revision, hashed
operation/binding labels, and whether the low-level executor returned
successfully. It never persists prompts, provider responses, credentials,
paths, or result values. A missing, malformed, stale, or conflicting record is
treated as unknown completion evidence by the runtime adapter.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Callable

from codex_master.admission import AdmissionRecord
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_JOURNAL_RECORDS = 4096
MAX_OPERATION_LENGTH = 128
_JOURNAL_RELATIVE_PATH = PurePosixPath("admission-completion.json")


class CompletionJournalError(RuntimeError):
    """Raised when completion evidence cannot be safely persisted."""


class CompletionJournal:
    """Protocol-shaped base class used by :class:`ServerAdmissionRuntime`."""

    def record_started(self, admission: AdmissionRecord, operation: str) -> None:
        raise NotImplementedError

    def record_completed(
        self,
        admission: AdmissionRecord,
        operation: str,
        result: Mapping[str, object],
    ) -> None:
        raise NotImplementedError

    def execution_completed(self, admission: AdmissionRecord) -> bool:
        raise NotImplementedError


class FileCompletionJournal(CompletionJournal):
    """Atomic private journal backed by :class:`HiveStateStore`.

    ``record_started`` is intentionally durable before the executor is
    called. If the process dies after the external operation but before
    ``record_completed``, recovery remains unresolved instead of guessing.
    """

    def __init__(
        self,
        state_root: Path,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            self._state = HiveStateStore(state_root)
        except HiveStateError as exc:
            raise CompletionJournalError("invalid_completion_journal_root") from exc
        self._now = now or (lambda: datetime.now(timezone.utc))

    def record_started(self, admission: AdmissionRecord, operation: str) -> None:
        self._validate_inputs(admission, operation)
        with self._state.locked():
            records = self._load_locked()
            current = records.get(admission.admission_id)
            if current is not None:
                if current["revision"] != admission.revision:
                    raise CompletionJournalError("completion_revision_conflict")
                if current["binding_digest"] != _admission_binding_digest(admission):
                    raise CompletionJournalError("completion_binding_conflict")
                if current["state"] == "completed":
                    raise CompletionJournalError("completion_already_recorded")
                if current["operation_digest"] != _digest(operation):
                    raise CompletionJournalError("completion_operation_conflict")
                return
            if len(records) >= MAX_JOURNAL_RECORDS:
                raise CompletionJournalError("completion_journal_full")
            records[admission.admission_id] = self._started_payload(admission, operation)
            self._write_locked(records)

    def record_completed(
        self,
        admission: AdmissionRecord,
        operation: str,
        result: Mapping[str, object],
    ) -> None:
        self._validate_inputs(admission, operation)
        if not isinstance(result, Mapping):
            raise CompletionJournalError("invalid_completion_result")
        with self._state.locked():
            records = self._load_locked()
            current = records.get(admission.admission_id)
            if current is None:
                raise CompletionJournalError("completion_start_missing")
            if current["revision"] != admission.revision:
                raise CompletionJournalError("completion_revision_conflict")
            if current["binding_digest"] != _admission_binding_digest(admission):
                raise CompletionJournalError("completion_binding_conflict")
            if current["operation_digest"] != _digest(operation):
                raise CompletionJournalError("completion_operation_conflict")
            if current["state"] == "completed":
                return
            records[admission.admission_id] = {
                **current,
                "state": "completed",
                "result_shape_digest": _result_shape_digest(result),
                "updated_at_utc": self._timestamp(),
            }
            self._write_locked(records)

    def execution_completed(self, admission: AdmissionRecord) -> bool:
        if not isinstance(admission, AdmissionRecord):
            return False
        try:
            with self._state.locked():
                record = self._load_locked().get(admission.admission_id)
        except (CompletionJournalError, HiveStateError, OSError, TypeError, ValueError):
            return False
        return bool(
            record is not None
            and record.get("state") == "completed"
            and record.get("revision") == admission.revision
            and record.get("binding_digest") == _admission_binding_digest(admission)
        )

    def status(self, admission_id: str) -> dict[str, object]:
        """Return bounded diagnostics without exposing journal internals."""

        if not isinstance(admission_id, str) or not admission_id:
            raise CompletionJournalError("invalid_completion_admission")
        with self._state.locked():
            record = self._load_locked().get(admission_id)
        if record is None:
            return {"present": False, "state": "unknown", "raw_output": "not_returned"}
        return {
            "present": True,
            "revision": record["revision"],
            "state": record["state"],
            "raw_output": "not_returned",
        }

    def _validate_inputs(self, admission: AdmissionRecord, operation: str) -> None:
        if not isinstance(admission, AdmissionRecord):
            raise CompletionJournalError("invalid_completion_admission")
        if (
            not isinstance(operation, str)
            or not 1 <= len(operation) <= MAX_OPERATION_LENGTH
            or any(ord(char) < 32 for char in operation)
        ):
            raise CompletionJournalError("invalid_completion_operation")

    def _load_locked(self) -> dict[str, dict[str, object]]:
        try:
            payload = self._state.read_json_locked(_JOURNAL_RELATIVE_PATH, max_bytes=4 * 1024 * 1024)
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return {}
            raise CompletionJournalError("completion_journal_invalid") from exc
        if payload.get("schema_version") != 1 or not isinstance(payload.get("records"), list):
            raise CompletionJournalError("completion_journal_invalid")
        raw_records = payload["records"]
        if len(raw_records) > MAX_JOURNAL_RECORDS:
            raise CompletionJournalError("completion_journal_full")
        result: dict[str, dict[str, object]] = {}
        for raw in raw_records:
            if not isinstance(raw, Mapping):
                raise CompletionJournalError("completion_journal_invalid")
            if set(raw) != {
                "admission_id",
                "revision",
                "binding_digest",
                "operation_digest",
                "state",
                "result_shape_digest",
                "updated_at_utc",
            }:
                raise CompletionJournalError("completion_journal_invalid")
            admission_id = raw["admission_id"]
            revision = raw["revision"]
            if (
                not isinstance(admission_id, str)
                or not admission_id
                or isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
                or not _is_digest(raw["binding_digest"])
                or raw["state"] not in {"started", "completed"}
                or not _is_digest(raw["operation_digest"])
                or raw["result_shape_digest"] is not None
                and not _is_digest(raw["result_shape_digest"])
                or not isinstance(raw["updated_at_utc"], str)
            ):
                raise CompletionJournalError("completion_journal_invalid")
            if admission_id in result:
                raise CompletionJournalError("duplicate_completion_admission")
            result[admission_id] = dict(raw)
        return result

    def _write_locked(self, records: Mapping[str, Mapping[str, object]]) -> None:
        payload = {
            "schema_version": 1,
            "records": [dict(value) for value in records.values()],
        }
        try:
            self._state.replace_json_locked(_JOURNAL_RELATIVE_PATH, payload)
        except HiveStateError as exc:
            raise CompletionJournalError("completion_journal_write_failed") from exc

    def _started_payload(self, admission: AdmissionRecord, operation: str) -> dict[str, object]:
        return {
            "admission_id": admission.admission_id,
            "revision": admission.revision,
            "binding_digest": _admission_binding_digest(admission),
            "operation_digest": _digest(operation),
            "state": "started",
            "result_shape_digest": None,
            "updated_at_utc": self._timestamp(),
        }

    def _timestamp(self) -> str:
        value = self._now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise CompletionJournalError("completion_clock_unavailable")
        return value.astimezone(timezone.utc).isoformat()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(
        char in "0123456789abcdef" for char in value[7:]
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _admission_binding_digest(admission: AdmissionRecord) -> str:
    """Hash assignment metadata without persisting private values or paths."""

    payload = {
        "schema_version": admission.schema_version,
        "admission_id": admission.admission_id,
        "request_id": admission.request_id,
        "dispatch_id": admission.dispatch_id,
        "workpackage_id": admission.workpackage_id,
        "assignment_intent_id": admission.assignment_intent_id,
        "repo_id": admission.repo_id,
        "principal_digest": _digest(admission.principal_id),
        "parent_principal_digest": _digest(admission.parent_principal_id),
        "grant_id": admission.grant_id,
        "grant_digest": admission.grant_digest,
        "work_item_version": admission.work_item_version,
        "scope": {"mode": admission.scope.mode, "digest": admission.scope.canonical_digest},
        "resource": {
            "agent_id": admission.resource.agent_id,
            "account_digest": _digest(admission.resource.account_key),
            "budget_key": admission.resource.budget_key,
            "model_id": admission.resource.model_id,
            "expected_usage_micro": admission.resource.expected_usage_micro,
        },
        "lease": {
            "expected_state": admission.lease_context.expected_state,
            "lease_digest": (
                _digest(admission.lease_context.lease_id)
                if admission.lease_context.lease_id is not None else None
            ),
        },
        "priority": {
            "dispatch": admission.priority.dispatch,
            "selection_reason": admission.priority.selection_reason,
        },
    }
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return _digest(canonical)


def _result_shape_digest(result: Mapping[str, object]) -> str:
    """Hash only the bounded result container type; never serialize values."""

    return _digest(type(result).__name__)


__all__ = ["CompletionJournal", "CompletionJournalError", "FileCompletionJournal"]
