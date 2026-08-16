from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master.admission import (
    AdmissionPriority,
    AdmissionState,
    AdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from codex_master.admission_journal import CompletionJournalError, FileCompletionJournal
from codex_master.admission_runtime import ADMISSION_RUNTIME_GATES, AdmissionRuntimeError, RuntimeGateDecision, ServerAdmissionRuntime
from codex_master.hive.events import HiveEventStore
from codex_master.selection_service import SelectionService


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def admission():
    return create_admission(
        admission_id="adm-journal",
        request_id="req-journal",
        dispatch_id="dsp-journal",
        workpackage_id="wp-journal",
        assignment_intent_id="intent-journal",
        repo_id="codex-master",
        principal_id="specialist-1",
        parent_principal_id="teamlead-1",
        grant_id="grant-journal",
        grant_digest="sha256:grant-journal",
        work_item_version=1,
        scope=ScopeBinding("write", ("src",), "sha256:scope-journal"),
        resource=ResourceBinding("agent-journal", "account-journal", "standard", "gpt-primary", 1),
        lease_context=LeaseBinding("available"),
        priority=AdmissionPriority("DP1", "selection"),
        now=NOW,
    )


def executing_record():
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=reserved.revision, now=NOW)
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=NOW,
    )
    return store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)


def allow_all():
    return {
        name: (lambda _record, name=name: RuntimeGateDecision(True, f"{name}_verified"))
        for name in ADMISSION_RUNTIME_GATES
    }


def test_file_completion_journal_survives_reload_without_result_values(tmp_path: Path) -> None:
    record = executing_record()
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)

    journal.record_started(record, "assign")
    assert journal.status(record.admission_id)["state"] == "started"
    journal.record_completed(record, "assign", {"status": "ok", "api_token": "must-not-persist"})

    reloaded = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    assert reloaded.execution_completed(record) is True
    assert reloaded.status(record.admission_id) == {
        "present": True,
        "revision": record.revision,
        "state": "completed",
        "raw_output": "not_returned",
    }
    raw = (tmp_path / "journal" / "admission-completion.json").read_text(encoding="utf-8")
    assert "must-not-persist" not in raw
    assert "api_token" not in raw


def test_file_completion_journal_can_emit_sanitized_hive_events(tmp_path: Path) -> None:
    record = executing_record()
    events = HiveEventStore(tmp_path / "events", now=lambda: NOW)
    journal = FileCompletionJournal(tmp_path / "journal", event_store=events, now=lambda: NOW)

    journal.record_started(record, "assign")
    journal.record_started(record, "assign")
    journal.record_completed(record, "assign", {"status": "ok", "api_token": "must-not-persist"})
    journal.record_completed(record, "assign", {"status": "ok", "api_token": "must-not-persist"})

    _, report_events = events.read_report_sources()

    assert [event["status"] for event in report_events] == ["executing", "completed"]
    raw = (tmp_path / "events" / "events.jsonl").read_text(encoding="utf-8")
    assert "must-not-persist" not in raw


def test_file_completion_journal_is_idempotent_but_rejects_revision_or_operation_conflicts(tmp_path: Path) -> None:
    record = executing_record()
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    journal.record_started(record, "assign")
    journal.record_started(record, "assign")

    with pytest.raises(CompletionJournalError, match="completion_operation_conflict"):
        journal.record_started(record, "cancel")
    with pytest.raises(CompletionJournalError, match="completion_operation_conflict"):
        journal.record_completed(record, "cancel", {"status": "ok"})

    changed_binding = replace(record, grant_digest="sha256:" + "f" * 64)
    with pytest.raises(CompletionJournalError, match="completion_binding_conflict"):
        journal.record_started(changed_binding, "assign")

    completed = record.advance(AdmissionState.FINALIZED, now=NOW)
    with pytest.raises(CompletionJournalError, match="completion_revision_conflict"):
        journal.record_completed(completed, "assign", {"status": "ok"})


def test_completion_evidence_is_bound_to_assignment_metadata(tmp_path: Path) -> None:
    record = executing_record()
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    journal.record_started(record, "assign")
    journal.record_completed(record, "assign", {"status": "ok"})

    changed = replace(record, grant_digest="sha256:" + "e" * 64)
    fresh = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    assert fresh.execution_completed(changed) is False


def test_runtime_writes_completion_before_a_fresh_process_recovers(tmp_path: Path) -> None:
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    executed: list[str] = []
    runtime = ServerAdmissionRuntime(
        allow_all(),
        execute=lambda _record, operation: executed.append(operation) or {"status": "ok"},
        completion_journal=journal,
        now=lambda: NOW,
    )
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=reserved.revision, now=NOW)
    assert runtime.revalidate(revalidating) is True
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=NOW,
    )
    executing = store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)

    assert runtime.execute(executing, "assign") == {"status": "ok"}
    assert executed == ["assign"]
    fresh_runtime = ServerAdmissionRuntime(allow_all(), completion_journal=FileCompletionJournal(tmp_path / "journal", now=lambda: NOW))
    assert fresh_runtime.execution_completed(executing) is True


def test_runtime_rejects_ambiguous_completion_sources_and_journal_failure(tmp_path: Path) -> None:
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    with pytest.raises(AdmissionRuntimeError, match="ambiguous_completion_evidence"):
        ServerAdmissionRuntime(
            allow_all(),
            execution_completed=lambda _record: True,
            completion_journal=journal,
        )

    record = executing_record()
    runtime = ServerAdmissionRuntime(allow_all(), completion_journal=journal, now=lambda: NOW)
    with pytest.raises(AdmissionRuntimeError, match="runtime_not_revalidated"):
        runtime.execute(record, "assign")


def test_selection_recovery_uses_persisted_completion_evidence(tmp_path: Path) -> None:
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=reserved.revision, now=NOW)
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=NOW,
    )
    executing = store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)
    journal = FileCompletionJournal(tmp_path / "journal", now=lambda: NOW)
    journal.record_started(executing, "assign")
    journal.record_completed(executing, "assign", {"status": "ok"})
    runtime = ServerAdmissionRuntime(allow_all(), completion_journal=journal, now=lambda: NOW)

    result = SelectionService(store, runtime, now=lambda: NOW).reconcile_incomplete()

    assert result == {"recovered": 1, "compensated": 0, "unresolved": 0, "raw_output": "not_returned"}
    assert store.get(executing.admission_id).state is AdmissionState.FINALIZED
