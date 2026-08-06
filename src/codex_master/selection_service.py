"""Selection orchestration below the read-only planner.

The service owns only the hand-off between a planned AdmissionRecord and an
injected runtime.  Runtime adapters decide how to perform their own fresh
provider/lease/lifecycle checks; this module never calls those systems
directly and never accepts prompt text or shell commands.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Protocol

from codex_master.admission import AdmissionError, AdmissionRecord, AdmissionState, AdmissionStore
from codex_master.selection import (
    AdmissionPolicy,
    AdmissionPreview,
    FairnessLedger,
    SelectionPolicy,
    SelectionPreview,
    SelectionCandidate,
    preview_selection,
    preview_selection_admission,
)


MAX_EXECUTION_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (0.05, 0.1, 0.2)
MAX_OPERATION_LENGTH = 128


class SelectionServiceError(RuntimeError):
    """Raised when selection orchestration cannot produce a safe result."""


class RetryableSelectionError(SelectionServiceError):
    """A runtime race that may be retried from a fresh admission plan."""


class SelectionDeniedError(SelectionServiceError):
    """The fresh runtime revalidation rejected the planned admission."""


class SelectionRuntime(Protocol):
    """External execution boundary supplied by the existing server layer."""

    def revalidate(self, admission: AdmissionRecord) -> bool:
        """Re-check all authority, scope, account, model, lease and process gates."""

    def execute(self, admission: AdmissionRecord, operation: str) -> Mapping[str, object]:
        """Invoke one existing low-level operation after revalidation."""

    def execution_completed(self, admission: AdmissionRecord) -> bool:
        """Return whether recovery evidence proves the operation already completed."""


@dataclass(frozen=True, slots=True)
class SelectionRequest:
    candidates: tuple[SelectionCandidate, ...]
    selection_policy: SelectionPolicy
    now: datetime
    ledger: FairnessLedger | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple):
            raise SelectionServiceError("selection candidates must be a tuple")
        if not isinstance(self.selection_policy, SelectionPolicy):
            raise SelectionServiceError("invalid selection policy")
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise SelectionServiceError("selection time must be timezone-aware")
        if self.ledger is not None and not isinstance(self.ledger, FairnessLedger):
            raise SelectionServiceError("invalid fairness ledger")


class SelectionService:
    """Run selection, admission, revalidation and bounded retry as one flow."""

    def __init__(
        self,
        store: AdmissionStore,
        runtime: SelectionRuntime | None = None,
        *,
        now: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        backoff_seconds: tuple[float, ...] = RETRY_BACKOFF_SECONDS,
    ) -> None:
        if not isinstance(store, AdmissionStore):
            raise SelectionServiceError("invalid admission store")
        if not all(isinstance(delay, (int, float)) and delay >= 0 for delay in backoff_seconds):
            raise SelectionServiceError("invalid retry backoff")
        if len(backoff_seconds) != MAX_EXECUTION_ATTEMPTS:
            raise SelectionServiceError("retry backoff must contain three delays")
        self._store = store
        self._runtime = runtime
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._sleep = sleeper or time.sleep
        self._backoff = backoff_seconds

    def preview(self, request: SelectionRequest) -> SelectionPreview:
        """Use the same deterministic, non-mutating planner as the server preview."""

        return preview_selection(
            request.candidates,
            policy=request.selection_policy,
            now=request.now,
            ledger=request.ledger,
        )

    def admission_preview(
        self,
        request: SelectionRequest,
        admission_policy: AdmissionPolicy,
    ) -> AdmissionPreview:
        """Bind the same preview to gates without reserving or executing."""

        if not isinstance(admission_policy, AdmissionPolicy):
            raise SelectionServiceError("invalid admission policy")
        return preview_selection_admission(
            request.candidates,
            selection_policy=request.selection_policy,
            admission_policy=admission_policy,
            now=request.now,
            ledger=request.ledger,
        )

    def plan_admission(self, plan_factory: Callable[[], AdmissionRecord]) -> AdmissionRecord:
        """Obtain one fresh planned record without reserving it."""

        if not callable(plan_factory):
            raise SelectionServiceError("invalid admission plan factory")
        record = plan_factory()
        if not isinstance(record, AdmissionRecord) or record.state is not AdmissionState.PLANNED:
            raise SelectionServiceError("admission plan must be planned")
        return record

    def execute_with_retry(
        self,
        plan_factory: Callable[[], AdmissionRecord],
        operation: str,
    ) -> Mapping[str, object]:
        """Execute at most three fresh plans, compensating every failed attempt."""

        if not isinstance(operation, str) or not 1 <= len(operation) <= MAX_OPERATION_LENGTH:
            raise SelectionServiceError("invalid operation")
        if self._runtime is None:
            raise SelectionServiceError("selection runtime is unavailable")
        last_error: BaseException | None = None
        for attempt in range(MAX_EXECUTION_ATTEMPTS):
            current: AdmissionRecord | None = None
            try:
                planned = self.plan_admission(plan_factory)
                current = self._store.reserve(planned, now=self._now())
                current = self._store.begin_revalidation(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
                if self._runtime.revalidate(current) is not True:
                    current = self._store.complete_revalidation(
                        current.admission_id, expected_revision=current.revision, valid=False, now=self._now()
                    )
                    current = self._store.compensate(
                        current.admission_id, expected_revision=current.revision, now=self._now()
                    )
                    raise SelectionDeniedError("admission revalidation denied")
                current = self._store.complete_revalidation(
                    current.admission_id, expected_revision=current.revision, valid=True, now=self._now()
                )
                current = self._store.begin_execution(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
                result = self._runtime.execute(current, operation)
                if not isinstance(result, Mapping):
                    raise SelectionServiceError("runtime result must be a mapping")
                current = self._store.finalize(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
                return {
                    "result": dict(result),
                    "admission": current.public(),
                    "attempt": attempt + 1,
                    "raw_output": "not_returned",
                }
            except RetryableSelectionError as exc:
                last_error = exc
                self._compensate(current)
            except SelectionDeniedError:
                raise
            except AdmissionError as exc:
                if current is None and _is_retryable_admission_error(exc):
                    last_error = exc
                else:
                    self._compensate(current)
                    raise SelectionServiceError("admission execution failed") from exc
            except Exception:
                self._compensate(current)
                raise
            if attempt < MAX_EXECUTION_ATTEMPTS - 1:
                self._sleep(self._backoff[attempt])
        raise SelectionServiceError("admission retry exhausted") from last_error

    def reconcile_incomplete(self) -> Mapping[str, object]:
        """Reconcile executing records from runtime evidence without re-executing."""

        if self._runtime is None:
            raise SelectionServiceError("selection runtime is unavailable")
        recovered = 0
        compensated = 0
        unresolved = 0
        for record in self._store.records_snapshot():
            if record.state is AdmissionState.EXECUTING:
                if self._runtime.execution_completed(record):
                    recovered_record = self._store.recover_after_crash(
                        record.admission_id, expected_revision=record.revision, now=self._now()
                    )
                    self._store.finalize(
                        recovered_record.admission_id,
                        expected_revision=recovered_record.revision,
                        now=self._now(),
                    )
                    recovered += 1
                else:
                    unresolved += 1
            elif record.state in {
                AdmissionState.CONFLICT,
                AdmissionState.EXPIRED,
                AdmissionState.DENIED,
                AdmissionState.CANCELLED,
            }:
                self._store.compensate(record.admission_id, expected_revision=record.revision, now=self._now())
                compensated += 1
        return {
            "recovered": recovered,
            "compensated": compensated,
            "unresolved": unresolved,
            "raw_output": "not_returned",
        }

    def _compensate(self, record: AdmissionRecord | None) -> None:
        if record is None:
            return
        try:
            current = record
            if current.state in {
                AdmissionState.RESERVED,
                AdmissionState.REVALIDATING,
                AdmissionState.ADMITTED,
            }:
                current = self._store.cancel(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
            if current.state in {AdmissionState.CANCELLED, AdmissionState.CONFLICT, AdmissionState.EXPIRED, AdmissionState.DENIED}:
                current = self._store.compensate(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
            elif current.state in {AdmissionState.EXECUTING, AdmissionState.ADMITTED}:
                current = self._store.mark_execution_failed(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
            if current.state is AdmissionState.EXECUTION_FAILED:
                current = self._store.begin_compensation(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
            if current.state is AdmissionState.COMPENSATING:
                self._store.finish_compensation(
                    current.admission_id, expected_revision=current.revision, now=self._now()
                )
        except AdmissionError:
            # The original runtime failure remains authoritative; cleanup is
            # reported by the next reconciliation pass instead of masking it.
            return


def _is_retryable_admission_error(error: AdmissionError) -> bool:
    return any(
        marker in str(error)
        for marker in ("conflict", "capacity", "stale_admission_revision", "admission_expired")
    )
