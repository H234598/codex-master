"""Runtime boundary for authoritative execution admission.

The selection service deliberately knows nothing about the server's provider,
lease, process, or repository state.  This module is the narrow adapter
contract between both layers.  Every gate must return typed, data-sparse
evidence; a missing gate, malformed result, stale admission, or callback
failure denies execution.  The adapter never performs a mutation itself.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Protocol

from codex_master.admission import AdmissionRecord, AdmissionState
from codex_master.admission_journal import CompletionJournal, CompletionJournalError


ADMISSION_RUNTIME_GATES = (
    "authority",
    "repository",
    "scope",
    "account",
    "model",
    "usage",
    "lease",
    "process",
    "auth",
    "config",
)
MAX_REASON_LENGTH = 96
MAX_OPERATION_LENGTH = 128


class AdmissionRuntimeError(RuntimeError):
    """Raised when the runtime adapter cannot authorize or execute safely."""


@dataclass(frozen=True, slots=True)
class RuntimeGateDecision:
    """Bounded public evidence from one authoritative gate."""

    allowed: bool
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise AdmissionRuntimeError("invalid_runtime_gate_decision")
        if (
            not isinstance(self.reason_code, str)
            or not 1 <= len(self.reason_code) <= MAX_REASON_LENGTH
            or any(not (char.isalnum() or char in {"_", "-"}) for char in self.reason_code)
        ):
            raise AdmissionRuntimeError("invalid_runtime_gate_decision")

    def public(self) -> dict[str, object]:
        return {"allowed": self.allowed, "reason_code": self.reason_code}


class AdmissionGate(Protocol):
    def __call__(self, admission: AdmissionRecord) -> RuntimeGateDecision:
        """Return fresh, typed evidence for one admission gate."""


class AdmissionExecutor(Protocol):
    def __call__(self, admission: AdmissionRecord, operation: str) -> Mapping[str, object]:
        """Invoke an existing low-level operation after all gates pass."""


class CompletionEvidence(Protocol):
    def __call__(self, admission: AdmissionRecord) -> bool:
        """Return positive evidence that a crashed operation completed."""


class ServerAdmissionRuntime:
    """Fail-closed adapter used by the server-facing SelectionService.

    The gate mapping is intentionally explicit.  In particular, callers must
    provide the authority, repository, scope, and resource bindings from the
    Hive/Work runtime; those facts cannot be inferred from an agent id or a
    prompt.  Successful revalidation is single-use for one admission revision,
    which prevents a direct executor call from replaying an older decision.
    """

    def __init__(
        self,
        gates: Mapping[str, AdmissionGate | None],
        *,
        execute: AdmissionExecutor | None = None,
        execution_completed: CompletionEvidence | None = None,
        completion_journal: CompletionJournal | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(gates, Mapping):
            raise AdmissionRuntimeError("invalid_runtime_gates")
        unknown = set(gates) - set(ADMISSION_RUNTIME_GATES)
        if unknown:
            raise AdmissionRuntimeError("unknown_runtime_gate")
        if execute is not None and not callable(execute):
            raise AdmissionRuntimeError("invalid_runtime_executor")
        if execution_completed is not None and not callable(execution_completed):
            raise AdmissionRuntimeError("invalid_completion_evidence")
        if completion_journal is not None and (
            not callable(getattr(completion_journal, "record_started", None))
            or not callable(getattr(completion_journal, "record_completed", None))
            or not callable(getattr(completion_journal, "execution_completed", None))
        ):
            raise AdmissionRuntimeError("invalid_completion_journal")
        if completion_journal is not None and execution_completed is not None:
            raise AdmissionRuntimeError("ambiguous_completion_evidence")
        self._gates = dict(gates)
        self._execute = execute
        self._execution_completed = execution_completed
        self._completion_journal = completion_journal
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._revalidated: dict[str, int] = {}
        self._last_failure: RuntimeGateDecision | None = None

    def revalidate(self, admission: AdmissionRecord) -> bool:
        """Run every gate in a fixed order and remember one successful revision."""

        if not isinstance(admission, AdmissionRecord):
            return self._deny("invalid_admission")
        if admission.state is not AdmissionState.REVALIDATING:
            return self._deny("invalid_admission_state")
        try:
            now = self._now()
            if not isinstance(now, datetime) or now.tzinfo is None or admission.is_expired(now):
                return self._deny("admission_expired")
        except (TypeError, ValueError, OverflowError):
            return self._deny("runtime_clock_unavailable")

        for name in ADMISSION_RUNTIME_GATES:
            gate = self._gates.get(name)
            if not callable(gate):
                return self._deny(f"missing_{name}_gate")
            try:
                decision = gate(admission)
            except Exception:
                return self._deny(f"{name}_gate_unavailable")
            if not isinstance(decision, RuntimeGateDecision):
                return self._deny("invalid_runtime_gate_decision")
            if not decision.allowed:
                return self._deny(decision.reason_code)

        with self._lock:
            self._revalidated[admission.admission_id] = admission.revision
            self._last_failure = None
        return True

    def execute(self, admission: AdmissionRecord, operation: str) -> Mapping[str, object]:
        """Consume a successful revalidation and call the injected executor once."""

        if not isinstance(admission, AdmissionRecord):
            raise AdmissionRuntimeError("invalid_admission")
        if admission.state is not AdmissionState.EXECUTING:
            raise AdmissionRuntimeError("invalid_admission_state")
        if (
            not isinstance(operation, str)
            or not 1 <= len(operation) <= MAX_OPERATION_LENGTH
            or any(ord(char) < 32 for char in operation)
        ):
            raise AdmissionRuntimeError("invalid_runtime_operation")
        with self._lock:
            revalidated_revision = self._revalidated.get(admission.admission_id)
            if revalidated_revision is None or admission.revision <= revalidated_revision:
                raise AdmissionRuntimeError("runtime_not_revalidated")
        if self._completion_journal is not None:
            try:
                self._completion_journal.record_started(admission, operation)
            except (CompletionJournalError, OSError, RuntimeError, TypeError, ValueError) as exc:
                raise AdmissionRuntimeError("completion_journal_unavailable") from exc
        with self._lock:
            if self._revalidated.get(admission.admission_id) != revalidated_revision:
                raise AdmissionRuntimeError("runtime_not_revalidated")
            del self._revalidated[admission.admission_id]
        if not callable(self._execute):
            raise AdmissionRuntimeError("runtime_execution_unavailable")
        result = self._execute(admission, operation)
        if not isinstance(result, Mapping):
            raise AdmissionRuntimeError("runtime_result_invalid")
        if self._completion_journal is not None:
            try:
                self._completion_journal.record_completed(admission, operation, result)
            except (CompletionJournalError, OSError, RuntimeError, TypeError, ValueError) as exc:
                raise AdmissionRuntimeError("completion_journal_unavailable") from exc
        return dict(result)

    def execution_completed(self, admission: AdmissionRecord) -> bool:
        """Read only positive completion evidence; unknown means incomplete."""

        if self._completion_journal is not None:
            try:
                return self._completion_journal.execution_completed(admission) is True
            except (CompletionJournalError, OSError, RuntimeError, TypeError, ValueError):
                return False
        if not callable(self._execution_completed):
            return False
        try:
            result = self._execution_completed(admission)
        except Exception:
            return False
        return result is True

    def last_failure(self) -> dict[str, object] | None:
        """Return only the last bounded gate reason for local diagnostics."""

        with self._lock:
            return None if self._last_failure is None else self._last_failure.public()

    def _deny(self, reason_code: str) -> bool:
        try:
            decision = RuntimeGateDecision(False, reason_code)
        except AdmissionRuntimeError:
            decision = RuntimeGateDecision(False, "runtime_gate_denied")
        with self._lock:
            self._last_failure = decision
        return False
