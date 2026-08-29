"""Minimal deterministic test planning over canonical Hive test indexes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib

from codex_master.hive.test_evidence import (
    EvidenceContextV1,
    EvidenceReceiptV1,
    evaluate_evidence_reuse,
)
from codex_master.hive.test_index import FunctionEntryV1, TestEntryV1, TestIndexV1


_PHASES = frozenset({"change", "branch", "merge", "release"})


def _digest_set(values: tuple[str, ...]) -> str:
    return "sha256:" + hashlib.sha256("\n".join(sorted(values)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PlanRequestV1:
    repository_id: str
    index_digest: str
    base_revision: str
    target_revision: str
    changed_paths: tuple[str, ...]
    function_ids: tuple[str, ...]
    requested_phase: str
    executor_fingerprint: str
    boot_id_digest: str
    runner_version_digest: str
    environment_digest: str

    def __post_init__(self) -> None:
        if self.requested_phase not in _PHASES:
            raise ValueError("test.index_invalid")
        for values in (self.changed_paths, self.function_ids):
            if tuple(sorted(set(values))) != values:
                raise ValueError("test.index_invalid")


@dataclass(frozen=True, slots=True)
class PlannedTestV1:
    test_id: str
    action: str
    reason_code: str
    evidence_id: str | None
    timeout_seconds: int
    gate_id: str | None

    def public(self) -> dict[str, object]:
        return {
            "test_id": self.test_id,
            "action": self.action,
            "reason_code": self.reason_code,
            "evidence_id": self.evidence_id,
            "timeout_seconds": self.timeout_seconds,
            "gate_id": self.gate_id,
        }


@dataclass(frozen=True, slots=True)
class PlanResultV1:
    repository_id: str
    index_digest: str
    tests: tuple[PlannedTestV1, ...]

    def public(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "index_digest": self.index_digest,
            "tests": [item.public() for item in self.tests],
        }


def evidence_context(
    request: PlanRequestV1,
    index: TestIndexV1,
    test: TestEntryV1,
) -> EvidenceContextV1:
    functions = {item.function_id: item for item in index.functions}
    covered = tuple(functions[function_id] for function_id in test.covers)
    return EvidenceContextV1(
        repository_id=index.repository_id,
        index_digest=index.digest,
        function_ids=test.covers,
        test_id=test.test_id,
        source_digest_set_digest=_digest_set(tuple(item.source_digest for item in covered)),
        test_digest=test.test_digest,
        assertion_digest=test.assertion_digest,
        dependency_digest_set_digest=_digest_set(tuple(item.dependency_digest for item in covered)),
        executor_fingerprint=request.executor_fingerprint,
        boot_id_digest=request.boot_id_digest,
        runner_version_digest=request.runner_version_digest,
        environment_digest=request.environment_digest,
    )


class TestPlanner:
    """Choose only impacted tests plus required gates, then evaluate reuse."""

    def plan(
        self,
        request: PlanRequestV1,
        index: TestIndexV1,
        *,
        evidence: Mapping[str, EvidenceReceiptV1] | None = None,
        revoked_evidence_ids: frozenset[str] = frozenset(),
        now_monotonic_ns: int,
        base_index: TestIndexV1 | None = None,
    ) -> PlanResultV1:
        if request.repository_id != index.repository_id or request.index_digest != index.digest:
            raise ValueError("test.generation_stale")
        selected_functions = self._impacted_functions(request, index, base_index)
        selected: dict[str, str | None] = {
            test_id: None
            for function in selected_functions
            for test_id in function.test_ids
        }
        gate_mandatory: set[str] = set()
        for gate in index.gates:
            if gate.required and gate.phase == request.requested_phase:
                for test_id in gate.test_ids:
                    selected[test_id] = gate.gate_id
                    if not gate.cooldown_allowed or gate.phase in {"branch", "merge", "release"}:
                        gate_mandatory.add(test_id)
        tests = {item.test_id: item for item in index.tests}
        receipts = evidence or {}
        planned: list[PlannedTestV1] = []
        for test_id in sorted(selected):
            test = tests[test_id]
            decision = evaluate_evidence_reuse(
                receipts.get(test_id),
                evidence_context(request, index, test),
                now_monotonic_ns=now_monotonic_ns,
                mandatory_gate=test_id in gate_mandatory,
                revoked=bool(
                    receipts.get(test_id)
                    and receipts[test_id].evidence_id in revoked_evidence_ids
                ),
            )
            planned.append(
                PlannedTestV1(
                    test_id,
                    decision.action,
                    decision.reason_code,
                    decision.evidence_id,
                    test.timeout_seconds,
                    selected[test_id],
                )
            )
        return PlanResultV1(index.repository_id, index.digest, tuple(planned))

    @staticmethod
    def _impacted_functions(
        request: PlanRequestV1,
        index: TestIndexV1,
        base_index: TestIndexV1 | None,
    ) -> tuple[FunctionEntryV1, ...]:
        explicit = set(request.function_ids)
        paths = set(request.changed_paths)
        base = {item.function_id: item for item in base_index.functions} if base_index is not None else {}
        impacted: list[FunctionEntryV1] = []
        for function in index.functions:
            prior = base.get(function.function_id)
            digest_changed = prior is not None and (
                prior.source_digest != function.source_digest
                or prior.dependency_digest != function.dependency_digest
            )
            if function.function_id in explicit or function.path in paths or digest_changed:
                impacted.append(function)
        return tuple(impacted)


__all__ = [
    "PlanRequestV1",
    "PlanResultV1",
    "PlannedTestV1",
    "TestPlanner",
    "evidence_context",
]
