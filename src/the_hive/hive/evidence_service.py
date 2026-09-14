"""Single service contract shared by Hive test-evidence adapters."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from the_hive.hive.evidence_receipts import EvidenceReceiptV1
from the_hive.hive.indexed_tests import TestIndexV1
from the_hive.hive.evidence_planner import PlanRequestV1, PlanResultV1, TestPlanner
from the_hive.hive.evidence_runner import TestEvidenceRunner
from the_hive.hive.evidence_store import TestStatusStore


def probe_test_index(repository_root: Path | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "valid": False,
        "reason_code": "test.index_missing",
        "raw_output": "not_returned",
    }


def build_local_test_service(
    repository_root: Path | None = None,
    state_root: Path | None = None,
) -> HiveTestEvidenceService:
    raise ValueError("test.index_missing")


class HiveTestEvidenceService:
    """Bind validated index, local executor and private evidence state."""

    def __init__(
        self,
        index: TestIndexV1,
        store: TestStatusStore,
        runner: TestEvidenceRunner,
    ) -> None:
        self._index = index
        self._store = store
        self._runner = runner
        self._planner = TestPlanner()

    def request(
        self,
        *,
        changed_paths: Sequence[str] = (),
        function_ids: Sequence[str] = (),
        requested_phase: str = "change",
        base_revision: str = "working-tree",
        target_revision: str = "working-tree",
    ) -> PlanRequestV1:
        return PlanRequestV1(
            repository_id=self._index.repository_id,
            index_digest=self._index.digest,
            base_revision=base_revision,
            target_revision=target_revision,
            changed_paths=tuple(sorted(set(changed_paths))),
            function_ids=tuple(sorted(set(function_ids))),
            requested_phase=requested_phase,
            executor_fingerprint=self._runner.executor_fingerprint,
            boot_id_digest=self._runner.boot_id_digest,
            runner_version_digest=self._runner.runner_version_digest,
            environment_digest=self._runner.environment_digest,
        )

    def index_status(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "repository_id": self._index.repository_id,
            "index_generation": self._index.generation,
            "index_digest": self._index.digest,
            "valid": True,
            "function_count": len(self._index.functions),
            "test_count": len(self._index.tests),
            "gate_count": len(self._index.gates),
        }

    def plan(self, request: PlanRequestV1, *, now_monotonic_ns: int) -> PlanResultV1:
        receipts, revoked, _ = self._store.snapshot(
            self._index.repository_id,
            self._runner.executor_fingerprint,
            now_monotonic_ns=now_monotonic_ns,
        )
        return self._planner.plan(
            request,
            self._index,
            evidence=receipts,
            revoked_evidence_ids=revoked,
            now_monotonic_ns=now_monotonic_ns,
        )

    def run(self, test_id: str, *, expected_index_digest: str) -> EvidenceReceiptV1:
        return self._runner.run(
            self._index,
            test_id,
            expected_index_digest=expected_index_digest,
        )

    def status(self, request: PlanRequestV1, *, now_monotonic_ns: int) -> dict[str, object]:
        return self._store.status(self._index, request, now_monotonic_ns=now_monotonic_ns)

    def invalidate(self, evidence_id: str, *, expected_index_digest: str) -> None:
        if expected_index_digest != self._index.digest:
            raise ValueError("test.generation_stale")
        self._store.invalidate(
            self._index.repository_id,
            self._runner.executor_fingerprint,
            evidence_id,
        )


__all__ = [
    "HiveTestEvidenceService",
    "build_local_test_service",
    "probe_test_index",
]
