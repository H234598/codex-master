from __future__ import annotations

from pathlib import Path

from codex_master.hive.test_runner import TestEvidenceRunner as EvidenceRunner
from codex_master.hive.test_service import HiveTestEvidenceService
from codex_master.hive.test_status_store import TestStatusStore as StatusStore

from test_hive_test_evidence import DIGEST_A, DIGEST_B
from test_hive_test_runner import project


def service(root: Path):
    index, test_id = project(root, "    assert run() == 1\n")
    store = StatusStore(root / ".state")
    runner = EvidenceRunner(
        root,
        store,
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        environment_digest=DIGEST_A,
    )
    return HiveTestEvidenceService(index, store, runner), test_id


def test_service_plans_run_then_reuses_real_passed_receipt(tmp_path: Path) -> None:
    evidence_service, test_id = service(tmp_path)
    request = evidence_service.request(changed_paths=("src/example.py",))

    before = evidence_service.plan(request, now_monotonic_ns=1)
    receipt = evidence_service.run(test_id, expected_index_digest=request.index_digest)
    after = evidence_service.plan(request, now_monotonic_ns=receipt.finished_monotonic_ns)

    assert before.tests[0].action == "run"
    assert after.tests[0].action == "reuse"


def test_service_invalidation_turns_reuse_back_into_run(tmp_path: Path) -> None:
    evidence_service, test_id = service(tmp_path)
    request = evidence_service.request(changed_paths=("src/example.py",))
    receipt = evidence_service.run(test_id, expected_index_digest=request.index_digest)

    evidence_service.invalidate(receipt.evidence_id, expected_index_digest=request.index_digest)
    plan = evidence_service.plan(request, now_monotonic_ns=receipt.finished_monotonic_ns)

    assert (plan.tests[0].action, plan.tests[0].reason_code) == (
        "run",
        "test.evidence_stale",
    )


def test_service_index_status_is_data_sparse(tmp_path: Path) -> None:
    evidence_service, _ = service(tmp_path)

    status = evidence_service.index_status()

    assert status["valid"] is True
    assert status["function_count"] == 1
    assert status["test_count"] == 1
    assert "path" not in status
