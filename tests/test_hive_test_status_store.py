from __future__ import annotations

import os
from pathlib import Path
import stat
import json

from codex_master.hive.evidence_receipts import evaluate_evidence_reuse
from codex_master.hive.evidence_store import TestStatusStore as StatusStore
from codex_master.hive.evidence_planner import evidence_context

from test_hive_test_evidence import DIGEST_A, DIGEST_B, receipt
from test_hive_test_index import IndexV1, valid_index
from test_hive_test_planner import PlanRequestV1


def request(index_digest: str) -> PlanRequestV1:
    return PlanRequestV1(
        repository_id="codex-master",
        index_digest=index_digest,
        base_revision="base",
        target_revision="target",
        changed_paths=(),
        function_ids=(),
        requested_phase="change",
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        runner_version_digest=DIGEST_A,
        environment_digest=DIGEST_B,
    )


def matching_receipt():
    index = IndexV1.from_mapping(valid_index())
    context = evidence_context(request(index.digest), index, index.tests[0])
    return receipt(
        index_digest=context.index_digest,
        function_ids=context.function_ids,
        test_id=context.test_id,
        source_digest_set_digest=context.source_digest_set_digest,
        test_digest=context.test_digest,
        assertion_digest=context.assertion_digest,
        dependency_digest_set_digest=context.dependency_digest_set_digest,
        executor_fingerprint=context.executor_fingerprint,
        boot_id_digest=context.boot_id_digest,
        runner_version_digest=context.runner_version_digest,
        environment_digest=context.environment_digest,
    )


def test_store_round_trips_receipt_with_private_permissions(tmp_path: Path) -> None:
    store = StatusStore(tmp_path / "test-evidence" / "v1")
    value = matching_receipt()

    store.put(value)
    loaded = store.latest(value.repository_id, value.executor_fingerprint, value.test_id)

    assert loaded == value
    assert stat.S_IMODE(os.stat(tmp_path / "test-evidence" / "v1").st_mode) == 0o700
    state_files = tuple((tmp_path / "test-evidence" / "v1").rglob("*.json"))
    assert len(state_files) == 1
    assert stat.S_IMODE(os.stat(state_files[0]).st_mode) == 0o600


def test_invalidation_prevents_reuse_without_deleting_receipt(tmp_path: Path) -> None:
    store = StatusStore(tmp_path / "test-evidence" / "v1")
    value = matching_receipt()
    index = IndexV1.from_mapping(valid_index())
    context = evidence_context(request(index.digest), index, index.tests[0])
    store.put(value)

    store.invalidate(value.repository_id, value.executor_fingerprint, value.evidence_id)
    loaded = store.latest(value.repository_id, value.executor_fingerprint, value.test_id)
    decision = evaluate_evidence_reuse(
        loaded,
        context,
        now_monotonic_ns=2_000_000_000,
        revoked=store.is_revoked(value.repository_id, value.executor_fingerprint, value.evidence_id),
    )

    assert loaded == value
    assert (decision.action, decision.reason_code) == ("run", "test.evidence_stale")


def test_status_projection_reports_only_bounded_metadata(tmp_path: Path) -> None:
    store = StatusStore(tmp_path / "test-evidence" / "v1")
    value = matching_receipt()
    index = IndexV1.from_mapping(valid_index())
    store.put(value)

    status = store.status(index, request(index.digest), now_monotonic_ns=2_000_000_000)

    assert status["counts"]["passed"] == 1
    assert status["items"][0]["reuse_eligible"] is True
    assert "stdout" not in str(status)
    assert str(tmp_path) not in str(status)


def test_corrupt_record_is_never_used_as_evidence(tmp_path: Path) -> None:
    store = StatusStore(tmp_path / "test-evidence" / "v1")
    value = matching_receipt()
    store.put(value)
    state_file = next((tmp_path / "test-evidence" / "v1").rglob("*.json"))
    document = json.loads(state_file.read_text())
    document["receipts"].append({})
    state_file.write_text(json.dumps(document), encoding="utf-8")

    store.put(value)

    assert store.latest(value.repository_id, value.executor_fingerprint, value.test_id) == value
