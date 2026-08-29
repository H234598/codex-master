from __future__ import annotations

from codex_master.hive.test_index import TestIndexV1 as IndexV1
from codex_master.hive.test_planner import PlanRequestV1, TestPlanner

from test_hive_test_index import DIGEST_A, DIGEST_B, valid_index


def test_planner_selects_only_tests_covering_changed_functions() -> None:
    index = IndexV1.from_mapping(valid_index())
    request = PlanRequestV1(
        repository_id="codex-master",
        index_digest=index.digest,
        base_revision="base",
        target_revision="target",
        changed_paths=("src/example.py",),
        function_ids=(),
        requested_phase="change",
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        runner_version_digest=DIGEST_A,
        environment_digest=DIGEST_B,
    )

    result = TestPlanner().plan(request, index, now_monotonic_ns=1)

    assert [(item.test_id, item.action, item.reason_code) for item in result.tests] == [
        ("pytest:tests/test_example.py:test_example_run", "run", "test.evidence_unavailable")
    ]


def test_merge_gate_is_always_run_even_with_fresh_evidence() -> None:
    value = valid_index()
    test_id = value["tests"][0]["test_id"]
    value["gates"] = [
        {
            "gate_id": "merge",
            "phase": "merge",
            "test_ids": [test_id],
            "cooldown_allowed": False,
            "required": True,
        }
    ]
    index = IndexV1.from_mapping(value)
    request = PlanRequestV1(
        repository_id="codex-master",
        index_digest=index.digest,
        base_revision="base",
        target_revision="target",
        changed_paths=(),
        function_ids=(),
        requested_phase="merge",
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        runner_version_digest=DIGEST_A,
        environment_digest=DIGEST_B,
    )

    result = TestPlanner().plan(request, index, evidence={}, now_monotonic_ns=1)

    assert len(result.tests) == 1
    assert result.tests[0].gate_id == "merge"
    assert (result.tests[0].action, result.tests[0].reason_code) == (
        "run",
        "test.gate_required",
    )
