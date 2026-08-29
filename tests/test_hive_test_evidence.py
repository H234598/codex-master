from __future__ import annotations

from dataclasses import replace

import pytest

from codex_master.hive.evidence_receipts import (
    EvidenceContextV1,
    EvidenceReceiptV1,
    evaluate_evidence_reuse,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def receipt(**overrides: object) -> EvidenceReceiptV1:
    values: dict[str, object] = {
        "repository_id": "codex-master",
        "index_digest": DIGEST_A,
        "function_ids": ("python:src/example.py:run",),
        "test_id": "pytest:tests/test_example.py:test_run",
        "source_digest_set_digest": DIGEST_A,
        "test_digest": DIGEST_A,
        "assertion_digest": DIGEST_B,
        "dependency_digest_set_digest": DIGEST_B,
        "executor_fingerprint": DIGEST_A,
        "boot_id_digest": DIGEST_B,
        "runner_version_digest": DIGEST_A,
        "environment_digest": DIGEST_B,
        "attempt_id": "attempt-one",
        "started_at": "2026-08-29T18:00:00Z",
        "finished_at": "2026-08-29T18:00:01Z",
        "started_monotonic_ns": 1_000_000_000,
        "finished_monotonic_ns": 2_000_000_000,
        "result": "passed",
        "reason_code": "test.run_passed",
        "duration_ms": 1000,
        "cooldown_class": "deterministic",
        "expires_monotonic_ns": 1_802_000_000_000,
    }
    values.update(overrides)
    return EvidenceReceiptV1(**values)


def context() -> EvidenceContextV1:
    return EvidenceContextV1(
        repository_id="codex-master",
        index_digest=DIGEST_A,
        function_ids=("python:src/example.py:run",),
        test_id="pytest:tests/test_example.py:test_run",
        source_digest_set_digest=DIGEST_A,
        test_digest=DIGEST_A,
        assertion_digest=DIGEST_B,
        dependency_digest_set_digest=DIGEST_B,
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        runner_version_digest=DIGEST_A,
        environment_digest=DIGEST_B,
    )


def test_passed_fresh_identical_evidence_is_reused() -> None:
    decision = evaluate_evidence_reuse(receipt(), context(), now_monotonic_ns=2_000_000_000)

    assert decision.action == "reuse"
    assert decision.reason_code == "test.evidence_reused"
    assert decision.remaining_cooldown_seconds == 1800


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        ({"result": "failed"}, "test.run_failed"),
        ({"index_digest": DIGEST_B}, "test.evidence_stale"),
        ({"executor_fingerprint": DIGEST_B}, "test.executor_mismatch"),
        ({"boot_id_digest": DIGEST_A}, "test.boot_mismatch"),
        ({"expires_monotonic_ns": 1_999_999_999}, "test.cooldown_expired"),
    ],
)
def test_any_failed_or_stale_identity_forces_real_run(changed: dict[str, object], reason: str) -> None:
    decision = evaluate_evidence_reuse(
        receipt(**changed), context(), now_monotonic_ns=2_000_000_000
    )

    assert decision.action == "run"
    assert decision.reason_code == reason


def test_mandatory_gate_and_higher_risk_context_never_reuse() -> None:
    mandatory = evaluate_evidence_reuse(
        receipt(), context(), now_monotonic_ns=2_000_000_000, mandatory_gate=True
    )
    higher_risk = evaluate_evidence_reuse(
        receipt(), context(), now_monotonic_ns=2_000_000_000, higher_risk_context=True
    )

    assert (mandatory.action, mandatory.reason_code) == ("run", "test.gate_required")
    assert (higher_risk.action, higher_risk.reason_code) == ("run", "test.evidence_stale")


def test_zero_ttl_classes_cannot_mint_reusable_evidence() -> None:
    for cooldown_class in ("environmental", "external", "mandatory"):
        value = replace(
            receipt(), cooldown_class=cooldown_class, expires_monotonic_ns=2_000_000_000
        )
        decision = evaluate_evidence_reuse(value, context(), now_monotonic_ns=2_000_000_000)
        assert decision.action == "run"
