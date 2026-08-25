from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta

import pytest

from codex_master.usage_snapshot import (
    AccountUsageEvidenceV2,
    TrackerEvidenceV2,
    UsageEvidenceV2,
    UsageLimitV2,
    UsageTrendV2,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def evidence(
    *,
    status: str = "complete",
    pool: str = "main",
    evidence_pool: str | None = None,
    coverage: str = "complete",
    with_trend: bool = True,
    reset_generation: str = "reset-1",
    evidence_reset_generation: str | None = None,
    window_seconds: int = 18000,
    evidence_window_seconds: int | None = None,
) -> UsageEvidenceV2:
    limit = UsageLimitV2(
        pool=pool,
        window_seconds=window_seconds,
        reset_generation=reset_generation,
        used_percent=25.0,
        remaining_percent=75.0,
        reset_at=NOW + timedelta(minutes=30),
    )
    tracker_evidence = TrackerEvidenceV2(
        pool=evidence_pool or pool,
        window_seconds=evidence_window_seconds or window_seconds,
        reset_generation=evidence_reset_generation or reset_generation,
        coverage=coverage,
        last_sample_at=NOW,
    )
    trends = ()
    if with_trend:
        trends = (
            UsageTrendV2(
                pool=pool,
                window_seconds=window_seconds,
                reset_generation=reset_generation,
                coverage=coverage,
                last_sample_at=NOW,
                projected_exhaustion_at=NOW + timedelta(minutes=20),
            ),
        )
    return UsageEvidenceV2(
        accounts=(
            AccountUsageEvidenceV2("alpha", (limit,), trends, (tracker_evidence,)),
        ),
        status=status,
        captured_at=NOW - timedelta(seconds=60),
        generated_at=NOW,
    )


def derive(value: UsageEvidenceV2):
    tracker = importlib.import_module("codex_master.limit_tracker")
    return tracker.derive_limit_decisions(value, now=NOW)


def test_fresh_complete_matching_v2_evidence_is_descriptive_eligible() -> None:
    decisions = derive(evidence())

    assert len(decisions) == 1
    assert decisions[0].account_id == "alpha"
    assert decisions[0].pool == "main"
    assert decisions[0].window_seconds == 18000
    assert decisions[0].automatic is True
    assert decisions[0].reason == "eligible"


@pytest.mark.parametrize(
    "value",
    [
        evidence(status="stale"),
        evidence(status="partial"),
        evidence(status="busy"),
        evidence(status="unavailable"),
        evidence(status="invalid"),
        evidence(coverage="insufficient"),
        evidence(with_trend=False),
        evidence(evidence_reset_generation="other-reset"),
        evidence(evidence_window_seconds=604800),
        evidence(pool="main", evidence_pool="spark"),
    ],
)
def test_noncomplete_or_mismatched_evidence_never_activates(
    value: UsageEvidenceV2,
) -> None:
    decisions = derive(value)

    assert decisions
    assert all(decision.automatic is False for decision in decisions)


def test_tracker_is_deterministic_and_explicit_now_gates_reset() -> None:
    value = evidence()

    tracker = importlib.import_module("codex_master.limit_tracker")
    before_reset = tracker.derive_limit_decisions(value, now=NOW)
    after_reset = tracker.derive_limit_decisions(value, now=NOW + timedelta(hours=1))

    assert before_reset == derive(value)
    assert before_reset[0].automatic is True
    assert after_reset[0].automatic is False
    assert after_reset[0].reason == "reset_elapsed"
