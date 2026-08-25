"""Pure V2 limit-evidence evaluation. No I/O, state, refresh, or control path."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from codex_master.usage_snapshot import UsageEvidenceV2


@dataclass(frozen=True, slots=True)
class LimitDecision:
    account_id: str
    pool: str
    window_seconds: int
    reset_generation: str
    automatic: bool
    reason: str


def _now(value: datetime) -> datetime | None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        return None
    return value.astimezone(UTC)


def derive_limit_decisions(
    evidence: UsageEvidenceV2, *, now: datetime
) -> tuple[LimitDecision, ...]:
    """Describe eligibility from one supplied evidence value without taking action."""
    current = _now(now)
    if type(evidence) is not UsageEvidenceV2 or current is None:
        return ()
    decisions: list[LimitDecision] = []
    for account in evidence.accounts:
        trends = {
            (trend.pool, trend.window_seconds, trend.reset_generation): trend
            for trend in account.trends
        }
        tracker_evidence = {
            (item.pool, item.window_seconds, item.reset_generation): item
            for item in account.tracker_evidence
        }
        for limit in account.limits:
            key = (limit.pool, limit.window_seconds, limit.reset_generation)
            reason = "eligible"
            automatic = True
            if evidence.status != "complete":
                automatic, reason = False, "status_not_complete"
            elif current >= limit.reset_at:
                automatic, reason = False, "reset_elapsed"
            elif key not in tracker_evidence:
                automatic, reason = False, "evidence_mismatch"
            elif tracker_evidence[key].coverage != "complete":
                automatic, reason = False, "incomplete_coverage"
            elif key not in trends:
                automatic, reason = False, "missing_trend"
            elif trends[key].coverage != "complete":
                automatic, reason = False, "incomplete_coverage"
            elif trends[key].projected_exhaustion_at <= current:
                automatic, reason = False, "projection_elapsed"
            decisions.append(
                LimitDecision(
                    account.account_id,
                    limit.pool,
                    limit.window_seconds,
                    limit.reset_generation,
                    automatic,
                    reason,
                )
            )
    return tuple(decisions)


__all__ = ["LimitDecision", "derive_limit_decisions"]
