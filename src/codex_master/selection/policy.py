"""Typed facade over the single legacy Selection planner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from codex_master.selection import (
    FairnessLedger,
    SelectionCandidate,
    SelectionPolicy,
    SelectionResult,
    eligibility_reason,
    preview_selection,
)


Candidate = SelectionCandidate


@dataclass(frozen=True, slots=True)
class EligibilityResult:
    eligible: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, order=True, slots=True)
class SelectionPriorityKey:
    band_rank: int
    fairness_micro: int
    last_selected_epoch: int
    rotation_distance: int
    agent_id: str


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    selected: SelectionResult | None
    eligible_count: int
    reason_codes: tuple[str, ...]


def generate_candidates(request: object, snapshot: object) -> tuple[Candidate, ...]:
    values = getattr(request, "candidates", snapshot)
    if not isinstance(values, tuple):
        raise ValueError("selection_candidates_must_be_tuple")
    if any(not isinstance(value, SelectionCandidate) for value in values):
        raise ValueError("invalid_selection_candidate")
    return values


def evaluate_eligibility(candidate: Candidate, *, now: datetime | None = None) -> EligibilityResult:
    del now
    reason = eligibility_reason(candidate)
    return EligibilityResult(reason is None, () if reason is None else (reason,))


def priority_key(candidate: Candidate, state: FairnessLedger, *, now: datetime) -> SelectionPriorityKey:
    if not isinstance(state, FairnessLedger):
        raise ValueError("invalid_fairness_state")
    fairness = state.normalized_service(candidate.account_key, now)
    last_selected = state.last_selected_epoch(candidate.account_key)
    return SelectionPriorityKey(0, fairness, last_selected, candidate.rotation_distance, candidate.agent_id)


def select_candidate(
    candidates: tuple[Candidate, ...], *, policy: SelectionPolicy, now: datetime, ledger: FairnessLedger | None = None
) -> SelectionDecision:
    preview = preview_selection(candidates, policy=policy, now=now, ledger=ledger)
    return SelectionDecision(preview.selected, preview.eligible_count, tuple(reason for _agent, reason in preview.exclusions))


__all__ = [
    "Candidate",
    "EligibilityResult",
    "SelectionDecision",
    "SelectionPriorityKey",
    "evaluate_eligibility",
    "generate_candidates",
    "priority_key",
    "select_candidate",
]
