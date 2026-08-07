from datetime import datetime, timezone

import pytest

from codex_master.selection import FairnessLedger, ModelRole, SelectionCandidate, SelectionPolicy, TaskKind
from codex_master.selection.policy import evaluate_eligibility, priority_key, select_candidate


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def candidate(agent_id: str, **changes: object) -> SelectionCandidate:
    values: dict[str, object] = {
        "agent_id": agent_id, "account_key": f"account-{agent_id}", "model_id": "gpt-primary",
        "task_kind": TaskKind.SIMPLE, "model_role": ModelRole.PRIMARY,
    }
    values.update(changes)
    return SelectionCandidate(**values)


def test_selection_comparator_is_deterministic_and_preserves_eligibility() -> None:
    values = (candidate("agent-b"), candidate("agent-a"))
    first = select_candidate(values, policy=SelectionPolicy(sp3=True), now=NOW, ledger=FairnessLedger({}))
    second = select_candidate(tuple(reversed(values)), policy=SelectionPolicy(sp3=True), now=NOW, ledger=FairnessLedger({}))
    assert first.selected == second.selected
    assert first.eligible_count == second.eligible_count == 2


@pytest.mark.parametrize(
    ("changes", "reason"),
    [({"enabled": False}, "disabled"), ({"authenticated": False}, "unauthenticated"),
     ({"account_ready": False}, "account_unready"), ({"lease_available": False}, "lease_busy")],
)
def test_selection_eligibility_properties_are_fail_closed(changes: dict[str, object], reason: str) -> None:
    result = evaluate_eligibility(candidate("agent-one", **changes), now=NOW)
    assert result.eligible is False
    assert result.reason_codes == (reason,)


def test_priority_key_is_orderable_without_weighted_randomness() -> None:
    ledger = FairnessLedger({})
    first = priority_key(candidate("agent-a"), ledger, now=NOW)
    second = priority_key(candidate("agent-b"), ledger, now=NOW)
    assert first != second
    assert sorted((first, second)) == [first, second]
