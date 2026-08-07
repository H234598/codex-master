from datetime import datetime, timezone

from codex_master.selection import FairnessLedger, SelectionCandidate, SelectionPolicy, TaskKind, ModelRole
from codex_master.selection.policy import evaluate_eligibility, select_candidate


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def candidate(agent_id: str, *, ready: bool = True) -> SelectionCandidate:
    return SelectionCandidate(agent_id, "sha256:" + "a" * 64, "gpt-primary", TaskKind.COMPLEX, ModelRole.PRIMARY, account_ready=ready)


def test_policy_facade_uses_legacy_planner_and_exposes_bounded_reasons() -> None:
    assert evaluate_eligibility(candidate("a")).eligible is True
    assert evaluate_eligibility(candidate("b", ready=False)).reason_codes == ("account_unready",)
    decision = select_candidate((candidate("a"),), policy=SelectionPolicy(sp3=True), now=NOW, ledger=FairnessLedger({}))
    assert decision.selected.agent_id == "a"
