from datetime import datetime, timezone

import pytest

from codex_master.hive.decisions import DecisionError, DecisionRecord, record_decision, verify_decision_chain
from codex_master.hive.principals import Principal


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64


def principal(principal_id: str, class_id: str, repo_id: str | None) -> Principal:
    return Principal(principal_id, class_id, None, "profile", "global" if repo_id is None else "repository", repo_id, "active", DIGEST, 1)


def decision(*, scope_kind: str = "global", repo_id: str | None = None, actor: str = "godbee-main") -> DecisionRecord:
    return DecisionRecord(
        "decision-one", scope_kind, repo_id, "scheduling policy", "accepted", ({"option_id": "a", "summary": "separate planes"},),
        "a", "Separate work and resource scheduling.", ("adr:0003",), actor, (actor,), NOW,
    )


def test_decision_is_authorized_hashed_and_chain_verifiable() -> None:
    stored = record_decision(decision(), actor=principal("godbee-main", "gottbiene", None))
    assert stored.record_hash is not None
    assert verify_decision_chain([stored])["valid"] is True
    tampered = DecisionRecord(
        stored.decision_id, stored.scope_kind, stored.repo_id, "tampered", stored.status, stored.options,
        stored.selected_option_id, stored.rationale, stored.evidence_refs, stored.created_by, stored.approved_by,
        stored.created_at_utc, stored.supersedes, stored.previous_record_hash, stored.record_hash,
    )
    assert verify_decision_chain([tampered])["valid"] is False


def test_repository_decision_requires_matching_queen_or_teamlead() -> None:
    stored = record_decision(
        decision(scope_kind="repository", repo_id="repo-one", actor="queen-one"),
        actor=principal("queen-one", "koenigin", "repo-one"),
    )
    assert stored.scope_kind == "repository"
    with pytest.raises(DecisionError, match="decision_scope_unauthorized"):
        record_decision(
            decision(scope_kind="repository", repo_id="repo-one", actor="specialist-one"),
            actor=principal("specialist-one", "spezialistin", "repo-one"),
        )
