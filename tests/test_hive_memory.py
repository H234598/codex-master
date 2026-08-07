from datetime import datetime, timezone

import pytest

from codex_master.hive.memory import MemoryError, promote_queen_memory_to_global, promote_teamlead_report
from codex_master.hive.principals import Principal


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64


def principal(principal_id: str, class_id: str, repo_id: str | None) -> Principal:
    return Principal(principal_id, class_id, None, "profile", "global" if repo_id is None else "repository", repo_id, "active", DIGEST, 1)


def test_teamlead_report_is_redacted_and_queen_can_promote_only_repository_memory() -> None:
    repo_memory = promote_teamlead_report(
        {
            "source_principal_id": "specialist-one",
            "summary": "Use token=secret and inspect /home/teladi/private; tests passed.",
            "provenance_refs": ("report:one",),
            "trust_level": "verified",
        },
        actor=principal("lead-one", "teamleiterin", "repo-one"), memory_id="memory-repo", repo_id="repo-one", now=NOW,
    )
    assert "secret" not in repo_memory.summary
    assert "/home" not in repo_memory.summary
    global_memory = promote_queen_memory_to_global(repo_memory, actor=principal("queen-one", "koenigin", "repo-one"), memory_id="memory-global", now=NOW)
    assert global_memory.scope_kind == "global"
    assert "memory:memory-repo" in global_memory.provenance_refs


def test_specialist_cannot_promote_directly_to_global() -> None:
    with pytest.raises(MemoryError, match="teamlead_promotion_unauthorized"):
        promote_teamlead_report(
            {"source_principal_id": "specialist-one", "summary": "result", "provenance_refs": ("report:one",)},
            actor=principal("specialist-one", "spezialistin", "repo-one"), memory_id="memory-one", repo_id="repo-one", now=NOW,
        )
