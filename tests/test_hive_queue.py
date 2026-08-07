from datetime import datetime, timezone

import pytest

from codex_master.hive.dispatch import WorkPackage
from codex_master.hive.queue import QueueError, WorkQueue


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def work(work_id: str, priority: str, repo: str, *, deps: tuple[str, ...] = ()) -> WorkPackage:
    return WorkPackage(
        work_id, "dispatch-one", "lead-one", work_id, ("src",), (), ("tests",), (), "teamlead_commit", deps,
        {"dispatch_priority": priority, "repo_id": repo, "deadline_epoch_ms": 1}, "queued", NOW, 1,
    )


def test_queue_orders_dispatch_priority_then_deadline_and_keeps_account_fields_out() -> None:
    queue = WorkQueue([work("wp-two", "DP2", "repo-b"), work("wp-one", "DP1", "repo-a")])
    decision = queue.select_next(now=NOW)
    assert decision.workpackage.workpackage_id == "wp-one"
    assert "account" not in decision.public()


def test_queue_blocks_dependencies_and_supports_provisional_cost_rollback() -> None:
    done = set()
    queue = WorkQueue([work("wp-one", "DP1", "repo-a"), work("wp-two", "DP0", "repo-a", deps=("wp-one",))], dependency_done=done.__contains__)
    assert queue.select_next(now=NOW).workpackage.workpackage_id == "wp-one"
    done.add("wp-one")
    assert queue.select_next(now=NOW).workpackage.workpackage_id == "wp-two"
    queue.reserve_cost("wp-two", 10)
    queue.rollback_cost("wp-two")
    with pytest.raises(QueueError, match="queue_cost_not_reserved"):
        queue.finalize_cost("wp-two", 10)
