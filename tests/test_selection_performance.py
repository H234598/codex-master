from datetime import datetime, timezone
from time import perf_counter
import unittest

from codex_master.hive.dispatch import WorkPackage
from codex_master.hive.queue import WorkQueue
from codex_master.selection import (
    FairnessLedger,
    ModelRole,
    SelectionCandidate,
    SelectionPolicy,
    TaskKind,
    preview_selection,
)


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


class SelectionPerformanceTests(unittest.TestCase):
    def test_selection_handles_300_agents_20_accounts_and_3_models(self) -> None:
        candidates = tuple(
            SelectionCandidate(
                agent_id=f"agent-{index}",
                account_key=f"account-{index % 20}",
                model_id=("primary-model", "secondary-model", "tertiary-model")[index % 3],
                task_kind=TaskKind.SIMPLE,
                model_role=ModelRole.PRIMARY,
                rotation_distance=index % 17,
            )
            for index in range(300)
        )
        started = perf_counter()
        for _ in range(5):
            result = preview_selection(candidates, policy=SelectionPolicy(sp3=True), now=NOW, ledger=FairnessLedger({}))
            self.assertIsNotNone(result.selected)
        elapsed = perf_counter() - started
        self.assertLess(elapsed, 1.0)

    def test_work_queue_handles_25_repositories_and_100_work_items(self) -> None:
        items = tuple(
            WorkPackage(
                f"workpackage-{index}", f"dispatch-{index}", "lead-one", "bounded task", ("src",),
                (f"src/file-{index}.py",), ("tests pass",), ("pytest",), "teamlead_commit", (),
                {"repo_id": f"repo-{index % 25}", "dispatch_priority": "DP1"}, state="ready",
            )
            for index in range(100)
        )
        started = perf_counter()
        queue = WorkQueue(items)
        decisions = queue.preview(now=NOW, limit=100)
        elapsed = perf_counter() - started
        self.assertEqual(len(decisions), 100)
        self.assertLess(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
