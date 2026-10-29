"""The daily Qlty attempt ledger never invents activity or a writer owner."""

from contextlib import contextmanager
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/the-hive-qlty-maintenance"
loader = importlib.machinery.SourceFileLoader("qlty_maintenance", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
maintenance = importlib.util.module_from_spec(spec)
loader.exec_module(maintenance)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        clock = patch.object(maintenance.time, "time", return_value=1000)
        self.now = clock.start()
        self.addCleanup(clock.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix="qlty-check-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.calls = self.root / "calls"
        self.qlty = self.root / "qlty"
        self.qlty.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.calls}'\nsleep 0.1\nexit 0\n"
        )
        self.qlty.chmod(0o700)

    def test_upgrade_claim_is_independent_and_survives_restart(self):
        self.now.return_value = 100
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        self.now.return_value = 200
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        self.assertEqual(
            self.calls.read_text().splitlines(), ["upgrade --verify-attestations"]
        )
        self.now.return_value = 100 + maintenance.DAY
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)

    def test_parallel_processes_run_the_upgrade_only_once(self):
        command = [
            "python3",
            str(SCRIPT),
            "upgrade",
            "--state-root",
            str(self.state),
            "--qlty",
            str(self.qlty),
        ]
        processes = [subprocess.Popen(command) for _ in range(2)]
        self.assertEqual([process.wait() for process in processes], [0, 0])
        self.assertEqual(
            self.calls.read_text().splitlines(), ["upgrade --verify-attestations"]
        )

    def test_interrupted_attempt_and_backwards_clock_do_not_repeat(self):
        with maintenance.attempt(self.state, "repository") as claim:
            self.assertIsNotNone(claim)
        for now in (999, 1001, 1000 + maintenance.DAY - 1):
            self.now.return_value = now
            with maintenance.attempt(self.state, "repository") as claim:
                self.assertIsNone(claim)

    def test_failed_upgrade_does_not_repeat_within_a_day(self):
        self.qlty.write_text(f"#!/bin/sh\necho fail >> '{self.calls}'\nexit 9\n")
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 1)
        self.now.return_value = 1001
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        self.assertEqual(self.calls.read_text().splitlines(), ["fail"])

    def test_missing_cli_bootstraps_only_through_the_reviewed_installer(self):
        missing = str(self.root / "missing-qlty")
        with patch.object(maintenance, "execute_steps", return_value=1) as execute:
            self.assertEqual(maintenance.upgrade(self.state, missing), 1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(
            execute.call_args.args[2],
            [["/bin/bash", str(SCRIPT.with_name("install-qlty.sh"))]],
        )

    def test_actual_process_crash_retains_the_attempt(self):
        program = (
            f"import runpy,os; from pathlib import Path; m=runpy.run_path({str(SCRIPT)!r}); "
            f"claim=m['attempt'](Path({str(self.state)!r}), 'crash'); "
            "claim.__enter__(); os._exit(17)"
        )
        self.assertEqual(subprocess.run(["python3", "-c", program]).returncode, 17)
        self.now.return_value = 1001
        with maintenance.attempt(self.state, "crash") as claimed:
            self.assertIsNone(claimed)

    def test_invalid_persisted_time_fails_closed(self):
        with maintenance.attempt(self.state, "clock") as claimed:
            record, _ = claimed
        record.write_text(json.dumps({"attempted_at": float("nan")}))
        with self.assertRaisesRegex(ValueError, "qlty_attempt_invalid"):
            with maintenance.attempt(self.state, "clock"):
                self.fail("invalid state was accepted")

    def test_repository_chain_uses_shared_common_git_directory(self):
        repo = self.root / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        worktree = self.root / "worktree"
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "add",
                "-q",
                "--detach",
                str(worktree),
            ],
            check=True,
        )
        guards = []

        @contextmanager
        def guard(path):
            guards.append(path)
            yield

        activity = {"kind": "user_work", "worked_at": 999}
        for path in (repo, worktree):
            self.assertEqual(
                maintenance.run_repository(
                    path,
                    self.state,
                    str(self.qlty),
                    activity=activity,
                    now=1000,
                    mutation_guard=guard,
                ),
                0,
            )
        calls = self.calls.read_text().splitlines()
        self.assertEqual(
            [call.split()[0] for call in calls], ["metrics", "smells", "check", "fmt"]
        )
        self.assertEqual(len(guards), 2)
        self.assertTrue(all("--all" in call for call in calls))

    def test_unknown_or_self_generated_activity_never_runs(self):
        now = maintenance.DAY + 1000
        for activity in (
            {},
            {"kind": "qlty", "worked_at": now - 1},
            {"kind": "user_work", "worked_at": now + 1},
            {"kind": "user_work", "worked_at": 1},
        ):
            self.assertEqual(
                maintenance.run_repository(
                    self.root,
                    self.state,
                    str(self.qlty),
                    activity=activity,
                    now=now,
                    mutation_guard=None,
                ),
                0,
            )
        self.assertFalse(self.calls.exists())

    def test_actual_work_without_mutation_owner_holds_before_claim(self):
        with self.assertRaisesRegex(ValueError, "qlty_mutation_owner_unavailable"):
            maintenance.run_repository(
                self.root,
                self.state,
                str(self.qlty),
                activity={"kind": "user_work", "worked_at": 999},
                now=1000,
                mutation_guard=None,
            )
        self.assertFalse(self.state.exists())

    def test_symlinked_state_is_rejected(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.state.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "qlty_state_directory_untrusted"):
            maintenance.upgrade(self.state, str(self.qlty))

    def repository(self):
        repo = self.root / "registered-repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        return repo

    def test_local_work_event_uses_owner_time_and_actual_binding(self):
        repo = self.repository()
        with patch.object(maintenance.time, "time", return_value=1000):
            guard = maintenance.begin_guard(
                repo, self.state, owner="writer", phase="work"
            )
        document = maintenance.registered_state(repo, self.state)
        event = document["activities"][str(repo)]
        self.assertEqual(event["source"], "declared_local_work")
        self.assertEqual(event["worked_at"], 1000)
        self.assertEqual(event["binding"]["repository"], str(repo))
        self.assertEqual(document["guards"][0]["guard_id"], guard["guard_id"])

    def test_foreign_end_is_rejected_and_deferred_end_is_persisted(self):
        repo = self.repository()
        first = maintenance.begin_guard(repo, self.state, owner="first", phase="work")
        second = maintenance.begin_guard(repo, self.state, owner="second", phase="work")
        with self.assertRaisesRegex(ValueError, "qlty_guard_owner_mismatch"):
            maintenance.end_guard(
                repo,
                self.state,
                owner="foreign",
                guard_id=first["guard_id"],
                approve_format=True,
            )
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="first",
            guard_id=first["guard_id"],
            approve_format=True,
        )
        self.assertEqual(result["approval"], "deferred")
        document = maintenance.registered_state(repo, self.state)
        self.assertEqual(
            [row["guard_id"] for row in document["guards"]], [second["guard_id"]]
        )
        self.assertIsNone(document["approval"])
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="second",
            guard_id=second["guard_id"],
            approve_format=True,
        )
        self.assertEqual(result["approval"], "approved")

    def test_test_guard_invalidates_approval_without_reactivating_work(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        before = maintenance.registered_state(repo, self.state)["activities"]
        freeze = maintenance.begin_guard(
            repo, self.state, owner="test-owner", phase="test"
        )
        during = maintenance.registered_state(repo, self.state)
        self.assertEqual(during["activities"], before)
        self.assertIsNone(during["approval"])
        maintenance.end_guard(
            repo,
            self.state,
            owner="test-owner",
            guard_id=freeze["guard_id"],
            approve_format=True,
        )
        self.assertEqual(
            maintenance.registered_state(repo, self.state)["activities"], before
        )

    def test_registered_chain_requires_real_release_and_consumes_it_once(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        with self.assertRaisesRegex(ValueError, "qlty_work_guard_active"):
            maintenance.run_registered(repo, self.state, str(self.qlty))
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        before = maintenance.registered_state(repo, self.state)["activities"]
        self.assertEqual(
            maintenance.run_registered(repo, self.state, str(self.qlty)), 0
        )
        self.assertEqual(
            [line.split()[0] for line in self.calls.read_text().splitlines()],
            ["upgrade", "metrics", "smells", "check", "fmt"],
        )
        after = maintenance.registered_state(repo, self.state)
        self.assertEqual(after["activities"], before)
        self.assertIsNone(after["approval"])
        self.assertIsNone(after["format_guard"])
        self.assertEqual(
            maintenance.run_registered(repo, self.state, str(self.qlty)), 0
        )
        self.assertEqual(len(self.calls.read_text().splitlines()), 5)

    def test_source_changed_after_approval_holds_without_running(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        (repo / "new-source.py").write_text("print('changed')\n")
        with self.assertRaisesRegex(ValueError, "qlty_source_changed"):
            maintenance.run_registered(repo, self.state, str(self.qlty))
        self.assertEqual(
            self.calls.read_text().splitlines(), ["upgrade --verify-attestations"]
        )

    def test_source_freeze_blocks_new_declared_writers(self):
        repo = self.repository()
        maintenance.begin_guard(repo, self.state, owner="reviewer", phase="freeze")
        with self.assertRaisesRegex(ValueError, "qlty_source_freeze_active"):
            maintenance.begin_guard(repo, self.state, owner="writer", phase="work")

    def test_test_guard_waits_for_declared_writers_to_end(self):
        repo = self.repository()
        maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        with self.assertRaisesRegex(ValueError, "qlty_work_guard_active"):
            maintenance.begin_guard(repo, self.state, owner="tester", phase="test")

    def test_unknown_format_guard_is_not_cleared_by_time(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        program = (
            f"import runpy,os; from pathlib import Path; m=runpy.run_path({str(SCRIPT)!r}); "
            f"guard=m['quality_guard'](Path({str(repo)!r}), Path({str(self.state)!r})); "
            "guard.__enter__(); os._exit(17)"
        )
        self.assertEqual(subprocess.run(["python3", "-c", program]).returncode, 17)
        with self.assertRaisesRegex(ValueError, "qlty_format_owner_unresolved"):
            maintenance.begin_guard(repo, self.state, owner="new-writer", phase="work")

    def test_end_is_persisted_when_source_snapshot_is_unavailable(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        with patch.object(maintenance, "source_state", side_effect=OSError("fixture")):
            result = maintenance.end_guard(
                repo,
                self.state,
                owner="writer",
                guard_id=work["guard_id"],
                approve_format=True,
            )
        self.assertEqual(result["approval"], "deferred")
        self.assertFalse(maintenance.registered_state(repo, self.state)["guards"])

    def test_new_repository_without_head_can_be_bound(self):
        repo = self.root / "uncommitted-repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        self.assertEqual(result["approval"], "approved")
        self.assertIsNone(
            maintenance.registered_state(repo, self.state)["approval"]["source_state"][
                "head"
            ]
        )

    def test_external_source_drift_stops_before_formatting(self):
        repo = self.repository()
        self.qlty.write_text(
            f"#!/bin/sh\necho \"$1\" >> '{self.calls}'\nif [ \"$1\" = metrics ]; then touch '{repo / 'external.py'}'; fi\n"
        )
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        self.assertEqual(
            maintenance.run_registered(repo, self.state, str(self.qlty)), 1
        )
        self.assertEqual(self.calls.read_text().splitlines(), ["upgrade", "metrics"])

    def test_interrupted_quality_process_keeps_its_unknown_guard(self):
        repo = self.repository()
        maintenance.upgrade(self.state, str(self.qlty))
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        with patch.object(maintenance, "execute_steps", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                maintenance.run_registered(repo, self.state, str(self.qlty))
        self.assertIsNotNone(
            maintenance.registered_state(repo, self.state)["format_guard"]
        )

    def test_public_run_bootstrap_failure_preserves_approval_and_repository_day(self):
        repo = self.repository()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        with patch.object(maintenance, "upgrade", return_value=1) as upgrade:
            self.assertEqual(
                maintenance.run_registered(
                    repo, self.state, str(self.root / "missing")
                ),
                1,
            )
        upgrade.assert_called_once()
        document = maintenance.registered_state(repo, self.state)
        self.assertIsNotNone(document["approval"])
        self.assertIsNone(document["format_guard"])
        self.assertFalse(
            list(self.state.glob("[!.]*.json"))
            and any(
                "attempted_at" in json.loads(path.read_text())
                for path in self.state.glob("*.json")
            )
        )

    def test_repository_attempt_time_is_read_after_guard_wait(self):
        repo = self.repository()
        self.now.return_value = 100000

        @contextmanager
        def delayed_guard(path):
            self.now.return_value = 100100
            yield

        activity = {"kind": "user_work", "worked_at": 99999}
        self.assertEqual(
            maintenance.run_repository(
                repo,
                self.state,
                str(self.qlty),
                activity=activity,
                now=100000,
                mutation_guard=delayed_guard,
            ),
            0,
        )
        ledger = next(
            json.loads(path.read_text())
            for path in self.state.glob("*.json")
            if "attempted_at" in json.loads(path.read_text())
        )
        self.assertEqual(ledger["attempted_at"], 100100)
        self.now.return_value = 186401
        activity["worked_at"] = 186400

        @contextmanager
        def ready_guard(path):
            yield

        self.assertEqual(
            maintenance.run_repository(
                repo,
                self.state,
                str(self.qlty),
                activity=activity,
                now=186401,
                mutation_guard=ready_guard,
            ),
            0,
        )
        self.assertEqual(len(self.calls.read_text().splitlines()), 4)

    def test_upgrade_attempt_time_is_read_after_its_lock_wait(self):
        original = maintenance.record_lock

        @contextmanager
        def delayed_lock(*arguments, **keywords):
            with original(*arguments, **keywords) as record:
                self.now.return_value = 100100
                yield record

        self.now.return_value = 100000
        with patch.object(maintenance, "record_lock", delayed_lock):
            self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        ledger = json.loads(next(self.state.glob("*.json")).read_text())
        self.assertEqual(ledger["attempted_at"], 100100)

    def test_expired_work_after_day_lock_wait_never_starts_tools(self):
        original = maintenance.record_lock

        @contextmanager
        def delayed_lock(*arguments, **keywords):
            with original(*arguments, **keywords) as record:
                self.now.return_value = 100100
                yield record

        self.now.return_value = 100000
        with patch.object(maintenance, "record_lock", delayed_lock):
            with maintenance.attempt(
                self.state, "expiry", activity_at=100000 - maintenance.DAY + 50
            ) as claimed:
                self.assertIsNone(claimed)
        self.assertFalse(list(self.state.glob("*.json")))

    def test_actual_public_cli_bootstrap_fails_before_repo_consumption(self):
        repo = self.repository()
        tooling = self.root / "private-tooling"
        tooling.mkdir()
        runner = tooling / SCRIPT.name
        runner.write_bytes(SCRIPT.read_bytes())
        (tooling / "install-qlty.sh").write_text("#!/bin/bash\nexit 31\n")
        base = [
            "python3",
            str(runner),
            "--repo",
            str(repo),
            "--state-root",
            str(self.state),
            "--owner",
            "fixture-writer",
        ]
        started = subprocess.run(
            [*base, "begin"], text=True, capture_output=True, check=True
        )
        guard_id = json.loads(started.stdout)["guard_id"]
        subprocess.run(
            [*base, "end", "--guard-id", guard_id, "--approve-format"],
            check=True,
            capture_output=True,
        )
        result = subprocess.run(
            [*base, "run", "--qlty", str(self.root / "missing")],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 1)
        document = maintenance.registered_state(repo, self.state)
        self.assertIsNotNone(document["approval"])
        self.assertIsNone(document["format_guard"])
        attempts = [
            json.loads(path.read_text())
            for path in self.state.glob("*.json")
            if not path.name.endswith(".work.json")
        ]
        self.assertEqual([row["identity"] for row in attempts], ["qlty-upgrade"])
        self.assertEqual(attempts[0]["steps"][0]["exit_code"], 31)

    def pending_format(self):
        repo = self.repository()
        with maintenance.attempt(
            self.state, maintenance.repository_identity(repo)
        ) as claimed:
            record, value = claimed
            value["steps"] = [
                {
                    "command": [command, "--all"],
                    "exit_code": 1 if command == "check" else 0,
                    "log": command + ".log",
                    "source_after": maintenance.source_state(repo),
                }
                for command in ["metrics", "smells", "check"]
            ]
            value["status"] = "source_changed"
            value["quality_guard"] = {"binding": maintenance.repository_binding(repo)}
            maintenance.atomic_json(record, value)
        original = json.loads(record.read_text())
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
            approve_format=True,
        )
        return repo, record, original

    def test_finish_fmt_rejects_other_physical_worktree(self):
        repo, record, original = self.pending_format()
        other = self.root / "linked"
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(other)],
            check=True,
            capture_output=True,
        )
        guard = maintenance.begin_guard(other, self.state, owner="writer", phase="work")
        maintenance.end_guard(
            other,
            self.state,
            owner="writer",
            guard_id=guard["guard_id"],
            approve_format=True,
        )
        state_before = maintenance.registered_state(other, self.state)
        with self.assertRaisesRegex(ValueError, "qlty_fmt_worktree_mismatch"):
            maintenance.finish_fmt(
                other,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"],
            )
        self.assertEqual(json.loads(record.read_text()), original)
        self.assertEqual(maintenance.registered_state(other, self.state), state_before)
        self.assertFalse(self.calls.exists())

    def test_finish_fmt_rejects_same_path_with_changed_inode(self):
        repo, record, original = self.pending_format()
        state_before = maintenance.registered_state(repo, self.state)
        old_root = repo.with_name("previous-root")
        repo.rename(old_root)
        repo.mkdir()
        for child in old_root.iterdir():
            child.rename(repo / child.name)
        self.assertNotEqual(
            maintenance.repository_binding(repo)["inode"],
            original["quality_guard"]["binding"]["inode"],
        )
        with self.assertRaisesRegex(ValueError, "qlty_fmt_worktree_mismatch"):
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"],
            )
        self.assertEqual(json.loads(record.read_text()), original)
        self.assertEqual(maintenance.registered_state(repo, self.state), state_before)
        self.assertFalse(self.calls.exists())

    def test_finish_fmt_rejects_missing_original_binding(self):
        repo, record, original = self.pending_format()
        del original["quality_guard"]
        maintenance.atomic_json(record, original)
        state_before = maintenance.registered_state(repo, self.state)
        with self.assertRaisesRegex(ValueError, "qlty_fmt_worktree_mismatch"):
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"],
            )
        self.assertEqual(json.loads(record.read_text()), original)
        self.assertEqual(maintenance.registered_state(repo, self.state), state_before)
        self.assertFalse(self.calls.exists())

    def test_only_four_generated_aliases_are_not_source_changes(self):
        repo = self.repository()
        metadata = repo / ".qlty"
        metadata.mkdir()
        (metadata / "qlty.toml").write_text('config_version = "0"\n')
        (metadata / ".gitignore").write_bytes(
            (SCRIPT.parents[1] / ".qlty/.gitignore").read_bytes()
        )
        before = maintenance.source_state(repo)
        cache = self.root / "cache"
        cache.mkdir()
        for name in ["logs", "out", "plugin_cachedir", "results"]:
            (metadata / name).symlink_to(cache, target_is_directory=True)
        self.assertEqual(before, maintenance.source_state(repo))
        (metadata / "actual-source.toml").write_text('source = "changed"\n')
        self.assertNotEqual(before, maintenance.source_state(repo))

    def test_finish_fmt_preserves_old_attempt_and_steps(self):
        repo, record, original = self.pending_format()
        before = json.dumps(original["steps"], sort_keys=True).encode()
        self.assertEqual(
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"],
            ),
            0,
        )
        after = json.loads(record.read_text())
        self.assertEqual(after["attempted_at"], original["attempted_at"])
        self.assertEqual(
            json.dumps(after["steps"][:3], sort_keys=True).encode(), before
        )
        self.assertEqual(after["steps"][2]["exit_code"], 1)
        self.assertEqual(after["steps"][3]["command"][0], "fmt")
        self.assertEqual(after["status"], "findings_or_error")
        self.assertEqual(after["fmt_continuation"]["original_status"], "source_changed")
        self.assertEqual(
            self.calls.read_text().splitlines(), ["fmt --all --no-upgrade-check"]
        )

    def test_finish_fmt_rejects_wrong_attempt_before_approval_consumption(self):
        repo, record, original = self.pending_format()
        with self.assertRaisesRegex(ValueError, "qlty_fmt_attempt_mismatch"):
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"] + 1,
            )
        self.assertEqual(json.loads(record.read_text()), original)
        self.assertIsNotNone(maintenance.registered_state(repo, self.state)["approval"])

    def test_parallel_finish_fmt_has_one_effect(self):
        repo, record, original = self.pending_format()
        command = [
            "python3",
            str(SCRIPT),
            "finish-fmt",
            "--repo",
            str(repo),
            "--state-root",
            str(self.state),
            "--qlty",
            str(self.qlty),
            "--attempted-at",
            str(original["attempted_at"]),
        ]
        children = [
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(2)
        ]
        exits = [child.communicate() or child.returncode for child in children]
        self.assertEqual(sorted(child.returncode for child in children), [0, 2], exits)
        self.assertEqual(
            self.calls.read_text().splitlines(), ["fmt --all --no-upgrade-check"]
        )
        self.assertEqual(len(json.loads(record.read_text())["steps"]), 4)

    def test_finish_fmt_crash_does_not_allow_repeated_effect(self):
        repo, record, original = self.pending_format()
        program = (
            f"import runpy,os; from pathlib import Path; m=runpy.run_path({str(SCRIPT)!r}); "
            "m['finish_fmt'].__globals__['execute_steps']=lambda *a,**k: os._exit(17); "
            f"m['finish_fmt'](Path({str(repo)!r}), Path({str(self.state)!r}), {str(self.qlty)!r}, expected_attempted_at={original['attempted_at']!r})"
        )
        self.assertEqual(subprocess.run(["python3", "-c", program]).returncode, 17)
        after = json.loads(record.read_text())
        self.assertEqual(after["attempted_at"], original["attempted_at"])
        self.assertEqual(after["steps"], original["steps"])
        self.assertEqual(after["fmt_continuation"]["status"], "started")
        with self.assertRaisesRegex(ValueError, "qlty_fmt_already_started"):
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.qlty),
                expected_attempted_at=original["attempted_at"],
            )

    def test_finish_fmt_without_cli_keeps_permission_and_old_record(self):
        repo, record, original = self.pending_format()
        with self.assertRaisesRegex(ValueError, "qlty_cli_unavailable"):
            maintenance.finish_fmt(
                repo,
                self.state,
                str(self.root / "missing"),
                expected_attempted_at=original["attempted_at"],
            )
        self.assertEqual(json.loads(record.read_text()), original)
        self.assertIsNotNone(maintenance.registered_state(repo, self.state)["approval"])


if __name__ == "__main__":
    unittest.main()
