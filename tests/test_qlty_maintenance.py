"""Only upgrades are time-limited; precommit checks bind current bytes and tools."""

from contextlib import contextmanager
import importlib.machinery
import importlib.util
import json
import hashlib
import copy
import tomllib
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/the-hive-qlty-maintenance"
loader = importlib.machinery.SourceFileLoader("qlty_maintenance", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
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
        with maintenance.upgrade_claim(self.state) as claim:
            self.assertIsNotNone(claim)
        for now in (999, 1001, 1000 + maintenance.DAY - 1):
            self.now.return_value = now
            with maintenance.upgrade_claim(self.state) as claim:
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
            "import runpy,os; from pathlib import Path; "
            f"m=runpy.run_path({str(SCRIPT)!r}); "
            f"claim=m['upgrade_claim'](Path({str(self.state)!r})); "
            "claim.__enter__(); os._exit(17)"
        )
        self.assertEqual(subprocess.run(["python3", "-c", program]).returncode, 17)
        self.now.return_value = 1001
        with maintenance.upgrade_claim(self.state) as claimed:
            self.assertIsNone(claimed)

    def test_invalid_persisted_time_fails_closed(self):
        with maintenance.upgrade_claim(self.state) as claimed:
            record, _ = claimed
        record.write_text(json.dumps({"attempted_at": float("nan")}))
        with self.assertRaisesRegex(ValueError, "qlty_attempt_invalid"):
            with maintenance.upgrade_claim(self.state):
                self.fail("invalid state was accepted")

    def test_symlinked_state_is_rejected(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.state.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "qlty_state_directory_untrusted"):
            maintenance.upgrade(self.state, str(self.qlty))

    def repository(self, suffix=""):
        repo = self.root / ("registered-repo" + suffix)
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

    def test_foreign_end_is_rejected_and_own_end_is_persisted(self):
        repo = self.repository()
        first = maintenance.begin_guard(repo, self.state, owner="first", phase="work")
        second = maintenance.begin_guard(repo, self.state, owner="second", phase="work")
        with self.assertRaisesRegex(ValueError, "qlty_guard_owner_mismatch"):
            maintenance.end_guard(
                repo,
                self.state,
                owner="foreign",
                guard_id=first["guard_id"],
            )
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="first",
            guard_id=first["guard_id"],
        )
        self.assertEqual(result["ended_guard_id"], first["guard_id"])
        document = maintenance.registered_state(repo, self.state)
        self.assertEqual(
            [row["guard_id"] for row in document["guards"]], [second["guard_id"]]
        )
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="second",
            guard_id=second["guard_id"],
        )
        self.assertEqual(result["ended_guard_id"], second["guard_id"])

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

    def test_new_repository_without_head_can_be_bound(self):
        repo = self.root / "uncommitted-repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        result = maintenance.end_guard(
            repo,
            self.state,
            owner="writer",
            guard_id=work["guard_id"],
        )
        self.assertEqual(result["ended_guard_id"], work["guard_id"])
        self.assertIsNone(maintenance.source_state(repo)["head"])

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

    def precommit_fixture(self):
        self.fixture_index = getattr(self, "fixture_index", 0) + 1
        repo = self.repository(f"-{self.fixture_index}")
        (repo / ".git/info/exclude").write_text("/.qlty/out/\n")
        (repo / "candidate.py").write_text("value=1\n")
        (repo / ".qlty/out").mkdir(parents=True)
        self.commands = []
        self.config = (
            "plugins:\n  definitions:\n    ruff:\n      hidden: false\n"
            "      drivers:\n        format:\n          driver_type: formatter\n"
            "        lint:\n          driver_type: linter\n"
            "    markdownlint:\n      hidden: false\n"
            "    tsc:\n      hidden: true\nlanguage: {}\nplugin:\n"
        )
        self.config += "".join(
            f"- name: {name}\n  mode: null\n  triggers: []\n  skip_upstream: null\n"
            for name in ("ruff", "tsc", "markdownlint")
        )
        self.config += "smells: {}\n"
        self.catalog = "2 available plugins:\n  ✔ ruff\n  ✔ markdownlint\n"
        # Actual 0.663.0 Ruff record 0SEKkj and SARIF schema; private path/time scaled.
        self.records = [
            {
                "id": "0SEKkj",
                "qltyCliVersion": "0.663.0",
                "pluginName": "ruff",
                "driverName": "lint",
                "pluginVersion": "0.14.6",
                "verb": "EXECUTION_VERB_CHECK",
                "targetsCount": 1,
                "targetPaths": ["candidate.py"],
                "cwd": str(repo) + "/",
                "startedAt": "1970-01-01T00:16:40+00:00",
                "durationSecs": 0.0,
                "exitCode": "0",
                "exitResult": "EXIT_RESULT_SUCCESS",
            }
        ]
        self.sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "qlty", "semanticVersion": "0.663.0"}},
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [
                                {
                                    "level": "note",
                                    "descriptor": {
                                        "id": (
                                            "qlty:message:invocation.concluded.success"
                                        )
                                    },
                                    "message": {
                                        "text": (
                                            "Successfully ran ruff in 0.62s [0SEKkj]"
                                        )
                                    },
                                }
                            ],
                        }
                    ],
                    "results": [],
                }
            ],
        }
        self.effect = lambda arguments, keywords: 0
        original = subprocess.run

        def execute(command, **keywords):
            if command[0] != str(self.qlty):
                return original(command, **keywords)
            arguments = command[1:]
            self.commands.append(arguments)
            code = self.effect(arguments, keywords)
            output = {
                "--version": "qlty 0.663.0 linux-x64\n",
                "config": self.config,
                "plugins": self.catalog,
                "check": json.dumps(self.sarif),
            }.get(arguments[0], "analyzed files\n")
            keywords["stdout"].write(output.encode())
            if arguments[0] == "check":
                for record in self.records:
                    header = f"\n# .qlty/out/invoke-{record['id']}.yaml:\n"
                    keywords["stderr"].write((header + yaml.safe_dump(record)).encode())
                    output = repo / ".qlty/out" / f"invoke-{record['id']}.yaml"
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(yaml.safe_dump(record))
            return subprocess.CompletedProcess(command, code)

        return repo, patch.object(maintenance.subprocess, "run", side_effect=execute)

    def invoke_precommit(self, repo, paths=None):
        return maintenance.precommit(
            repo,
            self.state,
            str(self.qlty),
            owner="queen-ordered-fixture",
            format_paths=paths or ["candidate.py"],
        )

    def receipts(self):
        return [
            json.loads(path.read_text())
            for path in (self.state / "logs").glob("*/precommit.json")
        ]

    def test_precommit_is_fresh_each_time_and_binds_formatted_endbytes(self):
        repo, spy = self.precommit_fixture()

        def format_candidate(arguments, keywords):
            if arguments[0] == "fmt":
                (repo / "candidate.py").write_text("value = 1\n")
            return 0

        self.effect = format_candidate
        with spy:
            self.assertEqual(self.invoke_precommit(repo), 0)
            self.assertEqual(self.invoke_precommit(repo), 0)
        self.assertEqual(
            [
                row[0]
                for row in self.commands
                if row[0] in {"fmt", "metrics", "smells", "check"}
            ],
            ["fmt", "metrics", "smells", "check"] * 2,
        )
        self.assertEqual(len(self.receipts()), 2)
        for receipt in self.receipts():
            self.assertEqual(receipt["formatted_source"], receipt["final_source"])
            self.assertEqual(
                receipt["candidate_sha256"]["candidate.py"],
                hashlib.sha256((repo / "candidate.py").read_bytes()).hexdigest(),
            )
            self.assertEqual(receipt["plugins_before"]["hidden"], ["tsc"])
            check = next(
                row for row in receipt["steps"] if row["command"][0] == "check"
            )
            self.assertIn("--all", check["command"])
            self.assertIn("--no-cache", check["command"])
            self.assertFalse(
                any(
                    arg.startswith(
                        (
                            "--filter",
                            "--skip=",
                            "--no-fail",
                            "--no-error",
                            "--sample",
                            "--no-formatters",
                        )
                    )
                    for arg in check["command"]
                )
            )
        self.assertEqual(maintenance.registered_state(repo, self.state)["guards"], [])

    def test_actual_producer_records_without_planner_text_complete(self):
        repo, spy = self.precommit_fixture()
        with spy:
            self.assertEqual(self.invoke_precommit(repo), 0)
        evidence = self.receipts()[0]["invocation_evidence"]
        self.assertEqual(evidence["completed"], 1)
        self.assertEqual(evidence["file_targets"], 1)

    def test_configured_findings_exit1_is_successful_execution(self):
        repo, spy = self.precommit_fixture()
        # Actual gKYha5/markdownlint0.46.0: raw1 + EXIT_RESULT_SUCCESS.
        self.records[0].update(
            id="gKYha5", pluginName="markdownlint", pluginVersion="0.46.0", exitCode="1"
        )
        notice = self.sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][
            0
        ]
        notice["message"]["text"] = "Successfully ran markdownlint in 0.01s [gKYha5]"
        with spy:
            self.assertEqual(self.invoke_precommit(repo), 0)

    def test_qlty_owned_cache_alias_is_bound_and_swaps_fail_closed(self):
        for failure in (None, "foreign", "link-swap", "same-link-swap", "root-swap"):
            with self.subTest(failure=failure):
                self.state = self.root / str(failure)
                repo, spy = self.precommit_fixture()
                home = self.root / f"home-{self.fixture_index}"
                home.mkdir(mode=0o700)
                fingerprint = hashlib.md5(
                    str(repo / ".qlty").encode(), usedforsecurity=False
                ).hexdigest()
                root = home / ".qlty/cache/repos" / fingerprint / "out"
                root.mkdir(parents=True)
                alias = repo / ".qlty/out"
                alias.rmdir()
                foreign = self.root / f"foreign-{self.fixture_index}"
                foreign.mkdir()
                alias.symlink_to(foreign if failure == "foreign" else root)

                def mutate(arguments, _keywords):
                    if arguments[0] == "check":
                        if failure == "link-swap":
                            alias.unlink()
                            alias.symlink_to(foreign)
                        elif failure == "same-link-swap":
                            alias.unlink()
                            alias.symlink_to(root)
                        elif failure == "root-swap":
                            root.rename(root.with_name("original"))
                            root.mkdir()
                    return 0

                self.effect = mutate
                with (
                    patch.object(
                        maintenance.pwd,
                        "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home)),
                    ),
                    spy,
                ):
                    result = self.invoke_precommit(repo)
                self.assertEqual(result, 0 if failure is None else 2)
                if failure:
                    self.assertEqual(self.receipts()[-1]["status"], "hold")

    def test_private_check_staging_binds_formatter_and_rejects_swaps(self):
        for failure in (
            None,
            "removed-stage",
            "linter",
            "foreign",
            "stage-symlink",
            "root-swap",
        ):
            with self.subTest(failure=failure):
                self.state = self.root / f"stage-{failure}"
                repo, spy = self.precommit_fixture()
                self.records[0]["driverName"] = (
                    "lint" if failure == "linter" else "format"
                )

                def make_stage(arguments, keywords):
                    if arguments[0] == "check":
                        tmp = Path(keywords["env"]["TMPDIR"])
                        root = tmp / "qlty"
                        root.mkdir()
                        stage = root / "Ab123456-rw"
                        if failure == "stage-symlink":
                            stage.symlink_to(repo, target_is_directory=True)
                        else:
                            stage.mkdir()
                        self.records[0]["cwd"] = str(
                            self.root / "foreign" if failure == "foreign" else stage
                        )
                        if failure == "removed-stage":
                            stage.rmdir()
                        if failure == "root-swap":
                            tmp.rename(tmp.with_name("held-check-tmp"))
                            tmp.mkdir(mode=0o700)
                    return 0

                self.effect = make_stage
                with spy:
                    result = self.invoke_precommit(repo)
                self.assertEqual(result, 0 if failure in (None, "removed-stage") else 2)
                if failure not in (None, "removed-stage"):
                    self.assertEqual(self.receipts()[-1]["status"], "hold")

    def test_config_snapshot_preserves_types_and_list_order(self):
        canonical = maintenance.config_semantic_sha256
        baseline = canonical("outer: {a: 1, b: [true, 2]}\n")
        self.assertEqual(baseline, canonical("outer: {b: [true, 2], a: 1}\n"))
        for changed in (
            "outer: {a: 2, b: [true, 2]}\n",
            "outer: {a: 1.0, b: [true, 2]}\n",
            "outer: {a: 1, b: [1, 2]}\n",
            "outer: {a: 1, b: [2, true]}\n",
        ):
            self.assertNotEqual(baseline, canonical(changed))
        with self.assertRaises(ValueError):
            canonical("1: value\n")

    def test_plugin_snapshot_compares_semantics_and_keeps_raw_digests(self):
        baseline = {
            "config_sha256": "raw-one",
            "config_semantic_sha256": "semantic",
            "version": "qlty 1",
            "catalog_sha256": "catalog",
        }
        rendered = {**baseline, "config_sha256": "raw-two"}
        self.assertTrue(maintenance.plugin_snapshots_equal(baseline, rendered))
        for key in ("config_semantic_sha256", "version", "catalog_sha256"):
            changed = {**rendered, key: "changed"}
            self.assertFalse(maintenance.plugin_snapshots_equal(baseline, changed))
        self.assertEqual(baseline["config_sha256"], "raw-one")

    def test_missing_candidates_get_separate_checked_supplement(self):
        for failure in (None, "missing", "failed", "duplicate-id", "cross-context"):
            with self.subTest(failure=failure):
                self.state = self.root / f"coverage-{failure}"
                repo, spy = self.precommit_fixture()
                (repo / "second.py").write_text("value=2\n")
                self.records[0]["driverName"] = "format"
                checks = []
                first_stage = None

                def effect(arguments, keywords):
                    nonlocal first_stage
                    if arguments[0] != "check":
                        return 0
                    temporary = Path(keywords["env"]["TMPDIR"])
                    stage = temporary / "qlty/Ab123456-rw"
                    stage.mkdir(parents=True)
                    checks.append((arguments, temporary))
                    if len(checks) == 1:
                        first_stage = stage
                        self.records[0]["cwd"] = str(stage)
                    else:
                        self.records[0]["id"] = (
                            "0SEKkj" if failure == "duplicate-id" else "extra1"
                        )
                        self.records[0]["targetPaths"] = [
                            "candidate.py" if failure == "missing" else "second.py"
                        ]
                        self.records[0]["cwd"] = str(
                            first_stage if failure == "cross-context" else stage
                        )
                        notice = self.sarif["runs"][0]["invocations"][0][
                            "toolExecutionNotifications"
                        ][0]
                        record_id = self.records[0]["id"]
                        notice["message"]["text"] = f"ok [{record_id}]"
                    return 9 if failure == "failed" and len(checks) == 2 else 0

                self.effect = effect
                with spy:
                    result = self.invoke_precommit(repo, ["candidate.py", "second.py"])
                self.assertEqual(result, 0 if failure is None else 2)
                self.assertEqual(len(checks), 2)
                self.assertIn("--all", checks[0][0])
                self.assertNotIn("--all", checks[1][0])
                self.assertEqual(checks[1][0][-1], "second.py")
                self.assertNotEqual(checks[0][1], checks[1][1])
                if failure:
                    self.assertEqual(self.receipts()[-1]["status"], "hold")
                else:
                    self.assertEqual(
                        self.receipts()[-1]["invocation_evidence"]["file_targets"], 2
                    )

    def test_inconsistent_or_stale_actual_records_hold(self):
        for failure in (
            "missing",
            "duplicate",
            "unmatched",
            "empty-targets",
            "wrong-count",
            "directory-only",
            "foreign-cwd",
            "stale",
            "wrong-version",
            "wrong-verb",
            "error-record",
            "missing-notification",
            "duplicate-notification",
            "record-symlink",
            "record-hardlink",
            "unsafe-mode",
        ):
            with self.subTest(failure=failure):
                self.state = self.root / failure
                repo, spy = self.precommit_fixture()
                record = self.records[0]
                notification = self.sarif["runs"][0]["invocations"][0]
                if failure == "missing":
                    self.records = []
                elif failure == "duplicate":
                    self.records *= 2
                    notification["toolExecutionNotifications"] *= 2
                elif failure == "unmatched":
                    record["id"] = "other"
                elif failure == "empty-targets":
                    record.update(targetsCount=0, targetPaths=[])
                elif failure == "wrong-count":
                    record["targetsCount"] = 64
                elif failure == "directory-only":
                    record["targetPaths"] = ["."]
                elif failure == "foreign-cwd":
                    record["cwd"] = str(self.root)
                elif failure == "stale":
                    record["startedAt"] = "1970-01-01T00:00:00+00:00"
                elif failure == "wrong-version":
                    record["qltyCliVersion"] = "0.662.0"
                elif failure == "wrong-verb":
                    record["verb"] = "EXECUTION_VERB_FMT"
                elif failure == "error-record":
                    record["exitResult"] = "EXIT_RESULT_UNKNOWN_ERROR"
                elif failure == "missing-notification":
                    notification["toolExecutionNotifications"] = []
                elif failure in {"record-symlink", "record-hardlink", "unsafe-mode"}:
                    output = repo / ".qlty/out/invoke-0SEKkj.yaml"
                    output.parent.mkdir(parents=True, exist_ok=True)
                    foreign = self.root / "foreign-record.yaml"
                    foreign.touch()
                    if failure == "record-symlink":
                        output.symlink_to(foreign)
                    elif failure == "record-hardlink":
                        output.hardlink_to(foreign)
                    else:
                        output.touch(mode=0o666)
                        output.chmod(0o666)
                else:
                    notification["toolExecutionNotifications"] *= 2
                with spy:
                    self.assertEqual(self.invoke_precommit(repo), 2)
                self.assertEqual(self.receipts()[-1]["status"], "hold")

    def test_real_failed_producers_cannot_become_a_pass(self):
        # Public fields from actual kWCokV/H7Dq0K/RlGAaC records, not a plan spy.
        for name, invocation_id, version, code, result in (
            ("vale", "kWCokV", "3.13.0", "2", "EXIT_RESULT_UNKNOWN_ERROR"),
            ("kube-linter", "H7Dq0K", "0.8.3", "0", "EXIT_RESULT_OUTPUT_MISSING_ERROR"),
            ("semgrep", "RlGAaC", "1.179.0", "7", "EXIT_RESULT_UNKNOWN_ERROR"),
        ):
            with self.subTest(plugin=name):
                self.state = self.root / name
                repo, spy = self.precommit_fixture()
                self.records[0].update(
                    id=invocation_id,
                    pluginName=name,
                    pluginVersion=version,
                    exitCode=code,
                    exitResult=result,
                )
                invocation = self.sarif["runs"][0]["invocations"][0]
                invocation["toolExecutionNotifications"] = [
                    {
                        "level": "error",
                        "descriptor": {"id": "qlty:message:invocation.concluded.error"},
                        "message": {
                            "text": f"Error occurred while running {name} (1.00s) "
                            f"[{invocation_id}]"
                        },
                    }
                ]
                # Even an inner tool's true flag cannot override the CLI3 failure.
                self.effect = lambda arguments, keywords: (
                    3 if arguments[0] == "check" else 0
                )
                with spy:
                    self.assertNotEqual(self.invoke_precommit(repo), 0)
                receipt = self.receipts()[-1]
                self.assertEqual(
                    next(
                        x["exit_code"]
                        for x in receipt["steps"]
                        if x["command"][0] == "check"
                    ),
                    3,
                )

    def test_shared_guards_block_precommit_and_precommit_blocks_all_phases(self):
        repo, spy = self.precommit_fixture()
        work = maintenance.begin_guard(repo, self.state, owner="writer", phase="work")
        with self.assertRaisesRegex(ValueError, "qlty_precommit_guard_active"):
            self.invoke_precommit(repo)
        maintenance.end_guard(
            repo, self.state, owner="writer", guard_id=work["guard_id"]
        )

        def writer(arguments, keywords):
            for phase in ("work", "freeze", "test", "precommit"):
                with self.assertRaisesRegex(ValueError, "qlty_precommit_guard_active"):
                    maintenance.begin_guard(
                        repo, self.state, owner="other", phase=phase
                    )
            return 0

        self.effect = writer
        with spy:
            self.assertEqual(self.invoke_precommit(repo), 0)

    def test_formatter_cannot_change_an_unapproved_path(self):
        repo, spy = self.precommit_fixture()
        other = repo / "closed.py"
        other.write_text("unchanged\n")

        def outside(arguments, keywords):
            if arguments[0] == "fmt":
                other.write_text("unexpected write\n")
                self.assertEqual(arguments[-1], "candidate.py")
                self.assertNotIn("--all", arguments)
            return 0

        self.effect = outside
        with spy:
            self.assertEqual(self.invoke_precommit(repo), 2)
        self.assertEqual(self.receipts()[0]["reason"], "qlty_format_scope_changed")
        self.assertNotIn("metrics", [row[0] for row in self.commands])
        self.assertEqual(maintenance.registered_state(repo, self.state)["guards"], [])

    def test_format_scope_requires_real_relative_non_symlink_files(self):
        repo, spy = self.precommit_fixture()
        (repo / "alias.py").symlink_to(repo / "candidate.py")
        for paths in (
            [],
            ["candidate.py"] * 2,
            ["../outside"],
            [str(repo / "candidate.py")],
            ["alias.py"],
        ):
            with (
                self.subTest(paths=paths),
                spy,
                self.assertRaises((ValueError, OSError)),
            ):
                maintenance.precommit(
                    repo,
                    self.state,
                    str(self.qlty),
                    owner="fixture",
                    format_paths=paths,
                )
        self.assertEqual(self.commands, [])

    def test_evidence_failures_hold_and_preserve_real_exits(self):
        repo, spy = self.precommit_fixture()
        for failure in (
            "missing-plugin",
            "restricted",
            "bad-sarif",
            "tool-error",
            "metrics-error",
            "empty-records",
            "source-drift",
            "plugin-drift",
            "catalog-exit",
            "execution-failed",
        ):
            with self.subTest(failure=failure):
                original_config = self.config
                original_sarif = copy.deepcopy(self.sarif)
                original_records = copy.deepcopy(self.records)
                known = {row["guard"]["guard_id"] for row in self.receipts()}

                def fail(arguments, keywords):
                    command = arguments[0]
                    if failure == "missing-plugin" and command == "config":
                        self.config = original_config.replace(
                            "- name: tsc\n", "- name: unknown\n"
                        )
                    if failure == "restricted" and command == "config":
                        self.config = original_config.replace(
                            "mode: null", "mode: comment"
                        )
                    if failure == "bad-sarif" and command == "check":
                        self.sarif = {}
                    if failure == "empty-records" and command == "check":
                        self.records = []
                        self.sarif["runs"][0]["invocations"][0][
                            "toolExecutionNotifications"
                        ] = []
                    if failure == "execution-failed" and command == "check":
                        self.sarif["runs"][0]["invocations"][0][
                            "executionSuccessful"
                        ] = False
                    if failure == "source-drift" and command == "metrics":
                        (repo / "candidate.py").write_text("changed during analysis\n")
                    if failure == "plugin-drift" and command == "plugins":
                        self.config = self.config.replace(
                            "smells: {}", "smells: {changed: true}"
                        )
                    return (
                        9
                        if failure == "tool-error"
                        and command == "check"
                        or failure == "metrics-error"
                        and command == "metrics"
                        or failure == "catalog-exit"
                        and command == "config"
                        else 0
                    )

                self.effect = fail
                with spy:
                    self.assertNotEqual(self.invoke_precommit(repo), 0)
                receipt = next(
                    row
                    for row in self.receipts()
                    if row["guard"]["guard_id"] not in known
                )
                self.assertNotEqual(receipt["status"], "complete")
                if failure == "empty-records":
                    self.assertEqual(receipt["reason"], "qlty_no_actual_invocations")
                if failure == "tool-error":
                    self.assertTrue(
                        any(
                            step["exit_code"] == 9
                            for row in self.receipts()
                            for step in row["steps"]
                        )
                    )
                self.config = original_config
                self.sarif = original_sarif
                self.records = original_records
                self.assertEqual(
                    maintenance.registered_state(repo, self.state)["guards"], []
                )

    def test_legacy_operations_and_format_approval_are_parse_errors(self):
        for arguments in (
            ["daily"],
            ["run"],
            ["finish-fmt"],
            ["end", "--approve-format"],
        ):
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    *arguments,
                    "--state-root",
                    str(self.state),
                    "--qlty",
                    str(self.qlty),
                ],
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.state.exists())

    def test_hourly_upgrade_checks_expire_a_non_aligned_claim_within_one_hour(self):
        timer = SCRIPT.parents[1] / "systemd/user/the-hive-qlty-maintenance.timer"
        self.assertIn("OnCalendar=hourly\n", timer.read_text())
        self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        first_started = self.now.return_value
        for hour in range(1, 26):
            self.now.return_value = hour * 3600
            self.assertEqual(maintenance.upgrade(self.state, str(self.qlty)), 0)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)
        record = json.loads(next(self.state.glob("*.json")).read_text())
        self.assertGreaterEqual(record["attempted_at"] - first_started, maintenance.DAY)
        self.assertLess(record["attempted_at"] - first_started, maintenance.DAY + 3600)

    def test_scheduler_is_upgrade_only_and_all_69_definitions_are_enabled(self):
        root = SCRIPT.parents[1]
        service = (root / "systemd/user/the-hive-qlty-maintenance.service").read_text()
        self.assertIn(
            "ExecStart=/usr/bin/python3 %h/the_hive/scripts/"
            "the-hive-qlty-maintenance upgrade\n",
            service,
        )
        self.assertNotIn("maintenance daily", service)
        self.assertIn(
            "OnCalendar=hourly\n",
            (root / "systemd/user/the-hive-qlty-maintenance.timer").read_text(),
        )
        config = tomllib.loads((root / ".qlty/qlty.toml").read_text())
        names = [entry["name"] for entry in config["plugin"]]
        self.assertEqual(len(names), 69)
        self.assertEqual(len(set(names)), 69)
        self.assertIn("tsc", names)
        self.assertTrue(all("mode" not in entry for entry in config["plugin"]))
