import os
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from codex_master.fleet_snapshot import (
    AgentProcessSnapshot,
    FleetSnapshot,
    ProcessSnapshot,
    TmuxSessionSnapshot,
    create_fleet_snapshot,
    summarize_agent_processes,
)


class FleetSnapshotTests(unittest.TestCase):
    def _write_process(
        self,
        proc_root: Path,
        pid: int,
        *,
        home: Path,
        name: str,
        managed: bool,
        ppid: int = 1,
        uid: int | None = None,
    ) -> None:
        process = proc_root / str(pid)
        process.mkdir()
        (process / "status").write_text(
            f"Name:\t{name}\nState:\tS (sleeping)\nPPid:\t{ppid}\nUid:\t{os.getuid() if uid is None else uid}\n",
            encoding="utf-8",
        )
        env = [f"CODEX_HOME={home}"]
        if managed:
            env.extend(("CODEX_AGENT_MCP=1", "CODEX_MASTER_MCP=1"))
        (process / "environ").write_bytes("\0".join(env).encode() + b"\0")
        (process / "cmdline").write_bytes(b"codex\0")

    def test_snapshot_scans_processes_and_tmux_once_and_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc_root = root / "proc"
            proc_root.mkdir()
            a1_home = root / "a1-home"
            a2_home = root / "a2-home"
            a1_home.mkdir()
            a2_home.mkdir()
            self._write_process(proc_root, 101, home=a1_home, name="codex", managed=True)
            self._write_process(proc_root, 102, home=a1_home, name="python", managed=False, ppid=101)
            calls = []

            def run_tmux(args, *, check=False):
                calls.append((args, check))
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "a1-session\t1\t101\nother\t1\t999\n",
                    "",
                )

            snapshot = create_fleet_snapshot(
                agent_homes={"a1": a1_home, "a2": a2_home},
                agent_sessions={"a1": "a1-session", "a2": "a2-session"},
                proc_root=proc_root,
                tmux_runner=run_tmux,
                created_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            )

            self.assertEqual(len(calls), 1)
            self.assertTrue(snapshot.process_scan_available)
            self.assertTrue(snapshot.tmux_scan_available)
            self.assertEqual(snapshot.tmux_sessions["a1-session"].pane_pid, 101)
            self.assertFalse(snapshot.tmux_sessions["a2-session"].alive)
            summary = summarize_agent_processes(snapshot, "a1")
            self.assertEqual(summary["process_count"], 2)
            self.assertEqual(summary["managed_process_count"], 1)
            self.assertEqual(summary["external_process_count"], 0)
            home_key = str(a1_home.resolve())
            self.assertEqual(snapshot.processes_by_codex_home[home_key][0].pid, 101)
            with self.assertRaises(FrozenInstanceError):
                snapshot.created_at = datetime.now(timezone.utc)
            with self.assertRaises(TypeError):
                snapshot.tmux_sessions["a1-session"] = snapshot.tmux_sessions["a2-session"]

    def test_nested_snapshot_collections_are_immutable(self) -> None:
        process = ProcessSnapshot(101, 1, "codex", "S (sleeping)", "/home/a1", True)
        agent_processes = AgentProcessSnapshot(True, [process])
        snapshot = FleetSnapshot(
            created_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            processes=[process],
            processes_by_codex_home={"/home/a1": [process]},
            tmux_sessions={"session-a": TmuxSessionSnapshot(True, 101)},
            agent_process_map={"a1": agent_processes},
            process_scan_available=True,
            tmux_scan_available=True,
        )

        self.assertIsInstance(snapshot.processes_by_codex_home["/home/a1"], tuple)
        self.assertIsInstance(snapshot.agent_process_map["a1"].processes, tuple)
        with self.assertRaises(AttributeError):
            snapshot.agent_process_map["a1"].processes.append(process)
        with self.assertRaises(TypeError):
            snapshot.processes_by_codex_home["/home/a1"] = ()

    def test_fleet_watchdog_reuses_one_snapshot_for_selected_agent(self) -> None:
        from codex_master import server

        sentinel = object()
        passed_snapshots = []

        def fake_status(agent, *, initialize_state=True, snapshot=None):
            passed_snapshots.append(snapshot)
            return {
                "agent": agent,
                "running": False,
                "lease": {"state": "unclaimed", "held_by_this_server": False},
            }

        with patch("codex_master.server.create_fleet_snapshot", return_value=sentinel) as create:
            with patch("codex_master.server.status_agent", side_effect=fake_status):
                result = server.fleet_watchdog("a1", action="none", dry_run=True)

        create.assert_called_once()
        self.assertEqual(passed_snapshots, [sentinel])
        self.assertEqual(result["results"][0]["watchdog_state"], "skipped_not_running")

    def test_fleet_watchdog_continues_when_snapshot_creation_fails(self) -> None:
        from codex_master import server

        passed_snapshots = []

        def fake_status(agent, *, initialize_state=True, snapshot=None):
            passed_snapshots.append(snapshot)
            return {
                "agent": agent,
                "running": False,
                "lease": {"state": "unclaimed", "held_by_this_server": False},
            }

        with patch(
            "codex_master.server.create_fleet_snapshot",
            side_effect=RuntimeError("snapshot unavailable"),
        ), patch("codex_master.server.status_agent", side_effect=fake_status):
            result = server.fleet_watchdog("a1", action="none", dry_run=True)

        self.assertEqual(passed_snapshots, [None])
        self.assertEqual(result["results"][0]["watchdog_state"], "skipped_not_running")

    def test_fleet_watchdog_skips_actions_when_tmux_snapshot_is_unavailable(self) -> None:
        from codex_master import server

        status = {
            "agent": "a1",
            "running": False,
            "tmux_scan_available": False,
            "lease": {"state": "held", "held_by_this_server": True},
            "response_state": {"state": "not_running"},
        }
        with patch("codex_master.server.status_agent", return_value=status), patch(
            "codex_master.server.release_agent"
        ) as release, patch("codex_master.server.stop_agent") as stop, patch(
            "codex_master.server.interrupt_agent"
        ) as interrupt:
            result = server._watchdog_agent_unlocked(
                "a1",
                idle_seconds=60,
                action="release",
                report_grace_seconds=15,
                require_lease=False,
                manage_unclaimed=True,
                dry_run=False,
            )

        self.assertEqual(result["watchdog_state"], "skipped_tmux_scan_unavailable")
        self.assertEqual(result["action_taken"], "none")
        release.assert_not_called()
        stop.assert_not_called()
        interrupt.assert_not_called()

    def test_snapshot_fails_closed_on_incomplete_process_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc_root = root / "proc"
            proc_root.mkdir()
            home = root / "a1-home"
            home.mkdir()
            self._write_process(proc_root, 101, home=home, name="codex", managed=True)
            (proc_root / "101" / "status").write_text(
                "Name:\tcodex\nState:\tS (sleeping)\n",
                encoding="utf-8",
            )

            snapshot = create_fleet_snapshot(
                agent_homes={"a1": home},
                agent_sessions={"a1": "a1-session"},
                proc_root=proc_root,
            )

        self.assertFalse(snapshot.process_scan_available)
        self.assertEqual(snapshot.processes, ())
        summary = summarize_agent_processes(snapshot, "a1")
        self.assertIsNone(summary["process_count"])
        self.assertEqual(summary["raw_output"], "not_returned")

    def test_snapshot_fails_closed_on_foreign_process_uid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc_root = root / "proc"
            proc_root.mkdir()
            home = root / "a1-home"
            home.mkdir()
            self._write_process(proc_root, 101, home=home, name="codex", managed=True)
            foreign_uid = 0 if os.getuid() != 0 else 65534
            (proc_root / "101" / "status").write_text(
                f"Name:\tcodex\nState:\tS (sleeping)\nPPid:\t1\nUid:\t{foreign_uid}\n",
                encoding="utf-8",
            )

            snapshot = create_fleet_snapshot(
                agent_homes={"a1": home},
                agent_sessions={"a1": "a1-session"},
                proc_root=proc_root,
            )

        self.assertFalse(snapshot.process_scan_available)
        self.assertIsNone(summarize_agent_processes(snapshot, "a1")["process_count"])

    def test_snapshot_ignores_unrelated_foreign_process_uid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc_root = root / "proc"
            proc_root.mkdir()
            home = root / "a1-home"
            unrelated_home = root / "other-home"
            home.mkdir()
            unrelated_home.mkdir()
            foreign_uid = 0 if os.getuid() != 0 else 65534
            self._write_process(
                proc_root,
                101,
                home=unrelated_home,
                name="python",
                managed=False,
                uid=foreign_uid,
            )

            snapshot = create_fleet_snapshot(
                agent_homes={"a1": home},
                agent_sessions={"a1": "a1-session"},
                proc_root=proc_root,
            )

        self.assertTrue(snapshot.process_scan_available)
        self.assertEqual(summarize_agent_processes(snapshot, "a1")["process_count"], 0)

    def test_snapshot_ignores_unreadable_non_codex_process_outside_managed_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc_root = root / "proc"
            proc_root.mkdir()
            home = root / "a1-home"
            home.mkdir()
            process = proc_root / "101"
            process.mkdir()
            (process / "status").write_text(
                f"Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t1\nUid:\t{os.getuid()}\n",
                encoding="utf-8",
            )

            with patch("codex_master.fleet_snapshot._read_proc_environ", return_value=None), patch(
                "codex_master.fleet_snapshot._resolve_proc_cwd", return_value=(None, True)
            ):
                snapshot = create_fleet_snapshot(
                    agent_homes={"a1": home},
                    agent_sessions={"a1": "a1-session"},
                    proc_root=proc_root,
                )

        self.assertTrue(snapshot.process_scan_available)
        self.assertEqual(summarize_agent_processes(snapshot, "a1")["process_count"], 0)

    def test_release_guard_rechecks_live_identity(self) -> None:
        from codex_master import server

        clear_summary = {
            "process_count": 0,
            "external_process_count": 0,
            "managed_process_count": 0,
            "managed_process_ids": [],
        }
        with patch("codex_master.server.tmux_alive", return_value=False), patch(
            "codex_master.server.agent_home_process_summary", return_value=clear_summary
        ):
            self.assertTrue(server.watchdog_release_identity_is_current("a1", expected_running=False))

        running_summary = {
            "process_count": 1,
            "external_process_count": 0,
            "managed_process_count": 1,
            "managed_process_ids": [101],
        }
        with patch("codex_master.server.tmux_alive", return_value=True), patch(
            "codex_master.server.agent_home_process_summary", return_value=running_summary
        ), patch("codex_master.server.require_managed_tmux_session") as require:
            self.assertTrue(server.watchdog_release_identity_is_current("a1", expected_running=True))
        require.assert_called_once_with("a1", process_summary=running_summary)


if __name__ == "__main__":
    unittest.main()
