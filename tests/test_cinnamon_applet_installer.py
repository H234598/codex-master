from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL_SOURCE = ROOT / "scripts" / "codex-master-cinnamon-applet"
UUID = "codex-master@H234598"


class CinnamonAppletInstallerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.home = self.root / "home"
        self.bin = self.root / "bin"
        self.log = self.root / "gdbus.jsonl"
        (self.repo / "scripts").mkdir(parents=True)
        self.home.mkdir()
        self.bin.mkdir()
        shutil.copy2(TOOL_SOURCE, self.repo / "scripts" / TOOL_SOURCE.name)
        self.source = self.repo / "cinnamon" / "applets" / UUID
        self.source.mkdir(parents=True)
        self._write_tree(self.source, "new")
        self.tool = self.repo / "scripts" / TOOL_SOURCE.name
        self._write_fake_gdbus()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def target(self) -> Path:
        return self.home / ".local" / "share" / "cinnamon" / "applets" / UUID

    @property
    def backup(self) -> Path:
        return self.target.with_name(f"{UUID}.rollback")

    def _write_tree(self, root: Path, marker: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "applet.js").write_text(f"// {marker}\n", encoding="utf-8")
        (root / "metadata.json").write_text(
            json.dumps({"uuid": UUID, "name": "Flottenmanagement", "marker": marker}),
            encoding="utf-8",
        )
        (root / "settings-schema.json").write_text(
            json.dumps({"tracked-agents": {"type": "entry", "default": "a1,b1"}}),
            encoding="utf-8",
        )

    def _write_fake_gdbus(self) -> None:
        fake = self.bin / "gdbus"
        fake.write_text(
            """#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

log = Path(os.environ["FAKE_GDBUS_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
mode = os.environ.get("FAKE_GDBUS_MODE", "ok")
method = sys.argv[sys.argv.index("--method") + 1]
if method.endswith("ReloadXlet"):
    if sys.argv[-1] != "APPLET":
        print("type is undefined", file=sys.stderr)
        raise SystemExit(8)
    if mode == "reload-fail":
        print("reload failed", file=sys.stderr)
        raise SystemExit(7)
if method.endswith("GetRunningXletUUIDs"):
    if mode == "missing":
        print("(@as [],)")
    elif mode == "spoofed":
        print("({'running': 'codex-master@H234598'},)")
    elif mode == "large":
        print("X" * 70000)
    else:
        print("(['codex-master@H234598'],)")
else:
    print("(true,)")
""",
            encoding="utf-8",
        )
        fake.chmod(0o755)

    def _run(self, *args: str, mode: str = "ok") -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(self.home),
                "PATH": f"{self.bin}{os.pathsep}{env.get('PATH', '')}",
                "FAKE_GDBUS_LOG": str(self.log),
                "FAKE_GDBUS_MODE": mode,
            }
        )
        return subprocess.run(
            [sys.executable, str(self.tool), *args],
            cwd=self.repo,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    def _manifest(self, root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def _load_tool_module(self):
        name = f"codex_master_cinnamon_installer_{id(self)}"
        loader = SourceFileLoader(name, str(self.tool))
        spec = importlib.util.spec_from_loader(name, loader)
        if spec is None or spec.loader is None:
            self.fail("installer module could not be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_dry_run_changes_nothing_and_calls_no_dbus(self) -> None:
        result = self._run("install", "--dry-run")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.target.parent.exists())
        self.assertFalse(self.log.exists())

    def test_install_stages_exact_tree_keeps_one_backup_and_uses_fixed_dbus(self) -> None:
        self._write_tree(self.target, "old")
        self._write_tree(self.backup, "older")

        result = self._run("install")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._manifest(self.target), self._manifest(self.source))
        self.assertIn(b"old", (self.backup / "applet.js").read_bytes())
        backups = list(self.target.parent.glob(f"{UUID}.rollback*"))
        self.assertEqual(backups, [self.backup])
        self.assertEqual(list(self.target.parent.glob(f".{UUID}.retired*")), [])
        calls = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        joined = "\n".join(" ".join(call) for call in calls)
        self.assertIn(f"org.Cinnamon.ReloadXlet {UUID} APPLET", joined)
        self.assertIn("org.Cinnamon.GetRunningXletUUIDs applet", joined)
        self.assertNotIn("RestartCinnamon", joined)
        self.assertNotIn("Eval", joined)

    def test_failed_backup_rotation_preserves_existing_rollback(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "known-good")
        module = self._load_tool_module()
        real_replace = module.os.replace

        def fail_rotation(source, destination):
            if Path(source) == self.target and Path(destination) == self.backup:
                raise OSError("injected rename failure")
            return real_replace(source, destination)

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module.os, "replace", side_effect=fail_rotation):
                with self.assertRaises(OSError):
                    module.install(dry_run=False, no_reload=True)

        self.assertIn("current", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("known-good", (self.backup / "applet.js").read_text(encoding="utf-8"))
        self.assertEqual(list(self.target.parent.glob(f".{UUID}.*")), [])

    def test_cleanup_failure_does_not_mask_install_error(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "known-good")
        retired = self.target.parent / f".{UUID}.retired"
        module = self._load_tool_module()
        real_replace = module.os.replace

        def fail_rotation_and_restore(source, destination):
            source = Path(source)
            destination = Path(destination)
            if source == self.target and destination == self.backup:
                raise OSError("primary rotation failure")
            if source == retired and destination == self.backup:
                raise OSError("cleanup restore failure")
            return real_replace(source, destination)

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module.os, "replace", side_effect=fail_rotation_and_restore):
                with self.assertRaisesRegex(OSError, "primary rotation failure") as caught:
                    module.install(dry_run=False, no_reload=True)

        self.assertIn("cleanup restore failure", "\n".join(caught.exception.__notes__))
        self.assertIn("current", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("known-good", (retired / "applet.js").read_text(encoding="utf-8"))
        self.assertFalse(self.backup.exists())

    def test_failed_stage_promotion_preserves_existing_rollback(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "known-good")
        module = self._load_tool_module()
        real_replace = module.os.replace

        def fail_promotion(source, destination):
            source = Path(source)
            if Path(destination) == self.target and source.name.startswith(f".{UUID}.staging-"):
                raise OSError("injected promotion failure")
            return real_replace(source, destination)

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module.os, "replace", side_effect=fail_promotion):
                with self.assertRaises(OSError):
                    module.install(dry_run=False, no_reload=True)

        self.assertIn("current", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("known-good", (self.backup / "applet.js").read_text(encoding="utf-8"))
        self.assertEqual(list(self.target.parent.glob(f".{UUID}.*")), [])

    def test_failed_deployment_preserves_existing_rollback(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "known-good")

        result = self._run("install", mode="reload-fail")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("known-good", (self.backup / "applet.js").read_text(encoding="utf-8"))
        self.assertEqual(list(self.target.parent.glob(f".{UUID}.retired*")), [])

    def test_restore_failure_preserves_retired_rollback_for_recovery(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "known-good")
        module = self._load_tool_module()
        real_remove = module.remove_validated_tree

        def fail_failed_target_removal(path, label):
            if label == "failed installed applet":
                raise module.InstallerError("injected restore failure")
            return real_remove(path, label)

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module, "verify_files", side_effect=module.InstallerError("injected")):
                with mock.patch.object(module, "remove_validated_tree", side_effect=fail_failed_target_removal):
                    with self.assertRaises(module.InstallerError):
                        module.install(dry_run=False, no_reload=True)

        self.assertIn("new", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("current", (self.backup / "applet.js").read_text(encoding="utf-8"))
        retired = self.target.parent / f".{UUID}.retired"
        self.assertIn("known-good", (retired / "applet.js").read_text(encoding="utf-8"))

    def test_unfinished_rollback_rotation_fails_closed(self) -> None:
        retired = self.target.parent / f".{UUID}.retired"
        self._write_tree(retired, "unfinished")

        result = self._run("install", "--dry-run")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unfinished", (retired / "applet.js").read_text(encoding="utf-8"))
        self.assertFalse(self.target.exists())

    def test_no_reload_install_and_verify_behave_separately(self) -> None:
        install = self._run("install", "--no-reload")
        self.assertEqual(install.returncode, 0, install.stderr)
        self.assertFalse(self.log.exists())

        verify = self._run("verify")
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn("GetRunningXletUUIDs", self.log.read_text(encoding="utf-8"))

    def test_reload_or_running_verification_failure_restores_previous_tree(self) -> None:
        for mode in ("reload-fail", "missing", "spoofed"):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                if self.target.exists():
                    shutil.rmtree(self.target)
                if self.backup.exists():
                    shutil.rmtree(self.backup)
                self._write_tree(self.target, f"old-{mode}")

                result = self._run("install", mode=mode)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"old-{mode}", (self.target / "applet.js").read_text(encoding="utf-8"))
                self.assertFalse(self.backup.exists())
                calls = self.log.read_text(encoding="utf-8").count("org.Cinnamon.ReloadXlet")
                self.assertEqual(calls, 2, "restored applet must be reloaded after failed deployment")

    def test_verify_rejects_byte_difference_and_unbounded_dbus_output(self) -> None:
        shutil.copytree(self.source, self.target)
        (self.target / "applet.js").write_text("changed\n", encoding="utf-8")
        different = self._run("verify")
        self.assertNotEqual(different.returncode, 0)

        shutil.rmtree(self.target)
        shutil.copytree(self.source, self.target)
        large = self._run("verify", mode="large")
        self.assertNotEqual(large.returncode, 0)

    def test_source_symlink_hardlink_and_fifo_are_rejected(self) -> None:
        cases = ("symlink", "hardlink", "fifo")
        for case in cases:
            with self.subTest(case=case):
                path = self.source / "applet.js"
                path.unlink()
                if case == "symlink":
                    path.symlink_to(self.source / "metadata.json")
                elif case == "hardlink":
                    os.link(self.source / "metadata.json", path)
                else:
                    os.mkfifo(path)

                result = self._run("install", "--dry-run")
                self.assertNotEqual(result.returncode, 0)

                path.unlink()
                path.write_text("// new\n", encoding="utf-8")

    def test_source_wrong_owner_or_group_writable_mode_is_rejected(self) -> None:
        source_file = self.source / "applet.js"
        source_file.chmod(0o664)

        wrong_mode = self._run("install", "--dry-run")

        self.assertNotEqual(wrong_mode.returncode, 0)
        source_file.chmod(0o644)
        module = self._load_tool_module()
        with mock.patch.object(module.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(module.InstallerError):
                module.validate_source(self.source)

    def test_source_swap_during_staging_fails_without_touching_installed_tree(self) -> None:
        self._write_tree(self.target, "old")
        module = self._load_tool_module()
        original = module.copy_file_checked
        swapped = False

        def swap_before_copy(source, destination, expected_hash, mode):
            nonlocal swapped
            if not swapped:
                swapped = True
                source.write_text("raced\n", encoding="utf-8")
            return original(source, destination, expected_hash, mode)

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module, "copy_file_checked", side_effect=swap_before_copy):
                with self.assertRaises(module.InstallerError):
                    module.install(dry_run=False, no_reload=True)

        self.assertIn("old", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertFalse(self.backup.exists())
        self.assertEqual(list(self.target.parent.glob(f".{UUID}.staging-*")), [])

    def test_source_mode_change_between_stat_and_open_is_rejected(self) -> None:
        module = self._load_tool_module()
        source_file = self.source / "applet.js"
        expected = source_file.lstat()
        real_open = module.os.open

        def change_mode_then_open(path, flags, *args):
            if Path(path) == source_file:
                source_file.chmod(0o666)
            return real_open(path, flags, *args)

        try:
            with mock.patch.object(module.os, "open", side_effect=change_mode_then_open):
                with self.assertRaises(module.InstallerError):
                    module.hash_regular_file(source_file, expected)
        finally:
            source_file.chmod(0o644)

    def test_target_parent_and_target_symlinks_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.home / ".local").symlink_to(outside, target_is_directory=True)
        parent_result = self._run("install")
        self.assertNotEqual(parent_result.returncode, 0)
        self.assertFalse((outside / "share").exists())

        (self.home / ".local").unlink()
        self.target.parent.mkdir(parents=True)
        self.target.symlink_to(outside, target_is_directory=True)
        target_result = self._run("install")
        self.assertNotEqual(target_result.returncode, 0)

    def test_rollback_swaps_exact_tree_and_rejects_missing_or_symlink_backup(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "previous")

        result = self._run("rollback", "--no-reload")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("previous", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("current", (self.backup / "applet.js").read_text(encoding="utf-8"))

        shutil.rmtree(self.backup)
        missing = self._run("rollback", "--no-reload")
        self.assertNotEqual(missing.returncode, 0)
        self.backup.symlink_to(self.source, target_is_directory=True)
        linked = self._run("rollback", "--no-reload")
        self.assertNotEqual(linked.returncode, 0)

    def test_rollback_reload_failure_restores_current_and_backup(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "previous")

        result = self._run("rollback", mode="reload-fail")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("previous", (self.backup / "applet.js").read_text(encoding="utf-8"))
        calls = self.log.read_text(encoding="utf-8").count("org.Cinnamon.ReloadXlet")
        self.assertEqual(calls, 2, "restored current applet must be reloaded after failed rollback")

    def test_rollback_works_without_repository_source(self) -> None:
        self._write_tree(self.target, "current")
        self._write_tree(self.backup, "previous")
        shutil.rmtree(self.source)

        result = self._run("rollback", "--no-reload")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("previous", (self.target / "applet.js").read_text(encoding="utf-8"))
        self.assertIn("current", (self.backup / "applet.js").read_text(encoding="utf-8"))

    def test_mutating_commands_are_serialized_by_uuid_lock(self) -> None:
        module = self._load_tool_module()
        entered = 0
        entered_lock = threading.Lock()
        first_entered = threading.Event()
        release_first = threading.Event()
        results: list[int] = []

        def fake_install(*, dry_run, no_reload):
            nonlocal entered
            with entered_lock:
                entered += 1
                current = entered
            if current == 1:
                first_entered.set()
                release_first.wait(timeout=5)
            return {"ok": True, "action": "install"}

        def invoke() -> None:
            results.append(module.main(["install", "--no-reload"]))

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with mock.patch.object(module.os, "umask"):
                with mock.patch.object(module, "install", side_effect=fake_install):
                    first = threading.Thread(target=invoke)
                    second = threading.Thread(target=invoke)
                    first.start()
                    try:
                        self.assertTrue(first_entered.wait(timeout=2))
                        second.start()
                        time.sleep(0.2)
                        self.assertEqual(entered, 1, "second mutator entered before first released lock")
                    finally:
                        release_first.set()
                        first.join(timeout=5)
                        if second.ident is not None:
                            second.join(timeout=5)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(sorted(results), [0, 0])

    def test_uuid_lock_does_not_reclassify_operation_oserror(self) -> None:
        module = self._load_tool_module()

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with self.assertRaisesRegex(OSError, "injected operation failure"):
                with module.operation_lock(create_parent=True):
                    raise OSError("injected operation failure")

    def test_kill_and_wait_remains_bounded_when_process_cannot_be_reaped(self) -> None:
        module = self._load_tool_module()

        class StubbornProcess:
            def __init__(self):
                self.kill_count = 0
                self.wait_timeouts = []

            def poll(self):
                return None

            def kill(self):
                self.kill_count += 1

            def wait(self, timeout=None):
                self.wait_timeouts.append(timeout)
                if timeout is None:
                    raise AssertionError("unbounded wait")
                raise subprocess.TimeoutExpired("gdbus", timeout)

        process = StubbornProcess()

        module.kill_and_wait(process)

        self.assertEqual(process.kill_count, 2)
        self.assertEqual(process.wait_timeouts, [1, 1])


if __name__ == "__main__":
    unittest.main()
