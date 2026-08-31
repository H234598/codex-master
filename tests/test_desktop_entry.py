import contextlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import codex_master.server as server


class FleetDesktopEntryTest(unittest.TestCase):
    def test_serializes_fixed_control_center_command(self) -> None:
        content = server.fleet_desktop_entry_bytes(
            Path("/home/user/Codex Fleet/bin/codex-master-mcp")
        )

        self.assertEqual(
            content.decode("utf-8"),
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Flottenmanagement\n"
            "Comment=Codex-Flotte steuern und verwalten\n"
            'Exec="/home/user/Codex Fleet/bin/codex-master-mcp" control-center-launch\n'
            "Icon=utilities-system-monitor\n"
            "Terminal=false\n"
            "Categories=System;\n"
            "StartupNotify=true\n",
        )

    def test_recognizes_legacy_generated_entry_only_for_safe_cleanup(self) -> None:
        command = Path("/home/user/.local/lib/codex-master-runtime/bin/codex-master-mcp")
        current = server.fleet_desktop_entry_bytes(command)
        legacy = current.replace(b" control-center-launch\n", b" control-center\n")

        self.assertTrue(server._is_generated_fleet_desktop_entry(current))
        self.assertTrue(server._is_generated_fleet_desktop_entry(legacy))
        self.assertFalse(
            server._is_generated_fleet_desktop_entry(
                legacy.replace(b"StartupNotify=true", b"StartupNotify=false")
            )
        )

    def test_rejects_relative_or_control_character_command_path(self) -> None:
        for path in (
            Path("relative/codex-master-mcp"),
            Path("/tmp/bad\ncommand"),
            Path("/tmp/bad=command"),
            Path("/tmp/nicht-ascii-ä"),
            Path("/tmp/dollar$/codex"),
            Path("/tmp/tick`/codex"),
            Path('/tmp/quote"/codex'),
            Path("/tmp/percent%/codex"),
            Path("/tmp/backslash\\/codex"),
        ):
            with self.subTest(path=repr(str(path))):
                with self.assertRaisesRegex(
                    server.AgentError, "desktop command path is invalid"
                ):
                    server.fleet_desktop_entry_bytes(path)

    def test_relative_xdg_data_home_falls_back_to_home(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"HOME": tmpdir, "XDG_DATA_HOME": "relative-data"},
            ),
        ):
            self.assertEqual(
                server.fleet_desktop_entry_path(),
                Path(tmpdir)
                / ".local"
                / "share"
                / "applications"
                / server.FLEET_DESKTOP_ENTRY_NAME,
            )

    def test_install_verify_and_restore_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            path.parent.mkdir()
            path.write_bytes(b"old desktop\n")
            path.chmod(0o640)

            result, snapshot = server.install_fleet_desktop_entry(
                Path("/usr/bin/codex-master-mcp"), path
            )

            self.assertEqual(
                result, {"requested": True, "status": "installed", "verified": True}
            )
            self.assertEqual(
                server.verify_fleet_desktop_entry(
                    Path("/usr/bin/codex-master-mcp"), path
                )["ok"],
                True,
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            server.restore_fleet_desktop_entry(snapshot)
            self.assertEqual(path.read_bytes(), b"old desktop\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_install_is_idempotent_and_restore_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"

            server.install_fleet_desktop_entry(Path("/usr/bin/codex-master-mcp"), path)
            before = path.stat()
            result, snapshot = server.install_fleet_desktop_entry(
                Path("/usr/bin/codex-master-mcp"), path
            )
            server.restore_fleet_desktop_entry(snapshot)

            self.assertEqual(result["status"], "already_installed")
            self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_restore_removes_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"

            _result, snapshot = server.install_fleet_desktop_entry(
                Path("/usr/bin/codex-master-mcp"), path
            )
            server.restore_fleet_desktop_entry(snapshot)

            self.assertFalse(path.exists())

    def test_install_rejects_symlink_hardlink_unsafe_mode_and_wrong_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target"
            target.write_text("target\n", encoding="utf-8")
            symlink = root / "symlink.desktop"
            symlink.symlink_to(target)
            hardlink = root / "hardlink.desktop"
            os.link(target, hardlink)
            unsafe = root / "unsafe.desktop"
            unsafe.write_text("unsafe\n", encoding="utf-8")
            unsafe.chmod(0o666)
            owner = root / "owner.desktop"
            owner.write_text("owner\n", encoding="utf-8")

            for path in (symlink, hardlink, unsafe):
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(
                        server.AgentError, "desktop entry is unsafe"
                    ):
                        server.install_fleet_desktop_entry(
                            Path("/usr/bin/codex-master-mcp"), path
                        )
            with patch(
                "codex_master.server.os.getuid", return_value=owner.stat().st_uid + 1
            ):
                with self.assertRaisesRegex(
                    server.AgentError, "desktop entry is unsafe"
                ):
                    server._validate_fleet_desktop_stat(owner.stat())

    def test_install_rejects_writable_parent_and_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            writable_parent = root / "writable"
            writable_parent.mkdir(mode=0o700)
            writable_parent.chmod(0o777)
            with self.assertRaisesRegex(
                server.AgentError, "desktop entry parent is unsafe"
            ):
                server.install_fleet_desktop_entry(
                    Path("/usr/bin/codex-master-mcp"),
                    writable_parent / "fleet.desktop",
                )

            real_parent = root / "real" / "applications"
            real_parent.mkdir(parents=True)
            linked_parent = root / "linked"
            linked_parent.symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(
                server.AgentError, "desktop entry parent is unsafe"
            ):
                server.install_fleet_desktop_entry(
                    Path("/usr/bin/codex-master-mcp"),
                    linked_parent / "applications" / "fleet.desktop",
                )

            writable_ancestor = root / "writable-ancestor"
            writable_ancestor.mkdir(mode=0o700)
            safe_child = writable_ancestor / "safe-child"
            safe_child.mkdir(mode=0o700)
            writable_ancestor.chmod(0o777)
            with self.assertRaisesRegex(
                server.AgentError, "desktop entry parent is unsafe"
            ):
                server.install_fleet_desktop_entry(
                    Path("/usr/bin/codex-master-mcp"),
                    safe_child / "fleet.desktop",
                )

    def test_secure_parent_policy_rejects_foreign_owned_readonly_directory(
        self,
    ) -> None:
        foreign = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.getuid() + 1)

        self.assertFalse(server._fleet_desktop_directory_stat_is_safe(foreign))

    def test_keyboard_interrupt_cleans_new_temp_file(self) -> None:
        class InterruptingWriter:
            def __init__(self, fd):
                self.fd = fd

            def __enter__(self):
                return self

            def write(self, _data):
                raise KeyboardInterrupt

            def __exit__(self, _exc_type, _exc, _traceback):
                os.close(self.fd)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "new-file"
            with patch(
                "codex_master.server.os.fdopen",
                side_effect=lambda fd, *_args, **_kwargs: InterruptingWriter(fd),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.write_private_new_bytes(path, b"data")

            self.assertFalse(path.exists())

    def test_desktop_mode_failure_preserves_previous_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"old desktop\n")
            path.chmod(0o644)

            with (
                patch(
                    "codex_master.server.os.fchmod",
                    side_effect=PermissionError("injected mode failure"),
                ),
                self.assertRaisesRegex(server.AgentError, "temp file mode"),
            ):
                server.install_fleet_desktop_entry(
                    Path("/usr/bin/codex-master-mcp"), path
                )

            self.assertEqual(path.read_bytes(), b"old desktop\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_keyboard_interrupt_after_replace_restores_previous_absence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            real_replace = server._replace_fleet_desktop_entry

            def replace_then_interrupt(*args, **kwargs):
                real_replace(*args, **kwargs)
                raise KeyboardInterrupt

            with patch(
                "codex_master.server._replace_fleet_desktop_entry",
                side_effect=replace_then_interrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.install_fleet_desktop_entry(
                        Path("/usr/bin/codex-master-mcp"), path
                    )

            self.assertFalse(path.exists())

    def test_install_call_assignment_interrupt_restores_desktop_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "bin" / "codex-master-mcp"
            desktop_path = (
                root / "share" / "applications" / server.FLEET_DESKTOP_ENTRY_NAME
            )
            real_install = server.install_fleet_desktop_entry

            def install_then_interrupt(*args, **kwargs):
                real_install(*args, **kwargs)
                raise KeyboardInterrupt

            with (
                patch(
                    "codex_master.server.install_lock",
                    return_value=contextlib.nullcontext(),
                ),
                patch("codex_master.server.repo_wrapper_path", return_value=wrapper),
                patch(
                    "codex_master.server.fleet_desktop_entry_path",
                    return_value=desktop_path,
                ),
                patch("codex_master.server.ensure_applet_action_key"),
                patch(
                    "codex_master.server.install_fleet_desktop_entry",
                    side_effect=install_then_interrupt,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.install(
                        register=False,
                        install_path=install_path,
                        sync_plugin_cache=False,
                        install_desktop=True,
                    )

            self.assertFalse(desktop_path.exists())
            self.assertFalse(install_path.exists())

    def test_restore_refuses_changed_installed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            _result, snapshot = server.install_fleet_desktop_entry(
                Path("/usr/bin/codex-master-mcp"), path
            )
            path.write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(
                server.AgentError, "desktop entry changed unexpectedly"
            ):
                server.restore_fleet_desktop_entry(snapshot)

    def test_install_transaction_restores_desktop_after_later_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "bin" / "codex-master-mcp"
            desktop_path = (
                root / "share" / "applications" / server.FLEET_DESKTOP_ENTRY_NAME
            )
            desktop_path.parent.mkdir(parents=True)
            desktop_path.write_text("old desktop\n", encoding="utf-8")
            with (
                patch(
                    "codex_master.server.install_lock",
                    return_value=contextlib.nullcontext(),
                ),
                patch("codex_master.server.repo_wrapper_path", return_value=wrapper),
                patch(
                    "codex_master.server.fleet_desktop_entry_path",
                    return_value=desktop_path,
                ),
                patch("codex_master.server.ensure_applet_action_key"),
                patch(
                    "codex_master.server.sync_plugin_cache_from_repo",
                    side_effect=server.AgentError("injected failure"),
                ),
            ):
                with self.assertRaisesRegex(server.AgentError, "injected failure"):
                    server.install(
                        register=False,
                        install_path=install_path,
                        sync_plugin_cache=True,
                        install_desktop=True,
                    )

            self.assertEqual(desktop_path.read_text(encoding="utf-8"), "old desktop\n")
            self.assertFalse(install_path.exists())

    def test_install_with_nonportable_path_skips_desktop_without_breaking_install(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "nicht-portabel-ä" / "codex-master-mcp"
            desktop_path = (
                root / "share" / "applications" / server.FLEET_DESKTOP_ENTRY_NAME
            )
            old_command = Path("/usr/bin/codex-master-mcp")
            server.install_fleet_desktop_entry(old_command, desktop_path)
            with (
                patch(
                    "codex_master.server.install_lock",
                    return_value=contextlib.nullcontext(),
                ),
                patch("codex_master.server.repo_wrapper_path", return_value=wrapper),
                patch(
                    "codex_master.server.fleet_desktop_entry_path",
                    return_value=desktop_path,
                ),
                patch("codex_master.server.ensure_applet_action_key"),
            ):
                result = server.install(
                    register=False,
                    install_path=install_path,
                    sync_plugin_cache=False,
                    install_desktop=True,
                )

            self.assertEqual(
                result["desktop_entry"]["status"],
                "skipped_unsupported_command_path",
            )
            self.assertEqual(result["desktop_entry"]["stale_entry"], "removed")
            self.assertEqual(install_path.resolve(strict=False), wrapper)
            self.assertFalse(desktop_path.exists())

    def test_remove_and_restore_desktop_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            command = Path("/usr/bin/codex-master-mcp")
            server.install_fleet_desktop_entry(command, path)

            result, snapshot = server.remove_fleet_desktop_entry(command, path)

            self.assertEqual(result["status"], "removed")
            self.assertFalse(path.exists())
            server.restore_removed_fleet_desktop_entry(snapshot)
            self.assertTrue(server.verify_fleet_desktop_entry(command, path)["ok"])

    def test_remove_nonportable_path_removes_only_recognized_generated_entry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "applications" / "fleet.desktop"
            server.install_fleet_desktop_entry(Path("/usr/bin/codex-master-mcp"), path)

            result, snapshot = server.remove_fleet_desktop_entry(
                Path("/tmp/nicht-portabel-ä/codex-master-mcp"),
                path,
            )

            self.assertEqual(result["status"], "removed")
            self.assertFalse(path.exists())
            server.restore_removed_fleet_desktop_entry(snapshot)
            path.write_text(
                "[Desktop Entry]\nType=Application\nName=Other\n", encoding="utf-8"
            )
            path.chmod(0o644)
            result, _snapshot = server.remove_fleet_desktop_entry(
                Path("/tmp/nicht-portabel-ä/codex-master-mcp"),
                path,
            )
            self.assertEqual(result["status"], "left_in_place_different_content")
            self.assertTrue(path.exists())

    def test_uninstall_failure_restores_symlink_and_desktop_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "bin" / "codex-master-mcp"
            install_path.parent.mkdir()
            install_path.symlink_to(wrapper)
            desktop_path = (
                root / "share" / "applications" / server.FLEET_DESKTOP_ENTRY_NAME
            )
            server.install_fleet_desktop_entry(install_path, desktop_path)
            with (
                patch(
                    "codex_master.server.install_lock",
                    return_value=contextlib.nullcontext(),
                ),
                patch("codex_master.server.repo_wrapper_path", return_value=wrapper),
                patch(
                    "codex_master.server.fleet_desktop_entry_path",
                    return_value=desktop_path,
                ),
                patch(
                    "codex_master.server.check_mcp_registration",
                    return_value={"registered": True, "command_matches": True},
                ),
                patch(
                    "codex_master.server.run_command",
                    return_value=server.subprocess.CompletedProcess(
                        ["codex", "mcp", "remove"], 1, "", ""
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    server.AgentError, "codex mcp remove failed"
                ):
                    server.uninstall(
                        unregister=True,
                        remove_symlink=True,
                        install_path=install_path,
                        remove_desktop=True,
                    )

            self.assertEqual(install_path.resolve(strict=False), wrapper)
            self.assertTrue(
                server.verify_fleet_desktop_entry(install_path, desktop_path)["ok"]
            )

    def test_uninstall_call_assignment_interrupt_restores_desktop_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "bin" / "codex-master-mcp"
            install_path.parent.mkdir()
            install_path.symlink_to(wrapper)
            desktop_path = (
                root / "share" / "applications" / server.FLEET_DESKTOP_ENTRY_NAME
            )
            server.install_fleet_desktop_entry(install_path, desktop_path)
            real_remove = server.remove_fleet_desktop_entry

            def remove_then_interrupt(*args, **kwargs):
                real_remove(*args, **kwargs)
                raise KeyboardInterrupt

            with (
                patch(
                    "codex_master.server.install_lock",
                    return_value=contextlib.nullcontext(),
                ),
                patch("codex_master.server.repo_wrapper_path", return_value=wrapper),
                patch(
                    "codex_master.server.fleet_desktop_entry_path",
                    return_value=desktop_path,
                ),
                patch(
                    "codex_master.server.remove_fleet_desktop_entry",
                    side_effect=remove_then_interrupt,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    server.uninstall(
                        unregister=False,
                        remove_symlink=True,
                        install_path=install_path,
                        remove_desktop=True,
                    )

            self.assertEqual(install_path.resolve(strict=False), wrapper)
            self.assertTrue(
                server.verify_fleet_desktop_entry(install_path, desktop_path)["ok"]
            )

    @patch("codex_master.server.print_json", return_value=0)
    @patch("codex_master.server.uninstall", return_value={"ok": True})
    def test_cli_remove_symlink_requests_desktop_removal(
        self, mock_uninstall, _mock_print_json
    ) -> None:
        result = server.main_cli(["uninstall", "--remove-symlink"])

        self.assertEqual(result, 0)
        self.assertEqual(mock_uninstall.call_args.kwargs["remove_desktop"], True)

    @patch("codex_master.server.print_json", return_value=0)
    @patch("codex_master.server.install", return_value={"ok": True})
    def test_cli_install_requests_desktop_entry(
        self, mock_install, _mock_print_json
    ) -> None:
        result = server.main_cli(["install"])

        self.assertEqual(result, 0)
        self.assertEqual(mock_install.call_args.kwargs["install_desktop"], True)


if __name__ == "__main__":
    unittest.main()
