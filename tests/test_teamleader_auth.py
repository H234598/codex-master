import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from codex_master import server


class TeamleaderAuthorizationTest(unittest.TestCase):
    def _paths(self, root: Path):
        return (
            patch.object(server, "STATE_ROOT", root / "state"),
            patch.object(server, "LOCK_DIR", root / "state" / "locks"),
            patch.object(server, "TEAMLEADER_REGISTRY_FILE", root / "state" / "teamleaders.json"),
        )

    def test_install_enrollment_authorizes_main_home_without_storing_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True)
            state_patch, lock_patch, registry_patch = self._paths(root)
            with state_patch, lock_patch, registry_patch, patch.dict(
                os.environ, {"HOME": str(home)}, clear=False
            ), patch.object(server, "managed_home_in_process_ancestry", return_value=False):
                os.environ.pop("CODEX_HOME", None)
                enrolled = server.enroll_current_teamleader()
                status = server.master_tool_access_status()

                self.assertTrue(enrolled["authorized"])
                self.assertTrue(status["authorized"])
                self.assertEqual(enrolled["role"], "koenigin")
                self.assertEqual(status["principal_class"], "koenigin")
                registry = server.TEAMLEADER_REGISTRY_FILE
                self.assertEqual(stat.S_IMODE(registry.stat().st_mode), 0o600)
                stored = registry.read_text(encoding="utf-8")
                self.assertNotIn(str(codex_home), stored)
                self.assertNotIn(str(home), stored)

    def test_legacy_registry_migration_keeps_only_current_default_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True)
            current = server.teamleader_principal_digest(codex_home)
            foreign = "f" * 64
            state_patch, lock_patch, registry_patch = self._paths(root)
            with state_patch, lock_patch, registry_patch, patch.dict(
                os.environ, {"HOME": str(home)}, clear=False
            ):
                os.environ.pop("CODEX_HOME", None)
                server.ensure_private_dir(server.STATE_ROOT)
                server.TEAMLEADER_REGISTRY_FILE.write_text(
                    json.dumps({"schema_version": 1, "principals": [current, foreign]}),
                    encoding="utf-8",
                )
                server.TEAMLEADER_REGISTRY_FILE.chmod(0o600)

                server.enroll_current_teamleader()
                payload = json.loads(server.TEAMLEADER_REGISTRY_FILE.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(
            payload["principals"],
            [{"agent_id": None, "class": "koenigin", "digest": current}],
        )

    def test_managed_agent_home_is_denied_even_if_digest_is_registered(self) -> None:
        managed_home = server.AGENTS["a1"]["home"]
        with patch.dict(os.environ, {"CODEX_HOME": str(managed_home)}, clear=False), patch(
            "codex_master.server.read_teamleader_principals",
            return_value={server.teamleader_principal_digest(managed_home)},
        ):
            status = server.master_tool_access_status()

        self.assertFalse(status["authorized"])
        self.assertEqual(status["role"], "non_teamleader")
        self.assertEqual(status["visible_tool_count"], 0)

    def test_class_bound_managed_teamleader_is_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            managed_home = Path(tmp) / "q1"
            managed_home.mkdir()
            digest = server.teamleader_principal_digest(managed_home)
            record = {"class": "teamleiterin", "agent_id": "q1"}
            with patch.dict(os.environ, {"CODEX_HOME": str(managed_home)}, clear=False), patch(
                "codex_master.server.codex_home_context",
                return_value={"home_kind": "managed_agent_home", "matched_agent": "q1"},
            ), patch(
                "codex_master.server.read_hive_principals",
                return_value={digest: record},
            ), patch(
                "codex_master.server.managed_home_in_process_ancestry",
                return_value=True,
            ):
                status = server.master_tool_access_status()

        self.assertTrue(status["authorized"])
        self.assertEqual(status["role"], "teamleiterin")
        self.assertEqual(status["principal_class"], "teamleiterin")
        self.assertGreater(status["visible_tool_count"], 0)
        self.assertLess(status["visible_tool_count"], len(server.TOOLS))

    def test_queen_can_enroll_exact_managed_q_teamleader_without_storing_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            managed_home = root / "q1"
            managed_home.mkdir(mode=0o700)
            descriptor = SimpleNamespace(
                agent_id="q1",
                home=managed_home,
                series_prefix="q",
                skill_profile="teamleiterin",
            )
            state_patch, lock_patch, registry_patch = self._paths(root)
            with state_patch, lock_patch, registry_patch, patch(
                "codex_master.server.current_agent_inventory",
                return_value=SimpleNamespace(agents={"q1": descriptor}),
            ):
                result = server.enroll_managed_principal("q1", "teamleiterin")
                stored = server.TEAMLEADER_REGISTRY_FILE.read_text(encoding="utf-8")

            self.assertTrue(result["authorized"])
            self.assertEqual(result["principal_class"], "teamleiterin")
            self.assertNotIn(str(managed_home), stored)
            self.assertIn('"class":"teamleiterin"', stored)
            self.assertIn('"agent_id":"q1"', stored)

    def test_managed_worker_cannot_reuse_teamleader_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            managed_home = Path(tmp) / "d1"
            managed_home.mkdir()
            digest = server.teamleader_principal_digest(managed_home)
            with patch.dict(os.environ, {"CODEX_HOME": str(managed_home)}, clear=False), patch(
                "codex_master.server.codex_home_context",
                return_value={"home_kind": "managed_agent_home", "matched_agent": "d1"},
            ), patch(
                "codex_master.server.read_hive_principals",
                return_value={digest: {"class": "teamleiterin", "agent_id": "q1"}},
            ), patch(
                "codex_master.server.managed_home_in_process_ancestry",
                return_value=True,
            ):
                status = server.master_tool_access_status()

        self.assertFalse(status["authorized"])

    def test_managed_ancestor_blocks_forged_main_home_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)

            def write_process(pid: int, ppid: int, codex_home: Path | None) -> None:
                node = proc / str(pid)
                node.mkdir()
                node.joinpath("status").write_text(
                    f"Name:\tpython\nState:\tS\nPPid:\t{ppid}\nUid:\t{os.geteuid()}\t{os.geteuid()}\n",
                    encoding="utf-8",
                )
                env = b"" if codex_home is None else f"CODEX_HOME={codex_home}\0".encode("utf-8")
                node.joinpath("environ").write_bytes(env)

            write_process(200, 100, None)
            write_process(100, 1, server.AGENTS["a1"]["home"])
            self.assertTrue(server.managed_home_in_process_ancestry(start_pid=200, proc_root=proc))

    def test_rpc_hides_catalog_and_rejects_cached_call_before_dispatch(self) -> None:
        denied = {"authorized": False, "role": "non_teamleader", "visible_tool_count": 0}
        with patch("codex_master.server.master_tool_access_status", return_value=denied), patch(
            "codex_master.server.call_tool"
        ) as dispatch:
            listed = server.handle_rpc(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                enforce_master_role=True,
            )
            called = server.handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "agent_status", "arguments": {"agent": "a1"}},
                },
                enforce_master_role=True,
            )

        self.assertEqual(listed["result"]["tools"], [])
        self.assertTrue(called["result"]["isError"])
        self.assertIn("teamleader", called["result"]["content"][0]["text"])
        dispatch.assert_not_called()

    def test_authorized_queen_rpc_sees_exact_runtime_catalog(self) -> None:
        visible_tools = server._masterjet_visible_tools(server.TOOLS)
        allowed = {
            "authorized": True,
            "role": "koenigin",
            "principal_class": "koenigin",
            "visible_tool_count": len(visible_tools),
        }
        with patch("codex_master.server.master_tool_access_status", return_value=allowed):
            listed = server.handle_rpc(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                enforce_master_role=True,
            )

        self.assertEqual(listed["result"]["tools"], visible_tools)

    def test_teamleader_rpc_catalog_hides_admin_and_credential_tools(self) -> None:
        allowed = {
            "authorized": True,
            "role": "teamleiterin",
            "principal_class": "teamleiterin",
            "visible_tool_count": 1,
        }
        with patch("codex_master.server.master_tool_access_status", return_value=allowed):
            listed = server.handle_rpc(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                enforce_master_role=True,
            )

        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("agent_assign_write", names)
        self.assertIn("agent_selection_options", names)
        self.assertNotIn("fleet_account_set_secret", names)
        self.assertNotIn("fleet_series_delete", names)
        self.assertNotIn("agent_pool_destroy_pool", names)

    def test_teamleader_cached_admin_call_is_rejected_before_dispatch(self) -> None:
        allowed = {
            "authorized": True,
            "role": "teamleiterin",
            "principal_class": "teamleiterin",
            "visible_tool_count": 1,
        }
        with patch("codex_master.server.master_tool_access_status", return_value=allowed), patch(
            "codex_master.server.call_tool"
        ) as dispatch:
            called = server.handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "fleet_account_delete",
                        "arguments": {"account_id": "x", "expected_generation": 1},
                    },
                },
                enforce_master_role=True,
            )

        self.assertTrue(called["result"]["isError"])
        self.assertIn("not allowed", called["result"]["content"][0]["text"])
        dispatch.assert_not_called()

    def test_internal_teamleader_dispatch_rechecks_role_before_validation(self) -> None:
        with patch("codex_master.server.require_teamleader_tool_access", side_effect=server.AgentError("denied")), patch(
            "codex_master.server.call_validated_tool"
        ) as dispatch:
            with self.assertRaisesRegex(server.AgentError, "denied"):
                server.call_teamleader_tool("agent_status", {"agent": "a1"})
        dispatch.assert_not_called()

    def test_authorized_catalog_is_detached_from_runtime_definition(self) -> None:
        allowed = {
            "authorized": True,
            "role": "teamleiterin",
            "principal_class": "teamleiterin",
        }
        with patch("codex_master.server.require_teamleader_tool_access", return_value=allowed):
            catalog = server.teamleader_tool_catalog()
        catalog[0]["name"] = "changed"
        self.assertNotEqual(server.TOOLS[0]["name"], "changed")

    def test_cli_tools_rechecks_teamleader_role(self) -> None:
        with patch("codex_master.server.require_teamleader_tool_access", side_effect=server.AgentError("denied")), patch(
            "codex_master.server.print_json"
        ) as output, patch("builtins.print"):
            self.assertEqual(server.main_cli(["tools"]), 1)
        output.assert_not_called()

    def test_malformed_or_insecure_registry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            (home / ".codex").mkdir(parents=True)
            state_patch, lock_patch, registry_patch = self._paths(root)
            with state_patch, lock_patch, registry_patch, patch.dict(
                os.environ, {"HOME": str(home)}, clear=False
            ), patch.object(server, "managed_home_in_process_ancestry", return_value=False):
                os.environ.pop("CODEX_HOME", None)
                server.ensure_private_dir(server.STATE_ROOT)
                registry = server.TEAMLEADER_REGISTRY_FILE
                registry.write_text(json.dumps({"schema_version": 1, "principals": ["x"]}), encoding="utf-8")
                registry.chmod(0o600)
                self.assertFalse(server.master_tool_access_status()["authorized"])

                registry.write_text(json.dumps({"schema_version": 1, "principals": ["a" * 64]}), encoding="utf-8")
                registry.chmod(0o644)
                self.assertFalse(server.master_tool_access_status()["authorized"])

                registry.unlink()
                source = root / "source.json"
                source.write_text(json.dumps({"schema_version": 1, "principals": ["a" * 64]}), encoding="utf-8")
                source.chmod(0o600)
                registry.symlink_to(source)
                self.assertFalse(server.master_tool_access_status()["authorized"])

                registry.unlink()
                os.link(source, registry)
                self.assertFalse(server.master_tool_access_status()["authorized"])

                registry.unlink()
                registry.write_bytes(b"x" * (server.MAX_TEAMLEADER_REGISTRY_BYTES + 1))
                registry.chmod(0o600)
                self.assertFalse(server.master_tool_access_status()["authorized"])

    def test_server_schema_validator_rejects_unknown_types(self) -> None:
        with self.assertRaisesRegex(server.AgentError, "unsupported schema"):
            server.validate_schema_value("payload", "value", {"type": "number"})

    def test_failed_preflight_rolls_back_new_teamleader_enrollment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = Path(tmp) / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            with patch("codex_master.server.assert_install_context_allows_master_registration"), patch(
                "codex_master.server.repo_wrapper_path", return_value=wrapper
            ), patch(
                "codex_master.server.enroll_current_teamleader",
                return_value={"changed": True},
            ), patch(
                "codex_master.server.revoke_current_teamleader"
            ) as revoke, patch(
                "codex_master.server.mcp_command_startup_self_test",
                return_value={"ok": False},
            ):
                with self.assertRaisesRegex(server.AgentError, "startup self-test"):
                    server._install_unlocked(register=True, sync_plugin_cache=False)
            revoke.assert_called_once_with()

    def test_failure_after_preflight_also_rolls_back_new_enrollment(self) -> None:
        with patch(
            "codex_master.server.assert_install_context_allows_master_registration"
        ), patch(
            "codex_master.server.enroll_current_teamleader",
            return_value={"changed": True},
        ), patch(
            "codex_master.server._install_enrolled_unlocked",
            side_effect=server.AgentError("later failure"),
        ), patch(
            "codex_master.server.revoke_current_teamleader"
        ) as revoke:
            with self.assertRaisesRegex(server.AgentError, "later failure"):
                server._install_unlocked(register=True)
        revoke.assert_called_once_with()

    def test_keyboard_interrupt_after_enrollment_still_revokes(self) -> None:
        with patch(
            "codex_master.server.assert_install_context_allows_master_registration"
        ), patch(
            "codex_master.server.enroll_current_teamleader",
            return_value={"changed": True},
        ), patch(
            "codex_master.server._install_enrolled_unlocked",
            side_effect=KeyboardInterrupt,
        ), patch(
            "codex_master.server.revoke_current_teamleader"
        ) as revoke:
            with self.assertRaises(KeyboardInterrupt):
                server._install_unlocked(register=True)
        revoke.assert_called_once_with()

    def test_successful_mcp_uninstall_revokes_current_teamleader(self) -> None:
        with patch(
            "codex_master.server.check_mcp_registration",
            return_value={"registered": True, "command_matches": True},
        ), patch(
            "codex_master.server.run_command",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ), patch(
            "codex_master.server.revoke_current_teamleader",
            return_value={"changed": True},
        ) as revoke:
            result = server._uninstall_unlocked(unregister=True, remove_symlink=False)
        self.assertEqual(result["teamleader"], "removed")
        revoke.assert_called_once_with()

    def test_idempotent_uninstall_revokes_without_existing_mcp_registration(self) -> None:
        with patch(
            "codex_master.server.check_mcp_registration",
            return_value={"registered": False, "lookup_status": "not_registered"},
        ), patch(
            "codex_master.server.revoke_current_teamleader",
            return_value={"changed": True},
        ) as revoke:
            result = server._uninstall_unlocked(unregister=True, remove_symlink=False)
        self.assertEqual(result["teamleader"], "removed")
        revoke.assert_called_once_with()

    def test_uninstall_revocation_failure_restores_symlink_and_mcp_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrapper = root / "wrapper"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            install_path = root / "bin" / "codex-master-mcp"
            install_path.parent.mkdir()
            install_path.symlink_to(wrapper)
            with patch(
                "codex_master.server.repo_wrapper_path", return_value=wrapper
            ), patch(
                "codex_master.server.check_mcp_registration",
                return_value={"registered": True, "command_matches": True},
            ), patch(
                "codex_master.server.run_command",
                side_effect=[
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                ],
            ) as command, patch(
                "codex_master.server.revoke_current_teamleader",
                side_effect=server.AgentError("registry failure"),
            ):
                with self.assertRaisesRegex(server.AgentError, "registry failure"):
                    server._uninstall_unlocked(
                        unregister=True,
                        remove_symlink=True,
                        install_path=install_path,
                    )
            self.assertEqual(install_path.resolve(), wrapper)
            self.assertEqual(command.call_count, 2)


if __name__ == "__main__":
    unittest.main()
