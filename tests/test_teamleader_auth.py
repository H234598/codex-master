import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
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
            ):
                os.environ.pop("CODEX_HOME", None)
                enrolled = server.enroll_current_teamleader()
                status = server.master_tool_access_status()

                self.assertTrue(enrolled["authorized"])
                self.assertTrue(status["authorized"])
                registry = server.TEAMLEADER_REGISTRY_FILE
                self.assertEqual(stat.S_IMODE(registry.stat().st_mode), 0o600)
                stored = registry.read_text(encoding="utf-8")
                self.assertNotIn(str(codex_home), stored)
                self.assertNotIn(str(home), stored)

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

    def test_authorized_rpc_sees_exact_runtime_catalog(self) -> None:
        allowed = {"authorized": True, "role": "teamleader", "visible_tool_count": len(server.TOOLS)}
        with patch("codex_master.server.master_tool_access_status", return_value=allowed):
            listed = server.handle_rpc(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                enforce_master_role=True,
            )

        self.assertEqual(listed["result"]["tools"], server.TOOLS)

    def test_internal_teamleader_dispatch_rechecks_role_before_validation(self) -> None:
        with patch("codex_master.server.require_teamleader_tool_access", side_effect=server.AgentError("denied")), patch(
            "codex_master.server.call_validated_tool"
        ) as dispatch:
            with self.assertRaisesRegex(server.AgentError, "denied"):
                server.call_teamleader_tool("agent_status", {"agent": "a1"})
        dispatch.assert_not_called()

    def test_authorized_catalog_is_detached_from_runtime_definition(self) -> None:
        with patch("codex_master.server.require_teamleader_tool_access"):
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
            ):
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


if __name__ == "__main__":
    unittest.main()
