import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
import os
from unittest.mock import patch

from codex_master.server import (
    AgentError,
    DEFAULT_AGENT_LEASE_SECONDS,
    MAX_ASSIGNMENT_LIST_ITEMS,
    MAX_ASSIGNMENT_LOG_BYTES,
    MAX_CAPABILITY_PLUGINS,
    MAX_ERROR_CHARS,
    MAX_META_BYTES,
    MAX_RPC_MESSAGE_BYTES,
    MAX_RAW_LOG_BYTES,
    MAX_SEND_TEXT,
    MAX_SKILL_NAMES,
    MAX_TASK_TEXT,
    MAX_WAIT_POLL_SECONDS,
    MAX_WAIT_SECONDS,
    RAW_LOG_TRUNCATION_MARKER,
    BRACKETED_PASTE_BEGIN,
    BRACKETED_PASTE_END,
    COMMAND_TIMEOUT_RETURN_CODE,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS,
    DEFAULT_WAIT_POLL_SECONDS,
    DEFAULT_WAIT_SECONDS,
    DEFAULT_WATCHDOG_IDLE_SECONDS,
    DEFAULT_WATCHDOG_POLL_SECONDS,
    DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS,
    DEFAULT_TMUX_TIMEOUT_SECONDS,
    allowed_raw_log_path,
    append_bounded_raw_log,
    agent_lifecycle_lock,
    agent_home_process_summary,
    check_mcp_registration,
    call_tool,
    claim_agent,
    claim_agent_with_wait,
    classify_limit_text,
    classify_tui_context,
    codex_related_process_summary,
    DEFAULT_AGENT_MODEL,
    doctor,
    ensure_state,
    handle_rpc,
    install,
    installed_source_worktree_state,
    agent_lease_status,
    interrupt_agent,
    mcp_command_startup_self_test,
    mcp_probe_response_ok,
    mcp_registration_command_matches,
    master_app_bridge_status,
    main_cli,
    prune_raw_logs,
    raw_log_retention_status,
    read_message,
    read_meta,
    record_assignment,
    redact,
    release_agent,
    replace_private_text,
    resolve_path_no_throw,
    run_command,
    run_tmux,
    send_agent,
    start_agent,
    start_agent_with_lease,
    strip_ansi,
    sync_plugin_cache_from_repo,
    trim_chars,
    trim_lines,
    uninstall,
    wait_agent,
    WRITE_AGENT_MODEL,
    write_bounded_raw_log,
    write_meta,
    worktree_create_for_agent,
    worktree_status,
    codex_home_context,
    codex_client_mcp_config_status,
    ensure_private_dir,
    ensure_mcp_startup_timeout_configured,
    fleet_watchdog,
    mcp_startup_timeout_seconds,
    updated_mcp_startup_timeout_config,
    mcp_command_tools_list_self_test,
    mcp_tools_list_probe_result,
    master_namespace_status,
    master_release_status,
    plugin_cache_status,
    plugin_manifest_version,
)


class FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


class ServerHelpersTest(unittest.TestCase):
    def test_redacts_common_secret_shapes(self) -> None:
        text = "OPENAI_API_KEY=sk-testtoken1234567890 and jwt eyJabcabcabcabc.abcabcabcabc.sigsignaturesig"
        redacted, changed = redact(text)
        self.assertTrue(changed)
        self.assertNotIn("sk-testtoken1234567890", redacted)
        self.assertNotIn("eyJabcabcabcabc.abcabcabcabc.sigsignaturesig", redacted)

    def test_strip_ansi(self) -> None:
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m\r\n"), "red\n\n")

    def test_trim_limits(self) -> None:
        truncated_lines = trim_lines("line1\nline2\nline3", 1)
        self.assertIn("... truncated to last 1 lines ...", truncated_lines)
        self.assertIn("line3", truncated_lines)
        self.assertNotIn("line1", truncated_lines)

        truncated_chars = trim_chars("abcdef", 3)
        self.assertTrue(truncated_chars.endswith("def"))
        self.assertIn("... truncated to last characters ...", truncated_chars)

    def test_resolve_path_no_throw_returns_none_for_symlink_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            loop = Path(tmpdir) / "loop"
            loop.symlink_to(loop)

            resolved = resolve_path_no_throw(loop)

        self.assertIsNone(resolved)

    def test_mcp_registration_command_match_is_exact_command_field(self) -> None:
        output = "\n".join(
            [
                "codex-master-mcp",
                "  enabled: true",
                "  transport: stdio",
                "  command: /home/teladi/.local/bin/codex-master-mcp",
                "  args: -",
                "  startup_timeout_sec: 120",
                "  remove: codex mcp remove codex-master-mcp",
            ]
        )
        suffixed = output.replace("codex-master-mcp", "codex-master-mcp-old", 1).replace(
            "command: /home/teladi/.local/bin/codex-master-mcp",
            "command: /home/teladi/.local/bin/codex-master-mcp-old",
        )
        no_command = "codex-master-mcp\n  remove: codex mcp remove codex-master-mcp\n"

        self.assertTrue(mcp_registration_command_matches(output, Path("/home/teladi/.local/bin/codex-master-mcp")))
        self.assertFalse(mcp_registration_command_matches(suffixed, Path("/home/teladi/.local/bin/codex-master-mcp")))
        self.assertFalse(mcp_registration_command_matches(no_command, Path("/home/teladi/.local/bin/codex-master-mcp")))
        self.assertEqual(mcp_startup_timeout_seconds(output), 120)

    def test_redact_removes_absolute_paths(self) -> None:
        text, changed = redact("worktree /home/teladi/private/repo\nrelative/path stays\n")

        self.assertTrue(changed)
        self.assertIn("/<redacted>", text)
        self.assertIn("relative/path stays", text)
        self.assertNotIn("/home/teladi/private/repo", text)

    def test_codex_home_context_classifies_agent_home_without_returning_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            tmp_path = Path(tmp_home)
            agent_home = tmp_path / "agent-a-home-secret"
            agents = {
                "a": {"label": "A", "runner": tmp_path / "a-runner", "home": agent_home, "session": "session-a"},
                "b": {
                    "label": "B",
                    "runner": tmp_path / "b-runner",
                    "home": tmp_path / "agent-b-home",
                    "session": "session-b",
                },
            }
            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": str(agent_home)}), patch.dict(
                "codex_master.server.AGENTS", agents, clear=True
            ):
                result = codex_home_context()

        self.assertFalse(result["ok"])
        self.assertEqual(result["codex_home_env"], "set")
        self.assertEqual(result["home_kind"], "managed_agent_home")
        self.assertEqual(result["matched_agent"], "a")
        self.assertEqual(result["mcp_visibility"], "not_expected_for_master_mcp")
        self.assertEqual(result["active_home_path"], "not_returned")
        self.assertNotIn(str(agent_home), json.dumps(result, sort_keys=True))

    def test_updated_mcp_startup_timeout_config_updates_or_inserts_value(self) -> None:
        existing_low = "\n".join(
            [
                '[projects."/tmp/example"]',
                'trust_level = "trusted"',
                "",
                "[mcp_servers.codex-master-mcp]",
                'command = "/tmp/codex-master-mcp"',
                "startup_timeout_sec = 30",
                "",
                "[features]",
                "memories = true",
            ]
        )
        updated, changed, previous = updated_mcp_startup_timeout_config(existing_low)
        self.assertTrue(changed)
        self.assertEqual(previous, 30)
        self.assertIn("startup_timeout_sec = 120", updated)
        self.assertIn("[features]", updated)

        existing_high = existing_low.replace("startup_timeout_sec = 30", "startup_timeout_sec = 180")
        high_updated, high_changed, high_previous = updated_mcp_startup_timeout_config(existing_high)
        self.assertFalse(high_changed)
        self.assertEqual(high_previous, 180)
        self.assertIn("startup_timeout_sec = 180", high_updated)

        missing_value = existing_low.replace("\nstartup_timeout_sec = 30", "")
        inserted, inserted_changed, inserted_previous = updated_mcp_startup_timeout_config(missing_value)
        self.assertTrue(inserted_changed)
        self.assertIsNone(inserted_previous)
        self.assertIn('command = "/tmp/codex-master-mcp"\nstartup_timeout_sec = 120', inserted)

    def test_ensure_mcp_startup_timeout_configured_is_path_sparse_and_no_follow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / ".codex" / "config.toml"
            result = ensure_mcp_startup_timeout_configured(config)
            content = config.read_text(encoding="utf-8")

        self.assertEqual(result["status"], "updated")
        self.assertEqual(result["config_path"], "not_returned")
        self.assertIn("[mcp_servers.codex-master-mcp]", content)
        self.assertIn("startup_timeout_sec = 120", content)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            target = tmp_path / "target.toml"
            link = tmp_path / ".codex" / "config.toml"
            link.parent.mkdir()
            target.write_text("SECRET_CONFIG_SHOULD_NOT_BE_READ\n", encoding="utf-8")
            link.symlink_to(target)

            with self.assertRaisesRegex(AgentError, "codex config path must be a regular file") as raised:
                ensure_mcp_startup_timeout_configured(link)

        self.assertNotIn(str(target), str(raised.exception))

    def test_codex_client_mcp_config_status_detects_ready_config_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / ".codex" / "config.toml"
            install_path = Path(tmpdir) / "bin" / "codex-master-mcp"
            config.parent.mkdir()
            config.write_text(
                "\n".join(
                    [
                        "[mcp_servers.codex-master-mcp]",
                        f'command = "{install_path}"',
                        "startup_timeout_sec = 120",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = codex_client_mcp_config_status(config, install_path)

        self.assertTrue(result["ok"])
        self.assertTrue(result["server_declared"])
        self.assertTrue(result["command_matches_install_path"])
        self.assertTrue(result["startup_timeout_ok"])
        self.assertEqual(result["path"], "not_returned")
        self.assertNotIn(str(install_path), json.dumps(result, sort_keys=True))

    def test_codex_client_mcp_config_status_detects_mismatch_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / ".codex" / "config.toml"
            install_path = Path(tmpdir) / "bin" / "codex-master-mcp"
            wrong_path = Path(tmpdir) / "bin" / "wrong-mcp"
            config.parent.mkdir()
            config.write_text(
                "\n".join(
                    [
                        "[mcp_servers.codex-master-mcp]",
                        f'command = "{wrong_path}"',
                        "startup_timeout_sec = 30",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = codex_client_mcp_config_status(config, install_path)

        self.assertFalse(result["ok"])
        self.assertTrue(result["server_declared"])
        self.assertFalse(result["command_matches_install_path"])
        self.assertFalse(result["startup_timeout_ok"])
        self.assertEqual(result["reason"], "mcp_command_mismatch")
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(install_path), serialized)
        self.assertNotIn(str(wrong_path), serialized)

    def test_codex_client_mcp_config_status_rejects_symlink_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            target = tmp_path / "target.toml"
            link = tmp_path / ".codex" / "config.toml"
            link.parent.mkdir()
            target.write_text("SECRET_CONFIG_SHOULD_NOT_BE_READ\n", encoding="utf-8")
            link.symlink_to(target)

            result = codex_client_mcp_config_status(link, tmp_path / "bin" / "codex-master-mcp")

        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "codex_config_not_regular_file")
        self.assertNotIn("SECRET_CONFIG_SHOULD_NOT_BE_READ", json.dumps(result, sort_keys=True))
        self.assertNotIn(str(target), json.dumps(result, sort_keys=True))

    @patch("codex_master.server.run_command")
    @patch("codex_master.server.shutil.which", return_value="/usr/bin/codex")
    def test_check_mcp_registration_rejects_substring_command_match(self, _mock_which, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["codex", "mcp", "get", "codex-master-mcp"],
            0,
            "\n".join(
                [
                    "codex-master-mcp",
                    "  enabled: true",
                    "  transport: stdio",
                    "  command: /tmp/bin/codex-master-mcp-old",
                    "  startup_timeout_sec: 30",
                    "  remove: codex mcp remove codex-master-mcp",
                ]
            ),
            "",
        )

        result = check_mcp_registration(Path("/tmp/bin/codex-master-mcp"))

        self.assertTrue(result["registered"])
        self.assertFalse(result["command_matches"])
        self.assertEqual(result["startup_timeout_sec"], 30)
        self.assertFalse(result["startup_timeout_ok"])
        self.assertFalse(result["ok"])
        self.assertIn("command: /<redacted>", result["output_excerpt"])
        self.assertNotIn("/tmp/bin/codex-master-mcp-old", result["output_excerpt"])

    def test_mcp_tools_list(self) -> None:
        response = handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIsNotNone(response)
        self.assertEqual(response["id"], 1)
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("agent_start", names)
        self.assertIn("agent_safe_tail", names)
        self.assertIn("agent_wait", names)
        self.assertIn("fleet_watchdog", names)
        self.assertIn("agent_lease_status", names)
        self.assertIn("agent_claim", names)
        self.assertIn("agent_release", names)
        self.assertIn("agent_assign", names)
        self.assertIn("agent_assignments", names)
        self.assertIn("agent_skill_match", names)
        self.assertIn("agent_capabilities", names)
        self.assertIn("agent_scope_check", names)
        self.assertIn("agent_assign_readonly", names)
        self.assertIn("agent_assign_write", names)
        self.assertIn("worktree_status", names)
        self.assertIn("commit_ready_check", names)
        self.assertIn("master_app_bridge_status", names)
        self.assertIn("master_plugin_status", names)
        self.assertIn("master_namespace_status", names)
        self.assertIn("master_release_status", names)
        by_name = {tool["name"]: tool for tool in response["result"]["tools"]}
        assign_props = by_name["agent_assign"]["inputSchema"]["properties"]
        claim_props = by_name["agent_claim"]["inputSchema"]["properties"]
        wait_props = by_name["agent_wait"]["inputSchema"]["properties"]
        watchdog_props = by_name["fleet_watchdog"]["inputSchema"]["properties"]
        skill_props = by_name["agent_skills"]["inputSchema"]["properties"]
        self.assertEqual(assign_props["task"]["maxLength"], MAX_TASK_TEXT)
        self.assertEqual(assign_props["context"]["maxItems"], MAX_ASSIGNMENT_LIST_ITEMS)
        self.assertEqual(DEFAULT_WAIT_SECONDS, 120)
        self.assertEqual(MAX_WAIT_SECONDS, 600)
        self.assertEqual(DEFAULT_WAIT_POLL_SECONDS, 30)
        self.assertEqual(MAX_WAIT_POLL_SECONDS, 900)
        self.assertEqual(wait_props["timeout_seconds"]["default"], DEFAULT_WAIT_SECONDS)
        self.assertEqual(wait_props["timeout_seconds"]["maximum"], MAX_WAIT_SECONDS)
        self.assertEqual(wait_props["poll_interval_seconds"]["default"], DEFAULT_WAIT_POLL_SECONDS)
        self.assertEqual(wait_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertEqual(claim_props["wait_seconds"]["maximum"], MAX_WAIT_SECONDS)
        self.assertEqual(claim_props["poll_interval_seconds"]["default"], DEFAULT_WAIT_POLL_SECONDS)
        self.assertEqual(claim_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertEqual(DEFAULT_WATCHDOG_IDLE_SECONDS, 60)
        self.assertEqual(DEFAULT_WATCHDOG_POLL_SECONDS, 15)
        self.assertEqual(DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS, 120)
        self.assertEqual(watchdog_props["idle_seconds"]["default"], DEFAULT_WATCHDOG_IDLE_SECONDS)
        self.assertEqual(watchdog_props["poll_interval_seconds"]["default"], DEFAULT_WATCHDOG_POLL_SECONDS)
        self.assertEqual(watchdog_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertEqual(watchdog_props["report_grace_seconds"]["default"], DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS)
        self.assertEqual(by_name["agent_send"]["inputSchema"]["properties"]["text"]["maxLength"], MAX_SEND_TEXT)
        self.assertEqual(skill_props["limit"]["maximum"], MAX_SKILL_NAMES)
        self.assertEqual(skill_props["names_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_limit"]["default"], MAX_CAPABILITY_PLUGINS)
        self.assertEqual(skill_props["plugins_limit"]["maximum"], MAX_SKILL_NAMES)

    def test_master_app_bridge_status_is_path_sparse_and_reads_connector_id(self) -> None:
        result = master_app_bridge_status()

        self.assertTrue(result["ok"])
        self.assertEqual(result["app_name"], "codex-master")
        self.assertEqual(result["connector_id"], "connector_26697a678b7ec999dc005131eb5c087c")
        self.assertEqual(result["connector_id_kind"], "connector")
        self.assertTrue(result["connector_id_format_ok"])
        self.assertTrue(result["plugin_apps"]["ok"])
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    def test_plugin_cache_status_detects_installed_repo_version_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "repo"
            cache = Path(tmpdir) / "cache"
            manifest = root / ".codex-plugin" / "plugin.json"
            cached_manifest = cache / "0.2.18+codex.test" / ".codex-plugin" / "plugin.json"
            manifest.parent.mkdir(parents=True)
            cached_manifest.parent.mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.2.18+codex.test"}
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            cached_manifest.write_text(json.dumps(payload), encoding="utf-8")

            result = plugin_cache_status(root, cache)

        self.assertTrue(result["ok"])
        self.assertTrue(result["repo_version_installed"])
        self.assertEqual(result["installed_versions"], ["0.2.18+codex.test"])
        self.assertEqual(result["repo_manifest"]["version"], "0.2.18+codex.test")
        self.assertEqual(result["path"], "not_returned")
        self.assertNotIn(str(root), json.dumps(result, sort_keys=True))
        self.assertNotIn(str(cache), json.dumps(result, sort_keys=True))

    def test_plugin_cache_status_rejects_symlinked_cache_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "repo"
            cache = Path(tmpdir) / "cache"
            target = Path(tmpdir) / "target"
            manifest = root / ".codex-plugin" / "plugin.json"
            target_manifest = target / ".codex-plugin" / "plugin.json"
            manifest.parent.mkdir(parents=True)
            target_manifest.parent.mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.2.18+codex.test"}
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            target_manifest.write_text(json.dumps(payload), encoding="utf-8")
            cache.mkdir()
            (cache / "0.2.18+codex.test").symlink_to(target, target_is_directory=True)

            result = plugin_cache_status(root, cache)

        self.assertFalse(result["ok"])
        self.assertFalse(result["repo_version_installed"])
        self.assertEqual(result["symlink_entry_count"], 1)
        self.assertEqual(result["installed_versions"], [])
        self.assertNotIn(str(target), json.dumps(result, sort_keys=True))

    def test_plugin_cache_status_rejects_cache_root_swap_without_counting_redirected_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            backup_cache = tmp_path / "cache-backup"
            redirected_cache = tmp_path / "redirected-cache"
            version = "0.3.8+codex.test"
            manifest = root / ".codex-plugin" / "plugin.json"
            redirected_manifest = redirected_cache / version / ".codex-plugin" / "plugin.json"
            manifest.parent.mkdir(parents=True)
            redirected_manifest.parent.mkdir(parents=True)
            payload = {"name": "codex-master", "version": version}
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            redirected_manifest.write_text(json.dumps(payload), encoding="utf-8")
            cache.mkdir()
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if not swapped and dir_fd is None and Path(path) == cache:
                    swapped = True
                    cache.rename(backup_cache)
                    cache.symlink_to(redirected_cache, target_is_directory=True)
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch("codex_master.server.os.open", side_effect=swapping_open):
                result = plugin_cache_status(root, cache)

        self.assertTrue(swapped)
        self.assertFalse(result["ok"])
        self.assertFalse(result["repo_version_installed"])
        self.assertEqual(result["installed_version_count"], 0)
        self.assertNotIn(str(redirected_cache), json.dumps(result, sort_keys=True))

    def test_sync_plugin_cache_from_repo_copies_runtime_allowlist_without_paths_or_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills" / "codex-master-fleet").mkdir(parents=True)
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master" / "__pycache__").mkdir(parents=True)
            (root / "tests" / "__pycache__").mkdir(parents=True)
            (root / ".git").mkdir()
            (root / ".pytest_cache").mkdir()
            payload = {"name": "codex-master", "version": "0.3.4+codex.test"}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            bin_wrapper = root / "bin" / "codex-master-mcp"
            bin_wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            bin_wrapper.chmod(bin_wrapper.stat().st_mode | stat.S_IXUSR)
            (root / "skills" / "codex-master-fleet" / "SKILL.md").write_text("skill", encoding="utf-8")
            (root / "src" / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "src" / "codex_master" / "__pycache__" / "server.pyc").write_bytes(b"cache")
            (root / "src" / "codex_master" / ".env").write_text("SECRET=not-copied", encoding="utf-8")
            (root / "src" / "codex_master" / "server.py.swp").write_text("swap", encoding="utf-8")
            (root / "skills" / "codex-master-fleet" / "SKILL.md.tmp").write_text("tmp", encoding="utf-8")
            (root / "tests" / "test_server.py").write_text("should not copy", encoding="utf-8")
            (root / ".git" / "config").write_text("secret", encoding="utf-8")
            (root / ".pytest_cache" / "README.md").write_text("cache", encoding="utf-8")

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False):
                result = sync_plugin_cache_from_repo(root, cache)

            entry = cache / "0.3.4+codex.test"
            copied_state = {
                "manifest": (entry / ".codex-plugin" / "plugin.json").exists(),
                "app": (entry / ".app.json").exists(),
                "mcp": (entry / ".mcp.json").exists(),
                "bin": (entry / "bin" / "codex-master-mcp").exists(),
                "bin_executable": os.access(entry / "bin" / "codex-master-mcp", os.X_OK),
                "skill": (entry / "skills" / "codex-master-fleet" / "SKILL.md").exists(),
                "systemd": (entry / "systemd" / "user").exists(),
                "server": (entry / "src" / "codex_master" / "server.py").exists(),
                "git": (entry / ".git").exists(),
                "pytest_cache": (entry / ".pytest_cache").exists(),
                "tests": (entry / "tests").exists(),
                "pycache": (entry / "src" / "codex_master" / "__pycache__").exists(),
                "hidden_env": (entry / "src" / "codex_master" / ".env").exists(),
                "swap": (entry / "src" / "codex_master" / "server.py.swp").exists(),
                "tmp": (entry / "skills" / "codex-master-fleet" / "SKILL.md.tmp").exists(),
            }

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "synced")
        self.assertEqual(result["cache_entry"], "not_returned")
        self.assertTrue(copied_state["manifest"])
        self.assertTrue(copied_state["app"])
        self.assertTrue(copied_state["mcp"])
        self.assertTrue(copied_state["bin"])
        self.assertTrue(copied_state["bin_executable"])
        self.assertTrue(copied_state["skill"])
        self.assertTrue(copied_state["systemd"])
        self.assertTrue(copied_state["server"])
        self.assertFalse(copied_state["git"])
        self.assertFalse(copied_state["pytest_cache"])
        self.assertFalse(copied_state["tests"])
        self.assertFalse(copied_state["pycache"])
        self.assertFalse(copied_state["hidden_env"])
        self.assertFalse(copied_state["swap"])
        self.assertFalse(copied_state["tmp"])
        self.assertTrue(result["plugin_cache"]["repo_version_installed"])
        self.assertNotIn(str(entry), json.dumps(result, sort_keys=True))
        self.assertNotIn(str(cache), json.dumps(result, sort_keys=True))

    def test_sync_plugin_cache_from_repo_rejects_symlink_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.3.4+codex.test"}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "codex-master-fleet").symlink_to(root / "src", target_is_directory=True)
            (root / "src" / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False):
                with self.assertRaisesRegex(AgentError, "unsupported symlink"):
                    sync_plugin_cache_from_repo(root, cache)
            entry_exists = (cache / "0.3.4+codex.test").exists()
            tmp_entries = list(cache.glob(".*.tmp.*")) if cache.exists() else []

        self.assertFalse(entry_exists)
        self.assertEqual(tmp_entries, [])

    def test_sync_plugin_cache_from_repo_preserves_preexisting_temp_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            cache.mkdir()
            version = "0.3.8+codex.test"
            tmp_entry = cache / f".{version}.tmp.fixed.nonce"
            tmp_entry.mkdir()
            marker = tmp_entry / "marker"
            marker.write_text("owned by another sync\n", encoding="utf-8")
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            payload = {"name": "codex-master", "version": version}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            (root / "src" / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")
            fixed_uuid = type("FixedUuid", (), {"hex": "nonce"})()

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False), patch(
                "codex_master.server.now_id", return_value="fixed"
            ), patch("codex_master.server.uuid.uuid4", return_value=fixed_uuid):
                with self.assertRaisesRegex(AgentError, "could_not_sync_plugin_cache") as raised:
                    sync_plugin_cache_from_repo(root, cache)
            marker_content = marker.read_text(encoding="utf-8")

        self.assertEqual(marker_content, "owned by another sync\n")
        self.assertNotIn(str(tmp_entry), str(raised.exception))

    def test_sync_plugin_cache_from_repo_rejects_hardlink_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.3.5+codex.test"}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            server = root / "src" / "codex_master" / "server.py"
            server.write_text("print('ok')\n", encoding="utf-8")
            os.link(server, root / "src" / "codex_master" / "server-hardlink.py")

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False):
                with self.assertRaisesRegex(AgentError, "unsupported hardlink"):
                    sync_plugin_cache_from_repo(root, cache)
            entry_exists = (cache / "0.3.5+codex.test").exists()
            tmp_entries = list(cache.glob(".*.tmp.*")) if cache.exists() else []

        self.assertFalse(entry_exists)
        self.assertEqual(tmp_entries, [])

    def test_sync_plugin_cache_from_repo_rejects_source_swap_to_symlink_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.3.8+codex.test"}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            server = root / "src" / "codex_master" / "server.py"
            server.write_text("print('ok')\n", encoding="utf-8")
            redirected = tmp_path / "redirected.py"
            redirected.write_text("SECRET_SHOULD_NOT_COPY\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if not swapped and dir_fd is not None and path == "server.py":
                    swapped = True
                    server.unlink()
                    server.symlink_to(redirected)
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False), patch(
                "codex_master.server.os.open", side_effect=swapping_open
            ):
                with self.assertRaisesRegex(AgentError, "could_not_sync_plugin_cache"):
                    sync_plugin_cache_from_repo(root, cache)
            entry = cache / "0.3.8+codex.test"
            tmp_entries = list(cache.glob(".*.tmp.*")) if cache.exists() else []

        self.assertTrue(swapped)
        self.assertFalse(entry.exists())
        self.assertEqual(tmp_entries, [])

    def test_sync_plugin_cache_from_repo_rejects_directory_swap_to_symlink_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            payload = {"name": "codex-master", "version": "0.3.8+codex.test"}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            source_dir = root / "src"
            backup_dir = root / "src-backup"
            (source_dir / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")
            redirected_dir = tmp_path / "redirected-src"
            (redirected_dir / "codex_master").mkdir(parents=True)
            (redirected_dir / "codex_master" / "server.py").write_text("SECRET_SHOULD_NOT_COPY\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if not swapped and dir_fd is None and Path(path) == source_dir:
                    swapped = True
                    source_dir.rename(backup_dir)
                    source_dir.symlink_to(redirected_dir, target_is_directory=True)
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False), patch(
                "codex_master.server.os.open", side_effect=swapping_open
            ):
                with self.assertRaisesRegex(AgentError, "could_not_sync_plugin_cache"):
                    sync_plugin_cache_from_repo(root, cache)
            entry = cache / "0.3.8+codex.test"
            tmp_entries = list(cache.glob(".*.tmp.*")) if cache.exists() else []

        self.assertTrue(swapped)
        self.assertFalse(entry.exists())
        self.assertEqual(tmp_entries, [])

    def test_sync_plugin_cache_from_repo_rejects_cache_root_swap_before_temp_create(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            backup_cache = tmp_path / "cache-backup"
            redirected_cache = tmp_path / "redirected-cache"
            cache.mkdir()
            redirected_cache.mkdir()
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            version = "0.3.8+codex.test"
            payload = {"name": "codex-master", "version": version}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            (root / "src" / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if not swapped and dir_fd is None and Path(path) == cache:
                    swapped = True
                    cache.rename(backup_cache)
                    cache.symlink_to(redirected_cache, target_is_directory=True)
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False), patch(
                "codex_master.server.os.open", side_effect=swapping_open
            ):
                with self.assertRaisesRegex(AgentError, "could_not_sync_plugin_cache"):
                    sync_plugin_cache_from_repo(root, cache)
            redirected_entries = list(redirected_cache.iterdir())
            backup_entries = list(backup_cache.iterdir())

        self.assertTrue(swapped)
        self.assertEqual(redirected_entries, [])
        self.assertEqual(backup_entries, [])

    def test_sync_plugin_cache_from_repo_prunes_old_valid_versions_without_touching_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / "repo"
            cache = tmp_path / "cache"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "skills").mkdir()
            (root / "systemd" / "user").mkdir(parents=True)
            (root / "src" / "codex_master").mkdir(parents=True)
            current = "0.3.5+codex.current"
            payload = {"name": "codex-master", "version": current}
            (root / ".codex-plugin" / "plugin.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / ".app.json").write_text("{}", encoding="utf-8")
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            (root / "bin" / "codex-master-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "skills" / "SKILL.md").write_text("skill", encoding="utf-8")
            (root / "src" / "codex_master" / "server.py").write_text("print('ok')\n", encoding="utf-8")
            cache.mkdir()
            old_versions = [f"0.3.{index}+codex.old" for index in range(5)]
            for index, version in enumerate(old_versions):
                manifest = cache / version / ".codex-plugin" / "plugin.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps({"name": "codex-master", "version": version}), encoding="utf-8")
                os.utime(cache / version, (1000 + index, 1000 + index))
            invalid = cache / "0.3.99+codex.invalid"
            invalid.mkdir()
            (invalid / ".codex-plugin").mkdir()
            (invalid / ".codex-plugin" / "plugin.json").write_text(
                json.dumps({"name": "different", "version": "0.3.99+codex.invalid"}),
                encoding="utf-8",
            )
            symlink_target = tmp_path / "symlink-target"
            symlink_target.mkdir()
            symlink_entry = cache / "0.3.100+codex.symlink"
            symlink_entry.symlink_to(symlink_target, target_is_directory=True)

            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": ""}, clear=False):
                result = sync_plugin_cache_from_repo(root, cache, retained_versions=3)
            remaining_versions = sorted(path.name for path in cache.iterdir())
            symlink_survived = symlink_entry.is_symlink()

        self.assertTrue(result["ok"])
        self.assertEqual(result["retention"]["max_versions"], 3)
        self.assertEqual(result["retention"]["pruned_version_count"], 3)
        self.assertEqual(result["retention"]["retained_old_version_count"], 2)
        self.assertIn(current, remaining_versions)
        self.assertIn(old_versions[-1], remaining_versions)
        self.assertIn(old_versions[-2], remaining_versions)
        self.assertNotIn(old_versions[0], remaining_versions)
        self.assertIn("0.3.99+codex.invalid", remaining_versions)
        self.assertIn("0.3.100+codex.symlink", remaining_versions)
        self.assertTrue(symlink_survived)
        self.assertNotIn(str(cache), json.dumps(result, sort_keys=True))

    def test_plugin_manifest_version_is_path_sparse(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest = root / ".codex-plugin" / "plugin.json"
            manifest.parent.mkdir()
            manifest.write_text(json.dumps({"name": "codex-master", "version": "0.2.18+codex.test"}), encoding="utf-8")

            result = plugin_manifest_version(root)

        self.assertTrue(result["ok"])
        self.assertEqual(result["version"], "0.2.18+codex.test")
        self.assertEqual(result["path"], "not_returned")
        self.assertNotIn(str(root), json.dumps(result, sort_keys=True))

    def test_mcp_tools_list_probe_result_detects_required_tool_without_returning_names(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "agent_status"}, {"name": "master_app_bridge_status"}]},
        }
        output = "Content-Length: 123\r\n\r\n" + json.dumps(payload)

        result = mcp_tools_list_probe_result(output, "master_app_bridge_status")

        self.assertTrue(result["response_found"])
        self.assertEqual(result["tool_count"], 2)
        self.assertTrue(result["required_tool_available"])
        self.assertNotIn("agent_status", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_tools_list_self_test_is_data_sparse(self, mock_run) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "master_app_bridge_status"}]},
        }
        mock_run.return_value = subprocess.CompletedProcess(["/tmp/codex-master-mcp"], 0, json.dumps(payload), "")

        result = mcp_command_tools_list_self_test(Path("/tmp/codex-master-mcp"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["tool_count"], 1)
        self.assertTrue(result["required_tool_available"])
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("/tmp/codex-master-mcp", json.dumps(result, sort_keys=True))

    def test_codex_related_process_summary_is_aggregate_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            home = root / "home"
            agent_home = root / "agent-a-home"
            custom_home = root / "custom-home"
            agents = {
                "a": {"label": "A", "runner": root / "a-runner", "home": agent_home, "session": "session-a"},
                "b": {"label": "B", "runner": root / "b-runner", "home": root / "agent-b-home", "session": "session-b"},
            }

            def write_proc(pid: str, name: str, argv: list[str], env: dict[str, str]) -> None:
                proc = root / pid
                proc.mkdir()
                proc.joinpath("status").write_text(f"Name:\t{name}\nState:\tS (sleeping)\nPPid:\t1\n", encoding="utf-8")
                proc.joinpath("cmdline").write_bytes(b"\0".join(item.encode("utf-8") for item in argv) + b"\0")
                proc.joinpath("environ").write_bytes(
                    b"\0".join(f"{key}={value}".encode("utf-8") for key, value in env.items()) + b"\0"
                )

            write_proc("100", "node", ["/usr/bin/node", "/x/node_modules/@openai/codex/bin/codex.js"], {})
            write_proc("101", "codex", ["/tmp/codex"], {"CODEX_HOME": str(agent_home)})
            write_proc("102", "codex", ["/tmp/codex"], {"CODEX_HOME": str(custom_home)})
            write_proc("103", "python3", ["python3", "-m", "codex_master.server"], {})
            write_proc("104", "bash", ["bash"], {})

            with patch.dict("os.environ", {"HOME": str(home)}, clear=False), patch.dict(
                "codex_master.server.AGENTS", agents, clear=True
            ):
                result = codex_related_process_summary(root)

        self.assertEqual(result["codex_client_process_count"], 3)
        self.assertEqual(result["mcp_server_process_count"], 1)
        self.assertEqual(result["home_kind_counts"]["unknown"], 1)
        self.assertEqual(result["home_kind_counts"]["managed_agent_home"], 1)
        self.assertEqual(result["home_kind_counts"]["custom_home"], 1)
        self.assertEqual(result["namespace_visibility"]["main_default_home_clients"], 0)
        self.assertEqual(result["namespace_visibility"]["custom_home_clients"], 1)
        self.assertEqual(result["namespace_visibility"]["managed_agent_home_clients"], 1)
        self.assertEqual(result["namespace_visibility"]["unknown_home_clients"], 1)
        self.assertTrue(result["namespace_visibility"]["custom_home_clients_need_own_mcp_config"])
        self.assertTrue(result["namespace_visibility"]["managed_agent_home_clients_expect_no_master_mcp"])
        self.assertTrue(result["namespace_visibility"]["unknown_home_clients_need_manual_check"])
        self.assertEqual(result["namespace_visibility"]["raw_output"], "not_returned")
        self.assertNotIn(str(root), json.dumps(result, sort_keys=True))

    def test_codex_related_process_summary_has_stable_shape_without_proc(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_proc = Path(tmpdir) / "missing-proc"

            result = codex_related_process_summary(missing_proc)

        self.assertEqual(result["codex_client_process_count"], 0)
        self.assertEqual(result["mcp_server_process_count"], 0)
        self.assertFalse(result["namespace_visibility"]["custom_home_clients_need_own_mcp_config"])
        self.assertFalse(result["namespace_visibility"]["managed_agent_home_clients_expect_no_master_mcp"])
        self.assertFalse(result["namespace_visibility"]["unknown_home_clients_need_manual_check"])
        self.assertEqual(result["namespace_visibility"]["raw_output"], "not_returned")
        self.assertNotIn(str(missing_proc), json.dumps(result, sort_keys=True))

    @patch("codex_master.server.codex_related_process_summary")
    @patch("codex_master.server.codex_home_context")
    @patch("codex_master.server.master_app_bridge_status")
    @patch("codex_master.server.plugin_cache_status")
    @patch("codex_master.server.codex_client_mcp_config_status")
    @patch("codex_master.server.mcp_command_tools_list_self_test")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.check_mcp_registration")
    def test_master_namespace_status_explains_client_visibility_without_raw_output(
        self,
        mock_registration,
        mock_startup,
        mock_tools,
        mock_client_config,
        mock_cache,
        mock_app_bridge,
        mock_home_context,
        mock_processes,
    ) -> None:
        mock_registration.return_value = {"ok": True, "registered": True, "raw_output": "not_returned"}
        mock_startup.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
        mock_tools.return_value = {
            "ok": True,
            "status": "ok",
            "tool_count": 25,
            "required_tool": "master_app_bridge_status",
            "required_tool_available": True,
            "raw_output": "not_returned",
        }
        mock_cache.return_value = {"ok": True, "repo_version_installed": True, "raw_output": "not_returned"}
        mock_client_config.return_value = {"ok": True, "raw_output": "not_returned"}
        mock_home_context.return_value = {
            "ok": True,
            "home_kind": "main_default_home",
            "raw_output": "not_returned",
        }
        mock_app_bridge.return_value = {"ok": True, "connector_id": "connector_test", "raw_output": "not_returned"}
        mock_processes.return_value = {
            "codex_client_process_count": 2,
            "mcp_server_process_count": 1,
            "home_kind_counts": {},
            "raw_output": "not_returned",
        }

        result = master_namespace_status()

        self.assertTrue(result["ok"])
        self.assertEqual(result["server_name"], "codex-master-mcp")
        self.assertTrue(result["expected_tools"]["master_app_bridge_status"])
        self.assertTrue(result["expected_tools"]["master_namespace_status"])
        self.assertTrue(result["expected_tools"]["master_release_status"])
        self.assertFalse(result["tool_search"]["authoritative_for_local_stdio_mcp_tools"])
        self.assertTrue(result["client_refresh"]["existing_sessions_may_need_restart"])
        self.assertTrue(result["mcp_server_ready"])
        self.assertTrue(result["plugin_cache_ready"])
        self.assertTrue(result["client_config_ready"])
        self.assertTrue(result["active_home_ready"])
        self.assertTrue(result["namespace_ready"])
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.codex_related_process_summary")
    @patch("codex_master.server.codex_home_context")
    @patch("codex_master.server.master_app_bridge_status")
    @patch("codex_master.server.plugin_cache_status")
    @patch("codex_master.server.codex_client_mcp_config_status")
    @patch("codex_master.server.mcp_command_tools_list_self_test")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.check_mcp_registration")
    def test_master_namespace_status_fails_when_plugin_cache_is_stale(
        self,
        mock_registration,
        mock_startup,
        mock_tools,
        mock_client_config,
        mock_cache,
        mock_app_bridge,
        mock_home_context,
        mock_processes,
    ) -> None:
        mock_registration.return_value = {"ok": True, "registered": True, "raw_output": "not_returned"}
        mock_startup.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
        mock_tools.return_value = {
            "ok": True,
            "status": "ok",
            "tool_count": 25,
            "required_tool": "master_app_bridge_status",
            "required_tool_available": True,
            "raw_output": "not_returned",
        }
        mock_cache.return_value = {
            "ok": False,
            "repo_version_installed": False,
            "reason": "repo_plugin_version_not_installed",
            "raw_output": "not_returned",
        }
        mock_client_config.return_value = {"ok": True, "raw_output": "not_returned"}
        mock_home_context.return_value = {
            "ok": True,
            "home_kind": "main_default_home",
            "raw_output": "not_returned",
        }
        mock_app_bridge.return_value = {"ok": True, "connector_id": "connector_test", "raw_output": "not_returned"}
        mock_processes.return_value = {
            "codex_client_process_count": 2,
            "mcp_server_process_count": 1,
            "home_kind_counts": {},
            "raw_output": "not_returned",
        }

        result = master_namespace_status()

        self.assertFalse(result["ok"])
        self.assertTrue(result["mcp_server_ready"])
        self.assertFalse(result["plugin_cache_ready"])
        self.assertTrue(result["client_config_ready"])
        self.assertTrue(result["active_home_ready"])
        self.assertFalse(result["namespace_ready"])
        self.assertEqual(result["plugin_cache"]["reason"], "repo_plugin_version_not_installed")
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.codex_related_process_summary")
    @patch("codex_master.server.codex_home_context")
    @patch("codex_master.server.master_app_bridge_status")
    @patch("codex_master.server.plugin_cache_status")
    @patch("codex_master.server.codex_client_mcp_config_status")
    @patch("codex_master.server.mcp_command_tools_list_self_test")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.check_mcp_registration")
    def test_master_namespace_status_fails_when_client_config_is_stale(
        self,
        mock_registration,
        mock_startup,
        mock_tools,
        mock_client_config,
        mock_cache,
        mock_app_bridge,
        mock_home_context,
        mock_processes,
    ) -> None:
        mock_registration.return_value = {"ok": True, "registered": True, "raw_output": "not_returned"}
        mock_startup.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
        mock_tools.return_value = {
            "ok": True,
            "status": "ok",
            "tool_count": 25,
            "required_tool": "master_app_bridge_status",
            "required_tool_available": True,
            "raw_output": "not_returned",
        }
        mock_cache.return_value = {"ok": True, "repo_version_installed": True, "raw_output": "not_returned"}
        mock_client_config.return_value = {
            "ok": False,
            "reason": "mcp_command_mismatch",
            "raw_output": "not_returned",
        }
        mock_home_context.return_value = {
            "ok": True,
            "home_kind": "main_default_home",
            "raw_output": "not_returned",
        }
        mock_app_bridge.return_value = {"ok": True, "connector_id": "connector_test", "raw_output": "not_returned"}
        mock_processes.return_value = {
            "codex_client_process_count": 2,
            "mcp_server_process_count": 1,
            "home_kind_counts": {},
            "raw_output": "not_returned",
        }

        result = master_namespace_status()

        self.assertFalse(result["ok"])
        self.assertTrue(result["mcp_server_ready"])
        self.assertTrue(result["plugin_cache_ready"])
        self.assertFalse(result["client_config_ready"])
        self.assertTrue(result["active_home_ready"])
        self.assertFalse(result["namespace_ready"])
        self.assertEqual(result["client_config"]["reason"], "mcp_command_mismatch")
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.codex_related_process_summary")
    @patch("codex_master.server.codex_home_context")
    @patch("codex_master.server.master_app_bridge_status")
    @patch("codex_master.server.plugin_cache_status")
    @patch("codex_master.server.codex_client_mcp_config_status")
    @patch("codex_master.server.mcp_command_tools_list_self_test")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.check_mcp_registration")
    def test_master_namespace_status_fails_inside_managed_agent_home(
        self,
        mock_registration,
        mock_startup,
        mock_tools,
        mock_client_config,
        mock_cache,
        mock_app_bridge,
        mock_home_context,
        mock_processes,
    ) -> None:
        mock_registration.return_value = {"ok": True, "registered": True, "raw_output": "not_returned"}
        mock_startup.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
        mock_tools.return_value = {
            "ok": True,
            "status": "ok",
            "tool_count": 25,
            "required_tool": "master_app_bridge_status",
            "required_tool_available": True,
            "raw_output": "not_returned",
        }
        mock_cache.return_value = {"ok": True, "repo_version_installed": True, "raw_output": "not_returned"}
        mock_client_config.return_value = {"ok": True, "raw_output": "not_returned"}
        mock_home_context.return_value = {
            "ok": False,
            "home_kind": "managed_agent_home",
            "mcp_visibility": "not_expected_for_master_mcp",
            "active_home_path": "not_returned",
            "raw_output": "not_returned",
        }
        mock_app_bridge.return_value = {"ok": True, "connector_id": "connector_test", "raw_output": "not_returned"}
        mock_processes.return_value = {
            "codex_client_process_count": 2,
            "mcp_server_process_count": 1,
            "home_kind_counts": {"managed_agent_home": 1},
            "raw_output": "not_returned",
        }

        result = master_namespace_status()

        self.assertFalse(result["ok"])
        self.assertTrue(result["mcp_server_ready"])
        self.assertTrue(result["plugin_cache_ready"])
        self.assertTrue(result["client_config_ready"])
        self.assertFalse(result["active_home_ready"])
        self.assertFalse(result["namespace_ready"])
        self.assertEqual(result["codex_home_context"]["home_kind"], "managed_agent_home")
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.plugin_manifest_version")
    @patch("codex_master.server.shutil.which", return_value="/usr/bin/gh")
    @patch("codex_master.server.run_command")
    def test_master_release_status_detects_release_drift_without_paths(
        self,
        mock_run_command,
        _mock_which,
        mock_plugin_manifest,
    ) -> None:
        mock_plugin_manifest.return_value = {
            "ok": True,
            "version": "0.4.0+codex.test",
            "raw_output": "not_returned",
        }

        def fake_run(command, cwd=None, env=None, timeout_seconds=None):
            if command[:5] == ["git", "tag", "--merged", "HEAD", "--sort=-v:refname"]:
                return subprocess.CompletedProcess(command, 0, "v0.3.0\nv0.2.22\n", "")
            if command == ["git", "rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(command, 0, "HEADSHA\n", "")
            if command == ["git", "rev-list", "--count", "v0.3.0..HEAD"]:
                return subprocess.CompletedProcess(command, 0, "6\n", "")
            if command == ["gh", "release", "list", "--limit", "100"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "v0.3.0\tLatest\tv0.3.0\t2026-06-07T16:05:40Z\n"
                    "v0.2.21\t\tv0.2.21\t2026-06-07T15:41:37Z\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 1, "", "unexpected")

        mock_run_command.side_effect = fake_run

        result = master_release_status()

        self.assertFalse(result["ok"])
        self.assertTrue(result["release_needed"])
        self.assertEqual(result["expected_tag"], "v0.4.0")
        self.assertFalse(result["current_tag_exists"])
        self.assertFalse(result["current_version_has_github_release"])
        self.assertEqual(result["latest_local_tag"], "v0.3.0")
        self.assertEqual(result["latest_github_release_tag"], "v0.3.0")
        self.assertEqual(result["commits_since_latest_github_release"], 6)
        self.assertEqual(result["local_tag_without_github_release_count"], 1)
        self.assertIn("current_version_tag_missing", result["blockers"])
        self.assertIn("github_release_missing_for_current_version", result["blockers"])
        self.assertIn("latest_github_release_behind_head", result["warnings"])
        self.assertIn("local_tags_without_github_release", result["warnings"])
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("/home/", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.subprocess.run")
    def test_run_command_returns_bounded_timeout_result(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(["git", "status"], DEFAULT_COMMAND_TIMEOUT_SECONDS)

        result = run_command(["git", "status"])

        self.assertEqual(result.returncode, COMMAND_TIMEOUT_RETURN_CODE)
        self.assertIn("timed out", result.stderr)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], DEFAULT_COMMAND_TIMEOUT_SECONDS)

    @patch("codex_master.server.subprocess.run")
    def test_run_tmux_returns_bounded_timeout_result(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(
            ["tmux", "capture-pane"], DEFAULT_TMUX_TIMEOUT_SECONDS, output="partial"
        )

        result = run_tmux(["capture-pane"], check=False)

        self.assertEqual(result.returncode, COMMAND_TIMEOUT_RETURN_CODE)
        self.assertEqual(result.stdout, "partial")
        self.assertIn("timed out", result.stderr)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], DEFAULT_TMUX_TIMEOUT_SECONDS)

    def test_initialize_rejects_unsupported_protocol(self) -> None:
        response = handle_rpc(
            {"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2025-12-31"}}
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["id"], 10)
        self.assertEqual(response["error"]["code"], -32602)
        self.assertEqual(response["error"]["message"], "Unsupported protocol version")

    def test_initialize_accepts_supported_protocol(self) -> None:
        response = handle_rpc(
            {"jsonrpc": "2.0", "id": 16, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}
        )

        result = response["result"]
        self.assertEqual(result["protocolVersion"], "2025-11-25")
        self.assertEqual(result["serverInfo"]["name"], "codex-master-mcp")
        self.assertIn("tools", result["capabilities"])
        self.assertIn("resources", result["capabilities"])
        self.assertIn("prompts", result["capabilities"])

    def test_mcp_resources_and_prompts_list_empty(self) -> None:
        resources = handle_rpc({"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
        prompts = handle_rpc({"jsonrpc": "2.0", "id": 12, "method": "prompts/list"})

        self.assertIsNotNone(resources)
        self.assertEqual(resources["result"], {"resources": []})
        self.assertEqual(prompts["result"], {"prompts": []})

    def test_read_message_rejects_oversized_content_length(self) -> None:
        data = f"Content-Length: {MAX_RPC_MESSAGE_BYTES + 1}\r\n\r\n".encode("ascii")
        with patch("sys.stdin", FakeStdin(data)):
            with self.assertRaisesRegex(AgentError, "Content-Length exceeds"):
                read_message()

    def test_read_message_rejects_oversized_json_line(self) -> None:
        data = b"{" + (b"x" * MAX_RPC_MESSAGE_BYTES)
        with patch("sys.stdin", FakeStdin(data)):
            with self.assertRaisesRegex(AgentError, "RPC message line exceeds"):
                read_message()

    def test_read_message_rejects_incomplete_content_body(self) -> None:
        with patch("sys.stdin", FakeStdin(b"Content-Length: 20\r\n\r\n{}")):
            with self.assertRaisesRegex(AgentError, "incomplete RPC message body"):
                read_message()

    def test_mcp_tool_call_error_is_structured(self) -> None:
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "agent_send", "arguments": {"agent": "both", "text": "x"}},
            }
        )
        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertIn("error", payload)

    def test_mcp_error_text_is_redacted_and_bounded(self) -> None:
        secret_tool = "unknown-" + ("x" * 1800) + "-OPENAI_API_KEY=sk-testtoken1234567890"
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 28,
                "method": "tools/call",
                "params": {"name": secret_tool, "arguments": {}},
            }
        )
        method_response = handle_rpc(
            {"jsonrpc": "2.0", "id": 29, "method": "bad OPENAI_API_KEY=sk-testtoken1234567890"}
        )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertNotIn("sk-testtoken1234567890", payload["error"])
        self.assertIn("OPENAI_API_KEY=<redacted>", payload["error"])
        self.assertLessEqual(len(payload["error"]), MAX_ERROR_CHARS + 40)
        self.assertEqual(method_response["error"]["code"], -32601)
        self.assertNotIn("sk-testtoken1234567890", method_response["error"]["message"])
        self.assertIn("OPENAI_API_KEY=<redacted>", method_response["error"]["message"])

    def test_mcp_tool_call_rejects_stringified_booleans_and_integers(self) -> None:
        boolean_response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "agent_assign_readonly",
                    "arguments": {"agent": "a", "task": "Pruefe.", "enter": "false"},
                },
            }
        )
        integer_response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {"name": "agent_skills", "arguments": {"agent": "a", "limit": "2"}},
            }
        )

        self.assertTrue(boolean_response["result"]["isError"])
        boolean_payload = json.loads(boolean_response["result"]["content"][0]["text"])
        self.assertEqual(boolean_payload["error"], "enter must be a boolean")
        self.assertTrue(integer_response["result"]["isError"])
        integer_payload = json.loads(integer_response["result"]["content"][0]["text"])
        self.assertEqual(integer_payload["error"], "limit must be an integer")

    def test_mcp_tool_call_validates_params_and_argument_shape(self) -> None:
        params_response = handle_rpc({"jsonrpc": "2.0", "id": 33, "method": "tools/call", "params": "not-an-object"})
        arguments_response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 34,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": ["not", "an", "object"]},
            }
        )

        self.assertTrue(params_response["result"]["isError"])
        params_payload = json.loads(params_response["result"]["content"][0]["text"])
        self.assertEqual(params_payload["error"], "tools/call params must be an object")
        self.assertTrue(arguments_response["result"]["isError"])
        arguments_payload = json.loads(arguments_response["result"]["content"][0]["text"])
        self.assertEqual(arguments_payload["error"], "tools/call arguments must be an object")

    def test_mcp_tool_call_enforces_schema_properties_and_required_fields(self) -> None:
        unknown_response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 35,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": "a", "surprise": True}},
            }
        )
        missing_response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 36,
                "method": "tools/call",
                "params": {"name": "agent_send", "arguments": {"agent": "a"}},
            }
        )

        self.assertTrue(unknown_response["result"]["isError"])
        unknown_payload = json.loads(unknown_response["result"]["content"][0]["text"])
        self.assertEqual(unknown_payload["error"], "unknown argument(s) for agent_status: surprise")
        self.assertTrue(missing_response["result"]["isError"])
        missing_payload = json.loads(missing_response["result"]["content"][0]["text"])
        self.assertEqual(missing_payload["error"], "missing required argument(s) for agent_send: text")

    def test_mcp_tool_call_enforces_schema_value_types_and_bounds(self) -> None:
        wrong_type = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 37,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": 1}},
            }
        )
        bad_enum = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 38,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": "both"}},
            }
        )
        over_limit = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 39,
                "method": "tools/call",
                "params": {"name": "agent_skills", "arguments": {"limit": MAX_SKILL_NAMES + 1}},
            }
        )
        bad_array = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 40,
                "method": "tools/call",
                "params": {"name": "agent_scope_check", "arguments": {"scope": "src"}},
            }
        )

        self.assertTrue(wrong_type["result"]["isError"])
        wrong_type_payload = json.loads(wrong_type["result"]["content"][0]["text"])
        self.assertEqual(wrong_type_payload["error"], "agent must be a string")
        self.assertTrue(bad_enum["result"]["isError"])
        bad_enum_payload = json.loads(bad_enum["result"]["content"][0]["text"])
        self.assertEqual(bad_enum_payload["error"], "agent must be one of: a, b, all")
        self.assertTrue(over_limit["result"]["isError"])
        over_limit_payload = json.loads(over_limit["result"]["content"][0]["text"])
        self.assertEqual(over_limit_payload["error"], f"limit must be <= {MAX_SKILL_NAMES}")
        self.assertTrue(bad_array["result"]["isError"])
        bad_array_payload = json.loads(bad_array["result"]["content"][0]["text"])
        self.assertEqual(bad_array_payload["error"], "scope must be an array")

    def test_agent_wait_tool_validates_bounds(self) -> None:
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "agent_wait",
                    "arguments": {"agent": "a", "timeout_seconds": MAX_WAIT_SECONDS + 1},
                },
            }
        )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error"], f"timeout_seconds must be <= {MAX_WAIT_SECONDS}")

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.pane_tail")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_tools_call_limits_and_redacts(self, _mock_ensure_state, mock_pane_tail, _mock_tmux_alive) -> None:
        raw = "\n".join([f"line-{i:03d}" for i in range(1, 101)])
        raw += "\n\x1b[31mOPENAI_API_KEY=sk-testtoken1234567890\x1b[0m"
        mock_pane_tail.return_value = raw

        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {"name": "agent_safe_tail", "arguments": {"agent": "a", "source": "pane", "lines": 80, "chars": 8192}},
            }
        )
        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])

        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["lines_limit"], 80)
        self.assertEqual(payload["chars_limit"], 8192)
        self.assertIn("... truncated to last 80 lines ...", payload["output"])
        self.assertNotIn("line-001", payload["output"])
        self.assertNotIn("OPENAI_API_KEY=sk-testtoken1234567890", payload["output"])
        self.assertIn("OPENAI_API_KEY=<redacted>", payload["output"])
        self.assertFalse("\x1b[" in payload["output"])
        self.assertTrue(payload["redaction_applied"])

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.pane_tail")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_tools_call_applies_char_limit(self, _mock_ensure_state, mock_pane_tail, _mock_tmux_alive) -> None:
        raw = "x" * 8190 + "\x1b[31mOPENAI_API_KEY=sk-verylongtoken01234567890\x1b[0m"
        mock_pane_tail.return_value = raw

        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {"name": "agent_safe_tail", "arguments": {"agent": "a", "source": "pane", "lines": 1, "chars": 8192}},
            }
        )
        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["chars_limit"], 8192)
        self.assertTrue(payload["output"].startswith("... truncated to last characters ..."))
        self.assertNotIn("sk-verylongtoken01234567890", payload["output"])

    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_reads_caps_and_redacts(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "agent.log"
            log_path.write_text(
                "first\nsecond\n\x1b[32mOPENAI_API_KEY=sk-logtoken1234567890\x1b[0m\n",
                encoding="utf-8",
            )
            with patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch(
                "codex_master.server.read_meta", return_value={"raw_log": str(log_path)}
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 15,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_safe_tail",
                            "arguments": {"agent": "a", "source": "log", "lines": 2, "chars": 4000},
                        },
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["source"], "log")
        self.assertNotIn("first", payload["output"])
        self.assertNotIn("sk-logtoken1234567890", payload["output"])
        self.assertIn("OPENAI_API_KEY=<redacted>", payload["output"])
        self.assertTrue(payload["redaction_applied"])
        self.assertEqual(payload["raw_log"], "not_returned")
        self.assertNotIn(str(log_path), json.dumps(payload, sort_keys=True))

    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_rejects_unmanaged_meta_path(self, _mock_ensure_state) -> None:
        with patch("codex_master.server.read_meta", return_value={"raw_log": "/etc/passwd"}):
            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 19,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_safe_tail",
                        "arguments": {"agent": "a", "source": "log", "lines": 2, "chars": 4000},
                    },
                }
            )

        self.assertIsNotNone(response)
        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertIn("outside managed raw log state", payload["error"])

    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_ignores_non_regular_log_file(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir)
            fifo_path = raw_dir / "agent.log"
            os.mkfifo(fifo_path)
            with patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.read_meta", return_value={"raw_log": str(fifo_path)}
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 46,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_safe_tail",
                            "arguments": {"agent": "a", "source": "log", "lines": 2, "chars": 4000},
                        },
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["source"], "log")
        self.assertEqual(payload["output"], "")
        self.assertEqual(payload["raw_log"], "not_returned")
        self.assertNotIn(str(fifo_path), json.dumps(payload, sort_keys=True))

    def test_classify_limit_text_distinguishes_default_daily_and_spark_weekly(self) -> None:
        default_limit = classify_limit_text(
            "Daily usage limit reached for gpt-5.4-mini. Try again tomorrow.",
            {},
            None,
        )
        spark_limit = classify_limit_text(
            "Weekly limit reached for Codex Spark.",
            {},
            {"role": "arbeitsbiene", "model": WRITE_AGENT_MODEL},
        )

        self.assertTrue(default_limit["limited"])
        self.assertEqual(default_limit["window"], "daily")
        self.assertEqual(default_limit["kind"], "usage")
        self.assertEqual(default_limit["model"], DEFAULT_AGENT_MODEL)
        self.assertEqual(default_limit["model_source"], "limit_evidence_text")
        self.assertEqual(default_limit["model_pool"], "default_agent_model")
        self.assertEqual(default_limit["session_model"], "unknown")
        self.assertEqual(default_limit["assignment_model"], None)
        self.assertTrue(spark_limit["limited"])
        self.assertEqual(spark_limit["window"], "weekly")
        self.assertEqual(spark_limit["model"], WRITE_AGENT_MODEL)
        self.assertEqual(spark_limit["model_source"], "limit_evidence_text")
        self.assertEqual(spark_limit["model_pool"], "spark_write_model")
        self.assertEqual(spark_limit["assignment_model"], WRITE_AGENT_MODEL)
        self.assertEqual(spark_limit["assignment_model_pool"], "spark_write_model")
        self.assertEqual(spark_limit["role"], "arbeitsbiene")
        self.assertEqual(spark_limit["evidence"], "not_returned")

    def test_classify_limit_text_prefers_assignment_model_for_unqualified_limit(self) -> None:
        limit = classify_limit_text(
            "Session model: gpt-5.4-mini\nWeekly limit reached. Try later.",
            {"model": DEFAULT_AGENT_MODEL},
            {"role": "arbeitsbiene", "model": WRITE_AGENT_MODEL},
        )

        self.assertTrue(limit["limited"])
        self.assertEqual(limit["window"], "weekly")
        self.assertEqual(limit["model"], WRITE_AGENT_MODEL)
        self.assertEqual(limit["model_source"], "assignment_metadata")
        self.assertEqual(limit["model_pool"], "spark_write_model")
        self.assertEqual(limit["session_model"], DEFAULT_AGENT_MODEL)
        self.assertEqual(limit["session_model_pool"], "default_agent_model")
        self.assertEqual(limit["assignment_model"], WRITE_AGENT_MODEL)
        self.assertEqual(limit["assignment_model_pool"], "spark_write_model")
        self.assertEqual(limit["evidence"], "not_returned")

    def test_classify_tui_context_detects_starter_placeholder_without_output(self) -> None:
        result = classify_tui_context("Find and fix a bug in @filename\nSECRET_SHOULD_NOT_RETURN", running=True)

        self.assertEqual(result["state"], "starter_placeholder")
        self.assertEqual(result["source"], "classified_from_bounded_pane_text")
        self.assertEqual(result["evidence"], "not_returned")
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET_SHOULD_NOT_RETURN", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.pane_pid", return_value=None)
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 0,
            "external_process_count": 0,
            "managed_process_count": 0,
            "external_processes": [],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_agent_status_reports_limit_state_without_returning_output(
        self, _mock_summary, _mock_tmux_alive, _mock_pane_pid, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            raw_dir = tmp_path / "raw"
            raw_dir.mkdir()
            log_path = raw_dir / "agent.log"
            log_path.write_text(
                "Weekly limit reached for Codex Spark.\nOPENAI_API_KEY=sk-logtoken1234567890\n",
                encoding="utf-8",
            )
            runner = tmp_path / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": tmp_path, "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.read_meta", return_value={"raw_log": str(log_path), "model": DEFAULT_AGENT_MODEL}
            ), patch(
                "codex_master.server.latest_assignment_summary",
                return_value={"assignment_id": "1-a", "role": "arbeitsbiene", "model": WRITE_AGENT_MODEL},
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 49,
                        "method": "tools/call",
                        "params": {"name": "agent_status", "arguments": {"agent": "a"}},
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(payload["limit_state"]["limited"], True)
        self.assertEqual(payload["limit_state"]["window"], "weekly")
        self.assertEqual(payload["limit_state"]["model_pool"], "spark_write_model")
        self.assertEqual(payload["response_state"]["state"], "blocked_by_limit")
        self.assertEqual(payload["home"], "not_returned")
        self.assertEqual(payload["home_kind"], "managed_agent_home")
        self.assertEqual(payload["runner"], "not_returned")
        self.assertEqual(payload["cwd_state"], "not_set")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("Weekly limit reached", payload_text)
        self.assertNotIn("sk-logtoken1234567890", payload_text)
        self.assertNotIn(str(log_path), payload_text)
        self.assertNotIn(str(tmp_path), payload_text)

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.latest_assignment_summary", return_value=None)
    @patch("codex_master.server.pane_tail", return_value="")
    @patch("codex_master.server.pane_pid", return_value=456)
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 1,
            "external_process_count": 0,
            "managed_process_count": 1,
            "external_processes": [],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_agent_status_does_not_return_raw_log_path(
        self, _mock_summary, _mock_tmux_alive, _mock_pane_pid, _mock_pane_tail, _mock_latest, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            raw_dir = tmp_path / "raw"
            raw_dir.mkdir()
            log_path = raw_dir / "agent.log"
            log_path.write_text("log\n", encoding="utf-8")
            runner = tmp_path / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": tmp_path, "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.read_meta", return_value={"raw_log": str(log_path)}
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 48,
                        "method": "tools/call",
                        "params": {"name": "agent_status", "arguments": {"agent": "a"}},
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(payload["raw_log"], "not_returned")
        self.assertEqual(payload["raw_log_bytes"], 4)
        self.assertTrue(payload["raw_log_path_valid"])
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["home"], "not_returned")
        self.assertEqual(payload["runner"], "not_returned")
        self.assertNotIn(str(log_path), payload_text)
        self.assertNotIn(str(tmp_path), payload_text)

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.latest_assignment_summary", return_value=None)
    @patch("codex_master.server.pane_tail", return_value="Find and fix a bug in @filename\n")
    @patch("codex_master.server.pane_pid", return_value=456)
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 1,
            "external_process_count": 0,
            "managed_process_count": 1,
            "external_processes": [],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_agent_status_reports_tui_starter_context_without_output(
        self, _mock_summary, _mock_tmux_alive, _mock_pane_pid, _mock_pane_tail, _mock_latest, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            runner = tmp_path / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": tmp_path, "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.read_meta", return_value={}):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 50,
                        "method": "tools/call",
                        "params": {"name": "agent_status", "arguments": {"agent": "a"}},
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(payload["tui_context"]["state"], "starter_placeholder")
        self.assertEqual(payload["tui_context"]["evidence"], "not_returned")
        self.assertEqual(payload["response_state"]["state"], "running_tui_starter_context")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["home"], "not_returned")
        self.assertEqual(payload["runner"], "not_returned")
        self.assertNotIn("Find and fix a bug", payload_text)
        self.assertNotIn("@filename", payload_text)
        self.assertNotIn(str(tmp_path), payload_text)

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.status_agent")
    def test_wait_agent_reports_activity_without_output(self, mock_status_agent, mock_sleep) -> None:
        mock_status_agent.side_effect = [
            {
                "agent": "a",
                "running": True,
                "raw_log_bytes": 10,
                "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
                "response_state": {"state": "idle"},
                "limit_state": {"limited": False},
            },
            {
                "agent": "a",
                "running": True,
                "raw_log_bytes": 11,
                "raw_log_updated_at_utc": "2026-06-07T10:00:01+00:00",
                "response_state": {"state": "active"},
                "limit_state": {"limited": False},
            },
        ]

        result = wait_agent("a", timeout_seconds=10, poll_interval_seconds=1)

        self.assertEqual(result["status"], "activity_observed")
        self.assertEqual(result["current"]["raw_log_bytes"], 11)
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertEqual(result["response_output"], "not_returned")
        self.assertNotIn("output", json.dumps(result["current"], sort_keys=True))
        mock_sleep.assert_called_once()

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.status_agent")
    def test_wait_agent_returns_blocked_by_limit_immediately(self, mock_status_agent, mock_sleep) -> None:
        mock_status_agent.return_value = {
            "agent": "a",
            "running": True,
            "raw_log_bytes": 10,
            "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
            "response_state": {"state": "blocked_by_limit"},
            "limit_state": {"limited": True, "window": "daily"},
        }

        result = wait_agent("a", timeout_seconds=10, poll_interval_seconds=1)

        self.assertEqual(result["status"], "blocked_by_limit")
        self.assertEqual(result["poll_count"], 0)
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertEqual(result["response_output"], "not_returned")
        mock_sleep.assert_not_called()

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.status_agent")
    def test_wait_agent_returns_tui_starter_context_immediately(self, mock_status_agent, mock_sleep) -> None:
        mock_status_agent.return_value = {
            "agent": "a",
            "running": True,
            "raw_log_bytes": 10,
            "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
            "response_state": {"state": "running_tui_starter_context"},
            "limit_state": {"limited": False},
            "tui_context": {"state": "starter_placeholder", "evidence": "not_returned"},
        }

        result = wait_agent("a", timeout_seconds=10, poll_interval_seconds=1)

        self.assertEqual(result["status"], "tui_starter_context")
        self.assertEqual(result["poll_count"], 0)
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertEqual(result["response_output"], "not_returned")
        mock_sleep.assert_not_called()

    def test_fleet_watchdog_requests_report_before_interrupt(self) -> None:
        meta_store: dict[str, object] = {}

        def fake_read_meta(_agent: str) -> dict[str, object]:
            return dict(meta_store)

        def fake_write_meta(_agent: str, data: dict[str, object]) -> None:
            meta_store.clear()
            meta_store.update(data)

        status = {
            "agent": "a",
            "running": True,
            "lease": {"state": "held", "held_by_this_server": True, "raw_output": "not_returned"},
            "response_state": {"state": "running_recent_output"},
            "raw_log_idle_seconds": 90,
            "raw_log_bytes": 100,
            "raw_log_updated_at_utc": "1970-01-01T00:15:00+00:00",
            "last_assignment": {"assignment_id": "assign-1", "created_at_utc": "2026-06-07T09:58:00+00:00"},
        }
        report = {
            "status": "report_requested",
            "submitted": True,
            "assignment_id": "assign-1",
            "send": {"status": "sent"},
        }
        with patch("codex_master.server.call_agent_lifecycle", side_effect=lambda _agent, fn: fn()), patch(
            "codex_master.server.status_agent", return_value=status
        ), patch("codex_master.server.read_meta", side_effect=fake_read_meta), patch(
            "codex_master.server.write_meta", side_effect=fake_write_meta
        ), patch("codex_master.server.request_agent_report", return_value=report) as mock_report, patch(
            "codex_master.server.interrupt_agent"
        ) as mock_interrupt:
            result = fleet_watchdog("a")

        payload = result["results"][0]
        self.assertEqual(payload["watchdog_state"], "report_requested")
        self.assertEqual(payload["action_taken"], "report_request")
        self.assertEqual(payload["report_request"]["send_status"], "sent")
        self.assertEqual(meta_store["watchdog"]["phase"], "report_requested")
        self.assertEqual(meta_store["watchdog"]["planned_action"], "interrupt")
        mock_report.assert_called_once()
        mock_interrupt.assert_not_called()

    def test_fleet_watchdog_waits_during_report_grace(self) -> None:
        status = {
            "agent": "a",
            "running": True,
            "lease": {"state": "held", "held_by_this_server": True, "raw_output": "not_returned"},
            "response_state": {"state": "running_recent_output"},
            "raw_log_idle_seconds": 90,
            "raw_log_bytes": 100,
            "raw_log_updated_at_utc": "1970-01-01T00:15:00+00:00",
            "last_assignment": {"assignment_id": "assign-1", "created_at_utc": "2026-06-07T09:58:00+00:00"},
        }
        marker = {
            "watchdog": {
                "phase": "report_requested",
                "requested_at_utc": "1970-01-01T00:16:10+00:00",
                "assignment_id": "assign-1",
                "planned_action": "interrupt",
                "raw_log_bytes": 100,
                "raw_log_updated_at_utc": "1970-01-01T00:15:00+00:00",
                "report_grace_seconds": DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS,
            }
        }
        with patch("codex_master.server.call_agent_lifecycle", side_effect=lambda _agent, fn: fn()), patch(
            "codex_master.server.time.time", return_value=1000.0
        ), patch("codex_master.server.status_agent", return_value=status), patch(
            "codex_master.server.read_meta", return_value=marker
        ), patch("codex_master.server.request_agent_report") as mock_report, patch(
            "codex_master.server.interrupt_agent"
        ) as mock_interrupt:
            result = fleet_watchdog("a")

        payload = result["results"][0]
        self.assertEqual(payload["watchdog_state"], "waiting_for_report")
        self.assertEqual(payload["action_taken"], "none")
        self.assertEqual(payload["report_elapsed_seconds"], 30)
        mock_report.assert_not_called()
        mock_interrupt.assert_not_called()

    def test_fleet_watchdog_interrupts_after_report_grace_without_activity(self) -> None:
        status = {
            "agent": "a",
            "running": True,
            "lease": {"state": "held", "held_by_this_server": True, "raw_output": "not_returned"},
            "response_state": {"state": "running_recent_output"},
            "raw_log_idle_seconds": 240,
            "raw_log_bytes": 100,
            "raw_log_updated_at_utc": "1970-01-01T00:12:00+00:00",
            "last_assignment": {"assignment_id": "assign-1", "created_at_utc": "2026-06-07T09:58:00+00:00"},
        }
        marker = {
            "watchdog": {
                "phase": "report_requested",
                "requested_at_utc": "1970-01-01T00:13:00+00:00",
                "assignment_id": "assign-1",
                "planned_action": "interrupt",
                "raw_log_bytes": 100,
                "raw_log_updated_at_utc": "1970-01-01T00:12:00+00:00",
                "report_grace_seconds": DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS,
            }
        }
        with patch("codex_master.server.call_agent_lifecycle", side_effect=lambda _agent, fn: fn()), patch(
            "codex_master.server.time.time", return_value=1000.0
        ), patch("codex_master.server.status_agent", return_value=status), patch(
            "codex_master.server.read_meta", return_value=marker
        ), patch("codex_master.server.write_meta") as mock_write_meta, patch(
            "codex_master.server.request_agent_report"
        ) as mock_report, patch(
            "codex_master.server.interrupt_agent",
            return_value={"agent": "a", "status": "interrupt_sent", "lease": status["lease"], "raw_output": "not_returned"},
        ) as mock_interrupt:
            result = fleet_watchdog("a")

        payload = result["results"][0]
        self.assertEqual(payload["watchdog_state"], "action_sent")
        self.assertEqual(payload["action_taken"], "interrupt")
        self.assertEqual(payload["action_result"]["status"], "interrupt_sent")
        mock_report.assert_not_called()
        mock_interrupt.assert_called_once_with("a", force=False)
        mock_write_meta.assert_called_once_with("a", {})

    def test_fleet_watchdog_skips_other_client_lease(self) -> None:
        status = {
            "agent": "a",
            "running": True,
            "lease": {"state": "held", "held_by_this_server": False, "raw_output": "not_returned"},
            "response_state": {"state": "running_recent_output"},
            "raw_log_idle_seconds": 90,
            "raw_log_bytes": 100,
            "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
            "last_assignment": {"assignment_id": "assign-1", "created_at_utc": "2026-06-07T09:58:00+00:00"},
        }
        with patch("codex_master.server.call_agent_lifecycle", side_effect=lambda _agent, fn: fn()), patch(
            "codex_master.server.status_agent", return_value=status
        ), patch("codex_master.server.request_agent_report") as mock_report, patch(
            "codex_master.server.interrupt_agent"
        ) as mock_interrupt:
            result = fleet_watchdog("a")

        payload = result["results"][0]
        self.assertEqual(payload["watchdog_state"], "skipped_not_leased_by_this_server")
        self.assertEqual(payload["action_taken"], "none")
        mock_report.assert_not_called()
        mock_interrupt.assert_not_called()

    def test_append_bounded_raw_log_caps_file_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "agent.log"
            append_bounded_raw_log(log_path, b"a" * 80, max_bytes=128)
            append_bounded_raw_log(log_path, b"b" * 160, max_bytes=128)
            data = log_path.read_bytes()

        self.assertLessEqual(len(data), 128)
        self.assertIn(RAW_LOG_TRUNCATION_MARKER.strip(), data)
        self.assertTrue(data.endswith(b"b" * min(160, 128 - len(RAW_LOG_TRUNCATION_MARKER))))

    def test_prune_raw_logs_bounds_count_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "raw"
            raw_dir.mkdir()
            for index in range(4):
                log_path = raw_dir / f"log-{index}.log"
                log_path.write_bytes(bytes([65 + index]) * 200)
                os.utime(log_path, (1000 + index, 1000 + index))
            with patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.LEGACY_STATE_ROOT", Path(tmpdir) / "legacy"
            ), patch("codex_master.server.META_DIR", Path(tmpdir) / "meta"), patch(
                "codex_master.server.LEGACY_META_DIR", Path(tmpdir) / "legacy" / "meta"
            ):
                result = prune_raw_logs(max_files=2, max_bytes=80)
                logs = sorted(raw_dir.glob("*.log"))
                log_names = [path.name for path in logs]
                log_sizes = [path.stat().st_size for path in logs]

        self.assertEqual(result["deleted_count"], 2)
        self.assertEqual(len(logs), 2)
        self.assertEqual(log_names, ["log-2.log", "log-3.log"])
        self.assertTrue(all(size <= 80 for size in log_sizes))

    def test_prune_raw_logs_unlinks_symlinks_without_touching_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "raw"
            raw_dir.mkdir()
            target = Path(tmpdir) / "outside.log"
            target.write_bytes(b"x" * 200)
            target.chmod(0o644)
            link = raw_dir / "linked.log"
            link.symlink_to(target)
            with patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.LEGACY_STATE_ROOT", Path(tmpdir) / "legacy"
            ), patch("codex_master.server.META_DIR", Path(tmpdir) / "meta"), patch(
                "codex_master.server.LEGACY_META_DIR", Path(tmpdir) / "legacy" / "meta"
            ):
                result = prune_raw_logs(max_files=2, max_bytes=80)
                target_size = target.stat().st_size
                target_mode = stat.S_IMODE(target.stat().st_mode)
                link_exists = link.exists() or link.is_symlink()

        self.assertEqual(result["deleted_symlink_count"], 1)
        self.assertEqual(target_size, 200)
        self.assertEqual(target_mode, 0o644)
        self.assertFalse(link_exists)

    def test_legacy_raw_symlink_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "raw"
            legacy_root = Path(tmpdir) / "legacy"
            outside_raw = Path(tmpdir) / "outside-raw"
            raw_dir.mkdir()
            legacy_root.mkdir()
            outside_raw.mkdir()
            outside_log = outside_raw / "outside.log"
            outside_log.write_bytes(b"x" * 200)
            legacy_raw = legacy_root / "raw"
            legacy_raw.symlink_to(outside_raw)

            with patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.LEGACY_STATE_ROOT", legacy_root
            ), patch("codex_master.server.META_DIR", Path(tmpdir) / "meta"), patch(
                "codex_master.server.LEGACY_META_DIR", legacy_root / "meta"
            ):
                allowed = allowed_raw_log_path(str(legacy_raw / "outside.log"))
                retention = raw_log_retention_status()
                result = prune_raw_logs(max_files=1, max_bytes=80)
                outside_exists = outside_log.exists()

        self.assertIsNone(allowed)
        self.assertEqual(retention["file_count"], 0)
        self.assertEqual(retention["total_bytes"], 0)
        self.assertEqual(retention["managed_dirs"], "not_returned")
        self.assertEqual(retention["managed_dir_count"], 2)
        self.assertNotIn(str(raw_dir), json.dumps(retention, sort_keys=True))
        self.assertNotIn(str(legacy_root), json.dumps(retention, sort_keys=True))
        self.assertEqual(result["deleted_count"], 0)
        self.assertEqual(result["truncated_count"], 0)
        self.assertTrue(outside_exists)

    def test_append_bounded_raw_log_rejects_symlink_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.log"
            target.write_bytes(b"target")
            link = Path(tmpdir) / "linked.log"
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "without following symlinks"):
                append_bounded_raw_log(link, b"payload", max_bytes=128)
            target_content = target.read_bytes()

        self.assertEqual(target_content, b"target")

    def test_write_bounded_raw_log_requires_real_state_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            outside_raw = Path(tmpdir) / "outside-raw"
            state_root.mkdir()
            outside_raw.mkdir()
            raw_dir = state_root / "raw"
            raw_dir.symlink_to(outside_raw)

            with patch("codex_master.server.STATE_ROOT", state_root), patch(
                "codex_master.server.RAW_DIR", raw_dir
            ), patch("codex_master.server.META_DIR", state_root / "meta"), patch(
                "codex_master.server.LEGACY_STATE_ROOT", Path(tmpdir) / "legacy"
            ), patch(
                "codex_master.server.LEGACY_META_DIR", Path(tmpdir) / "legacy" / "meta"
            ):
                with self.assertRaisesRegex(AgentError, "must not be a symlink"):
                    write_bounded_raw_log(raw_dir / "agent.log", max_bytes=128)

    def test_write_bounded_raw_log_rejects_out_of_policy_max_bytes_before_state(self) -> None:
        with patch("codex_master.server.ensure_state") as mock_ensure_state:
            with self.assertRaisesRegex(AgentError, f"raw log max_bytes must be <= {MAX_RAW_LOG_BYTES}"):
                write_bounded_raw_log(Path("/tmp/agent.log"), max_bytes=MAX_RAW_LOG_BYTES + 1)

        mock_ensure_state.assert_not_called()

    def test_write_meta_replaces_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / "meta"
            meta_dir.mkdir()
            target = Path(tmpdir) / "target.json"
            target.write_text('{"external": true}\n', encoding="utf-8")
            link = meta_dir / "a.json"
            link.symlink_to(target)

            with patch("codex_master.server.META_DIR", meta_dir):
                write_meta("a", {"safe": True})

            mode = stat.S_IMODE(link.stat().st_mode)
            payload = json.loads(link.read_text(encoding="utf-8"))
            target_content = target.read_text(encoding="utf-8")
            link_is_symlink = link.is_symlink()

        self.assertEqual(target_content, '{"external": true}\n')
        self.assertFalse(link_is_symlink)
        self.assertEqual(payload, {"safe": True})
        self.assertEqual(mode, 0o600)

    def test_read_meta_refuses_symlink_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / "meta"
            legacy_meta_dir = Path(tmpdir) / "legacy" / "meta"
            meta_dir.mkdir()
            target = Path(tmpdir) / "target.json"
            target.write_text('{"secret": "SECRET_META_SHOULD_NOT_LEAK"}\n', encoding="utf-8")
            symlink_meta = meta_dir / "a.json"
            symlink_meta.symlink_to(target)
            oversized_meta = meta_dir / "b.json"
            oversized_meta.write_text('{"payload": "' + ("x" * MAX_META_BYTES) + '"}\n', encoding="utf-8")

            with patch("codex_master.server.META_DIR", meta_dir), patch(
                "codex_master.server.LEGACY_META_DIR", legacy_meta_dir
            ):
                symlink_result = read_meta("a")
                oversized_result = read_meta("b")
                symlink_still_exists = symlink_meta.is_symlink()

        self.assertIn("meta_error", symlink_result)
        self.assertEqual(symlink_result["meta_error"], "could_not_read")
        self.assertNotIn(str(meta_dir), json.dumps(symlink_result, sort_keys=True))
        self.assertNotIn("SECRET_META_SHOULD_NOT_LEAK", json.dumps(symlink_result, sort_keys=True))
        self.assertTrue(symlink_still_exists)
        self.assertIn("meta_error", oversized_result)
        self.assertEqual(oversized_result["meta_error"], "could_not_read")
        self.assertNotIn(str(meta_dir), json.dumps(oversized_result, sort_keys=True))
        self.assertNotIn("payload", oversized_result)

    def test_read_meta_uses_generic_legacy_source_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / "meta"
            legacy_meta_dir = Path(tmpdir) / "legacy" / "meta"
            legacy = legacy_meta_dir / "a.json"
            meta_dir.mkdir()
            legacy_meta_dir.mkdir(parents=True)
            legacy.write_text('{"safe": true}\n', encoding="utf-8")

            with patch("codex_master.server.META_DIR", meta_dir), patch(
                "codex_master.server.LEGACY_META_DIR", legacy_meta_dir
            ):
                result = read_meta("a")

        self.assertEqual(result["safe"], True)
        self.assertEqual(result["meta_source"], "legacy")
        self.assertNotIn(str(legacy_meta_dir), json.dumps(result, sort_keys=True))

    def test_read_meta_does_not_bypass_primary_symlink_via_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / "meta"
            legacy_meta_dir = Path(tmpdir) / "legacy" / "meta"
            missing_target = Path(tmpdir) / "missing.json"
            primary = meta_dir / "a.json"
            legacy = legacy_meta_dir / "a.json"
            meta_dir.mkdir()
            legacy_meta_dir.mkdir(parents=True)
            primary.symlink_to(missing_target)
            legacy.write_text('{"legacy": "SHOULD_NOT_BE_USED"}\n', encoding="utf-8")

            with patch("codex_master.server.META_DIR", meta_dir), patch(
                "codex_master.server.LEGACY_META_DIR", legacy_meta_dir
            ):
                result = read_meta("a")
                primary_still_symlink = primary.is_symlink()

        self.assertIn("meta_error", result)
        self.assertEqual(result["meta_error"], "could_not_read")
        self.assertNotIn(str(meta_dir), json.dumps(result, sort_keys=True))
        self.assertNotIn("legacy", result)
        self.assertNotIn("SHOULD_NOT_BE_USED", json.dumps(result, sort_keys=True))
        self.assertTrue(primary_still_symlink)

    def test_replace_private_text_refuses_preexisting_nonce_temp_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            target = Path(tmpdir) / "external.json"
            target.write_text("external\n", encoding="utf-8")
            tmp_path = path.with_name(f".{path.name}.fixed.nonce.tmp")
            tmp_path.symlink_to(target)
            fixed_uuid = type("FixedUuid", (), {"hex": "nonce"})()

            with patch("codex_master.server.now_id", return_value="fixed"), patch(
                "codex_master.server.uuid.uuid4", return_value=fixed_uuid
            ):
                with self.assertRaisesRegex(AgentError, "temp file without following symlinks") as raised:
                    replace_private_text(path, "safe\n")

            target_content = target.read_text(encoding="utf-8")
            tmp_is_symlink = tmp_path.is_symlink()
            path_exists = path.exists()

        self.assertNotIn(str(tmp_path), str(raised.exception))
        self.assertNotIn(str(target), str(raised.exception))
        self.assertEqual(target_content, "external\n")
        self.assertTrue(tmp_is_symlink)
        self.assertFalse(path_exists)

    def test_replace_private_text_uses_nonce_temp_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            target = Path(tmpdir) / "external.json"
            target.write_text("external\n", encoding="utf-8")
            predictable_tmp = path.with_name(f".{path.name}.fixed.tmp")
            predictable_tmp.symlink_to(target)
            fixed_uuid = type("FixedUuid", (), {"hex": "nonce"})()

            with patch("codex_master.server.now_id", return_value="fixed"), patch(
                "codex_master.server.uuid.uuid4", return_value=fixed_uuid
            ):
                replace_private_text(path, "safe\n")

            target_content = target.read_text(encoding="utf-8")
            written_content = path.read_text(encoding="utf-8")
            predictable_tmp_is_symlink = predictable_tmp.is_symlink()
            nonce_tmp_exists = path.with_name(f".{path.name}.fixed.nonce.tmp").exists()

        self.assertEqual(target_content, "external\n")
        self.assertEqual(written_content, "safe\n")
        self.assertTrue(predictable_tmp_is_symlink)
        self.assertFalse(nonce_tmp_exists)

    def test_ensure_state_rejects_symlink_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "external-state"
            target.mkdir()
            state_root = Path(tmpdir) / "state"
            state_root.symlink_to(target)

            with patch("codex_master.server.STATE_ROOT", state_root), patch(
                "codex_master.server.RAW_DIR", state_root / "raw"
            ), patch("codex_master.server.META_DIR", state_root / "meta"):
                with self.assertRaisesRegex(AgentError, "must not be a symlink") as raised:
                    ensure_state()

            target_exists = target.is_dir()
            link_is_symlink = state_root.is_symlink()

        self.assertNotIn(str(state_root), str(raised.exception))
        self.assertNotIn(str(target), str(raised.exception))
        self.assertTrue(target_exists)
        self.assertTrue(link_is_symlink)

    def test_ensure_private_dir_rejects_symlink_parent_without_creating_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_parent = tmp_path / "real-parent"
            link_parent = tmp_path / "linked-parent"
            real_parent.mkdir()
            link_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(AgentError, "parent directories must be real directories") as raised:
                ensure_private_dir(link_parent / "state")

            redirected_state = real_parent / "state"

        self.assertFalse(redirected_state.exists())
        self.assertNotIn(str(real_parent), str(raised.exception))

    def test_ensure_state_rejects_file_state_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            state_root.write_text("not a directory\n", encoding="utf-8")

            with patch("codex_master.server.STATE_ROOT", state_root), patch(
                "codex_master.server.RAW_DIR", state_root / "raw"
            ), patch("codex_master.server.META_DIR", state_root / "meta"):
                with self.assertRaisesRegex(AgentError, "not a directory") as raised:
                    ensure_state()

        self.assertNotIn(str(state_root), str(raised.exception))

    def test_record_assignment_refuses_symlink_log_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "external.jsonl"
            target.write_text("external\n", encoding="utf-8")
            link = Path(tmpdir) / "assignments.jsonl"
            link.symlink_to(target)

            with patch("codex_master.server.ASSIGNMENT_LOG", link), patch("codex_master.server.ensure_state"):
                with self.assertRaisesRegex(AgentError, "without following symlinks") as raised:
                    record_assignment({"assignment_id": "1", "agent": "a"})
            target_content = target.read_text(encoding="utf-8")
            link_is_symlink = link.is_symlink()

        self.assertNotIn(str(link), str(raised.exception))
        self.assertNotIn(str(target), str(raised.exception))
        self.assertEqual(target_content, "external\n")
        self.assertTrue(link_is_symlink)

    @patch("codex_master.server.ensure_state")
    def test_list_assignments_refuses_symlink_log_without_leaking_path(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "external.jsonl"
            link = Path(tmpdir) / "assignments.jsonl"
            target.write_text('{"agent":"a","secret":"ASSIGNMENT_SECRET_SHOULD_NOT_LEAK"}\n', encoding="utf-8")
            link.symlink_to(target)

            with patch("codex_master.server.ASSIGNMENT_LOG", link):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 47,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "all", "limit": 10}},
                    }
                )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error"], "could_not_read_assignment_log")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("ASSIGNMENT_SECRET_SHOULD_NOT_LEAK", payload_text)
        self.assertNotIn(str(target), payload_text)
        self.assertNotIn(str(link), payload_text)

    @patch("codex_master.server.ensure_state")
    def test_list_assignments_refuses_oversized_log_without_leaking_path(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            assignment_log = Path(tmpdir) / "assignments.jsonl"
            assignment_log.write_text("x" * (MAX_ASSIGNMENT_LOG_BYTES + 1), encoding="utf-8")

            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 48,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "all", "limit": 10}},
                    }
                )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error"], "could_not_read_assignment_log")
        self.assertNotIn(str(assignment_log), json.dumps(payload, sort_keys=True))

    def test_agent_home_process_summary_flags_external_codex_home_users(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "agent-home"
            home.mkdir()
            proc_root = Path(tmpdir) / "proc"
            external = proc_root / "100"
            managed = proc_root / "101"
            external.mkdir(parents=True)
            managed.mkdir()
            external.joinpath("environ").write_bytes(f"CODEX_HOME={home}\0".encode("utf-8"))
            external.joinpath("status").write_text("Name:\tcodex\nState:\tS (sleeping)\nPPid:\t1\n", encoding="utf-8")
            managed.joinpath("environ").write_bytes(f"CODEX_HOME={home}\0CODEX_AGENT_MCP=1\0".encode("utf-8"))
            managed.joinpath("status").write_text("Name:\tcodex\nState:\tS (sleeping)\nPPid:\t1\n", encoding="utf-8")
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                summary = agent_home_process_summary("a", proc_root)

        self.assertEqual(summary["process_count"], 2)
        self.assertEqual(summary["managed_process_count"], 1)
        self.assertEqual(summary["external_process_count"], 1)
        self.assertEqual(summary["home"], "not_returned")
        self.assertEqual(summary["home_kind"], "managed_agent_home")
        self.assertEqual(summary["external_processes"][0]["pid"], 100)
        self.assertEqual(summary["external_processes"][0]["raw_output"], "not_returned")
        self.assertNotIn(str(home), json.dumps(summary, sort_keys=True))

    def test_agent_lifecycle_lock_refuses_symlink_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_root = tmp_path / "state"
            lock_dir = state_root / "locks"
            lock_dir.mkdir(parents=True)
            target = tmp_path / "outside.lock"
            target.write_text("outside", encoding="utf-8")
            lock_path = lock_dir / "agent-a.lock"
            lock_path.symlink_to(target)

            with patch("codex_master.server.STATE_ROOT", state_root), patch("codex_master.server.LOCK_DIR", lock_dir):
                with self.assertRaisesRegex(AgentError, "without following symlinks"):
                    with agent_lifecycle_lock("a"):
                        pass
                lock_still_symlink = lock_path.is_symlink()

        self.assertTrue(lock_still_symlink)

    def test_agent_lease_blocks_other_client_with_retry_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    first = claim_agent("b", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    response = handle_rpc(
                        {
                            "jsonrpc": "2.0",
                            "id": 49,
                            "method": "tools/call",
                            "params": {"name": "agent_send", "arguments": {"agent": "b", "text": "hi"}},
                        }
                    )

        self.assertEqual(first["status"], "claimed")
        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error_code"], "agent_lease_held_by_other_client")
        self.assertTrue(payload["retryable"])
        self.assertGreaterEqual(payload["retry_after_seconds"], 1)
        self.assertEqual(payload["lease"]["holder"], "other_server")
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertNotIn("owner-one", json.dumps(payload, sort_keys=True))

    def test_agent_release_requires_holder_or_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    blocked = handle_rpc(
                        {
                            "jsonrpc": "2.0",
                            "id": 50,
                            "method": "tools/call",
                            "params": {"name": "agent_release", "arguments": {"agent": "a"}},
                        }
                    )
                    forced = release_agent("a", force=True)

        self.assertTrue(blocked["result"]["isError"])
        blocked_payload = json.loads(blocked["result"]["content"][0]["text"])
        self.assertEqual(blocked_payload["error_code"], "agent_lease_held_by_other_client")
        self.assertEqual(forced["status"], "released")
        self.assertEqual(forced["lease"]["state"], "unclaimed")

    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.start_agent")
    def test_start_agent_with_lease_releases_fresh_successful_start(self, mock_start_agent, _mock_tmux_alive) -> None:
        def fake_start(agent, cwd=None, prompt=None, lease=None, release_lease_on_failure=False):
            return {
                "agent": agent,
                "status": "started",
                "lease": lease,
                "release_lease_on_failure": release_lease_on_failure,
                "raw_output": "not_returned",
            }

        mock_start_agent.side_effect = fake_start
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    result = start_agent_with_lease("a", "/tmp/work", "hi")
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    next_claim = claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)

        self.assertEqual(result["status"], "started")
        self.assertEqual(result["lease"]["state"], "unclaimed")
        self.assertTrue(mock_start_agent.call_args.kwargs["release_lease_on_failure"])
        self.assertEqual(next_claim["status"], "claimed")

    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.start_agent")
    def test_start_agent_with_lease_keeps_existing_same_client_claim(self, mock_start_agent, _mock_tmux_alive) -> None:
        def fake_start(agent, cwd=None, prompt=None, lease=None, release_lease_on_failure=False):
            return {
                "agent": agent,
                "status": "started",
                "lease": lease,
                "release_lease_on_failure": release_lease_on_failure,
                "raw_output": "not_returned",
            }

        mock_start_agent.side_effect = fake_start
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                    result = start_agent_with_lease("a", "/tmp/work", "hi")
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    with self.assertRaisesRegex(AgentError, "leased by another MCP client"):
                        claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)

        self.assertEqual(result["status"], "started")
        self.assertEqual(result["lease"]["holder"], "this_server")
        self.assertFalse(mock_start_agent.call_args.kwargs["release_lease_on_failure"])

    def test_agent_claim_wait_rejects_invalid_direct_interval_values(self) -> None:
        with self.assertRaisesRegex(AgentError, "wait_seconds must be an integer"):
            claim_agent_with_wait("a", wait_seconds="nope")
        with self.assertRaisesRegex(AgentError, "poll_interval_seconds must be an integer"):
            claim_agent_with_wait("a", poll_interval_seconds=True)
        with self.assertRaisesRegex(AgentError, f"poll_interval_seconds must be <= {MAX_WAIT_POLL_SECONDS}"):
            claim_agent_with_wait("a", poll_interval_seconds=MAX_WAIT_POLL_SECONDS + 1)

    def test_wait_agent_rejects_invalid_direct_interval_values(self) -> None:
        with self.assertRaisesRegex(AgentError, "timeout_seconds must be an integer"):
            wait_agent("a", timeout_seconds=None)
        with self.assertRaisesRegex(AgentError, "poll_interval_seconds must be an integer"):
            wait_agent("a", poll_interval_seconds=False)
        with self.assertRaisesRegex(AgentError, f"poll_interval_seconds must be <= {MAX_WAIT_POLL_SECONDS}"):
            wait_agent("a", poll_interval_seconds=MAX_WAIT_POLL_SECONDS + 1)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.run_tmux")
    def test_interrupt_releases_fresh_lease_when_tmux_fails(self, mock_run_tmux, _mock_alive) -> None:
        mock_run_tmux.return_value = subprocess.CompletedProcess(["tmux", "send-keys"], 1, "", "interrupt failed")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ), patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": root / "codex", "home": root / "home", "session": "session-a"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "tmux interrupt failed"):
                    interrupt_agent("a")
                lease = agent_lease_status("a")

        self.assertEqual(lease["state"], "unclaimed")
        self.assertEqual(lease["holder"], "none")

    @patch("codex_master.server.start_agent", return_value={"agent": "a", "status": "started"})
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.agent_lifecycle_lock")
    def test_call_tool_agent_start_acquires_lifecycle_lock(self, mock_lock, _mock_alive, mock_start_agent) -> None:
        events = []

        class FakeLock:
            def __init__(self, agent: str):
                self.agent = agent

            def __enter__(self):
                events.append(("lock", self.agent))

            def __exit__(self, exc_type, exc, tb):
                events.append(("unlock", self.agent))
                return False

        mock_lock.side_effect = lambda agent: FakeLock(agent)

        result = call_tool("agent_start", {"agent": "a", "cwd": "/tmp/work", "prompt": "hi"})

        self.assertEqual(result["results"], [{"agent": "a", "status": "started"}])
        self.assertEqual(events, [("lock", "a"), ("unlock", "a")])
        mock_start_agent.assert_called_once_with("a", "/tmp/work", "hi")

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 1,
            "external_process_count": 1,
            "managed_process_count": 0,
            "external_processes": [{"pid": 100, "raw_output": "not_returned"}],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_start_agent_blocks_external_codex_home_user(
        self, mock_summary, mock_run_tmux, _mock_tmux_alive, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "CODEX_HOME is already used"):
                    start_agent("a", cwd=tmpdir)

        mock_summary.assert_called_once_with("a")
        mock_run_tmux.assert_not_called()

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.run_tmux")
    def test_start_agent_refuses_symlink_runner(self, mock_run_tmux, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target-codex"
            runner = Path(tmpdir) / "codex"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(target.stat().st_mode | stat.S_IXUSR)
            runner.symlink_to(target)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "regular executable file"):
                    start_agent("a", cwd=tmpdir)
                runner_is_symlink = runner.is_symlink()

        self.assertTrue(runner_is_symlink)
        mock_run_tmux.assert_not_called()

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.read_meta", return_value={"raw_log": "/tmp/private-agent.log"})
    @patch("codex_master.server.pane_pid", return_value=321)
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 1,
            "external_process_count": 0,
            "managed_process_count": 1,
            "external_processes": [],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_start_agent_already_running_allows_managed_session_without_external_home_user(
        self, _mock_summary, _mock_tmux_alive, _mock_pane_pid, _mock_read_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ):
                result = start_agent("a", cwd=tmpdir)

        self.assertEqual(result["status"], "already_running")
        self.assertEqual(result["home_external_process_count"], 0)
        self.assertEqual(result["meta"]["raw_log"], "not_returned")
        self.assertNotIn("/tmp/private-agent.log", json.dumps(result, sort_keys=True))
        self.assertEqual(result["raw_output"], "not_returned")

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.pane_pid", return_value=321)
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch(
        "codex_master.server.agent_home_process_summary",
        return_value={
            "process_count": 2,
            "external_process_count": 1,
            "managed_process_count": 1,
            "external_processes": [{"pid": 100, "raw_output": "not_returned"}],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        },
    )
    def test_start_agent_blocks_external_codex_home_user_even_when_tmux_session_exists(
        self, _mock_summary, _mock_tmux_alive, _mock_pane_pid, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "already running in tmux"):
                    start_agent("a", cwd=tmpdir)

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.write_meta")
    @patch("codex_master.server.pane_pid", return_value=123)
    @patch("codex_master.server.tmux_alive", side_effect=[False, True])
    @patch("codex_master.server.run_tmux")
    def test_start_agent_cleans_up_session_when_pipe_fails(
        self, mock_run_tmux, _mock_alive, _mock_pane_pid, _mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)

            def fake_run_tmux(args, **_kwargs):
                if args and args[0] == "new-session":
                    return subprocess.CompletedProcess(["tmux", *args], 0, "", "")
                if args and args[0] == "pipe-pane":
                    return subprocess.CompletedProcess(["tmux", *args], 1, "", "pipe failed")
                if args and args[0] == "kill-session":
                    return subprocess.CompletedProcess(["tmux", *args], 0, "", "")
                return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

            mock_run_tmux.side_effect = fake_run_tmux
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch("codex_master.server.META_DIR", Path(tmpdir)):
                with self.assertRaisesRegex(RuntimeError, "pipe-pane failed"):
                    start_agent("a", cwd=tmpdir)

            new_session_calls = [call for call in mock_run_tmux.call_args_list if call.args[0][0] == "new-session"]
            self.assertEqual(len(new_session_calls), 1)
            start_command = new_session_calls[0].args[0][-1]
            self.assertIn("--model gpt-5.4-mini", start_command)
            self.assertIn('model="gpt-5.4-mini"', start_command)
            self.assertIn('model_reasoning_effort="medium"', start_command)
            kill_calls = [call for call in mock_run_tmux.call_args_list if call.args[0][0] == "kill-session"]
            self.assertEqual(len(kill_calls), 1)
            self.assertFalse(any(Path(tmpdir).glob("*.log")))

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.write_meta")
    @patch("codex_master.server.pane_pid", return_value=123)
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    def test_start_agent_does_not_return_raw_log_path(
        self, mock_run_tmux, _mock_alive, _mock_pane_pid, mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            runner = tmp_path / "codex"
            raw_dir = tmp_path / "raw"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            raw_dir.mkdir()
            mock_run_tmux.return_value = subprocess.CompletedProcess(["tmux"], 0, "", "")

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": tmp_path, "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", raw_dir), patch("codex_master.server.META_DIR", tmp_path / "meta"), patch(
                "codex_master.server.now_id", return_value="fixed"
            ), patch(
                "codex_master.server.agent_home_process_summary",
                return_value={
                    "process_count": 0,
                    "external_process_count": 0,
                    "managed_process_count": 0,
                    "external_processes": [],
                    "external_processes_truncated": False,
                    "raw_output": "not_returned",
                },
            ):
                result = start_agent("a", cwd=tmpdir)

            raw_log_path = str(raw_dir / "fixed-a.log")

        self.assertEqual(result["raw_log"], "not_returned")
        self.assertNotIn(raw_log_path, json.dumps(result, sort_keys=True))
        self.assertEqual(mock_write_meta.call_args.args[1]["raw_log"], raw_log_path)

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.write_meta")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    def test_start_agent_removes_raw_log_when_new_session_fails(
        self, mock_run_tmux, _mock_alive, _mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            mock_run_tmux.return_value = subprocess.CompletedProcess(["tmux", "new-session"], 1, "", "start failed")

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch("codex_master.server.META_DIR", Path(tmpdir)), patch(
                "codex_master.server.agent_home_process_summary",
                return_value={
                    "process_count": 0,
                    "external_process_count": 0,
                    "managed_process_count": 0,
                    "external_processes": [],
                    "external_processes_truncated": False,
                    "raw_output": "not_returned",
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "tmux start failed"):
                    start_agent("a", cwd=tmpdir)
                leftover_logs = list(Path(tmpdir).glob("*.log"))

        self.assertEqual(leftover_logs, [])

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.write_meta")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    def test_start_agent_does_not_kill_session_when_new_session_fails(
        self, mock_run_tmux, _mock_alive, _mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            mock_run_tmux.return_value = subprocess.CompletedProcess(["tmux", "new-session"], 1, "", "duplicate session")

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch("codex_master.server.META_DIR", Path(tmpdir)), patch(
                "codex_master.server.agent_home_process_summary",
                return_value={
                    "process_count": 0,
                    "external_process_count": 0,
                    "managed_process_count": 0,
                    "external_processes": [],
                    "external_processes_truncated": False,
                    "raw_output": "not_returned",
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "tmux start failed"):
                    start_agent("a", cwd=tmpdir)

            kill_calls = [call for call in mock_run_tmux.call_args_list if call.args[0][0] == "kill-session"]
            leftover_logs = list(Path(tmpdir).glob("*.log"))

        self.assertEqual(kill_calls, [])
        self.assertEqual(leftover_logs, [])

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.write_meta")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    def test_start_agent_redacts_tmux_start_error(
        self, mock_run_tmux, _mock_alive, _mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            mock_run_tmux.return_value = subprocess.CompletedProcess(
                ["tmux", "new-session"], 1, "", "OPENAI_API_KEY=sk-testtoken1234567890"
            )

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch("codex_master.server.META_DIR", Path(tmpdir)), patch(
                "codex_master.server.agent_home_process_summary",
                return_value={
                    "process_count": 0,
                    "external_process_count": 0,
                    "managed_process_count": 0,
                    "external_processes": [],
                    "external_processes_truncated": False,
                    "raw_output": "not_returned",
                },
            ):
                with self.assertRaises(AgentError) as raised:
                    start_agent("a", cwd=tmpdir)

        error_text = str(raised.exception)
        self.assertNotIn("sk-testtoken1234567890", error_text)
        self.assertIn("OPENAI_API_KEY=<redacted>", error_text)

    @patch("codex_master.server.ensure_state")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
    def test_start_agent_refuses_preexisting_raw_log_symlink(
        self, mock_run_tmux, _mock_alive, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            raw_dir = Path(tmpdir) / "raw"
            target = Path(tmpdir) / "target.log"
            link = raw_dir / "fixed-a.log"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            raw_dir.mkdir()
            target.write_text("external\n", encoding="utf-8")
            link.symlink_to(target)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", raw_dir), patch(
                "codex_master.server.META_DIR", Path(tmpdir) / "meta"
            ), patch(
                "codex_master.server.agent_home_process_summary",
                return_value={
                    "process_count": 0,
                    "external_process_count": 0,
                    "managed_process_count": 0,
                    "external_processes": [],
                    "external_processes_truncated": False,
                    "raw_output": "not_returned",
                },
            ), patch(
                "codex_master.server.now_id", return_value="fixed"
            ):
                with self.assertRaisesRegex(AgentError, "without following symlinks") as raised:
                    start_agent("a", cwd=tmpdir)
                target_content = target.read_text(encoding="utf-8")
                link_is_symlink = link.is_symlink()

        mock_run_tmux.assert_not_called()
        self.assertNotIn(str(link), str(raised.exception))
        self.assertNotIn(str(target), str(raised.exception))
        self.assertEqual(target_content, "external\n")
        self.assertTrue(link_is_symlink)

    @patch("codex_master.server.run_command")
    def test_worktree_create_refuses_symlink_parent_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            repo = tmp_path / "repo"
            real_parent = repo / "real-parent"
            link_parent = repo / "linked-parent"
            repo.mkdir()
            real_parent.mkdir()
            link_parent.symlink_to(real_parent, target_is_directory=True)
            target = link_parent / "agent-a"

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "parent directories must be real directories") as raised:
                    worktree_create_for_agent("a", path=str(target))

            redirected_target = real_parent / "agent-a"

        mock_run_command.assert_not_called()
        self.assertNotIn(str(link_parent), str(raised.exception))
        self.assertNotIn(str(real_parent), str(raised.exception))
        self.assertFalse(redirected_target.exists())

    @patch("codex_master.server.run_command")
    def test_worktree_create_refuses_broken_target_symlink_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            target = repo / "agent-a"
            target.symlink_to(repo / "missing-target")

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "worktree path already exists") as raised:
                    worktree_create_for_agent("a", path=str(target))
            target_is_symlink = target.is_symlink()

        mock_run_command.assert_not_called()
        self.assertNotIn(str(target), str(raised.exception))
        self.assertTrue(target_is_symlink)

    @patch("codex_master.server.run_command")
    def test_worktree_create_relative_path_is_repo_scoped_and_parent_checked(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            relative = ".codex-master-worktrees/agent-a"
            expected_target = repo / relative
            mock_run_command.return_value = subprocess.CompletedProcess(["git"], 0, "", "")

            with patch("codex_master.server.repo_root", return_value=repo):
                result = worktree_create_for_agent("a", path=relative)

        self.assertEqual(result["path"], relative)
        self.assertEqual(result["path_state"], "set")
        self.assertEqual(result["path_kind"], "repo_relative")
        self.assertEqual(result["status"], "created")
        self.assertEqual(mock_run_command.call_args.args[0], ["git", "worktree", "add", str(expected_target)])
        self.assertEqual(mock_run_command.call_args.kwargs["cwd"], repo)
        self.assertNotIn(str(repo), json.dumps(result, sort_keys=True))

    @patch("codex_master.server.run_command")
    def test_worktree_create_refuses_relative_escape_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            repo = tmp_path / "repo"
            outside = tmp_path / "outside"
            repo.mkdir()

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "worktree path must stay inside repo") as raised:
                    worktree_create_for_agent("a", path="../outside/agent-a")

        mock_run_command.assert_not_called()
        self.assertFalse(outside.exists())
        self.assertNotIn(str(outside), str(raised.exception))

    @patch("codex_master.server.run_command")
    def test_worktree_status_refuses_symlink_path_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            real_dir = repo / "real"
            link_dir = repo / "linked"
            repo.mkdir()
            real_dir.mkdir()
            link_dir.symlink_to(real_dir, target_is_directory=True)

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "worktree status path must be a real directory") as raised:
                    worktree_status(str(link_dir))

        mock_run_command.assert_not_called()
        self.assertNotIn(str(link_dir), str(raised.exception))
        self.assertNotIn(str(real_dir), str(raised.exception))

    @patch("codex_master.server.run_command")
    def test_worktree_status_refuses_non_directory_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            file_path = repo / "not-a-dir"
            file_path.write_text("x\n", encoding="utf-8")

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "worktree status path must be a real directory") as raised:
                    worktree_status(str(file_path))

        mock_run_command.assert_not_called()
        self.assertNotIn(str(file_path), str(raised.exception))

    @patch("codex_master.server.run_command")
    def test_worktree_status_relative_path_is_repo_scoped_and_real_directory(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            target = repo / ".codex-master-worktrees" / "agent-a"
            target.mkdir(parents=True)
            mock_run_command.side_effect = [
                subprocess.CompletedProcess(["git"], 0, "", ""),
                subprocess.CompletedProcess(["git"], 0, f"worktree {repo}\nworktree {target}\n", ""),
            ]

            with patch("codex_master.server.repo_root", return_value=repo):
                result = worktree_status(".codex-master-worktrees/agent-a")

        self.assertEqual(result["path"], "not_returned")
        self.assertEqual(result["path_state"], "set")
        self.assertEqual(mock_run_command.call_args_list[0].args[0], ["git", "status", "--short"])
        self.assertEqual(mock_run_command.call_args_list[0].kwargs["cwd"], target)
        result_text = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(repo), result_text)
        self.assertNotIn(str(target), result_text)
        self.assertIn("/<redacted>", result["worktrees"]["output_excerpt"])

    @patch("codex_master.server.run_command")
    def test_worktree_status_refuses_relative_escape_without_git_call(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            repo = tmp_path / "repo"
            outside = tmp_path / "outside"
            repo.mkdir()

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "worktree status path must stay inside repo") as raised:
                    worktree_status("../outside")

        mock_run_command.assert_not_called()
        self.assertFalse(outside.exists())
        self.assertNotIn(str(outside), str(raised.exception))

    def test_repo_wrapper_works_via_symlink(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        wrapper = repo_root / "bin" / "codex-master-mcp"
        with tempfile.TemporaryDirectory() as tmpdir:
            symlink = Path(tmpdir) / "codex-master-mcp"
            symlink.symlink_to(wrapper)
            result = subprocess.run(
                [str(symlink), "tools"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        payload = json.loads(result.stdout)
        self.assertIn("agent_start", {tool["name"] for tool in payload["tools"]})

    def test_agent_skills_inventory_is_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            skill_paths = [
                home / "skills" / ".system" / "openai-docs" / "SKILL.md",
                home / "skills" / ".system" / "imagegen" / "SKILL.md",
                home / "plugins" / "cache" / "openai-curated" / "github" / "hash" / "skills" / "github" / "SKILL.md",
                home / ".tmp" / "plugins" / "plugins" / "codex-security" / "skills" / "security-scan" / "SKILL.md",
            ]
            for path in skill_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK\n", encoding="utf-8")

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 17,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_skills",
                            "arguments": {"agent": "a", "include_names": True, "limit": 2},
                        },
                    }
                )
                names_page = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 18,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_skills",
                            "arguments": {
                                "agent": "a",
                                "include_names": True,
                                "limit": 2,
                                "names_offset": 2,
                            },
                        },
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])["results"][0]
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["total"], 4)
        self.assertEqual(payload["by_source"]["system"], 2)
        self.assertEqual(payload["by_source"]["plugin_cache"], 1)
        self.assertEqual(payload["by_source"]["tmp_plugin_cache"], 1)
        self.assertEqual(payload["plugin_count"], 2)
        self.assertEqual(payload["plugins_limit"], 20)
        self.assertEqual(payload["plugins"]["github@openai-curated"], 1)
        self.assertEqual(payload["plugins"]["codex-security@tmp"], 1)
        self.assertFalse(payload["plugins_truncated"])
        self.assertEqual(payload["home"], "not_returned")
        self.assertEqual(payload["home_kind"], "managed_agent_home")
        self.assertTrue(all(root["path"] == "not_returned" for root in payload["roots"]))
        self.assertEqual(payload["skill_file_contents"], "not_returned")
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertEqual(payload["names_total"], 4)
        self.assertEqual(payload["names_offset"], 0)
        self.assertEqual(payload["names_limit"], 2)
        self.assertEqual(len(payload["names"]), 2)
        self.assertTrue(payload["names_truncated"])
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", payload_text)
        self.assertNotIn(str(home), payload_text)

        self.assertFalse(names_page["result"]["isError"])
        names_page_payload = json.loads(names_page["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(names_page_payload["names_total"], 4)
        self.assertEqual(names_page_payload["names_offset"], 2)
        self.assertEqual(names_page_payload["names_limit"], 2)
        self.assertEqual(len(names_page_payload["names"]), 2)
        self.assertFalse(names_page_payload["names_truncated"])
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", json.dumps(names_page_payload, sort_keys=True))
        self.assertNotIn(str(home), json.dumps(names_page_payload, sort_keys=True))

    def test_agent_skills_inventory_ignores_symlinked_skill_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            real_skill = home / "skills" / ".system" / "real-skill" / "SKILL.md"
            linked_skill = home / "skills" / ".system" / "linked-skill" / "SKILL.md"
            outside_skill = Path(tmpdir) / "outside" / "SKILL.md"
            symlink_root = home / "plugins" / "cache"
            outside_root = Path(tmpdir) / "outside-cache"
            outside_root_skill = outside_root / "openai-curated" / "github" / "hash" / "skills" / "linked" / "SKILL.md"

            real_skill.parent.mkdir(parents=True, exist_ok=True)
            real_skill.write_text("real\n", encoding="utf-8")
            outside_skill.parent.mkdir(parents=True, exist_ok=True)
            outside_skill.write_text("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK\n", encoding="utf-8")
            linked_skill.parent.mkdir(parents=True, exist_ok=True)
            linked_skill.symlink_to(outside_skill)
            outside_root_skill.parent.mkdir(parents=True, exist_ok=True)
            outside_root_skill.write_text("outside-root\n", encoding="utf-8")
            symlink_root.parent.mkdir(parents=True, exist_ok=True)
            symlink_root.symlink_to(outside_root)

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                skills = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 44,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_skills",
                            "arguments": {"agent": "a", "include_names": True},
                        },
                    }
                )
                match = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 45,
                        "method": "tools/call",
                        "params": {"name": "agent_skill_match", "arguments": {"agent": "a", "skill": "linked-skill"}},
                    }
                )

        self.assertFalse(skills["result"]["isError"])
        skills_payload = json.loads(skills["result"]["content"][0]["text"])["results"][0]
        payload_text = json.dumps(skills_payload, sort_keys=True)
        self.assertEqual(skills_payload["total"], 1)
        self.assertEqual(skills_payload["roots"][0]["skill_count"], 1)
        self.assertEqual(skills_payload["roots"][1]["skill_count"], 0)
        self.assertEqual(skills_payload["roots"][0]["path"], "not_returned")
        self.assertEqual(skills_payload["home"], "not_returned")
        self.assertEqual(skills_payload["names_total"], 1)
        self.assertEqual(skills_payload["names"][0]["name"], "real-skill")
        self.assertEqual(skills_payload["names"][0]["plugin"], "")
        self.assertEqual(skills_payload["names"][0]["source"], "system")
        self.assertNotIn("linked-skill", payload_text)
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", payload_text)
        self.assertNotIn(str(home), payload_text)
        self.assertNotIn(str(outside_root), payload_text)

        self.assertFalse(match["result"]["isError"])
        match_payload = json.loads(match["result"]["content"][0]["text"])["results"][0]
        self.assertFalse(match_payload["available"])
        self.assertEqual(match_payload["skill_file_contents"], "not_returned")

    def test_skill_match_and_capabilities_are_data_sparse(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            skill = home / ".tmp" / "plugins" / "plugins" / "github" / "skills" / "gh-fix-ci" / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK\n", encoding="utf-8")
            for index in range(25):
                extra = home / ".tmp" / "plugins" / "plugins" / f"plugin-{index:02d}" / "skills" / "extra" / "SKILL.md"
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text("extra\n", encoding="utf-8")

            with patch.dict(
                "codex_master.server.AGENTS",
                {"b": {"label": "B", "runner": home / "codex", "home": home, "session": "session-b"}},
                clear=False,
            ):
                skills = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 42,
                        "method": "tools/call",
                        "params": {"name": "agent_skills", "arguments": {"agent": "b"}},
                    }
                )
                skills_next_page = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 43,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_skills",
                            "arguments": {"agent": "b", "plugins_offset": 20, "plugins_limit": 10},
                        },
                    }
                )
                match = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 24,
                        "method": "tools/call",
                        "params": {"name": "agent_skill_match", "arguments": {"agent": "b", "skill": "github:gh-fix-ci"}},
                    }
                )
                capabilities = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 25,
                        "method": "tools/call",
                        "params": {"name": "agent_capabilities", "arguments": {"agent": "b"}},
                    }
                )

        self.assertFalse(skills["result"]["isError"])
        skills_payload = json.loads(skills["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(skills_payload["plugin_count"], 26)
        self.assertEqual(skills_payload["home"], "not_returned")
        self.assertEqual(skills_payload["plugins_offset"], 0)
        self.assertEqual(skills_payload["plugins_limit"], 20)
        self.assertTrue(skills_payload["plugins_truncated"])
        self.assertEqual(len(skills_payload["plugins"]), 20)

        self.assertFalse(skills_next_page["result"]["isError"])
        next_page_payload = json.loads(skills_next_page["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(next_page_payload["plugin_count"], 26)
        self.assertEqual(next_page_payload["plugins_offset"], 20)
        self.assertEqual(next_page_payload["plugins_limit"], 10)
        self.assertEqual(len(next_page_payload["plugins"]), 6)
        self.assertFalse(next_page_payload["plugins_truncated"])

        self.assertFalse(match["result"]["isError"])
        match_payload = json.loads(match["result"]["content"][0]["text"])["results"][0]
        match_text = json.dumps(match_payload, sort_keys=True)
        self.assertTrue(match_payload["available"])
        self.assertEqual(match_payload["skill_file_contents"], "not_returned")
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", match_text)

        self.assertFalse(capabilities["result"]["isError"])
        capability_payload = json.loads(capabilities["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(capability_payload["models"]["default"], "gpt-5.4-mini")
        self.assertEqual(capability_payload["models"]["write"], "gpt-5.3-codex-spark")
        self.assertEqual(capability_payload["master_mcp_tools"], "not_configured_for_agent")
        self.assertEqual(capability_payload["plugin_count"], 26)
        self.assertEqual(capability_payload["plugin_page_count"], 20)
        self.assertEqual(capability_payload["plugins_offset"], 0)
        self.assertEqual(capability_payload["plugins_limit"], 20)
        self.assertTrue(capability_payload["plugins_truncated"])
        self.assertEqual(len(capability_payload["plugins"]), 20)
        self.assertEqual(capability_payload["home"], "not_returned")
        self.assertNotIn(str(home), json.dumps(capability_payload, sort_keys=True))

    def test_scope_check_blocks_writes_outside_scope(self) -> None:
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 26,
                "method": "tools/call",
                "params": {
                    "name": "agent_scope_check",
                    "arguments": {"scope": ["src/codex_master"], "write_paths": ["tests/test_server.py"]},
                },
            }
        )
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["violations"], ["tests/test_server.py"])
        self.assertEqual(payload["cwd"], "not_returned")
        self.assertEqual(payload["cwd_state"], "set")

    @patch("codex_master.server.ensure_state")
    def test_assignments_redact_historical_absolute_paths(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            assignment_log = Path(tmpdir) / "assignments.jsonl"
            assignment_log.write_text(
                json.dumps(
                    {
                        "assignment_id": "1-a",
                        "agent": "a",
                        "scope": ["/home/teladi/private/repo"],
                        "write_paths": ["/home/teladi/private/repo/file.py"],
                        "skill": {"requested": "/home/teladi/secret-skill"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 51,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "all", "limit": 10}},
                    }
                )

        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        record = payload["records"][0]
        self.assertEqual(record["scope"], ["/<redacted>"])
        self.assertEqual(record["write_paths"], ["/<redacted>"])
        self.assertEqual(record["skill"]["requested"], "/<redacted>")
        self.assertEqual(record["prompt_output"], "not_returned")
        self.assertEqual(record["response_output"], "not_returned")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("/home/teladi/private", payload_text)
        self.assertNotIn("/home/teladi/secret-skill", payload_text)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.send_agent")
    def test_agent_assign_sends_structured_prompt_without_returning_prompt(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            state = home / "state"
            assignment_log = home / "assignments.jsonl"
            skill = home / ".tmp" / "plugins" / "plugins" / "codex-security" / "skills" / "security-scan" / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("Skill body must not be returned\n", encoding="utf-8")

            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch(
                "codex_master.server.ASSIGNMENT_LOG", assignment_log
            ), patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 18,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign",
                            "arguments": {
                                "agent": "a",
                                "role": "exploriererin",
                                "skill": "codex-security:security-scan",
                                "scope": ["src/codex_master/server.py"],
                                "task": "Pruefe nur lesend.",
                                "name": "Mila",
                            },
                        },
                    }
                )
                ledger_response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 23,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "a", "limit": 1}},
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        assignment_id = payload["assignment_id"]
        self.assertEqual(payload["status"], "assigned")
        self.assertEqual(payload["role"], "exploriererin")
        self.assertEqual(payload["model"], "gpt-5.4-mini")
        self.assertEqual(payload["write_policy"], "read_only")
        self.assertFalse(payload["subagents_allowed"])
        self.assertEqual(payload["skill"]["requested"], "codex-security:security-scan")
        self.assertTrue(payload["skill"]["available"])
        self.assertEqual(payload["prompt_output"], "not_returned")
        self.assertEqual(payload["response_output"], "not_returned")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("[EXPLORER_BEE_TASK]", payload_text)
        self.assertNotIn("Skill body must not be returned", payload_text)

        mock_send_agent.assert_called_once()
        sent_agent, sent_prompt, sent_enter = mock_send_agent.call_args.args
        self.assertEqual(sent_agent, "a")
        self.assertTrue(sent_enter)
        self.assertIn("[EXPLORER_BEE_TASK]", sent_prompt)
        self.assertIn("Modell: gpt-5.4-mini", sent_prompt)
        self.assertIn("Skill: codex-security:security-scan", sent_prompt)
        self.assertIn("Darf schreiben: nein", sent_prompt)
        self.assertIn("Darf eigene Subagentinnen starten: nein", sent_prompt)

        self.assertIsNotNone(ledger_response)
        self.assertFalse(ledger_response["result"]["isError"])
        ledger = json.loads(ledger_response["result"]["content"][0]["text"])
        self.assertEqual(ledger["record_count"], 1)
        self.assertEqual(ledger["log_path"], "not_returned")
        record = ledger["records"][0]
        self.assertEqual(record["assignment_id"], assignment_id)
        self.assertEqual(record["agent"], "a")
        self.assertEqual(record["role"], "exploriererin")
        self.assertEqual(record["model"], "gpt-5.4-mini")
        self.assertEqual(record["scope"], ["src/codex_master/server.py"])
        self.assertEqual(record["write_policy"], "read_only")
        self.assertFalse(record["allow_subagents"])
        ledger_text = json.dumps(ledger, sort_keys=True)
        self.assertNotIn("[EXPLORER_BEE_TASK]", ledger_text)
        self.assertNotIn("Pruefe nur lesend.", ledger_text)
        self.assertNotIn("Skill body must not be returned", ledger_text)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.send_agent")
    def test_assignment_log_retention_prunes_metadata_records(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            state = home / "state"
            assignment_log = home / "assignments.jsonl"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch(
                "codex_master.server.ASSIGNMENT_LOG", assignment_log
            ), patch(
                "codex_master.server.MAX_ASSIGNMENT_LOG_RECORDS", 3
            ), patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                for index in range(5):
                    response = handle_rpc(
                        {
                            "jsonrpc": "2.0",
                            "id": 30 + index,
                            "method": "tools/call",
                            "params": {
                                "name": "agent_assign_readonly",
                                "arguments": {
                                    "agent": "a",
                                    "scope": [f"src/{index}"],
                                    "task": f"Pruefe nur lesend {index}.",
                                    "enter": False,
                                },
                            },
                        }
                    )
                    self.assertFalse(response["result"]["isError"])
                ledger_response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 40,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "a", "limit": 10}},
                    }
                )

            mode = stat.S_IMODE(assignment_log.stat().st_mode)
            lines = assignment_log.read_text(encoding="utf-8").splitlines()

        self.assertFalse(ledger_response["result"]["isError"])
        ledger = json.loads(ledger_response["result"]["content"][0]["text"])
        self.assertEqual(ledger["record_count"], 3)
        self.assertEqual(ledger["retained_count"], 3)
        self.assertEqual(ledger["retention_limit"], 3)
        self.assertEqual(ledger["log_path"], "not_returned")
        self.assertFalse(ledger["records_truncated"])
        self.assertEqual([record["scope"] for record in ledger["records"]], [["src/2"], ["src/3"], ["src/4"]])
        self.assertEqual(len(lines), 3)
        self.assertEqual(mode, 0o600)
        ledger_text = json.dumps(ledger, sort_keys=True)
        self.assertNotIn("Pruefe nur lesend", ledger_text)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.send_agent")
    def test_agent_assign_allows_nested_subagents_only_when_explicit(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "b", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            state = home / "state"
            assignment_log = home / "assignments.jsonl"
            skill = home / ".tmp" / "plugins" / "plugins" / "github" / "skills" / "gh-fix-ci" / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("body\n", encoding="utf-8")

            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch(
                "codex_master.server.ASSIGNMENT_LOG", assignment_log
            ), patch.dict(
                "codex_master.server.AGENTS",
                {"b": {"label": "B", "runner": home / "codex", "home": home, "session": "session-b"}},
                clear=False,
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 22,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign",
                            "arguments": {
                                "agent": "b",
                                "role": "arbeitsbiene",
                                "skill": "github:gh-fix-ci",
                                "scope": [".github/workflows"],
                                "write_paths": [".github/workflows/ci.yml"],
                                "task": "Haerte CI.",
                                "allow_subagents": True,
                            },
                        },
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertTrue(payload["subagents_allowed"])
        self.assertEqual(payload["model"], "gpt-5.3-codex-spark")
        self.assertEqual(payload["write_policy"], "explicit_paths_only")
        sent_prompt = mock_send_agent.call_args.args[1]
        self.assertIn("[WORK_BEE_TASK]", sent_prompt)
        self.assertIn("Modell: gpt-5.3-codex-spark", sent_prompt)
        self.assertIn("Darf eigene Subagentinnen starten: ja, nur innerhalb Scope und Schreibpfaden", sent_prompt)

    def test_agent_assign_enforces_role_write_and_skill_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                readonly = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 19,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign",
                            "arguments": {
                                "agent": "a",
                                "role": "exploriererin",
                                "task": "nur lesen",
                                "write_paths": ["src/codex_master/server.py"],
                            },
                        },
                    }
                )
                worker = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 20,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign",
                            "arguments": {"agent": "a", "role": "arbeitsbiene", "task": "fix"},
                        },
                    }
                )
                missing_skill = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 21,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign",
                            "arguments": {
                                "agent": "a",
                                "role": "exploriererin",
                                "task": "nur lesen",
                                "skill": "missing-plugin:missing-skill",
                            },
                        },
                    }
                )
                outside_scope = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 27,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign_write",
                            "arguments": {
                                "agent": "a",
                                "task": "fix",
                                "scope": ["src"],
                                "write_paths": ["tests/test_server.py"],
                                "allow_missing_skill": True,
                            },
                        },
                    }
                )
                long_task = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 28,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign_readonly",
                            "arguments": {"agent": "a", "task": "x" * (MAX_TASK_TEXT + 1)},
                        },
                    }
                )
                too_many_context_items = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 29,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign_readonly",
                            "arguments": {
                                "agent": "a",
                                "task": "nur lesen",
                                "context": ["x"] * (MAX_ASSIGNMENT_LIST_ITEMS + 1),
                            },
                        },
                    }
                )

        self.assertTrue(readonly["result"]["isError"])
        self.assertIn("must not include write paths", readonly["result"]["content"][0]["text"])
        self.assertTrue(worker["result"]["isError"])
        self.assertIn("require at least one explicit write path", worker["result"]["content"][0]["text"])
        self.assertTrue(missing_skill["result"]["isError"])
        self.assertIn("skill not found", missing_skill["result"]["content"][0]["text"])
        self.assertTrue(outside_scope["result"]["isError"])
        self.assertIn("write paths must stay inside scope", outside_scope["result"]["content"][0]["text"])
        self.assertTrue(long_task["result"]["isError"])
        self.assertIn("task must not exceed", long_task["result"]["content"][0]["text"])
        self.assertTrue(too_many_context_items["result"]["isError"])
        self.assertIn("context must contain at most", too_many_context_items["result"]["content"][0]["text"])

    def test_agent_send_rejects_oversized_text_before_tmux(self) -> None:
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "agent_send",
                    "arguments": {"agent": "a", "text": "x" * (MAX_SEND_TEXT + 1)},
                },
            }
        )

        self.assertTrue(response["result"]["isError"])
        self.assertIn("text must not exceed", response["result"]["content"][0]["text"])

    def test_send_agent_uses_bracketed_paste_for_multiline_text(self) -> None:
        calls = []

        def fake_run_tmux(args, *, input_text=None, check=True, timeout=10):
            calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
            return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

        with patch("codex_master.server.tmux_alive", return_value=True), patch(
            "codex_master.server.run_tmux", side_effect=fake_run_tmux
        ):
            result = send_agent("a", "line 1\nline 2", enter=True)

        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["chars"], len("line 1\nline 2"))
        self.assertEqual(result["paste_mode"], "bracketed_paste")
        self.assertEqual(result["response_output"], "not_returned")
        load_call = next(call for call in calls if call["args"][0] == "load-buffer")
        self.assertEqual(load_call["input_text"], f"{BRACKETED_PASTE_BEGIN}line 1\nline 2{BRACKETED_PASTE_END}")
        self.assertTrue(any(call["args"][0] == "paste-buffer" for call in calls))
        self.assertTrue(any(call["args"][-1] == "Enter" for call in calls))

    def test_send_agent_keeps_single_line_plain_paste(self) -> None:
        calls = []

        def fake_run_tmux(args, *, input_text=None, check=True, timeout=10):
            calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
            return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

        with patch("codex_master.server.tmux_alive", return_value=True), patch(
            "codex_master.server.run_tmux", side_effect=fake_run_tmux
        ):
            result = send_agent("a", "single line", enter=False)

        self.assertEqual(result["paste_mode"], "plain_paste")
        self.assertFalse(result["submitted"])
        load_call = next(call for call in calls if call["args"][0] == "load-buffer")
        self.assertEqual(load_call["input_text"], "single line")
        self.assertFalse(any(call["args"][-1] == "Enter" for call in calls))


class CliLifecycleTest(unittest.TestCase):
    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"ok": True})
    def test_cli_tool_validation_drops_omitted_optional_arguments(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["start", "a"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with("agent_start", {"agent": "a"})

    @patch("codex_master.server.call_tool")
    @patch("builtins.print")
    def test_cli_tool_validation_rejects_out_of_bounds_arguments(self, mock_print, mock_call_tool) -> None:
        result = main_cli(["wait", "a", "--timeout-seconds", "-1"])

        self.assertEqual(result, 1)
        mock_call_tool.assert_not_called()
        payload = json.loads(mock_print.call_args.args[0])
        self.assertEqual(payload["error"], "timeout_seconds must be >= 0")

    @patch("codex_master.server.ensure_state")
    @patch("builtins.print")
    def test_cli_raw_log_writer_rejects_out_of_policy_max_bytes(self, mock_print, mock_ensure_state) -> None:
        result = main_cli(["raw-log-writer", "/tmp/agent.log", "--max-bytes", str(MAX_RAW_LOG_BYTES + 1)])

        self.assertEqual(result, 1)
        mock_ensure_state.assert_not_called()
        payload = json.loads(mock_print.call_args.args[0])
        self.assertEqual(payload["error"], f"raw log max_bytes must be <= {MAX_RAW_LOG_BYTES}")

    @patch("codex_master.server.run_command")
    @patch("codex_master.server.print_json")
    def test_cli_install_plans_expected_local_install_flow(self, mock_print_json, mock_run) -> None:
        captured_payloads = []
        link_created = False

        def _capture(payload):
            captured_payloads.append(payload)
            return 0

        mock_print_json.side_effect = _capture
        with tempfile.TemporaryDirectory() as tmp_home:
            local_bin = Path(tmp_home) / ".local" / "bin"
            local_bin.mkdir(parents=True, exist_ok=True)
            with patch.dict("os.environ", {"HOME": tmp_home}):
                with patch("codex_master.server.shutil.which", return_value="/usr/bin/codex"):
                    mock_run.side_effect = [
                        subprocess.CompletedProcess(["codex", "mcp", "get", "codex-master-mcp"], 1, "not found", ""),
                        subprocess.CompletedProcess(
                            [
                                "codex",
                                "mcp",
                                "add",
                                "codex-master-mcp",
                                "--",
                                str(Path(tmp_home) / ".local" / "bin" / "codex-master-mcp"),
                            ],
                            0,
                            "",
                            "",
                        ),
                    ]
                    result = main_cli(["install", "--path", str(Path(tmp_home) / ".local" / "bin" / "codex-master-mcp")])
                    link_created = (Path(tmp_home) / ".local" / "bin" / "codex-master-mcp").exists()
                    config_content = (Path(tmp_home) / ".codex" / "config.toml").read_text(encoding="utf-8")

        install_link = Path(tmp_home) / ".local" / "bin" / "codex-master-mcp"
        self.assertEqual(result, 0)
        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(payload.get("install_path"), "not_returned")
        self.assertEqual(payload.get("install_path_state"), "set")
        self.assertEqual(payload.get("install_path_kind"), "configured_install_path")
        self.assertEqual(payload.get("target"), "not_returned")
        self.assertEqual(payload.get("target_state"), "repo_wrapper")
        self.assertEqual(payload.get("symlink"), "created")
        self.assertEqual(payload["mcp"]["requested"], True)
        self.assertEqual(payload["mcp"]["status"], "registered")
        self.assertEqual(payload["mcp"]["startup_timeout"]["status"], "updated")
        self.assertEqual(payload["mcp"]["startup_timeout"]["startup_timeout_sec"], 120)
        self.assertEqual(payload["mcp"]["startup_timeout"]["config_path"], "not_returned")
        self.assertTrue(payload["startup_self_test"]["ok"])
        self.assertEqual(payload["startup_self_test"]["raw_output"], "not_returned")
        self.assertTrue(payload["plugin_cache_install"]["ok"])
        self.assertEqual(payload["plugin_cache_install"]["status"], "synced")
        self.assertEqual(payload["plugin_cache_install"]["cache_entry"], "not_returned")
        self.assertEqual(payload["plugin_cache_install"]["plugin_cache"]["path"], "not_returned")
        self.assertIn("startup_timeout_sec = 120", config_content)
        self.assertTrue(link_created)
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn(str(install_link), payload_text)
        self.assertNotIn(str(Path(__file__).resolve().parents[1] / "bin" / "codex-master-mcp"), payload_text)
        self.assertNotIn(str(Path(tmp_home)), payload_text)
        mock_run.assert_any_call(["codex", "mcp", "add", "codex-master-mcp", "--", str(install_link)])

    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_refuses_failed_startup_self_test_before_writing_link(
        self, mock_wrapper_path, mock_self_test
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            install_link = tmp_path / "bin" / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            mock_wrapper_path.return_value = wrapper
            mock_self_test.return_value = {"ok": False, "status": "failed", "raw_output": "not_returned"}

            with self.assertRaisesRegex(AgentError, "startup self-test"):
                install(register=True, install_path=install_link)
            link_exists = install_link.exists() or install_link.is_symlink()

        self.assertFalse(link_exists)

    @patch("codex_master.server.check_mcp_registration")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_self_tests_installed_path_before_registration(
        self, mock_wrapper_path, mock_self_test, mock_registration
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            install_link = tmp_path / "bin" / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            mock_wrapper_path.return_value = wrapper
            mock_self_test.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
            mock_registration.return_value = {"registered": True, "ok": True, "startup_timeout_ok": True}

            install(register=True, install_path=install_link, sync_plugin_cache=False)

        self.assertEqual(mock_self_test.call_args_list[0].args[0], wrapper)
        self.assertEqual(mock_self_test.call_args_list[1].args[0], install_link)

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_is_data_sparse(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["codex-master-mcp"],
            0,
            (
                'Content-Length: 181\r\n\r\n{"jsonrpc":"2.0","id":1,'
                '"result":{"protocolVersion":"2024-11-05","capabilities":{},'
                '"serverInfo":{"name":"codex-master-mcp"}}} SECRET'
            ),
            "",
        )

        result = mcp_command_startup_self_test(Path("/tmp/codex-master-mcp"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET", json.dumps(result, sort_keys=True))
        self.assertEqual(mock_run.call_args.kwargs["timeout"], DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS)

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_handles_missing_command(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("SECRET_PATH_SHOULD_NOT_RETURN")

        result = mcp_command_startup_self_test(Path("/tmp/missing-codex-master-mcp"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET_PATH_SHOULD_NOT_RETURN", json.dumps(result, sort_keys=True))

    def test_mcp_probe_response_requires_json_rpc_server_info(self) -> None:
        self.assertTrue(
            mcp_probe_response_ok(
                'Content-Length: 181\r\n\r\n{"jsonrpc":"2.0","id":1,'
                '"result":{"protocolVersion":"2024-11-05","capabilities":{},'
                '"serverInfo":{"name":"codex-master-mcp"}}}'
            )
        )
        self.assertFalse(mcp_probe_response_ok('codex-master-mcp finished with "id":1 but no JSON-RPC response'))
        self.assertFalse(
            mcp_probe_response_ok(
                '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"codex-master-mcp"}}}'
            )
        )

    @patch("codex_master.server.run_command")
    def test_installed_source_worktree_state_warns_without_paths(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["git", "status", "--porcelain=v1"],
            0,
            " M src/codex_master/server.py\n?? SECRET_PATH_SHOULD_NOT_RETURN\n",
            "",
        )

        wrapper = Path("/tmp/repo/bin/codex-master-mcp")
        result = installed_source_worktree_state(wrapper, wrapper)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "dirty")
        self.assertEqual(result["severity"], "warning")
        self.assertEqual(result["tracked_change_count"], 1)
        self.assertEqual(result["untracked_count"], 1)
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET_PATH_SHOULD_NOT_RETURN", json.dumps(result, sort_keys=True))

    def test_install_refuses_master_registration_inside_managed_agent_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            install_link = tmp_path / "bin" / "codex-master-mcp"
            agent_home = tmp_path / "agent-a-home"
            agents = {
                "a": {"label": "A", "runner": tmp_path / "a-runner", "home": agent_home, "session": "session-a"},
                "b": {
                    "label": "B",
                    "runner": tmp_path / "b-runner",
                    "home": tmp_path / "agent-b-home",
                    "session": "session-b",
                },
            }
            with patch.dict("os.environ", {"HOME": str(tmp_path), "CODEX_HOME": str(agent_home)}), patch.dict(
                "codex_master.server.AGENTS", agents, clear=True
            ):
                with self.assertRaisesRegex(AgentError, "managed Agentin home"):
                    install(register=True, install_path=install_link)
            link_exists = install_link.exists() or install_link.is_symlink()

        self.assertFalse(link_exists)

    @patch("codex_master.server.print_json")
    def test_cli_uninstall_plans_expected_local_unregister_flow(self, mock_print_json) -> None:
        captured_payloads = []

        def _capture(payload):
            captured_payloads.append(payload)
            return 0

        mock_print_json.side_effect = _capture
        with tempfile.TemporaryDirectory() as tmp_home:
            wrapper = Path(__file__).resolve().parents[1] / "bin" / "codex-master-mcp"
            install_link = Path(tmp_home) / ".local" / "bin" / "codex-master-mcp"
            install_link.parent.mkdir(parents=True, exist_ok=True)
            install_link.symlink_to(wrapper)
            with patch.dict("os.environ", {"HOME": tmp_home}):
                result = main_cli(
                    ["uninstall", "--remove-symlink", "--keep-registration", "--path", str(install_link)]
                )

        self.assertEqual(result, 0)
        self.assertFalse(install_link.exists())
        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(payload.get("symlink"), "removed")
        self.assertEqual(payload.get("mcp"), "skipped")

    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_refuses_symlink_parent_without_writing_redirected_path(self, mock_wrapper_path, _mock_registration) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            real_bin = tmp_path / "real-bin"
            link_bin = tmp_path / "link-bin"
            redirected = real_bin / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            real_bin.mkdir()
            link_bin.symlink_to(real_bin, target_is_directory=True)
            mock_wrapper_path.return_value = wrapper

            with self.assertRaisesRegex(AgentError, "install parent directories must be real directories") as raised:
                install_path = link_bin / "codex-master-mcp"
                from codex_master.server import install

                install(register=False, install_path=install_path)

            redirected_exists = redirected.exists() or redirected.is_symlink()

        self.assertFalse(redirected_exists)
        self.assertNotIn(str(link_bin), str(raised.exception))
        self.assertNotIn(str(real_bin), str(raised.exception))

    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_handles_install_path_symlink_loop_without_crashing(
        self, mock_wrapper_path, _mock_registration
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            install_link = tmp_path / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            install_link.symlink_to(install_link)
            mock_wrapper_path.return_value = wrapper

            with self.assertRaisesRegex(AgentError, "install path exists and is not this wrapper symlink"):
                install(register=False, install_path=install_link)

            still_symlink = install_link.is_symlink()

        self.assertTrue(still_symlink)

    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.repo_wrapper_path")
    @patch("codex_master.server.ensure_directory_chain_no_symlink")
    def test_install_refuses_parent_swap_after_validation_without_redirecting(
        self, mock_ensure_chain, mock_wrapper_path, _mock_registration
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            real_bin = tmp_path / "real-bin"
            link_bin = tmp_path / "link-bin"
            redirected = real_bin / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            real_bin.mkdir()
            link_bin.mkdir()
            mock_wrapper_path.return_value = wrapper

            def swap_parent(path, _error_text):
                if Path(path) == link_bin:
                    link_bin.rmdir()
                    link_bin.symlink_to(real_bin, target_is_directory=True)

            mock_ensure_chain.side_effect = swap_parent

            with self.assertRaisesRegex(AgentError, "could_not_write_install_symlink") as raised:
                install(register=False, force=True, install_path=link_bin / "codex-master-mcp", sync_plugin_cache=False)

            redirected_exists = redirected.exists() or redirected.is_symlink()

        self.assertFalse(redirected_exists)
        self.assertNotIn(str(link_bin), str(raised.exception))
        self.assertNotIn(str(real_bin), str(raised.exception))

    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_force_replaces_mismatched_symlink_atomically(
        self, mock_wrapper_path, _mock_registration
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            other = tmp_path / "other-wrapper"
            install_link = tmp_path / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            other.write_text("#!/bin/sh\n", encoding="utf-8")
            install_link.symlink_to(other)
            mock_wrapper_path.return_value = wrapper

            result = install(register=False, force=True, install_path=install_link, sync_plugin_cache=False)
            resolved = install_link.resolve(strict=False)
            tmp_links = list(tmp_path.glob(".codex-master-mcp.tmp.*"))

        self.assertEqual(result["symlink"], "replaced")
        self.assertEqual(result["install_path"], "not_returned")
        self.assertEqual(resolved, wrapper)
        self.assertEqual(tmp_links, [])

    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.repo_wrapper_path")
    def test_uninstall_refuses_symlink_parent_without_removing_redirected_link(
        self, mock_wrapper_path, _mock_registration
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            real_bin = tmp_path / "real-bin"
            link_bin = tmp_path / "link-bin"
            redirected = real_bin / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            real_bin.mkdir()
            redirected.symlink_to(wrapper)
            link_bin.symlink_to(real_bin, target_is_directory=True)
            mock_wrapper_path.return_value = wrapper

            with self.assertRaisesRegex(AgentError, "install parent directories must be real directories") as raised:
                from codex_master.server import uninstall

                uninstall(unregister=False, remove_symlink=True, install_path=link_bin / "codex-master-mcp")

            redirected_is_symlink = redirected.is_symlink()

        self.assertTrue(redirected_is_symlink)
        self.assertNotIn(str(link_bin), str(raised.exception))
        self.assertNotIn(str(real_bin), str(raised.exception))

    @patch("codex_master.server.repo_wrapper_path")
    @patch("codex_master.server.ensure_directory_chain_no_symlink")
    def test_uninstall_refuses_parent_swap_after_validation_without_removing_redirected_link(
        self, mock_ensure_chain, mock_wrapper_path
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            real_bin = tmp_path / "real-bin"
            link_bin = tmp_path / "link-bin"
            redirected = real_bin / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            real_bin.mkdir()
            redirected.symlink_to(wrapper)
            link_bin.mkdir()
            mock_wrapper_path.return_value = wrapper

            def swap_parent(path, _error_text):
                if Path(path) == link_bin:
                    link_bin.rmdir()
                    link_bin.symlink_to(real_bin, target_is_directory=True)

            mock_ensure_chain.side_effect = swap_parent

            with self.assertRaisesRegex(AgentError, "could_not_remove_install_symlink") as raised:
                uninstall(unregister=False, remove_symlink=True, install_path=link_bin / "codex-master-mcp")

            redirected_is_symlink = redirected.is_symlink()

        self.assertTrue(redirected_is_symlink)
        self.assertNotIn(str(link_bin), str(raised.exception))
        self.assertNotIn(str(real_bin), str(raised.exception))

    @patch("codex_master.server.repo_wrapper_path")
    def test_uninstall_leaves_install_path_symlink_loop_without_crashing(self, mock_wrapper_path) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            install_link = tmp_path / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            install_link.symlink_to(install_link)
            mock_wrapper_path.return_value = wrapper

            result = uninstall(unregister=False, remove_symlink=True, install_path=install_link)
            still_symlink = install_link.is_symlink()

        self.assertEqual(result["symlink"], "left_in_place_not_repo_wrapper")
        self.assertTrue(still_symlink)

    @patch("codex_master.server.agent_home_process_summary")
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.shutil.which")
    @patch("codex_master.server.repo_wrapper_path")
    def test_doctor_reports_unreadable_install_symlink_loop_without_crashing(
        self,
        mock_wrapper_path,
        mock_shutil_which,
        _mock_check_mcp_registration,
        _mock_tmux_alive,
        mock_agent_home_process_summary,
    ) -> None:
        mock_shutil_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd in {"codex", "tmux"} else None

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "wrapper"
            install_link = tmp_path / "codex-master-mcp"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            install_link.symlink_to(install_link)
            mock_wrapper_path.return_value = wrapper
            mock_agent_home_process_summary.side_effect = lambda agent: {
                "home": agent,
                "external_process_count": 0,
                "external_processes": [],
                "external_processes_truncated": False,
            }

            agents = {
                "a": {"label": "A", "runner": tmp_path / "a-runner", "home": tmp_path / "a", "session": "session-a"},
                "b": {"label": "B", "runner": tmp_path / "b-runner", "home": tmp_path / "b", "session": "session-b"},
            }
            for cfg in agents.values():
                cfg["runner"].write_text("#!/bin/sh\n", encoding="utf-8")
                cfg["runner"].chmod(cfg["runner"].stat().st_mode | stat.S_IXUSR)
                cfg["home"].mkdir()

            with patch("codex_master.server.DEFAULT_INSTALL_PATH", install_link), patch.dict(
                "codex_master.server.AGENTS", agents, clear=True
            ), patch("codex_master.server.STATE_ROOT", tmp_path / "state"), patch(
                "codex_master.server.RAW_DIR", tmp_path / "state" / "raw"
            ), patch(
                "codex_master.server.META_DIR", tmp_path / "state" / "meta"
            ), patch("codex_master.server.LEGACY_STATE_ROOT", tmp_path / "legacy-state"), patch(
                "codex_master.server.LEGACY_META_DIR", tmp_path / "legacy-state" / "meta"
            ):
                result = doctor()

        installed = next(item for item in result["checks"] if item["name"] == "installed_symlink")
        self.assertFalse(installed["ok"])
        self.assertEqual(installed["path"], "not_returned")
        self.assertEqual(installed["target"], "<unreadable>")
        self.assertEqual(installed["target_state"], "unreadable")
        self.assertNotIn(str(install_link), json.dumps(result, sort_keys=True))

    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.check_mcp_registration", return_value={"registered": False, "ok": False})
    @patch("codex_master.server.shutil.which")
    @patch("codex_master.server.print_json")
    def test_cli_doctor_exposes_health_checks_without_secrets(
        self, mock_print_json, mock_shutil_which, mock_check_mcp_registration, _mock_tmux_alive
    ) -> None:
        captured_payloads = []

        def _capture(payload):
            captured_payloads.append(payload)
            return 0

        mock_print_json.side_effect = _capture
        mock_shutil_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd in {"codex", "tmux"} else None

        with tempfile.TemporaryDirectory() as tmp_home:
            with patch.dict(
                "os.environ",
                {
                    "HOME": tmp_home,
                    "OPENAI_API_KEY": "sk-doctor-test-secret",
                    "OPENAI_ACCESS_TOKEN": "sess-doctor-test",
                },
            ):
                with patch.dict(
                    "codex_master.server.AGENTS",
                    {
                        "a": {"label": "A", "runner": Path(tmp_home) / "a-runner", "home": Path(tmp_home) / "a", "session": "session-a"},
                        "b": {"label": "B", "runner": Path(tmp_home) / "b-runner", "home": Path(tmp_home) / "b", "session": "session-b"},
                    },
                    clear=False,
                ):
                    (Path(tmp_home) / "a-runner").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
                    (Path(tmp_home) / "a").mkdir(parents=True)
                    (Path(tmp_home) / "b-runner").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
                    (Path(tmp_home) / "b").mkdir(parents=True)
                    with patch("codex_master.server.STATE_ROOT", Path(tmp_home) / "state"), patch(
                        "codex_master.server.RAW_DIR", Path(tmp_home) / "state" / "raw"
                    ), patch(
                        "codex_master.server.META_DIR", Path(tmp_home) / "state" / "meta"
                    ), patch("codex_master.server.LEGACY_STATE_ROOT", Path(tmp_home) / "legacy-state"), patch(
                        "codex_master.server.LEGACY_META_DIR", Path(tmp_home) / "legacy-state" / "meta"
                    ):
                        result = main_cli(["doctor"])

        self.assertEqual(result, 0)
        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertIn("checks", payload)
        self.assertIsInstance(payload["checks"], list)
        self.assertTrue(all(isinstance(item, dict) for item in payload["checks"]))
        self.assertFalse(payload["ok"])
        self.assertTrue(any(item["name"] == "tmux_available" and item["ok"] is True for item in payload["checks"]))
        self.assertTrue(any(item["name"] == "codex_available" and item["ok"] is True for item in payload["checks"]))
        self.assertTrue(any(item["name"] == "mcp_registered" for item in payload["checks"]))
        self.assertFalse(next(item for item in payload["checks"] if item["name"] == "mcp_registered")["ok"])
        startup_timeout = next(item for item in payload["checks"] if item["name"] == "mcp_startup_timeout_configured")
        self.assertFalse(startup_timeout["ok"])
        self.assertEqual(startup_timeout["recommended_sec"], 120)
        home_context = next(item for item in payload["checks"] if item["name"] == "codex_home_context")
        self.assertTrue(home_context["ok"])
        self.assertEqual(home_context["home_kind"], "main_default_home")
        self.assertEqual(home_context["active_home_path"], "not_returned")
        session_state = next(item for item in payload["checks"] if item["name"] == "agent_a_tmux_session_state")
        self.assertTrue(session_state["ok"])
        self.assertFalse(session_state["running"])
        self.assertEqual(session_state["severity"], "info")
        runner_check = next(item for item in payload["checks"] if item["name"] == "agent_a_runner_executable")
        self.assertFalse(runner_check["ok"])
        self.assertFalse(runner_check["symlink_allowed"])
        self.assertEqual(runner_check["path"], "not_returned")
        retention = next(item for item in payload["checks"] if item["name"] == "raw_log_retention_configured")
        self.assertEqual(retention["max_bytes_per_file"], MAX_RAW_LOG_BYTES)
        self.assertEqual(retention["managed_dirs"], "not_returned")
        self.assertEqual(retention["raw_output"], "not_returned")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("sk-doctor-test-secret", payload_text)
        self.assertNotIn("sess-doctor-test", payload_text)
        self.assertNotIn(str(Path(tmp_home) / "a-runner"), payload_text)
        self.assertNotIn(str(Path(tmp_home) / "a"), payload_text)

if __name__ == "__main__":
    unittest.main()
