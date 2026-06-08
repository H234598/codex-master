import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
import os
from typing import Any
from unittest.mock import Mock, patch

from codex_master.server import (
    AgentError,
    AgentBusyError,
    AgentInputNotReadyError,
    DEFAULT_CLAIM_WAIT_FOREVER,
    DEFAULT_AGENT_LEASE_SECONDS,
    DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
    MAX_ASSIGNMENT_LIST_ITEMS,
    MAX_ASSIGNMENT_LOG_BYTES,
    MAX_ASSIGNMENT_RECORDS,
    MAX_CAPABILITY_PLUGINS,
    MAX_ERROR_CHARS,
    MAX_GIT_REF_TEXT,
    MAX_LIVE_DATA_TOPIC,
    MAX_META_BYTES,
    MAX_RPC_MESSAGE_BYTES,
    MAX_RAW_LOG_BYTES,
    MAX_SEND_TEXT,
    MAX_TAIL_CHARS,
    MAX_TAIL_LINES,
    MAX_SKILL_NAMES,
    MAX_TASK_TEXT,
    MAX_WAIT_POLL_SECONDS,
    MAX_WAIT_SECONDS,
    MAX_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
    RAW_LOG_TRUNCATION_MARKER,
    BRACKETED_PASTE_BEGIN,
    BRACKETED_PASTE_END,
    CODEX_TUI_SUBMIT_KEY,
    COMMAND_TIMEOUT_RETURN_CODE,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS,
    DEFAULT_SEND_READY_TIMEOUT_SECONDS,
    DEFAULT_WAIT_POLL_SECONDS,
    DEFAULT_WAIT_SECONDS,
    DEFAULT_WATCHDOG_IDLE_SECONDS,
    DEFAULT_WATCHDOG_POLL_SECONDS,
    DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS,
    DEFAULT_TMUX_TIMEOUT_SECONDS,
    SEND_READY_POLL_SECONDS,
    agent_ids,
    allowed_raw_log_path,
    append_bounded_raw_log,
    agent_lifecycle_lock,
    agent_identity_guard,
    agent_home_process_summary,
    check_mcp_registration,
    call_tool,
    claim_agent,
    claim_agent_with_wait,
    classify_limit_text,
    classify_tui_context,
    codex_related_process_summary,
    DEFAULT_AGENT_MODEL,
    DEFAULT_ORDINAL_AGENT_SERIES,
    doctor,
    ensure_state,
    handle_rpc,
    install,
    installed_source_worktree_state,
    agent_lease_status,
    agent_auth_status,
    interrupt_agent,
    mcp_command_startup_self_test,
    mcp_probe_response_ok,
    mcp_registration_command_matches,
    master_app_bridge_status,
    main_cli,
    master_timeout_policy,
    master_watchdog_status,
    list_assignments,
    prune_raw_logs,
    raw_log_retention_status,
    read_message,
    read_meta,
    safe_tail,
    same_path_text,
    skills_agent,
    record_assignment,
    redact,
    paged_mapping,
    release_agent,
    replace_private_text,
    resolve_path_no_throw,
    run_command,
    run_tmux,
    send_agent,
    server_instance_identity_status,
    selector_policy_series,
    selector_policy_status,
    start_agent,
    start_agent_with_lease,
    stop_agent,
    strip_ansi,
    skill_match_agent,
    sync_plugin_cache_from_repo,
    trim_chars,
    trim_lines,
    tui_accepts_input,
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
    default_server_instance_id,
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

    def test_tui_accepts_input_requires_visible_tail_prompt_marker_line(self) -> None:
        self.assertTrue(tui_accepts_input("some status\n› Ready"))
        self.assertTrue(tui_accepts_input("\x1b[32m›\x1b[0m Ready"))
        self.assertFalse(tui_accepts_input("assistant output used › as punctuation\nno prompt"))
        self.assertFalse(tui_accepts_input("Find and fix a bug in @filename\nImprove documentation in @filename"))
        old_prompt = "› old prompt\n" + "\n".join(f"line {index}" for index in range(9))
        self.assertFalse(tui_accepts_input(old_prompt))

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
        self.assertIn("agent_assign_live_data", names)
        self.assertIn("agent_assign_write", names)
        self.assertIn("agent_selector_policy", names)
        self.assertIn("agent_selector_preview", names)
        self.assertIn("worktree_status", names)
        self.assertIn("commit_ready_check", names)
        self.assertIn("master_app_bridge_status", names)
        self.assertIn("master_plugin_status", names)
        self.assertIn("master_namespace_status", names)
        self.assertIn("master_release_status", names)
        self.assertIn("master_watchdog_status", names)
        self.assertIn("master_timeout_policy", names)
        by_name = {tool["name"]: tool for tool in response["result"]["tools"]}
        assign_props = by_name["agent_assign"]["inputSchema"]["properties"]
        claim_props = by_name["agent_claim"]["inputSchema"]["properties"]
        start_props = by_name["agent_start"]["inputSchema"]["properties"]
        send_props = by_name["agent_send"]["inputSchema"]["properties"]
        report_props = by_name["agent_report_request"]["inputSchema"]["properties"]
        wait_props = by_name["agent_wait"]["inputSchema"]["properties"]
        watchdog_props = by_name["fleet_watchdog"]["inputSchema"]["properties"]
        assign_write_props = by_name["agent_assign_write"]["inputSchema"]["properties"]
        assign_readonly_props = by_name["agent_assign_readonly"]["inputSchema"]["properties"]
        assign_live_data_props = by_name["agent_assign_live_data"]["inputSchema"]["properties"]
        selector_policy_props = by_name["agent_selector_policy"]["inputSchema"]["properties"]
        worktree_create_props = by_name["worktree_create_for_agent"]["inputSchema"]["properties"]
        skill_props = by_name["agent_skills"]["inputSchema"]["properties"]
        tail_description = by_name["agent_safe_tail"]["description"]
        self.assertIn("held by other clients", tail_description)
        self.assertIn("before reading pane or log output", tail_description)
        self.assertEqual(assign_props["task"]["maxLength"], MAX_TASK_TEXT)
        self.assertEqual(assign_props["context"]["maxItems"], MAX_ASSIGNMENT_LIST_ITEMS)
        self.assertEqual(worktree_create_props["base_ref"]["maxLength"], MAX_GIT_REF_TEXT)
        self.assertEqual(DEFAULT_WAIT_SECONDS, 120)
        self.assertEqual(MAX_WAIT_SECONDS, 600)
        self.assertEqual(DEFAULT_WAIT_POLL_SECONDS, 30)
        self.assertEqual(MAX_WAIT_POLL_SECONDS, 900)
        self.assertEqual(wait_props["timeout_seconds"]["default"], DEFAULT_WAIT_SECONDS)
        self.assertEqual(wait_props["timeout_seconds"]["maximum"], MAX_WAIT_SECONDS)
        self.assertEqual(wait_props["poll_interval_seconds"]["default"], DEFAULT_WAIT_POLL_SECONDS)
        self.assertEqual(wait_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertEqual(DEFAULT_CLAIM_WAIT_FOREVER, True)
        self.assertNotIn("maximum", claim_props["wait_seconds"])
        self.assertEqual(claim_props["wait_forever"]["default"], DEFAULT_CLAIM_WAIT_FOREVER)
        self.assertEqual(claim_props["poll_interval_seconds"]["default"], DEFAULT_WAIT_POLL_SECONDS)
        self.assertEqual(claim_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertTrue(claim_props["recover_stopped"]["default"])
        self.assertEqual(claim_props["stopped_grace_seconds"]["default"], DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS)
        self.assertEqual(claim_props["stopped_grace_seconds"]["maximum"], MAX_STOPPED_LEASE_RECOVERY_GRACE_SECONDS)
        self.assertFalse(start_props["allow_unauthenticated"]["default"])
        self.assertFalse(send_props["allow_unauthenticated"]["default"])
        self.assertFalse(claim_props["allow_unauthenticated"]["default"])
        self.assertFalse(assign_props["allow_unauthenticated"]["default"])
        self.assertFalse(assign_readonly_props["allow_unauthenticated"]["default"])
        self.assertFalse(assign_live_data_props["allow_unauthenticated"]["default"])
        self.assertFalse(assign_write_props["allow_unauthenticated"]["default"])
        self.assertFalse(report_props["allow_unauthenticated"]["default"])
        self.assertEqual(assign_live_data_props["live_data_topic"]["maxLength"], MAX_LIVE_DATA_TOPIC)
        self.assertEqual(selector_policy_props["series"]["maxLength"], 32)
        self.assertEqual(DEFAULT_WATCHDOG_IDLE_SECONDS, 60)
        self.assertEqual(DEFAULT_WATCHDOG_POLL_SECONDS, 15)
        self.assertEqual(DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS, 15)
        self.assertEqual(watchdog_props["idle_seconds"]["default"], DEFAULT_WATCHDOG_IDLE_SECONDS)
        self.assertEqual(watchdog_props["poll_interval_seconds"]["default"], DEFAULT_WATCHDOG_POLL_SECONDS)
        self.assertEqual(watchdog_props["poll_interval_seconds"]["maximum"], MAX_WAIT_POLL_SECONDS)
        self.assertEqual(watchdog_props["report_grace_seconds"]["default"], DEFAULT_WATCHDOG_REPORT_GRACE_SECONDS)
        self.assertEqual(assign_write_props["write_paths"]["minItems"], 1)
        self.assertEqual(send_props["text"]["maxLength"], MAX_SEND_TEXT)
        self.assertEqual(skill_props["limit"]["maximum"], MAX_SKILL_NAMES)
        self.assertEqual(start_props["agent"]["default"], "both")
        self.assertEqual(by_name["agent_status"]["inputSchema"]["properties"]["agent"]["default"], "all")
        self.assertEqual(start_props["agent"]["maxLength"], 32)
        self.assertNotIn("enum", start_props["agent"])
        self.assertEqual(skill_props["names_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_limit"]["default"], MAX_CAPABILITY_PLUGINS)
        self.assertEqual(skill_props["plugins_limit"]["maximum"], MAX_SKILL_NAMES)

    def test_agent_selectors_scale_to_series_pool_with_legacy_aliases(self) -> None:
        self.assertEqual(agent_ids("a"), ["a1"])
        self.assertEqual(agent_ids("A"), ["a1"])
        self.assertEqual(agent_ids("A1"), ["a1"])
        self.assertEqual(agent_ids("b"), ["b1"])
        self.assertEqual(agent_ids("both"), ["a1", "b1"])
        self.assertEqual(agent_ids("a-series")[0], "a1")
        self.assertEqual(agent_ids("A-Series")[0], "a1")
        self.assertEqual(agent_ids("a-series")[-1], "a100")
        self.assertEqual(len(agent_ids("a-series")), 100)
        self.assertEqual(len(agent_ids("all")), 300)
        self.assertEqual(agent_ids("1"), ["a1"])
        self.assertEqual(agent_ids("2"), ["b1"])
        self.assertEqual(agent_ids("3"), ["a2"])
        self.assertEqual(agent_ids("4"), ["b2"])
        self.assertEqual(agent_ids("200"), ["b100"])

    def test_agent_selector_policy_can_switch_ordinal_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            with patch.dict("os.environ", {}, clear=True), patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch(
                "codex_master.server.SELECTOR_POLICY_FILE", state / "selector-policy.json"
            ):
                default_status = selector_policy_status()
                preview = call_tool("agent_selector_preview", {"series": "A,B,C", "limit": 6})
                changed = call_tool("agent_selector_policy", {"series": "A,B,C"})
                persisted_status = call_tool("agent_selector_policy", {})
                selected = [agent_ids(str(index))[0] for index in range(1, 7)]

        self.assertEqual(default_status["series"], list(DEFAULT_ORDINAL_AGENT_SERIES))
        self.assertEqual([item["agent"] for item in preview["ordinal_mapping"]], ["a1", "b1", "c1", "a2", "b2", "c2"])
        self.assertEqual(changed["series"], ["a", "b", "c"])
        self.assertEqual(persisted_status["series"], ["a", "b", "c"])
        self.assertEqual(selected, ["a1", "b1", "c1", "a2", "b2", "c2"])
        self.assertNotIn(tmpdir, json.dumps(changed, sort_keys=True))

    def test_agent_selector_errors_do_not_echo_request_values(self) -> None:
        unknown_agent = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 71,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": "SECRETAGENT"}},
            }
        )
        invalid_series = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 72,
                "method": "tools/call",
                "params": {"name": "agent_selector_preview", "arguments": {"series": "a,SECRET_SERIES"}},
            }
        )
        ordinal_outside_pool = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 73,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": "999999"}},
            }
        )

        self.assertTrue(unknown_agent["result"]["isError"])
        unknown_agent_text = unknown_agent["result"]["content"][0]["text"]
        self.assertIn("unknown agent", unknown_agent_text)
        self.assertNotIn("SECRETAGENT", unknown_agent_text)
        self.assertNotIn("secretagent", unknown_agent_text)

        self.assertTrue(invalid_series["result"]["isError"])
        invalid_series_text = invalid_series["result"]["content"][0]["text"]
        self.assertIn("unknown Agentinnen series", invalid_series_text)
        self.assertNotIn("SECRET_SERIES", invalid_series_text)
        self.assertNotIn("secret_series", invalid_series_text)

        self.assertTrue(ordinal_outside_pool["result"]["isError"])
        ordinal_text = ordinal_outside_pool["result"]["content"][0]["text"]
        self.assertIn("outside the installed Agentinnen pool", ordinal_text)
        self.assertNotIn("999999", ordinal_text)

    def test_agent_auth_status_is_data_sparse_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "home"
            home.mkdir()
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": Path(tmpdir) / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                missing = agent_auth_status("A")
                (home / "auth.json").write_text('{"token":"secret"}\n', encoding="utf-8")
                present = agent_auth_status("a")
                (home / "auth.json").unlink()
                outside = Path(tmpdir) / "outside-auth.json"
                outside.write_text("secret\n", encoding="utf-8")
                (home / "auth.json").symlink_to(outside)
                linked = agent_auth_status("a")

        self.assertFalse(missing["authenticated"])
        self.assertEqual(missing["auth_state"], "missing")
        self.assertTrue(present["authenticated"])
        self.assertEqual(present["auth_state"], "present_regular")
        self.assertFalse(linked["authenticated"])
        self.assertEqual(linked["auth_state"], "symlink_rejected")
        payload = json.dumps({"missing": missing, "present": present, "linked": linked}, sort_keys=True)
        self.assertNotIn(tmpdir, payload)
        self.assertNotIn("secret", payload)

    def test_master_watchdog_status_reports_hardened_systemd_state_without_paths(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        service_text = (source_root / "systemd" / "user" / "codex-master-watchdog.service").read_text(encoding="utf-8")
        timer_text = (source_root / "systemd" / "user" / "codex-master-watchdog.timer").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            systemd_user = Path(tmp) / "systemd-user"
            (root / "systemd" / "user").mkdir(parents=True)
            systemd_user.mkdir()
            (root / "systemd" / "user" / "codex-master-watchdog.service").write_text(service_text, encoding="utf-8")
            (root / "systemd" / "user" / "codex-master-watchdog.timer").write_text(timer_text, encoding="utf-8")
            (systemd_user / "codex-master-watchdog.service").write_text(service_text, encoding="utf-8")
            (systemd_user / "codex-master-watchdog.timer").write_text(timer_text, encoding="utf-8")

            def fake_run(command, *, check=False, cwd=None, env=None, timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS):
                if command[:3] == ["systemctl", "--user", "show"] and command[3] == "codex-master-watchdog.timer":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=(
                            "LoadState=loaded\n"
                            "ActiveState=active\n"
                            "SubState=waiting\n"
                            "Result=success\n"
                            "Unit=codex-master-watchdog.service\n"
                            "NextElapseUSecRealtime=Sun 2026-06-07 19:00:00 CEST\n"
                            "LastTriggerUSec=Sun 2026-06-07 18:45:00 CEST\n"
                        ),
                        stderr="",
                    )
                if command[:3] == ["systemctl", "--user", "show"] and command[3] == "codex-master-watchdog.service":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=(
                            "LoadState=loaded\n"
                            "ActiveState=inactive\n"
                            "SubState=dead\n"
                            "Result=success\n"
                            "ExecMainCode=1\n"
                            "ExecMainStatus=0\n"
                        ),
                        stderr="",
                    )
                if command[:3] == ["systemd-analyze", "--user", "security"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="Overall exposure level for codex-master-watchdog.service: 3.1 OK\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected")

            with patch("codex_master.server.run_command", side_effect=fake_run), patch(
                "codex_master.server.shutil.which", return_value="/usr/bin/systemd-analyze"
            ):
                result = master_watchdog_status(root=root, systemd_user_dir=systemd_user)

        payload = json.dumps(result, sort_keys=True)
        self.assertTrue(result["ok"])
        self.assertTrue(result["checks"]["timer_active"])
        self.assertTrue(result["checks"]["service_last_run_success"])
        self.assertTrue(result["unit_files"]["service"]["hardening_ok"])
        self.assertTrue(result["unit_files"]["service"]["matches_repo"])
        self.assertTrue(result["unit_files"]["timer"]["matches_repo"])
        self.assertEqual(result["security"]["exposure_score"], 3.1)
        self.assertEqual(result["security"]["exposure_level"], "OK")
        self.assertIn('"raw_output": "not_returned"', payload)
        self.assertNotIn(tmp, payload)
        self.assertNotIn(str(root), payload)
        self.assertNotIn(str(systemd_user), payload)

    def test_master_watchdog_status_detects_missing_hardening_directive(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        service_text = (source_root / "systemd" / "user" / "codex-master-watchdog.service").read_text(encoding="utf-8")
        timer_text = (source_root / "systemd" / "user" / "codex-master-watchdog.timer").read_text(encoding="utf-8")
        weakened_service = service_text.replace("IPAddressDeny=any\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            systemd_user = Path(tmp) / "systemd-user"
            (root / "systemd" / "user").mkdir(parents=True)
            systemd_user.mkdir()
            (root / "systemd" / "user" / "codex-master-watchdog.service").write_text(service_text, encoding="utf-8")
            (root / "systemd" / "user" / "codex-master-watchdog.timer").write_text(timer_text, encoding="utf-8")
            (systemd_user / "codex-master-watchdog.service").write_text(weakened_service, encoding="utf-8")
            (systemd_user / "codex-master-watchdog.timer").write_text(timer_text, encoding="utf-8")

            def fake_run(command, *, check=False, cwd=None, env=None, timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS):
                if command[:3] == ["systemctl", "--user", "show"] and command[3] == "codex-master-watchdog.timer":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="LoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n",
                        stderr="",
                    )
                if command[:3] == ["systemctl", "--user", "show"] and command[3] == "codex-master-watchdog.service":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\n",
                        stderr="",
                    )
                if command[:3] == ["systemd-analyze", "--user", "security"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="Overall exposure level for codex-master-watchdog.service: 3.1 OK\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected")

            with patch("codex_master.server.run_command", side_effect=fake_run), patch(
                "codex_master.server.shutil.which", return_value="/usr/bin/systemd-analyze"
            ):
                result = master_watchdog_status(root=root, systemd_user_dir=systemd_user)

        payload = json.dumps(result, sort_keys=True)
        self.assertFalse(result["ok"])
        self.assertFalse(result["unit_files"]["service"]["hardening_ok"])
        self.assertFalse(result["unit_files"]["service"]["hardening_directives"]["IPAddressDeny=any"])
        self.assertFalse(result["unit_files"]["service"]["matches_repo"])
        self.assertNotIn(tmp, payload)

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
            (root / "docs").mkdir()
            (root / "examples").mkdir()
            (root / "schemas").mkdir()
            (root / "scripts").mkdir()
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
            (root / "codex-agent-pool.json").write_text("{}", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='codex-master'\n", encoding="utf-8")
            bin_wrapper = root / "bin" / "codex-master-mcp"
            bin_wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            bin_wrapper.chmod(bin_wrapper.stat().st_mode | stat.S_IXUSR)
            (root / "docs" / "agent-pool.md").write_text("doc", encoding="utf-8")
            (root / "examples" / "codex-agent-pool.json").write_text("{}", encoding="utf-8")
            (root / "schemas" / "codex-agent-pool.schema.json").write_text("{}", encoding="utf-8")
            (root / "scripts" / "install-agent-pool").write_text("#!/bin/sh\n", encoding="utf-8")
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
                "pool_spec": (entry / "codex-agent-pool.json").exists(),
                "bin": (entry / "bin" / "codex-master-mcp").exists(),
                "bin_executable": os.access(entry / "bin" / "codex-master-mcp", os.X_OK),
                "docs": (entry / "docs" / "agent-pool.md").exists(),
                "examples": (entry / "examples" / "codex-agent-pool.json").exists(),
                "schemas": (entry / "schemas" / "codex-agent-pool.schema.json").exists(),
                "scripts": (entry / "scripts" / "install-agent-pool").exists(),
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
        self.assertTrue(copied_state["pool_spec"])
        self.assertTrue(copied_state["bin"])
        self.assertTrue(copied_state["bin_executable"])
        self.assertTrue(copied_state["docs"])
        self.assertTrue(copied_state["examples"])
        self.assertTrue(copied_state["schemas"])
        self.assertTrue(copied_state["scripts"])
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
        encoded = json.dumps(payload, separators=(",", ":"))
        output = f"Content-Length: {len(encoded)}\r\n\r\n{encoded}"

        result = mcp_tools_list_probe_result(output, "master_app_bridge_status")

        self.assertTrue(result["response_found"])
        self.assertEqual(result["tool_count"], 2)
        self.assertTrue(result["required_tool_available"])
        self.assertNotIn("agent_status", json.dumps(result, sort_keys=True))

    def test_mcp_tools_list_probe_result_rejects_embedded_json(self) -> None:
        output = (
            'Content-Length: 123\r\n\r\n{"jsonrpc":"2.0","id":2,'
            '"result":{"tools":[{"name":"master_app_bridge_status"}]}} SECRET'
        )
        result = mcp_tools_list_probe_result(output, "master_app_bridge_status")

        self.assertFalse(result["response_found"])
        self.assertEqual(result["required_tool_available"], False)

    def test_mcp_tools_list_probe_result_rejects_non_object_json_line(self) -> None:
        output = '["not-a-json-rpc-message"]\n{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"master_app_bridge_status"}]}}'

        result = mcp_tools_list_probe_result(output, "master_app_bridge_status")

        self.assertFalse(result["response_found"])
        self.assertFalse(result["required_tool_available"])

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

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_tools_list_self_test_accepts_content_length_frames(self, mock_run) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "master_app_bridge_status"}]},
        }
        encoded = json.dumps(payload, separators=(",", ":"))
        mock_run.return_value = subprocess.CompletedProcess(
            ["/tmp/codex-master-mcp"],
            0,
            f"Content-Length: {len(encoded)}\r\n\r\n{encoded}",
            "",
        )

        result = mcp_command_tools_list_self_test(Path("/tmp/codex-master-mcp"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["tool_count"], 1)
        self.assertTrue(result["required_tool_available"])

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_tools_list_self_test_rejects_stderr_only_response(self, mock_run) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "master_app_bridge_status"}]},
        }
        encoded = json.dumps(payload, separators=(",", ":"))
        mock_run.return_value = subprocess.CompletedProcess(
            ["/tmp/codex-master-mcp"],
            0,
            "",
            f"Content-Length: {len(encoded)}\r\n\r\n{encoded}",
        )

        result = mcp_command_tools_list_self_test(Path("/tmp/codex-master-mcp"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["tool_count"], 0)
        self.assertFalse(result["required_tool_available"])

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

    def test_codex_related_process_summary_handles_unreadable_proc_root(self) -> None:
        proc_root = Mock(spec=Path)
        proc_root.exists.return_value = True
        proc_root.iterdir.side_effect = PermissionError("denied")

        result = codex_related_process_summary(proc_root)

        self.assertEqual(result["codex_client_process_count"], 0)
        self.assertEqual(result["mcp_server_process_count"], 0)
        self.assertFalse(result["namespace_visibility"]["custom_home_clients_need_own_mcp_config"])
        self.assertFalse(result["namespace_visibility"]["managed_agent_home_clients_expect_no_master_mcp"])
        self.assertFalse(result["namespace_visibility"]["unknown_home_clients_need_manual_check"])
        self.assertEqual(result["namespace_visibility"]["raw_output"], "not_returned")

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
        self.assertTrue(result["expected_tools"]["master_timeout_policy"])
        self.assertTrue(result["expected_tools"]["agent_pool_validate"])
        self.assertTrue(result["expected_tools"]["agent_pool_install"])
        self.assertTrue(result["expected_tools"]["agent_pool_status"])
        self.assertTrue(result["expected_tools"]["agent_pool_copy_auth"])
        self.assertTrue(result["expected_tools"]["agent_pool_destroy_pool"])
        self.assertTrue(result["expected_tools"]["agent_assign_live_data"])
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
            "version": "0.9.22+codex.test",
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
        self.assertEqual(result["expected_tag"], "v0.9.22")
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

    @patch("codex_master.server.codex_client_mcp_config_status")
    def test_master_timeout_policy_reports_unbounded_claim_wait_without_paths(self, mock_client_config) -> None:
        mock_client_config.return_value = {
            "ok": True,
            "server_declared": True,
            "command_configured": True,
            "startup_timeout_ok": True,
            "startup_timeout_sec": 120,
            "raw_output": "not_returned",
        }

        result = master_timeout_policy()

        self.assertTrue(result["ok"])
        self.assertEqual(result["mcp_startup_timeout"]["configured_seconds"], 120)
        self.assertEqual(result["agent_claim_wait"]["default_wait_mode"], "forever")
        self.assertTrue(result["agent_claim_wait"]["default_wait_forever"])
        self.assertFalse(result["agent_claim_wait"]["finite_wait_seconds_has_maximum"])
        self.assertIsNone(result["agent_claim_wait"]["maximum_wait_seconds"])
        self.assertEqual(result["agent_claim_wait"]["default_poll_interval_seconds"], DEFAULT_WAIT_POLL_SECONDS)
        self.assertTrue(result["stopped_lease_recovery"]["default_enabled_for_explicit_claim"])
        self.assertEqual(
            result["stopped_lease_recovery"]["default_grace_seconds"],
            DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
        )
        self.assertEqual(
            result["stopped_lease_recovery"]["maximum_grace_seconds"],
            MAX_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
        )
        self.assertTrue(result["stopped_lease_recovery"]["requires_agent_not_running"])
        self.assertEqual(result["agent_wait"]["maximum_timeout_seconds"], MAX_WAIT_SECONDS)
        self.assertEqual(
            result["send_input_readiness"]["default_timeout_seconds"],
            DEFAULT_SEND_READY_TIMEOUT_SECONDS,
        )
        self.assertEqual(result["send_input_readiness"]["poll_interval_seconds"], SEND_READY_POLL_SECONDS)
        self.assertEqual(
            result["send_input_readiness"]["applies_to"],
            [
                "agent_send",
                "agent_assign",
                "agent_assign_readonly",
                "agent_assign_live_data",
                "agent_assign_write",
                "agent_report_request",
            ],
        )
        self.assertTrue(result["send_input_readiness"]["requires_visible_tui_input_prompt"])
        self.assertEqual(result["send_input_readiness"]["failure_mode"], "fail_closed_without_paste")
        self.assertEqual(result["send_input_readiness"]["raw_output"], "not_returned")
        self.assertEqual(result["server_instance_identity"]["identity"], "not_returned")
        self.assertIn(
            result["server_instance_identity"]["source"],
            {"explicit_env", "codex_thread_id_hash", "process_uuid"},
        )
        self.assertEqual(result["client_config"]["path"], "not_returned")
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

    def test_mcp_error_text_is_data_sparse_and_bounded(self) -> None:
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
        self.assertEqual(payload["error"], "unknown tool")
        self.assertNotIn("sk-testtoken1234567890", payload["error"])
        self.assertNotIn("OPENAI_API_KEY", payload["error"])
        self.assertNotIn("unknown-", payload["error"])
        self.assertLessEqual(len(payload["error"]), MAX_ERROR_CHARS + 40)
        self.assertEqual(method_response["error"]["code"], -32601)
        self.assertEqual(method_response["error"]["message"], "method not found")
        self.assertNotIn("sk-testtoken1234567890", method_response["error"]["message"])
        self.assertNotIn("OPENAI_API_KEY", method_response["error"]["message"])

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

    def test_paged_mapping_rejects_direct_non_integer_inputs(self) -> None:
        with self.assertRaisesRegex(AgentError, "offset must be an integer"):
            paged_mapping({"a": 1}, offset="0", limit=1)
        with self.assertRaisesRegex(AgentError, "offset must be >= 0"):
            paged_mapping({"a": 1}, offset=-1, limit=1)
        with self.assertRaisesRegex(AgentError, "limit must be an integer"):
            paged_mapping({"a": 1}, offset=0, limit=True)

    def test_skills_agent_rejects_non_integer_and_out_of_bounds_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": Path(tmpdir) / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "limit must be an integer"):
                    skills_agent("a", limit="10")
                with self.assertRaisesRegex(AgentError, f"plugins_limit must be <= {MAX_SKILL_NAMES}"):
                    skills_agent("a", plugins_limit=MAX_SKILL_NAMES + 1)
                with self.assertRaisesRegex(AgentError, "names_offset must be >= 0"):
                    skills_agent("a", names_offset=-1)

    def test_skill_match_agent_rejects_invalid_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": Path(tmpdir) / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "limit must be an integer"):
                    skill_match_agent("a", "some-skill", limit="8")
                with self.assertRaisesRegex(AgentError, "limit must be >= 1"):
                    skill_match_agent("a", "some-skill", limit=0)

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
        self.assertEqual(unknown_payload["error"], "unknown argument(s) for agent_status")
        self.assertNotIn("surprise", unknown_payload["error"])
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
        overlong_agent = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 38,
                "method": "tools/call",
                "params": {"name": "agent_status", "arguments": {"agent": "x" * 33}},
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
        empty_write_paths = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "agent_assign_write",
                    "arguments": {"agent": "a", "task": "Fix.", "write_paths": []},
                },
            }
        )

        self.assertTrue(wrong_type["result"]["isError"])
        wrong_type_payload = json.loads(wrong_type["result"]["content"][0]["text"])
        self.assertEqual(wrong_type_payload["error"], "agent must be a string")
        self.assertTrue(overlong_agent["result"]["isError"])
        overlong_agent_payload = json.loads(overlong_agent["result"]["content"][0]["text"])
        self.assertEqual(overlong_agent_payload["error"], "agent must not exceed 32 characters")
        self.assertTrue(over_limit["result"]["isError"])
        over_limit_payload = json.loads(over_limit["result"]["content"][0]["text"])
        self.assertEqual(over_limit_payload["error"], f"limit must be <= {MAX_SKILL_NAMES}")
        self.assertTrue(bad_array["result"]["isError"])
        bad_array_payload = json.loads(bad_array["result"]["content"][0]["text"])
        self.assertEqual(bad_array_payload["error"], "scope must be an array")
        self.assertTrue(empty_write_paths["result"]["isError"])
        empty_write_paths_payload = json.loads(empty_write_paths["result"]["content"][0]["text"])
        self.assertEqual(empty_write_paths_payload["error"], "write_paths must contain at least 1 item(s)")

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
    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_tools_call_limits_and_redacts(
        self, _mock_ensure_state, mock_lease, mock_pane_tail, _mock_tmux_alive
    ) -> None:
        mock_lease.return_value = {"state": "unclaimed", "holder": "none", "raw_output": "not_returned"}
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
        self.assertTrue(payload["output_truncated"])
        self.assertTrue(payload["output_truncated_by_lines"])
        self.assertFalse(payload["output_truncated_by_chars"])
        self.assertEqual(payload["output_chars"], len(payload["output"]))
        self.assertEqual(payload["output_lines"], len(payload["output"].splitlines()))
        self.assertIn("... truncated to last 80 lines ...", payload["output"])
        self.assertNotIn("line-001", payload["output"])
        self.assertNotIn("OPENAI_API_KEY=sk-testtoken1234567890", payload["output"])
        self.assertIn("OPENAI_API_KEY=<redacted>", payload["output"])
        self.assertFalse("\x1b[" in payload["output"])
        self.assertTrue(payload["redaction_applied"])
        self.assertEqual(payload["lease"]["state"], "unclaimed")

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.pane_tail")
    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_tools_call_applies_char_limit(
        self, _mock_ensure_state, mock_lease, mock_pane_tail, _mock_tmux_alive
    ) -> None:
        mock_lease.return_value = {"state": "unclaimed", "holder": "none", "raw_output": "not_returned"}
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
        self.assertTrue(payload["output_truncated"])
        self.assertFalse(payload["output_truncated_by_lines"])
        self.assertTrue(payload["output_truncated_by_chars"])
        self.assertEqual(payload["output_chars"], len(payload["output"]))
        self.assertEqual(payload["output_lines"], len(payload["output"].splitlines()))
        self.assertTrue(payload["output"].startswith("... truncated to last characters ..."))
        self.assertNotIn("sk-verylongtoken01234567890", payload["output"])

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.pane_tail", return_value="")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_direct_calls_reject_invalid_limits(
        self, _mock_ensure_state, _mock_pane_tail, _mock_tmux_alive
    ) -> None:
        with self.assertRaisesRegex(AgentError, "lines must be an integer"):
            safe_tail("a", lines="40", chars=4000)
        with self.assertRaisesRegex(AgentError, "chars must be an integer"):
            safe_tail("a", lines=40, chars=False)
        with self.assertRaisesRegex(AgentError, "lines must be >= 1"):
            safe_tail("a", lines=0, chars=4000)
        with self.assertRaisesRegex(AgentError, f"chars must be <= {MAX_TAIL_CHARS}"):
            safe_tail("a", lines=1, chars=MAX_TAIL_CHARS + 1)

    @patch("codex_master.server.pane_tail")
    def test_safe_tail_blocks_foreign_lease_before_reading_output(self, mock_pane_tail) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    with patch("codex_master.server.ensure_state"), patch(
                        "codex_master.server.read_meta"
                    ) as mock_read_meta:
                        response = handle_rpc(
                            {
                                "jsonrpc": "2.0",
                                "id": 47,
                                "method": "tools/call",
                                "params": {
                                    "name": "agent_safe_tail",
                                    "arguments": {"agent": "a", "source": "pane", "lines": 2, "chars": 4000},
                                },
                            }
                        )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error_code"], "agent_lease_held_by_other_client")
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["lease"]["holder"], "other_server")
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertNotIn("owner-one", json.dumps(payload, sort_keys=True))
        mock_pane_tail.assert_not_called()
        mock_read_meta.assert_not_called()

    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_reads_caps_and_redacts(self, _mock_ensure_state, mock_lease) -> None:
        mock_lease.return_value = {"state": "unclaimed", "holder": "none", "raw_output": "not_returned"}
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
        self.assertTrue(payload["output_truncated"])
        self.assertTrue(payload["output_truncated_by_lines"])
        self.assertFalse(payload["output_truncated_by_chars"])
        self.assertEqual(payload["output_chars"], len(payload["output"]))
        self.assertEqual(payload["output_lines"], len(payload["output"].splitlines()))
        self.assertNotIn("first", payload["output"])
        self.assertNotIn("sk-logtoken1234567890", payload["output"])
        self.assertIn("OPENAI_API_KEY=<redacted>", payload["output"])
        self.assertTrue(payload["redaction_applied"])
        self.assertEqual(payload["raw_log"], "not_returned")
        self.assertNotIn(str(log_path), json.dumps(payload, sort_keys=True))

    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_rejects_unmanaged_meta_path(self, _mock_ensure_state, mock_lease) -> None:
        mock_lease.return_value = {"state": "unclaimed", "holder": "none", "raw_output": "not_returned"}
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

    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.ensure_state")
    def test_safe_tail_log_source_ignores_non_regular_log_file(self, _mock_ensure_state, mock_lease) -> None:
        mock_lease.return_value = {"state": "unclaimed", "holder": "none", "raw_output": "not_returned"}
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
        self.assertFalse(payload["output_truncated"])
        self.assertFalse(payload["output_truncated_by_lines"])
        self.assertFalse(payload["output_truncated_by_chars"])
        self.assertEqual(payload["output_chars"], 0)
        self.assertEqual(payload["output_lines"], 0)
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
        self.assertEqual(payload["home_managed_process_count"], 0)
        self.assertTrue(payload["identity_guard"]["ok"])
        self.assertEqual(payload["identity_guard"]["state"], "clear")
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
        self.assertEqual(payload["home_managed_process_count"], 1)
        self.assertTrue(payload["identity_guard"]["ok"])
        self.assertEqual(payload["identity_guard"]["state"], "managed_session_running")
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

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.status_agent")
    def test_wait_agent_waits_past_assigned_tui_starter_context_until_activity(
        self, mock_status_agent, mock_sleep
    ) -> None:
        initial = {
            "agent": "a",
            "running": True,
            "raw_log_bytes": 10,
            "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
            "last_assignment": {
                "assignment_id": "assign-1",
                "created_at_utc": "2026-06-07T10:00:30+00:00",
            },
            "response_state": {"state": "running_tui_starter_context"},
            "limit_state": {"limited": False},
            "tui_context": {"state": "starter_placeholder", "evidence": "not_returned"},
        }
        current = {
            **initial,
            "raw_log_bytes": 20,
            "raw_log_updated_at_utc": "2026-06-07T10:00:45+00:00",
        }
        mock_status_agent.side_effect = [initial, current]

        result = wait_agent("a", timeout_seconds=10, poll_interval_seconds=1)

        self.assertEqual(result["status"], "activity_observed")
        self.assertEqual(result["poll_count"], 1)
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertEqual(result["response_output"], "not_returned")
        mock_sleep.assert_called_once()

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.status_agent")
    def test_wait_agent_times_out_in_assigned_tui_starter_context_without_activity(
        self, mock_status_agent, mock_sleep
    ) -> None:
        mock_status_agent.return_value = {
            "agent": "a",
            "running": True,
            "raw_log_bytes": 10,
            "raw_log_updated_at_utc": "2026-06-07T10:00:00+00:00",
            "last_assignment": {
                "assignment_id": "assign-1",
                "created_at_utc": "2026-06-07T10:00:30+00:00",
            },
            "response_state": {"state": "running_tui_starter_context"},
            "limit_state": {"limited": False},
            "tui_context": {"state": "starter_placeholder", "evidence": "not_returned"},
        }

        result = wait_agent("a", timeout_seconds=0, poll_interval_seconds=1)

        self.assertEqual(result["status"], "timeout")
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
                "requested_at_utc": "1970-01-01T00:16:30+00:00",
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
        self.assertEqual(payload["report_elapsed_seconds"], 10)
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
        mock_interrupt.assert_called_once_with("a1", force=False)
        mock_write_meta.assert_called_once_with("a1", {})

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
            link = meta_dir / "a1.json"
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

    def test_agent_home_process_summary_handles_unreadable_proc_root(self) -> None:
        proc_root = Mock(spec=Path)
        proc_root.exists.return_value = True
        proc_root.iterdir.side_effect = PermissionError("denied")

        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(
            "codex_master.server.AGENTS",
            {"a": {"label": "A", "runner": Path(tmpdir) / "codex", "home": Path(tmpdir) / "home", "session": "a"}},
            clear=False,
        ):
            summary = agent_home_process_summary("a", proc_root)

        self.assertEqual(summary["process_count"], 0)
        self.assertEqual(summary["external_process_count"], 0)
        self.assertEqual(summary["managed_process_count"], 0)
        self.assertEqual(summary["raw_output"], "not_returned")

    def test_same_path_text_handles_resolution_runtime_error(self) -> None:
        with patch("pathlib.Path.resolve", side_effect=RuntimeError("loop")):
            result = same_path_text("/tmp/loop", Path("/tmp/loop"))

        self.assertFalse(result)

    def test_agent_identity_guard_blocks_orphaned_managed_home_process(self) -> None:
        summary = {
            "process_count": 1,
            "managed_process_count": 1,
            "external_process_count": 0,
            "raw_output": "not_returned",
        }

        result = agent_identity_guard(False, summary)

        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "blocked_orphaned_managed_home_process")
        self.assertTrue(result["single_identity_required"])
        self.assertEqual(result["home_managed_process_count"], 1)
        self.assertEqual(result["raw_output"], "not_returned")

    def test_agent_lifecycle_lock_refuses_symlink_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_root = tmp_path / "state"
            lock_dir = state_root / "locks"
            lock_dir.mkdir(parents=True)
            target = tmp_path / "outside.lock"
            target.write_text("outside", encoding="utf-8")
            lock_path = lock_dir / "agent-a1.lock"
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
                            "params": {
                                "name": "agent_send",
                                "arguments": {"agent": "b", "text": "hi", "allow_unauthenticated": True},
                            },
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

    def test_agent_claim_recovers_stopped_foreign_lease_after_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            stopped_status = {
                "running": False,
                "raw_log_idle_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS + 1,
                "home_process_count": 0,
                "home_external_process_count": 0,
                "raw_output": "not_returned",
                "response_output": "not_returned",
            }
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    first = claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"), patch(
                    "codex_master.server.status_agent", return_value=stopped_status
                ):
                    recovered = claim_agent("a", recover_stopped=True)

        self.assertEqual(first["status"], "claimed")
        self.assertEqual(recovered["status"], "claimed_stopped_orphan")
        self.assertEqual(recovered["previous_lease"]["holder"], "other_server")
        self.assertTrue(recovered["stopped_lease_recovery"]["recoverable"])
        self.assertEqual(recovered["stopped_lease_recovery"]["reason"], "stopped_foreign_lease_orphan")
        self.assertEqual(recovered["lease"]["holder"], "this_server")
        self.assertEqual(recovered["raw_output"], "not_returned")
        self.assertNotIn("owner-one", json.dumps(recovered, sort_keys=True))

    def test_agent_claim_does_not_recover_running_foreign_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            running_status = {
                "running": True,
                "raw_log_idle_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS + 1,
                "home_process_count": 0,
                "home_external_process_count": 0,
                "raw_output": "not_returned",
                "response_output": "not_returned",
            }
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"), patch(
                    "codex_master.server.status_agent", return_value=running_status
                ):
                    with self.assertRaises(AgentBusyError) as caught:
                        claim_agent("a", recover_stopped=True)

        payload = caught.exception.payload
        self.assertEqual(payload["error_code"], "agent_lease_held_by_other_client")
        self.assertEqual(payload["lease"]["holder"], "other_server")
        self.assertNotIn("owner-one", json.dumps(payload, sort_keys=True))

    def test_agent_claim_does_not_recover_foreign_lease_inside_stopped_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            recent_status = {
                "running": False,
                "raw_log_idle_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS - 1,
                "home_process_count": 0,
                "home_external_process_count": 0,
                "raw_output": "not_returned",
                "response_output": "not_returned",
            }
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch(
                "codex_master.server.LEASE_DIR", state / "leases"
            ):
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-one"):
                    claim_agent("b", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"), patch(
                    "codex_master.server.status_agent", return_value=recent_status
                ):
                    with self.assertRaises(AgentBusyError):
                        claim_agent("b", recover_stopped=True)

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
                    result = start_agent_with_lease("a", "/tmp/work", "hi", allow_unauthenticated=True)
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
                    result = start_agent_with_lease("a", "/tmp/work", "hi", allow_unauthenticated=True)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    with self.assertRaisesRegex(AgentError, "leased by another MCP client"):
                        claim_agent("a", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)

        self.assertEqual(result["status"], "started")
        self.assertEqual(result["lease"]["holder"], "this_server")
        self.assertFalse(mock_start_agent.call_args.kwargs["release_lease_on_failure"])

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.start_agent")
    def test_start_agent_with_lease_blocks_running_foreign_lease(self, mock_start_agent, _mock_tmux_alive) -> None:
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
                    claim_agent("b", ttl_seconds=DEFAULT_AGENT_LEASE_SECONDS)
                with patch("codex_master.server.SERVER_INSTANCE_ID", "owner-two"):
                    with self.assertRaises(AgentBusyError) as caught:
                        start_agent_with_lease("b", "/tmp/work", "hi", allow_unauthenticated=True)

        self.assertEqual(caught.exception.payload["error_code"], "agent_lease_held_by_other_client")
        self.assertEqual(caught.exception.payload["lease"]["holder"], "other_server")
        self.assertEqual(caught.exception.payload["raw_output"], "not_returned")
        mock_start_agent.assert_not_called()

    def test_agent_claim_wait_rejects_invalid_direct_interval_values(self) -> None:
        with self.assertRaisesRegex(AgentError, "wait_seconds must be an integer or forever"):
            claim_agent_with_wait("a", wait_seconds="nope")
        with self.assertRaisesRegex(AgentError, "poll_interval_seconds must be an integer"):
            claim_agent_with_wait("a", poll_interval_seconds=True)
        with self.assertRaisesRegex(AgentError, f"poll_interval_seconds must be <= {MAX_WAIT_POLL_SECONDS}"):
            claim_agent_with_wait("a", poll_interval_seconds=MAX_WAIT_POLL_SECONDS + 1)

    def test_default_server_instance_id_prefers_explicit_override(self) -> None:
        with patch.dict(
            "os.environ",
            {"CODEX_MASTER_MCP_INSTANCE_ID": "explicit-owner", "CODEX_THREAD_ID": "thread-one"},
            clear=False,
        ):
            self.assertEqual(default_server_instance_id(), "explicit-owner")

    def test_default_server_instance_id_uses_stable_hashed_thread_id(self) -> None:
        with patch.dict("os.environ", {"CODEX_THREAD_ID": "thread-one"}, clear=True):
            first = default_server_instance_id()
            second = default_server_instance_id()
        with patch.dict("os.environ", {"CODEX_THREAD_ID": "thread-two"}, clear=True):
            other = default_server_instance_id()

        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first.startswith("codex-thread-"))
        self.assertNotIn("thread-one", first)

    def test_server_instance_identity_status_is_stable_and_path_sparse(self) -> None:
        with patch.dict("os.environ", {"CODEX_THREAD_ID": "thread-one"}, clear=True):
            result = server_instance_identity_status()

        self.assertEqual(result["source"], "codex_thread_id_hash")
        self.assertTrue(result["stable_across_cli_invocations"])
        self.assertTrue(result["thread_env_detected"])
        self.assertEqual(result["identity"], "not_returned")
        self.assertEqual(result["raw_output"], "not_returned")

    @patch("codex_master.server.time.sleep")
    @patch("codex_master.server.call_agent_lifecycle")
    def test_agent_claim_wait_defaults_to_forever_and_retries_until_free(self, mock_lifecycle, mock_sleep) -> None:
        success = {
            "agent": "a",
            "status": "claimed",
            "lease": {"state": "held", "holder": "this_server", "raw_output": "not_returned"},
            "previous_lease": {"state": "unclaimed", "raw_output": "not_returned"},
            "raw_output": "not_returned",
        }
        mock_lifecycle.side_effect = [
            AgentBusyError("agent is busy", {"error_code": "agent_busy", "raw_output": "not_returned"}),
            success,
        ]

        result = claim_agent_with_wait("a", poll_interval_seconds=30)

        self.assertEqual(result["status"], "claimed")
        self.assertTrue(result["wait_forever"])
        self.assertIsNone(result["wait_limit_seconds"])
        self.assertTrue(result["recover_stopped"])
        self.assertEqual(result["stopped_grace_seconds"], DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS)
        self.assertEqual(result["poll_count"], 1)
        mock_sleep.assert_called_once_with(30.0)

    @patch("codex_master.server.call_agent_lifecycle")
    def test_agent_claim_wait_finite_seconds_has_no_600_second_maximum(self, mock_lifecycle) -> None:
        mock_lifecycle.return_value = {
            "agent": "a",
            "status": "claimed",
            "lease": {"state": "held", "holder": "this_server", "raw_output": "not_returned"},
            "previous_lease": {"state": "unclaimed", "raw_output": "not_returned"},
            "raw_output": "not_returned",
        }

        result = claim_agent_with_wait("a", wait_seconds=MAX_WAIT_SECONDS + 1)

        self.assertFalse(result["wait_forever"])
        self.assertEqual(result["wait_limit_seconds"], MAX_WAIT_SECONDS + 1)
        self.assertTrue(result["recover_stopped"])
        self.assertEqual(result["stopped_grace_seconds"], DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS)

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
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mock_run_tmux.return_value = subprocess.CompletedProcess(
                ["tmux", "send-keys"],
                1,
                "",
                f"SECRET_INTERRUPT_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
            )
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
                with self.assertRaisesRegex(AgentError, "tmux interrupt failed") as raised:
                    interrupt_agent("a")
                lease = agent_lease_status("a")

        self.assertEqual(lease["state"], "unclaimed")
        self.assertEqual(lease["holder"], "none")
        error_text = str(raised.exception)
        self.assertNotIn("SECRET_INTERRUPT_OUTPUT_SHOULD_NOT_RETURN", error_text)
        self.assertNotIn(tmpdir, error_text)

    @patch("codex_master.server.start_agent", return_value={"agent": "a", "status": "started"})
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch(
        "codex_master.server.agent_auth_status",
        return_value={
            "authenticated": True,
            "auth_state": "present_regular",
            "auth_file": "not_returned",
            "raw_output": "not_returned",
        },
    )
    @patch("codex_master.server.agent_lifecycle_lock")
    def test_call_tool_agent_start_acquires_lifecycle_lock(
        self, mock_lock, _mock_auth, _mock_alive, mock_start_agent
    ) -> None:
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

        self.assertEqual(result["results"][0]["agent"], "a")
        self.assertEqual(result["results"][0]["status"], "started")
        self.assertEqual(result["results"][0]["auth_gate"]["auth_state"], "present_regular")
        self.assertEqual(events, [("lock", "a1"), ("unlock", "a1")])
        mock_start_agent.assert_called_once_with("a1", "/tmp/work", "hi")

    @patch("codex_master.server.claim_agent_with_wait")
    def test_mutating_tools_require_auth_by_default_and_allow_bootstrap_override(self, mock_claim_with_wait) -> None:
        mock_claim_with_wait.return_value = {
            "agent": "c2",
            "status": "claimed",
            "raw_output": "not_returned",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            home = Path(tmpdir) / "c2"
            home.mkdir()
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch.dict(
                "codex_master.server.AGENTS",
                {"c2": {"label": "C2", "runner": home / "codex", "home": home, "session": "session-c2"}},
                clear=False,
            ):
                start_result = call_tool("agent_start", {"agent": "c2"})
                with self.assertRaisesRegex(AgentError, "agent_claim requires authenticated Agentin c2"):
                    call_tool("agent_claim", {"agent": "c2", "wait_forever": False})
                with self.assertRaisesRegex(AgentError, "agent_send requires authenticated Agentin c2"):
                    call_tool("agent_send", {"agent": "c2", "text": "hi"})
                claim_result = call_tool(
                    "agent_claim",
                    {"agent": "c2", "wait_forever": False, "allow_unauthenticated": True},
                )

        self.assertIn("requires authenticated Agentin c2", start_result["results"][0]["error"])
        self.assertEqual(claim_result["status"], "claimed")
        self.assertFalse(claim_result["auth_gate"]["required"])
        self.assertTrue(claim_result["auth_gate"]["override"])
        mock_claim_with_wait.assert_called_once()

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
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
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
    def test_start_agent_blocks_orphaned_managed_codex_home_user(
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
                with self.assertRaisesRegex(AgentError, "managed process\\(es\\) without the managed tmux session"):
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
    @patch("codex_master.server.tmux_alive", return_value=False)
    @patch("codex_master.server.run_tmux")
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
    def test_start_agent_missing_cwd_error_is_path_sparse(
        self, _mock_summary, mock_run_tmux, _mock_tmux_alive, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            runner = tmp_path / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            secret_cwd = tmp_path / "secret-cwd-do-not-return"

            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": tmp_path, "session": "test_session"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "cwd is not a directory") as raised:
                    start_agent("a", cwd=str(secret_cwd))

        error_text = str(raised.exception)
        self.assertNotIn(str(tmp_path), error_text)
        self.assertNotIn("secret-cwd-do-not-return", error_text)
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
                    return subprocess.CompletedProcess(
                        ["tmux", *args],
                        1,
                        "",
                        f"SECRET_PIPE_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
                    )
                if args and args[0] == "kill-session":
                    return subprocess.CompletedProcess(["tmux", *args], 0, "", "")
                return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

            mock_run_tmux.side_effect = fake_run_tmux
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": runner, "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ), patch("codex_master.server.RAW_DIR", Path(tmpdir)), patch("codex_master.server.META_DIR", Path(tmpdir)):
                with self.assertRaisesRegex(RuntimeError, "pipe-pane failed") as raised:
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
            error_text = str(raised.exception)
            self.assertNotIn("SECRET_PIPE_OUTPUT_SHOULD_NOT_RETURN", error_text)
            self.assertNotIn(str(tmpdir), error_text)

    @patch("codex_master.server.ensure_agent_lease_available")
    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.run_tmux")
    def test_stop_agent_tmux_failure_is_data_sparse(self, mock_run_tmux, _mock_alive, _mock_lease) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_run_tmux.return_value = subprocess.CompletedProcess(
                ["tmux", "kill-session"],
                1,
                "",
                f"SECRET_STOP_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
            )
            with patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": Path(tmpdir) / "codex", "home": Path(tmpdir), "session": "test_session"}},
                clear=False,
            ):
                with self.assertRaisesRegex(AgentError, "tmux stop failed") as raised:
                    stop_agent("a")

            error_text = str(raised.exception)
            self.assertNotIn("SECRET_STOP_OUTPUT_SHOULD_NOT_RETURN", error_text)
            self.assertNotIn(tmpdir, error_text)

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
    def test_start_agent_omits_tmux_start_stderr(
        self, mock_run_tmux, _mock_alive, _mock_write_meta, _mock_ensure_state
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = Path(tmpdir) / "codex"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
            mock_run_tmux.return_value = subprocess.CompletedProcess(
                ["tmux", "new-session"],
                1,
                "",
                f"OPENAI_API_KEY=sk-testtoken1234567890 SECRET_START_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
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
        self.assertNotIn("OPENAI_API_KEY", error_text)
        self.assertNotIn("SECRET_START_OUTPUT_SHOULD_NOT_RETURN", error_text)
        self.assertNotIn(str(tmpdir), error_text)

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
    def test_worktree_create_base_ref_is_bounded_and_not_returned(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            relative = ".codex-master-worktrees/agent-a"
            expected_target = repo / relative
            mock_run_command.return_value = subprocess.CompletedProcess(["git"], 0, "", "")

            with patch("codex_master.server.repo_root", return_value=repo):
                result = worktree_create_for_agent("a", path=relative, base_ref="origin/main")

        self.assertEqual(result["base_ref"], "not_returned")
        self.assertEqual(result["base_ref_state"], "set")
        self.assertEqual(mock_run_command.call_args.args[0], ["git", "worktree", "add", str(expected_target), "origin/main"])
        self.assertNotIn("origin/main", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.run_command")
    def test_worktree_create_rejects_unsafe_base_ref_without_git_call(self, mock_run_command) -> None:
        for base_ref in ("--detach", "main with space", "main\nSECRET_BASE_REF_SHOULD_NOT_RETURN"):
            with self.subTest(base_ref=base_ref):
                with tempfile.TemporaryDirectory() as tmpdir:
                    repo = Path(tmpdir)
                    with patch("codex_master.server.repo_root", return_value=repo):
                        with self.assertRaisesRegex(AgentError, "base_ref contains unsupported characters") as raised:
                            worktree_create_for_agent("a", path=".codex-master-worktrees/agent-a", base_ref=base_ref)

                self.assertNotIn("SECRET_BASE_REF_SHOULD_NOT_RETURN", str(raised.exception))
        mock_run_command.assert_not_called()

    @patch("codex_master.server.run_command")
    def test_worktree_create_git_failure_is_data_sparse(self, mock_run_command) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            relative = ".codex-master-worktrees/agent-a"
            mock_run_command.return_value = subprocess.CompletedProcess(
                ["git"],
                128,
                "",
                f"SECRET_WORKTREE_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
            )

            with patch("codex_master.server.repo_root", return_value=repo):
                with self.assertRaisesRegex(AgentError, "git worktree add failed") as raised:
                    worktree_create_for_agent("a", path=relative)

        error_text = str(raised.exception)
        self.assertNotIn("SECRET_WORKTREE_OUTPUT_SHOULD_NOT_RETURN", error_text)
        self.assertNotIn(tmpdir, error_text)

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

    @patch("codex_master.server.ensure_state")
    def test_list_assignments_rejects_invalid_limits(self, _mock_ensure_state) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            assignment_log = Path(tmpdir) / "assignments.jsonl"
            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log):
                with self.assertRaisesRegex(AgentError, "limit must be an integer"):
                    list_assignments("a", limit="10")
                with self.assertRaisesRegex(AgentError, "limit must be >= 1"):
                    list_assignments("a", limit=0)
                with self.assertRaisesRegex(AgentError, f"limit must be <= {MAX_ASSIGNMENT_RECORDS}"):
                    list_assignments("a", limit=MAX_ASSIGNMENT_RECORDS + 1)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.send_agent")
    def test_agent_assign_sends_structured_prompt_without_returning_prompt(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
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
    def test_agent_assign_live_data_requires_search_without_returning_prompt(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
            state = home / "state"
            assignment_log = home / "assignments.jsonl"

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
                        "id": 24,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign_live_data",
                            "arguments": {
                                "agent": "a",
                                "scope": ["."],
                                "task": "Wie ist das Wetter gerade in Berlin?",
                                "live_data_topic": "Wetter Berlin heute",
                                "name": "Mila",
                            },
                        },
                    }
                )
                ledger_response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 25,
                        "method": "tools/call",
                        "params": {"name": "agent_assignments", "arguments": {"agent": "a", "limit": 1}},
                    }
                )

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "assigned")
        self.assertEqual(payload["role"], "exploriererin")
        self.assertEqual(payload["write_policy"], "read_only")
        self.assertTrue(payload["requires_search"])
        self.assertEqual(payload["live_data"]["topic_state"], "set")
        self.assertEqual(payload["prompt_output"], "not_returned")
        self.assertEqual(payload["response_output"], "not_returned")
        self.assertNotIn("Wetter Berlin heute", json.dumps(payload, sort_keys=True))

        sent_prompt = mock_send_agent.call_args.args[1]
        self.assertIn("[EXPLORER_BEE_TASK]", sent_prompt)
        self.assertIn("Live-/Webdatenauftrag: ja", sent_prompt)
        self.assertIn("Wetter Berlin heute", sent_prompt)
        self.assertIn("Muss Websuche/aktuelle Quellen nutzen", sent_prompt)
        self.assertIn("nicht raten", sent_prompt)

        self.assertIsNotNone(ledger_response)
        self.assertFalse(ledger_response["result"]["isError"])
        ledger = json.loads(ledger_response["result"]["content"][0]["text"])
        record = ledger["records"][0]
        self.assertTrue(record["requires_search"])
        self.assertEqual(record["live_data"]["topic_state"], "set")
        ledger_text = json.dumps(ledger, sort_keys=True)
        self.assertNotIn("Wie ist das Wetter gerade in Berlin?", ledger_text)
        self.assertNotIn("Wetter Berlin heute", ledger_text)

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.send_agent")
    def test_assignment_log_retention_prunes_metadata_records(self, mock_send_agent, _mock_alive) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
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
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
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
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
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
                                "skill": "missing-plugin:SECRET_SKILL_NAME_SHOULD_NOT_RETURN",
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
                                "write_paths": ["tests/SECRET_SCOPE_PATH_SHOULD_NOT_RETURN.py"],
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
        missing_skill_text = missing_skill["result"]["content"][0]["text"]
        self.assertIn("skill not found", missing_skill_text)
        self.assertNotIn("SECRET_SKILL_NAME_SHOULD_NOT_RETURN", missing_skill_text)
        self.assertTrue(outside_scope["result"]["isError"])
        outside_scope_text = outside_scope["result"]["content"][0]["text"]
        self.assertIn("write paths must stay inside scope", outside_scope_text)
        self.assertNotIn("SECRET_SCOPE_PATH_SHOULD_NOT_RETURN", outside_scope_text)
        self.assertTrue(long_task["result"]["isError"])
        self.assertIn("task must not exceed", long_task["result"]["content"][0]["text"])
        self.assertTrue(too_many_context_items["result"]["isError"])
        self.assertIn("context must contain at most", too_many_context_items["result"]["content"][0]["text"])

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.run_tmux")
    @patch("codex_master.server.wait_agent_input_ready")
    def test_agent_assign_fails_closed_when_tui_input_is_not_ready(
        self, mock_wait_ready, mock_run_tmux, _mock_alive
    ) -> None:
        mock_wait_ready.return_value = {
            "ready": False,
            "poll_count": 1,
            "timeout_seconds": 0,
            "evidence": "not_returned",
            "raw_output": "not_returned",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
            state = home / "state"
            assignment_log = home / "assignments.jsonl"
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
                        "id": 43,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_assign_readonly",
                            "arguments": {
                                "agent": "a",
                                "scope": ["src"],
                                "task": "Pruefe geheime Sache.",
                            },
                        },
                    }
                )
                ledger = list_assignments("a", limit=10)

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error_code"], "agent_input_not_ready")
        self.assertEqual(payload["operation"], "agent_assign_readonly")
        self.assertTrue(payload["retryable"])
        self.assertFalse(payload["paste_attempted"])
        self.assertFalse(payload["input_ready"]["ready"])
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertEqual(payload["response_output"], "not_returned")
        self.assertNotIn("Pruefe geheime Sache", json.dumps(payload, sort_keys=True))
        self.assertEqual(ledger["record_count"], 0)
        mock_run_tmux.assert_not_called()

    @patch("codex_master.server.tmux_alive", return_value=True)
    @patch("codex_master.server.run_tmux")
    @patch("codex_master.server.wait_agent_input_ready")
    def test_agent_report_request_fails_closed_when_tui_input_is_not_ready(
        self, mock_wait_ready, mock_run_tmux, _mock_alive
    ) -> None:
        mock_wait_ready.return_value = {
            "ready": False,
            "poll_count": 1,
            "timeout_seconds": 0,
            "evidence": "not_returned",
            "raw_output": "not_returned",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            (home / "auth.json").write_text("{}\n", encoding="utf-8")
            state = home / "state"
            with patch("codex_master.server.STATE_ROOT", state), patch(
                "codex_master.server.RAW_DIR", state / "raw"
            ), patch("codex_master.server.META_DIR", state / "meta"), patch(
                "codex_master.server.LOCK_DIR", state / "locks"
            ), patch("codex_master.server.LEASE_DIR", state / "leases"), patch.dict(
                "codex_master.server.AGENTS",
                {"a": {"label": "A", "runner": home / "codex", "home": home, "session": "session-a"}},
                clear=False,
            ):
                response = handle_rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 44,
                        "method": "tools/call",
                        "params": {
                            "name": "agent_report_request",
                            "arguments": {"agent": "a", "assignment_id": "assign-secret"},
                        },
                    }
                )

        self.assertTrue(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["error_code"], "agent_input_not_ready")
        self.assertEqual(payload["operation"], "agent_report_request")
        self.assertTrue(payload["retryable"])
        self.assertFalse(payload["paste_attempted"])
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertNotIn("assign-secret", json.dumps(payload, sort_keys=True))
        mock_run_tmux.assert_not_called()

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
            "codex_master.server.pane_tail", return_value="› Ready"
        ), patch("codex_master.server.run_tmux", side_effect=fake_run_tmux):
            result = send_agent("a", "line 1\nline 2", enter=True)

        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["chars"], len("line 1\nline 2"))
        self.assertEqual(result["paste_mode"], "bracketed_paste")
        self.assertEqual(result["submit_key"], CODEX_TUI_SUBMIT_KEY)
        self.assertEqual(result["response_output"], "not_returned")
        load_call = next(call for call in calls if call["args"][0] == "load-buffer")
        self.assertEqual(load_call["input_text"], f"{BRACKETED_PASTE_BEGIN}line 1\nline 2{BRACKETED_PASTE_END}")
        self.assertTrue(any(call["args"][0] == "paste-buffer" for call in calls))
        self.assertTrue(any(call["args"][-1] == CODEX_TUI_SUBMIT_KEY for call in calls))

    def test_send_agent_keeps_single_line_plain_paste(self) -> None:
        calls = []

        def fake_run_tmux(args, *, input_text=None, check=True, timeout=10):
            calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
            return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

        with patch("codex_master.server.tmux_alive", return_value=True), patch(
            "codex_master.server.pane_tail", return_value="› Ready"
        ), patch("codex_master.server.run_tmux", side_effect=fake_run_tmux):
            result = send_agent("a", "single line", enter=False)

        self.assertEqual(result["paste_mode"], "plain_paste")
        self.assertFalse(result["submitted"])
        self.assertIsNone(result["submit_key"])
        load_call = next(call for call in calls if call["args"][0] == "load-buffer")
        self.assertEqual(load_call["input_text"], "single line")
        self.assertFalse(any(call["args"][-1] == CODEX_TUI_SUBMIT_KEY for call in calls))

    def test_send_agent_fails_when_tui_input_is_not_ready(self) -> None:
        calls = []

        def fake_run_tmux(args, *, input_text=None, check=True, timeout=10):
            calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
            return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

        with patch("codex_master.server.tmux_alive", return_value=True), patch(
            "codex_master.server.pane_tail", return_value="MCP startup incomplete"
        ), patch("codex_master.server.run_tmux", side_effect=fake_run_tmux):
            with self.assertRaisesRegex(AgentInputNotReadyError, "input is not ready") as raised:
                send_agent("a", "single line", ready_timeout_seconds=0)

        self.assertEqual(raised.exception.payload["error_code"], "agent_input_not_ready")
        self.assertFalse(raised.exception.payload["paste_attempted"])
        self.assertTrue(raised.exception.payload["retryable"])
        self.assertEqual(raised.exception.payload["raw_output"], "not_returned")
        self.assertFalse(any(call["args"][0] == "load-buffer" for call in calls))

    def test_send_agent_tmux_failures_are_data_sparse(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [
                ("load-buffer", "tmux load-buffer failed"),
                ("paste-buffer", "tmux paste-buffer failed"),
                ("submit-key", "tmux send submit key failed"),
            ]
            for failing_step, expected_error in cases:
                with self.subTest(failing_step=failing_step):
                    calls = []

                    def fake_run_tmux(args, *, input_text=None, check=True, timeout=10):
                        calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
                        should_fail = args[0] == failing_step or (
                            failing_step == "submit-key"
                            and args[0] == "send-keys"
                            and args[-1] == CODEX_TUI_SUBMIT_KEY
                        )
                        if should_fail:
                            return subprocess.CompletedProcess(
                                ["tmux", *args],
                                1,
                                "",
                                f"SECRET_SEND_OUTPUT_SHOULD_NOT_RETURN {tmpdir}",
                            )
                        return subprocess.CompletedProcess(["tmux", *args], 0, "", "")

                    with patch("codex_master.server.tmux_alive", return_value=True), patch(
                        "codex_master.server.pane_tail", return_value="› Ready"
                    ), patch("codex_master.server.run_tmux", side_effect=fake_run_tmux):
                        with self.assertRaisesRegex(AgentError, expected_error) as raised:
                            send_agent("a", "line 1\nline 2", enter=True)

                    error_text = str(raised.exception)
                    self.assertNotIn("SECRET_SEND_OUTPUT_SHOULD_NOT_RETURN", error_text)
                    self.assertNotIn(tmpdir, error_text)


class CliLifecycleTest(unittest.TestCase):
    def test_watchdog_systemd_service_keeps_hardening_directives(self) -> None:
        service = Path(__file__).resolve().parents[1] / "systemd" / "user" / "codex-master-watchdog.service"
        text = service.read_text(encoding="utf-8")

        self.assertIn("CapabilityBoundingSet=", text)
        self.assertIn("KeyringMode=private", text)
        self.assertIn("NoNewPrivileges=yes", text)
        self.assertIn("PrivateTmp=yes", text)
        self.assertIn("PrivateDevices=yes", text)
        self.assertIn("ProtectClock=yes", text)
        self.assertIn("ProtectControlGroups=yes", text)
        self.assertIn("ProtectHostname=yes", text)
        self.assertIn("ProtectKernelLogs=yes", text)
        self.assertIn("ProtectKernelModules=yes", text)
        self.assertIn("ProtectKernelTunables=yes", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("ReadWritePaths=%h/.local/state/codex-master-mcp %t", text)
        self.assertIn("IPAddressDeny=any", text)
        self.assertIn("LockPersonality=yes", text)
        self.assertIn("MemoryDenyWriteExecute=yes", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", text)
        self.assertIn("RestrictNamespaces=yes", text)
        self.assertIn("RestrictRealtime=yes", text)
        self.assertIn("RestrictSUIDSGID=yes", text)
        self.assertIn("SystemCallArchitectures=native", text)
        self.assertIn("UMask=0077", text)
        self.assertIn("--report-grace-seconds 15", text)
        self.assertIn("--action stop", text)
        self.assertIn("--quiet", text)

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"ok": True})
    def test_cli_tool_validation_drops_omitted_optional_arguments(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["start", "a"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with("agent_start", {"agent": "a"})

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "assigned", "raw_output": "not_returned"})
    def test_cli_assign_live_data_dispatches_data_sparse_assignment(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(
            [
                "assign-live-data",
                "A1",
                "--task",
                "Wie ist das Wetter gerade in Berlin?",
                "--live-data-topic",
                "Wetter Berlin heute",
                "--scope",
                ".",
                "--no-enter",
            ]
        )

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with(
            "agent_assign_live_data",
            {
                "agent": "A1",
                "task": "Wie ist das Wetter gerade in Berlin?",
                "live_data_topic": "Wetter Berlin heute",
                "scope": ["."],
                "context": [],
                "forbidden": [],
                "enter": False,
                "allow_missing_skill": False,
                "allow_subagents": False,
            },
        )

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "claimed", "raw_output": "not_returned"})
    def test_cli_claim_defaults_to_wait_forever(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["claim", "b"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with(
            "agent_claim",
            {
                "agent": "b",
                "ttl_seconds": DEFAULT_AGENT_LEASE_SECONDS,
                "wait_forever": True,
                "poll_interval_seconds": DEFAULT_WAIT_POLL_SECONDS,
                "recover_stopped": True,
                "stopped_grace_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
                "force": False,
            },
        )

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "claimed", "raw_output": "not_returned"})
    def test_cli_claim_no_wait_keeps_immediate_attempt_available(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["claim", "b", "--no-wait"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with(
            "agent_claim",
            {
                "agent": "b",
                "ttl_seconds": DEFAULT_AGENT_LEASE_SECONDS,
                "wait_seconds": 0,
                "wait_forever": False,
                "poll_interval_seconds": DEFAULT_WAIT_POLL_SECONDS,
                "recover_stopped": True,
                "stopped_grace_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
                "force": False,
            },
        )

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "claimed", "raw_output": "not_returned"})
    def test_cli_claim_finite_wait_is_unbounded_by_schema(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["claim", "b", "--wait-seconds", str(MAX_WAIT_SECONDS + 1)])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with(
            "agent_claim",
            {
                "agent": "b",
                "ttl_seconds": DEFAULT_AGENT_LEASE_SECONDS,
                "wait_seconds": MAX_WAIT_SECONDS + 1,
                "wait_forever": False,
                "poll_interval_seconds": DEFAULT_WAIT_POLL_SECONDS,
                "recover_stopped": True,
                "stopped_grace_seconds": DEFAULT_STOPPED_LEASE_RECOVERY_GRACE_SECONDS,
                "force": False,
            },
        )

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "claimed", "raw_output": "not_returned"})
    def test_cli_claim_can_disable_stopped_lease_recovery(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["claim", "b", "--no-recover-stopped", "--stopped-grace-seconds", "300"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with(
            "agent_claim",
            {
                "agent": "b",
                "ttl_seconds": DEFAULT_AGENT_LEASE_SECONDS,
                "wait_forever": True,
                "poll_interval_seconds": DEFAULT_WAIT_POLL_SECONDS,
                "recover_stopped": False,
                "stopped_grace_seconds": 300,
                "force": False,
            },
        )

    @patch("codex_master.server.call_tool")
    def test_cli_claim_rejects_conflicting_wait_modes(self, mock_call_tool) -> None:
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as raised:
            main_cli(["claim", "b", "--forever", "--no-wait"])

        self.assertEqual(raised.exception.code, 2)
        mock_call_tool.assert_not_called()

    @patch("codex_master.server.call_tool")
    @patch("builtins.print")
    def test_cli_tool_validation_rejects_out_of_bounds_arguments(self, mock_print, mock_call_tool) -> None:
        result = main_cli(["wait", "a", "--timeout-seconds", "-1"])

        self.assertEqual(result, 1)
        mock_call_tool.assert_not_called()
        payload = json.loads(mock_print.call_args.args[0])
        self.assertEqual(payload["error"], "timeout_seconds must be >= 0")

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"status": "ok", "raw_output": "not_returned"})
    def test_cli_watchdog_quiet_suppresses_success_json(self, mock_call_tool, mock_print_json) -> None:
        result = main_cli(["watchdog", "all", "--manage-unclaimed", "--quiet"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once()
        name, args = mock_call_tool.call_args.args
        self.assertEqual(name, "fleet_watchdog")
        self.assertTrue(args["manage_unclaimed"])
        mock_print_json.assert_not_called()

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"ok": True, "raw_output": "not_returned"})
    def test_cli_watchdog_status_routes_to_master_tool(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["watchdog-status"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with("master_watchdog_status", {})
        mock_print_json.assert_called_once()

    @patch("codex_master.server.print_json")
    @patch("codex_master.server.call_tool", return_value={"ok": True, "raw_output": "not_returned"})
    def test_cli_timeout_policy_routes_to_master_tool(self, mock_call_tool, mock_print_json) -> None:
        mock_print_json.return_value = 0

        result = main_cli(["timeout-policy"])

        self.assertEqual(result, 0)
        mock_call_tool.assert_called_once_with("master_timeout_policy", {})
        mock_print_json.assert_called_once()

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

    @patch("codex_master.server.repo_wrapper_path")
    def test_install_missing_repo_wrapper_error_is_path_sparse(self, mock_wrapper_path) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "secret-repo" / "bin" / "codex-master-mcp"
            install_link = tmp_path / "bin" / "codex-master-mcp"
            mock_wrapper_path.return_value = wrapper

            with self.assertRaisesRegex(AgentError, "repo wrapper missing") as raised:
                install(register=False, install_path=install_link, sync_plugin_cache=False)

        self.assertNotIn(str(tmp_path), str(raised.exception))
        self.assertNotIn("secret-repo", str(raised.exception))

    @patch("codex_master.server.repo_wrapper_path")
    def test_install_non_executable_repo_wrapper_error_is_path_sparse(self, mock_wrapper_path) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "secret-repo" / "bin" / "codex-master-mcp"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o600)
            install_link = tmp_path / "bin" / "codex-master-mcp"
            mock_wrapper_path.return_value = wrapper

            with self.assertRaisesRegex(AgentError, "repo wrapper is not executable") as raised:
                install(register=False, install_path=install_link, sync_plugin_cache=False)

        self.assertNotIn(str(tmp_path), str(raised.exception))
        self.assertNotIn("secret-repo", str(raised.exception))

    @patch("codex_master.server.run_command")
    @patch("codex_master.server.check_mcp_registration")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_mcp_add_failure_is_data_sparse(
        self, mock_wrapper_path, mock_self_test, mock_registration, mock_run
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "secret-repo" / "bin" / "codex-master-mcp"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            install_link = tmp_path / "bin" / "codex-master-mcp"
            mock_wrapper_path.return_value = wrapper
            mock_self_test.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
            mock_registration.return_value = {"registered": False, "ok": False, "startup_timeout_ok": True}
            mock_run.return_value = subprocess.CompletedProcess(
                ["codex", "mcp", "add"],
                1,
                "",
                f"SECRET_OUTPUT_SHOULD_NOT_RETURN {tmp_path}\n",
            )

            with self.assertRaisesRegex(AgentError, "codex mcp add failed") as raised:
                install(register=True, install_path=install_link, sync_plugin_cache=False)

        error_text = str(raised.exception)
        self.assertNotIn(str(tmp_path), error_text)
        self.assertNotIn("SECRET_OUTPUT_SHOULD_NOT_RETURN", error_text)

    @patch("codex_master.server.run_command")
    @patch("codex_master.server.check_mcp_registration")
    @patch("codex_master.server.mcp_command_startup_self_test")
    @patch("codex_master.server.repo_wrapper_path")
    def test_install_mcp_remove_failure_is_data_sparse(
        self, mock_wrapper_path, mock_self_test, mock_registration, mock_run
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            wrapper = tmp_path / "secret-repo" / "bin" / "codex-master-mcp"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
            install_link = tmp_path / "bin" / "codex-master-mcp"
            mock_wrapper_path.return_value = wrapper
            mock_self_test.return_value = {"ok": True, "status": "ok", "raw_output": "not_returned"}
            mock_registration.return_value = {"registered": True, "ok": False, "startup_timeout_ok": True}
            mock_run.return_value = subprocess.CompletedProcess(
                ["codex", "mcp", "remove"],
                1,
                "",
                f"SECRET_OUTPUT_SHOULD_NOT_RETURN {tmp_path}\n",
            )

            with self.assertRaisesRegex(AgentError, "codex mcp remove failed") as raised:
                install(register=True, force=True, install_path=install_link, sync_plugin_cache=False)

        error_text = str(raised.exception)
        self.assertNotIn(str(tmp_path), error_text)
        self.assertNotIn("SECRET_OUTPUT_SHOULD_NOT_RETURN", error_text)

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
        response = (
            '{"jsonrpc":"2.0","id":1,'
            '"result":{"protocolVersion":"2024-11-05","capabilities":{},'
            '"serverInfo":{"name":"codex-master-mcp"}}}'
        )
        mock_run.return_value = subprocess.CompletedProcess(
            ["codex-master-mcp"],
            0,
            response,
            "",
        )

        result = mcp_command_startup_self_test(Path("/tmp/codex-master-mcp"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertEqual(mock_run.call_args.kwargs["timeout"], DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS)

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_accepts_content_length_frames(self, mock_run) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "codex-master-mcp"},
            },
        }
        encoded = json.dumps(response, separators=(",", ":"))
        mock_run.return_value = subprocess.CompletedProcess(
            ["codex-master-mcp"],
            0,
            f"Content-Length: {len(encoded)}\r\n\r\n{encoded}",
            "",
        )

        result = mcp_command_startup_self_test(Path("/tmp/codex-master-mcp"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["raw_output"], "not_returned")

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_rejects_embedded_json(self, mock_run) -> None:
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

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET", json.dumps(result, sort_keys=True))

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_rejects_stderr_only_response(self, mock_run) -> None:
        response = (
            '{"jsonrpc":"2.0","id":1,'
            '"result":{"protocolVersion":"2024-11-05","capabilities":{},'
            '"serverInfo":{"name":"codex-master-mcp"}}}'
        )
        mock_run.return_value = subprocess.CompletedProcess(
            ["codex-master-mcp"],
            0,
            "",
            response,
        )

        result = mcp_command_startup_self_test(Path("/tmp/codex-master-mcp"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["raw_output"], "not_returned")

    @patch("codex_master.server.subprocess.run")
    def test_mcp_command_startup_self_test_handles_missing_command(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("SECRET_PATH_SHOULD_NOT_RETURN")

        result = mcp_command_startup_self_test(Path("/tmp/missing-codex-master-mcp"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["raw_output"], "not_returned")
        self.assertNotIn("SECRET_PATH_SHOULD_NOT_RETURN", json.dumps(result, sort_keys=True))

    def test_mcp_probe_response_requires_json_rpc_server_info(self) -> None:
        frame = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {"name": "codex-master-mcp"},
                },
            },
            separators=(",", ":"),
        )
        self.assertTrue(
            mcp_probe_response_ok(
                f"Content-Length: {len(frame)}\r\n\r\n{frame}"
            )
        )
        self.assertTrue(
            mcp_probe_response_ok(
                frame
            )
        )
        self.assertFalse(mcp_probe_response_ok('codex-master-mcp finished with "id":1 but no JSON-RPC response'))
        self.assertFalse(
            mcp_probe_response_ok(
                '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"codex-master-mcp"}}}'
            )
        )
        self.assertFalse(
            mcp_probe_response_ok(
                f"Content-Length: {len(frame)}\r\n\r\n{frame} SECRET"
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

    @patch("codex_master.server.run_command")
    @patch("codex_master.server.check_mcp_registration")
    def test_uninstall_mcp_remove_failure_is_data_sparse(self, mock_registration, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            install_link = tmp_path / "bin" / "codex-master-mcp"
            mock_registration.return_value = {"registered": True, "ok": False}
            mock_run.return_value = subprocess.CompletedProcess(
                ["codex", "mcp", "remove"],
                1,
                "",
                f"SECRET_OUTPUT_SHOULD_NOT_RETURN {tmp_path}\n",
            )

            with self.assertRaisesRegex(AgentError, "codex mcp remove failed") as raised:
                uninstall(unregister=True, remove_symlink=False, install_path=install_link)

        error_text = str(raised.exception)
        self.assertNotIn(str(tmp_path), error_text)
        self.assertNotIn("SECRET_OUTPUT_SHOULD_NOT_RETURN", error_text)

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
                "process_count": 0,
                "managed_process_count": 0,
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


class AgentPoolManagementTest(unittest.TestCase):
    def _write_spec(self, root: Path, pool: Path) -> Path:
        spec = {
            "schema_version": 1,
            "pool_root": str(pool),
            "codex_bin": "/opt/codex/bin/codex",
            "series": [
                {"prefix": "a", "count": 2, "template": "a1", "authenticated": ["a1"]},
                {"prefix": "b", "count": 1, "template": "b1", "authenticated": ["b1"]},
                {"prefix": "c", "count": 1, "template": "c1", "authenticated": []},
            ],
            "aliases": {"a": "a1", "b": "b1", "both": ["a1", "b1"]},
            "shared_assets": ["skills", "plugins"],
            "runtime_dirs": ["sessions", "logs"],
            "auth": {"policy": "preserve_existing_only", "copy": []},
        }
        spec_path = root / "pool.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        return spec_path

    def _write_spec_payload(self, root: Path, payload: dict[str, Any]) -> Path:
        spec_path = root / "pool.json"
        spec_path.write_text(json.dumps(payload), encoding="utf-8")
        return spec_path

    def _pool_validate_error_text(self, spec_path: Path, pool: Path, message_id: int) -> str:
        response = handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "method": "tools/call",
                "params": {
                    "name": "agent_pool_validate",
                    "arguments": {"spec": str(spec_path), "target_dir": str(pool), "codex_bin": "/bin/codex"},
                },
            }
        )
        self.assertTrue(response["result"]["isError"])
        return response["result"]["content"][0]["text"]

    def test_agent_pool_spec_validation_errors_do_not_echo_request_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"

            schema_spec = self._write_spec_payload(
                tmp,
                {
                    "schema_version": "SECRET_SCHEMA_VERSION",
                    "pool_root": str(pool),
                    "codex_bin": "/bin/codex",
                    "series": [{"prefix": "a", "count": 1, "template": "a1", "authenticated": []}],
                },
            )
            schema_error = self._pool_validate_error_text(schema_spec, pool, 66)
            self.assertIn("unsupported pool schema_version", schema_error)
            self.assertNotIn("SECRET_SCHEMA_VERSION", schema_error)
            self.assertNotIn(str(pool), schema_error)

            duplicate_prefix = "secretprefix"
            duplicate_spec = self._write_spec_payload(
                tmp,
                {
                    "schema_version": 1,
                    "pool_root": str(pool),
                    "codex_bin": "/bin/codex",
                    "series": [
                        {
                            "prefix": duplicate_prefix,
                            "count": 1,
                            "template": f"{duplicate_prefix}1",
                            "authenticated": [],
                        },
                        {
                            "prefix": duplicate_prefix,
                            "count": 1,
                            "template": f"{duplicate_prefix}1",
                            "authenticated": [],
                        },
                    ],
                },
            )
            duplicate_error = self._pool_validate_error_text(duplicate_spec, pool, 67)
            self.assertIn("series prefix is duplicated", duplicate_error)
            self.assertNotIn(duplicate_prefix, duplicate_error)
            self.assertNotIn(str(pool), duplicate_error)

            auth_spec = self._write_spec_payload(
                tmp,
                {
                    "schema_version": 1,
                    "pool_root": str(pool),
                    "codex_bin": "/bin/codex",
                    "series": [
                        {
                            "prefix": "a",
                            "count": 1,
                            "template": "a1",
                            "authenticated": ["SECRET_AUTH_AGENT"],
                        }
                    ],
                },
            )
            auth_error = self._pool_validate_error_text(auth_spec, pool, 68)
            self.assertIn("authenticated contains unknown Agentin ids", auth_error)
            self.assertNotIn("SECRET_AUTH_AGENT", auth_error)
            self.assertNotIn(str(pool), auth_error)

            alias_spec = self._write_spec_payload(
                tmp,
                {
                    "schema_version": 1,
                    "pool_root": str(pool),
                    "codex_bin": "/bin/codex",
                    "series": [{"prefix": "a", "count": 1, "template": "a1", "authenticated": []}],
                    "aliases": {"SECRET_ALIAS": "SECRET_TARGET"},
                },
            )
            alias_error = self._pool_validate_error_text(alias_spec, pool, 69)
            self.assertIn("alias points to an unknown target", alias_error)
            self.assertNotIn("SECRET_ALIAS", alias_error)
            self.assertNotIn("SECRET_TARGET", alias_error)
            self.assertNotIn(str(pool), alias_error)

    def test_agent_pool_install_status_copy_auth_and_destroy_are_data_sparse(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            (pool / "a1" / "skills").mkdir(parents=True)
            (pool / "a1" / "plugins").mkdir()

            validation = server_module.agent_pool_validate(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")
            self.assertTrue(validation["ok"])
            self.assertEqual(validation["expected_agent_count"], 4)
            self.assertEqual(validation["pool_root"], "not_returned")

            install_result = server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")
            self.assertTrue(install_result["ok"])
            self.assertEqual(install_result["installed_agent_count"], 4)
            self.assertTrue((pool / "a1" / "codex").is_file())
            self.assertTrue(os.access(pool / "a1" / "codex", os.X_OK))
            self.assertIn('export CODEX_HOME="', (pool / "a1" / "codex").read_text(encoding="utf-8"))
            self.assertTrue((pool / "a2" / "skills").is_symlink())
            self.assertFalse((pool / "a2" / "auth.json").exists())

            (pool / "a1" / "auth.json").write_text('{"token":"secret"}\n', encoding="utf-8")
            dry_run = server_module.agent_pool_copy_auth(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                from_agent="a1",
                to="a-series",
            )
            self.assertTrue(dry_run["dry_run"])
            self.assertEqual(dry_run["target_selector"], "not_returned")
            self.assertEqual(dry_run["target_selector_state"], "set")
            self.assertEqual(dry_run["copyable_count"], 1)
            self.assertEqual(dry_run["copied_count"], 0)
            self.assertFalse((pool / "a2" / "auth.json").exists())

            copied = server_module.agent_pool_copy_auth(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                from_agent="a1",
                to="a-series",
                yes=True,
            )
            self.assertFalse(copied["dry_run"])
            self.assertEqual(copied["copied_count"], 1)
            self.assertEqual((pool / "a2" / "auth.json").read_text(encoding="utf-8"), '{"token":"secret"}\n')
            self.assertNotIn("a-series", json.dumps(copied, sort_keys=True))

            status = server_module.agent_pool_status(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")
            self.assertTrue(status["ok"])
            self.assertEqual(status["existing_agent_count"], 4)
            self.assertEqual(status["auth_count"], 2)
            status_text = json.dumps(status, sort_keys=True)
            self.assertNotIn(str(pool), status_text)
            self.assertIn("not_returned", status_text)

            with self.assertRaises(AgentError):
                server_module.agent_pool_destroy_pool(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")

            destroyed = server_module.agent_pool_destroy_pool(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                yes=True,
                remove_root=True,
            )
            self.assertTrue(destroyed["ok"])
            self.assertEqual(destroyed["removed_agent_entries"], 4)
            self.assertFalse(pool.exists())

    def test_agent_pool_copy_auth_does_not_echo_custom_target_selector(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"
            spec = {
                "schema_version": 1,
                "pool_root": str(pool),
                "codex_bin": "/bin/codex",
                "series": [{"prefix": "a", "count": 2, "template": "a1", "authenticated": ["a1"]}],
                "aliases": {"SECRET_COPY_TARGET": "a2"},
            }
            spec_path = self._write_spec_payload(tmp, spec)
            (pool / "a1").mkdir(parents=True)
            (pool / "a2").mkdir()
            (pool / "a1" / "auth.json").write_text('{"token":"secret"}\n', encoding="utf-8")

            result = server_module.agent_pool_copy_auth(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                from_agent="a1",
                to="SECRET_COPY_TARGET",
            )

            payload = json.dumps(result, sort_keys=True)
            self.assertEqual(result["target_selector"], "not_returned")
            self.assertEqual(result["target_selector_state"], "set")
            self.assertEqual(result["target_count"], 1)
            self.assertNotIn("SECRET_COPY_TARGET", payload)
            self.assertNotIn(str(pool), payload)

    def test_agent_pool_install_replaces_wrapper_and_config_symlinks_without_touching_targets(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            home = pool / "a1"
            home.mkdir(parents=True)
            (home / "skills").mkdir()
            (home / "plugins").mkdir()
            wrapper_target = tmp / "outside-wrapper-target"
            config_target = tmp / "outside-config-target"
            wrapper_target.write_text("external wrapper secret\n", encoding="utf-8")
            config_target.write_text("external config secret\n", encoding="utf-8")
            (home / "codex").symlink_to(wrapper_target)
            (home / "config.toml").symlink_to(config_target)

            result = server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")

            self.assertTrue(result["ok"])
            self.assertFalse((home / "codex").is_symlink())
            self.assertTrue((home / "codex").is_file())
            self.assertTrue(os.access(home / "codex", os.X_OK))
            self.assertFalse((home / "config.toml").is_symlink())
            self.assertTrue((home / "config.toml").is_file())
            self.assertEqual(wrapper_target.read_text(encoding="utf-8"), "external wrapper secret\n")
            self.assertEqual(config_target.read_text(encoding="utf-8"), "external config secret\n")

    def test_agent_pool_install_skips_broken_shared_asset_symlink_without_replacing_it(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            (pool / "a1" / "skills").mkdir(parents=True)
            (pool / "a1" / "plugins").mkdir()
            (pool / "a2").mkdir()
            (pool / "a2" / "skills").symlink_to("missing-skills")

            result = server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")

            self.assertTrue(result["ok"])
            self.assertEqual(result["skipped_existing_shared_assets"], 1)
            self.assertTrue((pool / "a2" / "skills").is_symlink())
            self.assertFalse((pool / "a2" / "skills").exists())
            self.assertTrue((pool / "a2" / "plugins").is_symlink())

    def test_agent_pool_copy_auth_treats_broken_target_symlink_as_existing(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            (pool / "a1").mkdir(parents=True)
            (pool / "a2").mkdir()
            (pool / "a1" / "auth.json").write_text('{"token":"secret"}\n', encoding="utf-8")
            (pool / "a2" / "auth.json").symlink_to("missing-auth.json")

            skipped = server_module.agent_pool_copy_auth(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                from_agent="a1",
                to="a-series",
                yes=True,
            )
            replaced = server_module.agent_pool_copy_auth(
                str(spec_path),
                target_dir=str(pool),
                codex_bin="/bin/codex",
                from_agent="a1",
                to="a-series",
                yes=True,
                overwrite=True,
            )

            self.assertEqual(skipped["skipped_existing_count"], 1)
            self.assertEqual(skipped["copied_count"], 0)
            self.assertEqual(replaced["copied_count"], 1)
            self.assertFalse((pool / "a2" / "auth.json").is_symlink())
            self.assertEqual((pool / "a2" / "auth.json").read_text(encoding="utf-8"), '{"token":"secret"}\n')

    def test_agent_pool_rejects_codex_bin_control_chars_without_path_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"
            spec_path = self._write_spec(tmp, pool)
            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 67,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_pool_validate",
                        "arguments": {
                            "spec": str(spec_path),
                            "target_dir": str(pool),
                            "codex_bin": "/bin/codex\nmalicious",
                        },
                    },
                }
            )

            self.assertTrue(response["result"]["isError"])
            payload_text = response["result"]["content"][0]["text"]
            self.assertIn("codex_bin contains unsupported characters", payload_text)
            self.assertNotIn(str(tmp), payload_text)
            self.assertNotIn("agents-secret", payload_text)

    def test_agent_pool_wrapper_quotes_codex_bin_special_chars_as_data(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            fake_codex = tmp / 'codex }"; echo BAD #'
            fake_codex.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "FAKE_OK:%s\\n" "${CODEX_HOME}"\n',
                encoding="utf-8",
            )
            fake_codex.chmod(0o700)

            result = server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin=str(fake_codex))
            self.assertTrue(result["ok"])
            completed = subprocess.run(
                [str(pool / "a1" / "codex")],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("FAKE_OK:", completed.stdout)
            self.assertNotIn("BAD", completed.stdout + completed.stderr)

    def test_agent_pool_install_rejects_runtime_dir_symlink_without_path_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"
            spec_path = self._write_spec(tmp, pool)
            home = pool / "a1"
            home.mkdir(parents=True)
            target = tmp / "outside-runtime-target"
            target.mkdir()
            (home / "logs").symlink_to(target)

            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 66,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_pool_install",
                        "arguments": {"spec": str(spec_path), "target_dir": str(pool)},
                    },
                }
            )

            self.assertTrue(response["result"]["isError"])
            payload_text = response["result"]["content"][0]["text"]
            self.assertIn("private state directory must not be a symlink", payload_text)
            self.assertNotIn(str(tmp), payload_text)
            self.assertNotIn("outside-runtime-target", payload_text)

    def test_agent_pool_destroy_requires_regular_marker_without_path_leak(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"
            spec_path = self._write_spec(tmp, pool)
            server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")
            marker = pool / server_module.POOL_MARKER_FILE
            marker.unlink()
            marker_target = tmp / "outside-marker"
            marker_target.write_text("marker\n", encoding="utf-8")
            marker.symlink_to(marker_target)

            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 68,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_pool_destroy_pool",
                        "arguments": {"spec": str(spec_path), "target_dir": str(pool), "yes": True},
                    },
                }
            )

            self.assertTrue(response["result"]["isError"])
            payload_text = response["result"]["content"][0]["text"]
            self.assertIn("destroy_pool requires an installed pool marker or force=true", payload_text)
            self.assertNotIn(str(tmp), payload_text)
            self.assertNotIn("outside-marker", payload_text)
            self.assertTrue(marker.is_symlink())

    def test_agent_pool_destroy_refuses_unsafe_rmtree_without_removing_pool(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            server_module.agent_pool_install(str(spec_path), target_dir=str(pool), codex_bin="/bin/codex")

            with patch.object(server_module.shutil.rmtree, "avoids_symlink_attacks", False, create=True):
                with self.assertRaises(AgentError) as ctx:
                    server_module.agent_pool_destroy_pool(
                        str(spec_path),
                        target_dir=str(pool),
                        codex_bin="/bin/codex",
                        yes=True,
                    )

            self.assertIn("safe pool removal is unavailable", str(ctx.exception))
            self.assertTrue((pool / "a1").is_dir())

    def test_agent_pool_tools_are_registered_and_cli_invokes_pool_namespace(self) -> None:
        from codex_master import server as server_module

        tool_names = {tool["name"] for tool in server_module.TOOLS}
        self.assertIn("agent_pool_validate", tool_names)
        self.assertIn("agent_pool_destroy_pool", tool_names)

        captured_payloads = []

        def _capture(payload):
            captured_payloads.append(payload)
            return 0

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents"
            spec_path = self._write_spec(tmp, pool)
            with patch("codex_master.server.print_json", side_effect=_capture):
                result = server_module.main_cli(["pool", "validate", "--spec", str(spec_path), "--target-dir", str(pool)])

        self.assertEqual(result, 0)
        self.assertEqual(len(captured_payloads), 1)
        self.assertTrue(captured_payloads[0]["ok"])
        self.assertEqual(captured_payloads[0]["pool_root"], "not_returned")

    def test_agent_pool_spec_reader_rejects_symlink_and_oversized_without_path_leak(self) -> None:
        from codex_master import server as server_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool = tmp / "agents-secret"
            real_spec = self._write_spec(tmp, pool)
            link = tmp / "pool-link.json"
            link.symlink_to(real_spec.name)
            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 64,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_pool_validate",
                        "arguments": {"spec": str(link), "target_dir": str(pool)},
                    },
                }
            )

            self.assertTrue(response["result"]["isError"])
            payload_text = response["result"]["content"][0]["text"]
            self.assertIn("pool spec must be a readable regular file within the size limit", payload_text)
            self.assertNotIn(str(tmp), payload_text)
            self.assertNotIn("agents-secret", payload_text)

            oversized = tmp / "oversized-pool.json"
            oversized.write_text("x" * (server_module.MAX_POOL_SPEC_BYTES + 1), encoding="utf-8")
            response = handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 65,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_pool_validate",
                        "arguments": {"spec": str(oversized), "target_dir": str(pool)},
                    },
                }
            )

            self.assertTrue(response["result"]["isError"])
            payload_text = response["result"]["content"][0]["text"]
            self.assertIn("pool spec must be a readable regular file within the size limit", payload_text)
            self.assertNotIn(str(tmp), payload_text)
            self.assertNotIn("agents-secret", payload_text)

if __name__ == "__main__":
    unittest.main()
