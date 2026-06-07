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
    RAW_LOG_TRUNCATION_MARKER,
    allowed_raw_log_path,
    append_bounded_raw_log,
    agent_home_process_summary,
    ensure_state,
    handle_rpc,
    main_cli,
    prune_raw_logs,
    raw_log_retention_status,
    read_message,
    read_meta,
    record_assignment,
    redact,
    replace_private_text,
    start_agent,
    strip_ansi,
    trim_chars,
    trim_lines,
    write_bounded_raw_log,
    write_meta,
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

    def test_mcp_tools_list(self) -> None:
        response = handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIsNotNone(response)
        self.assertEqual(response["id"], 1)
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("agent_start", names)
        self.assertIn("agent_safe_tail", names)
        self.assertIn("agent_assign", names)
        self.assertIn("agent_assignments", names)
        self.assertIn("agent_skill_match", names)
        self.assertIn("agent_capabilities", names)
        self.assertIn("agent_scope_check", names)
        self.assertIn("agent_assign_readonly", names)
        self.assertIn("agent_assign_write", names)
        self.assertIn("worktree_status", names)
        self.assertIn("commit_ready_check", names)
        self.assertIn("master_plugin_status", names)
        by_name = {tool["name"]: tool for tool in response["result"]["tools"]}
        assign_props = by_name["agent_assign"]["inputSchema"]["properties"]
        skill_props = by_name["agent_skills"]["inputSchema"]["properties"]
        self.assertEqual(assign_props["task"]["maxLength"], MAX_TASK_TEXT)
        self.assertEqual(assign_props["context"]["maxItems"], MAX_ASSIGNMENT_LIST_ITEMS)
        self.assertEqual(by_name["agent_send"]["inputSchema"]["properties"]["text"]["maxLength"], MAX_SEND_TEXT)
        self.assertEqual(skill_props["limit"]["maximum"], MAX_SKILL_NAMES)
        self.assertEqual(skill_props["names_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_offset"]["minimum"], 0)
        self.assertEqual(skill_props["plugins_limit"]["default"], MAX_CAPABILITY_PLUGINS)
        self.assertEqual(skill_props["plugins_limit"]["maximum"], MAX_SKILL_NAMES)

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

    def test_replace_private_text_refuses_preexisting_temp_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            target = Path(tmpdir) / "external.json"
            target.write_text("external\n", encoding="utf-8")
            tmp_path = path.with_name(f".{path.name}.fixed.tmp")
            tmp_path.symlink_to(target)

            with patch("codex_master.server.now_id", return_value="fixed"):
                with self.assertRaisesRegex(AgentError, "temp file without following symlinks"):
                    replace_private_text(path, "safe\n")

            target_content = target.read_text(encoding="utf-8")
            tmp_is_symlink = tmp_path.is_symlink()
            path_exists = path.exists()

        self.assertEqual(target_content, "external\n")
        self.assertTrue(tmp_is_symlink)
        self.assertFalse(path_exists)

    def test_ensure_state_rejects_symlink_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "external-state"
            target.mkdir()
            state_root = Path(tmpdir) / "state"
            state_root.symlink_to(target)

            with patch("codex_master.server.STATE_ROOT", state_root), patch(
                "codex_master.server.RAW_DIR", state_root / "raw"
            ), patch("codex_master.server.META_DIR", state_root / "meta"):
                with self.assertRaisesRegex(AgentError, "must not be a symlink"):
                    ensure_state()

            target_exists = target.is_dir()
            link_is_symlink = state_root.is_symlink()

        self.assertTrue(target_exists)
        self.assertTrue(link_is_symlink)

    def test_ensure_state_rejects_file_state_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            state_root.write_text("not a directory\n", encoding="utf-8")

            with patch("codex_master.server.STATE_ROOT", state_root), patch(
                "codex_master.server.RAW_DIR", state_root / "raw"
            ), patch("codex_master.server.META_DIR", state_root / "meta"):
                with self.assertRaisesRegex(AgentError, "not a directory"):
                    ensure_state()

    def test_record_assignment_refuses_symlink_log_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "external.jsonl"
            target.write_text("external\n", encoding="utf-8")
            link = Path(tmpdir) / "assignments.jsonl"
            link.symlink_to(target)

            with patch("codex_master.server.ASSIGNMENT_LOG", link), patch("codex_master.server.ensure_state"):
                with self.assertRaisesRegex(AgentError, "without following symlinks"):
                    record_assignment({"assignment_id": "1", "agent": "a"})
            target_content = target.read_text(encoding="utf-8")
            link_is_symlink = link.is_symlink()

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
        self.assertEqual(summary["external_processes"][0]["pid"], 100)
        self.assertEqual(summary["external_processes"][0]["raw_output"], "not_returned")

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
    @patch("codex_master.server.read_meta", return_value={})
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
                with self.assertRaisesRegex(AgentError, "without following symlinks"):
                    start_agent("a", cwd=tmpdir)
                target_content = target.read_text(encoding="utf-8")
                link_is_symlink = link.is_symlink()

        mock_run_tmux.assert_not_called()
        self.assertEqual(target_content, "external\n")
        self.assertTrue(link_is_symlink)

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
        self.assertEqual(payload["skill_file_contents"], "not_returned")
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertEqual(payload["names_total"], 4)
        self.assertEqual(payload["names_offset"], 0)
        self.assertEqual(payload["names_limit"], 2)
        self.assertEqual(len(payload["names"]), 2)
        self.assertTrue(payload["names_truncated"])
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", payload_text)

        self.assertFalse(names_page["result"]["isError"])
        names_page_payload = json.loads(names_page["result"]["content"][0]["text"])["results"][0]
        self.assertEqual(names_page_payload["names_total"], 4)
        self.assertEqual(names_page_payload["names_offset"], 2)
        self.assertEqual(names_page_payload["names_limit"], 2)
        self.assertEqual(len(names_page_payload["names"]), 2)
        self.assertFalse(names_page_payload["names_truncated"])
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", json.dumps(names_page_payload, sort_keys=True))

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
        self.assertEqual(skills_payload["names_total"], 1)
        self.assertEqual(skills_payload["names"][0]["name"], "real-skill")
        self.assertEqual(skills_payload["names"][0]["plugin"], "")
        self.assertEqual(skills_payload["names"][0]["source"], "system")
        self.assertNotIn("linked-skill", payload_text)
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", payload_text)

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

    @patch("codex_master.server.send_agent")
    def test_agent_assign_sends_structured_prompt_without_returning_prompt(self, mock_send_agent) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            assignment_log = home / "assignments.jsonl"
            skill = home / ".tmp" / "plugins" / "plugins" / "codex-security" / "skills" / "security-scan" / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("Skill body must not be returned\n", encoding="utf-8")

            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log), patch.dict(
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

    @patch("codex_master.server.send_agent")
    def test_assignment_log_retention_prunes_metadata_records(self, mock_send_agent) -> None:
        mock_send_agent.return_value = {"agent": "a", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            assignment_log = home / "assignments.jsonl"
            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log), patch(
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

    @patch("codex_master.server.send_agent")
    def test_agent_assign_allows_nested_subagents_only_when_explicit(self, mock_send_agent) -> None:
        mock_send_agent.return_value = {"agent": "b", "status": "sent", "response_output": "not_returned"}
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            assignment_log = home / "assignments.jsonl"
            skill = home / ".tmp" / "plugins" / "plugins" / "github" / "skills" / "gh-fix-ci" / "SKILL.md"
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("body\n", encoding="utf-8")

            with patch("codex_master.server.ASSIGNMENT_LOG", assignment_log), patch.dict(
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


class CliLifecycleTest(unittest.TestCase):
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
            wrapper_target = Path(__file__).resolve().parents[1] / "bin" / "codex-master-mcp"
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

        install_link = Path(tmp_home) / ".local" / "bin" / "codex-master-mcp"
        self.assertEqual(result, 0)
        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(payload.get("install_path"), str(install_link))
        self.assertEqual(payload.get("target"), str(wrapper_target))
        self.assertEqual(payload.get("symlink"), "created")
        self.assertEqual(payload.get("mcp"), {"requested": True, "status": "registered"})
        self.assertTrue(link_created)
        mock_run.assert_any_call(["codex", "mcp", "add", "codex-master-mcp", "--", str(install_link)])

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
        session_state = next(item for item in payload["checks"] if item["name"] == "agent_a_tmux_session_state")
        self.assertTrue(session_state["ok"])
        self.assertFalse(session_state["running"])
        self.assertEqual(session_state["severity"], "info")
        retention = next(item for item in payload["checks"] if item["name"] == "raw_log_retention_configured")
        self.assertEqual(retention["max_bytes_per_file"], MAX_RAW_LOG_BYTES)
        self.assertEqual(retention["raw_output"], "not_returned")
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("sk-doctor-test-secret", payload_text)
        self.assertNotIn("sess-doctor-test", payload_text)

if __name__ == "__main__":
    unittest.main()
