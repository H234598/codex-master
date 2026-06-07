import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
import os
from unittest.mock import patch

from codex_master.server import (
    MAX_ASSIGNMENT_LIST_ITEMS,
    MAX_SEND_TEXT,
    MAX_TASK_TEXT,
    handle_rpc,
    main_cli,
    redact,
    start_agent,
    strip_ansi,
    trim_chars,
    trim_lines,
)


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
        self.assertEqual(assign_props["task"]["maxLength"], MAX_TASK_TEXT)
        self.assertEqual(assign_props["context"]["maxItems"], MAX_ASSIGNMENT_LIST_ITEMS)
        self.assertEqual(by_name["agent_send"]["inputSchema"]["properties"]["text"]["maxLength"], MAX_SEND_TEXT)

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
                "params": {"name": "agent_safe_tail", "arguments": {"agent": "a", "source": "pane", "lines": 120, "chars": 16000}},
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
                "params": {"name": "agent_safe_tail", "arguments": {"agent": "a", "source": "pane", "lines": 1, "chars": 40000}},
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
            with patch("codex_master.server.read_meta", return_value={"raw_log": str(log_path)}):
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

        self.assertIsNotNone(response)
        self.assertFalse(response["result"]["isError"])
        payload = json.loads(response["result"]["content"][0]["text"])["results"][0]
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["total"], 4)
        self.assertEqual(payload["by_source"]["system"], 2)
        self.assertEqual(payload["by_source"]["plugin_cache"], 1)
        self.assertEqual(payload["by_source"]["tmp_plugin_cache"], 1)
        self.assertEqual(payload["plugins"]["github@openai-curated"], 1)
        self.assertEqual(payload["plugins"]["codex-security@tmp"], 1)
        self.assertEqual(payload["skill_file_contents"], "not_returned")
        self.assertEqual(payload["raw_output"], "not_returned")
        self.assertEqual(payload["names_limit"], 2)
        self.assertEqual(len(payload["names"]), 2)
        self.assertTrue(payload["names_truncated"])
        self.assertNotIn("SECRET_SKILL_CONTENT_SHOULD_NOT_LEAK", payload_text)

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
        self.assertEqual(capability_payload["plugins_limit"], 20)
        self.assertTrue(capability_payload["plugins_truncated"])
        self.assertLessEqual(len(capability_payload["plugins"]), 20)

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
        self.assertIn("task exceeds", long_task["result"]["content"][0]["text"])
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
        self.assertIn("text exceeds", response["result"]["content"][0]["text"])


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
                    result = main_cli(["doctor"])

        self.assertEqual(result, 0)
        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertIn("checks", payload)
        self.assertIsInstance(payload["checks"], list)
        self.assertTrue(all(isinstance(item, dict) for item in payload["checks"]))
        self.assertTrue(any(item["name"] == "tmux_available" and item["ok"] is True for item in payload["checks"]))
        self.assertTrue(any(item["name"] == "codex_available" and item["ok"] is True for item in payload["checks"]))
        self.assertTrue(any(item["name"] == "mcp_registered" for item in payload["checks"]))
        payload_text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("sk-doctor-test-secret", payload_text)
        self.assertNotIn("sess-doctor-test", payload_text)

if __name__ == "__main__":
    unittest.main()
