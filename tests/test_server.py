import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_master.server import handle_rpc, redact, start_agent, strip_ansi, trim_chars, trim_lines


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
        self.assertEqual(result["serverInfo"]["name"], "codex-agent-mcp")
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

            kill_calls = [call for call in mock_run_tmux.call_args_list if call.args[0][0] == "kill-session"]
            self.assertEqual(len(kill_calls), 1)
            self.assertFalse(any(Path(tmpdir).glob("*.log")))

    def test_repo_wrapper_works_via_symlink(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        wrapper = repo_root / "bin" / "codex-agent-mcp"
        with tempfile.TemporaryDirectory() as tmpdir:
            symlink = Path(tmpdir) / "codex-agent-mcp"
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

if __name__ == "__main__":
    unittest.main()
