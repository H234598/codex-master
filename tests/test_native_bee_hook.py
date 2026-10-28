import json
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "hooks" / "native_bee_event.py"
SPAWN_HOOK = REPO_ROOT / "hooks" / "native_spawn_admission.py"
HOOKS_MANIFEST = REPO_ROOT / "hooks" / "hooks.json"
PLUGIN_MANIFEST = REPO_ROOT / ".codex-plugin" / "plugin.json"
APP_MANIFEST = REPO_ROOT / ".app.json"
HOOK_ABI_V1_LAUNCHER = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
NATIVE_BEE_EVENT_COMMAND = f"{HOOK_ABI_V1_LAUNCHER} native_bee_event"
NATIVE_SPAWN_ADMISSION_COMMAND = f"{HOOK_ABI_V1_LAUNCHER} native_spawn_admission"


class NativeBeeHookTest(unittest.TestCase):
    def run_hook(
        self,
        payload: str,
        *,
        state_root: Path | None = None,
        codex_home: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(REPO_ROOT)
        if state_root is not None:
            env["CODEX_MASTER_MCP_STATE"] = str(state_root)
        if codex_home is not None:
            env["CODEX_HOME"] = str(codex_home)
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
            check=False,
        )

    def run_spawn_hook(self, payload: str, *, state_root: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(REPO_ROOT)
        if state_root is not None:
            env["CODEX_MASTER_MCP_STATE"] = str(state_root)
        return subprocess.run(
            [sys.executable, str(SPAWN_HOOK)], input=payload, text=True, capture_output=True, env=env, timeout=10, check=False
        )

    def test_hooks_manifest_uses_official_event_group_schema(self) -> None:
        payload = json.loads(HOOKS_MANIFEST.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        events = [
            "PreToolUse",
            "PostToolUse",
            "SessionStart",
            "UserPromptSubmit",
            "SubagentStart",
            "SubagentStop",
            "Stop",
            "SessionEnd",
        ]

        self.assertEqual(list(hooks), events)
        expected_by_event = {
            "PreToolUse": [
                {
                    "matcher": "spawn_agent|multi_agent_v1__spawn_agent",
                    "hooks": [
                        {
                            "type": "command",
                            "command": NATIVE_SPAWN_ADMISSION_COMMAND,
                            "timeout": 10,
                        }
                    ],
                },
                {
                    "matcher": "send_input|multi_agent_v1__send_input",
                    "hooks": [
                        {
                            "type": "command",
                            "command": NATIVE_BEE_EVENT_COMMAND,
                            "timeout": 10,
                        }
                    ],
                },
            ],
            "PostToolUse": [
                {
                    "matcher": "wait_agent|multi_agent_v1__wait_agent|close_agent|multi_agent_v1__close_agent",
                    "hooks": [
                        {
                            "type": "command",
                            "command": NATIVE_BEE_EVENT_COMMAND,
                            "timeout": 1,
                        }
                    ],
                }
            ],
        }
        default = {
            "hooks": [
                {
                    "type": "command",
                    "command": NATIVE_BEE_EVENT_COMMAND,
                    "timeout": 1,
                }
            ]
        }
        for event in events:
            with self.subTest(event=event):
                self.assertEqual(hooks[event], expected_by_event.get(event, [default]))

    def test_hooks_manifest_uses_only_the_immutable_abi_v1_launcher_and_allowlisted_hook_names(
        self,
    ) -> None:
        payload = json.loads(HOOKS_MANIFEST.read_text(encoding="utf-8"))
        commands = [
            hook["command"]
            for event_hooks in payload["hooks"].values()
            for registration in event_hooks
            for hook in registration["hooks"]
        ]

        self.assertEqual(
            set(commands),
            {NATIVE_BEE_EVENT_COMMAND, NATIVE_SPAWN_ADMISSION_COMMAND},
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(
                    command, {NATIVE_BEE_EVENT_COMMAND, NATIVE_SPAWN_ADMISSION_COMMAND}
                )
                self.assertNotIn("${", command)
                self.assertNotIn("python", command.casefold())
                self.assertNotIn("cache", command.casefold())
                self.assertNotIn("hooks/", command)

    def test_spawn_hook_rejects_invalid_json_with_structured_deny(self) -> None:
        completed = self.run_spawn_hook("{")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        output = json.loads(completed.stdout)
        specific = output["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PreToolUse")
        self.assertEqual(specific["permissionDecision"], "deny")
        self.assertIn("error_code=", specific["permissionDecisionReason"])

    def test_spawn_hook_rejects_oversized_input_without_echoing_secrets(self) -> None:
        sentinel = "SECRET_SPAWN_INPUT"
        completed = self.run_spawn_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "spawn_agent", "session_id": "parent", "secret": sentinel}) + "x" * 70000)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        specific = json.loads(completed.stdout)["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PreToolUse")
        self.assertEqual(specific["permissionDecision"], "deny")
        self.assertNotIn(sentinel, completed.stdout)

    def test_spawn_hook_allows_valid_payload_without_output(self) -> None:
        spec = importlib.util.spec_from_file_location("native_spawn_admission_test", SPAWN_HOOK)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "spawn_agent",
            "tool_input": {"task": "inspect", "scope": []},
            "session_id": "019fc541-a1e2-7a63-a4bf-b307fcb78457",
            "cwd": str(REPO_ROOT),
        }
        stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode("utf-8")))
        with (
            patch.object(sys, "stdin", stdin),
            patch.object(sys, "stdout", new_callable=io.StringIO) as stdout,
            patch.object(sys, "stderr", new_callable=io.StringIO) as stderr,
            patch("the_hive.server.reserve_native_agent_spawn", return_value={"allowed": True, "reservation_id": "res-token"}) as reserve,
        ):
            assert spec is not None and spec.loader is not None
            spec.loader.exec_module(module)
            result = module.main()

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        reserve.assert_called_once_with(payload)

    def test_plugin_and_app_manifests_bind_only_the_canonical_the_hive_identity(self) -> None:
        payload = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(payload["name"], "the-hive")
        self.assertEqual(payload["homepage"], "https://github.com/H234598/the-hive")
        self.assertEqual(payload["repository"], "https://github.com/H234598/the-hive")
        self.assertIn("the-hive-mcp", payload["description"])
        self.assertNotIn("codex-master-mcp", payload["description"])
        self.assertNotIn("compatibility alias", payload["description"].casefold())
        self.assertNotIn("compatibility alias", payload["interface"]["longDescription"].casefold())
        self.assertEqual(payload["hooks"], "./hooks/hooks.json")
        self.assertEqual(json.loads(APP_MANIFEST.read_text(encoding="utf-8"))["apps"], {"the-hive": {"id": "connector_26697a678b7ec999dc005131eb5c087c"}})

    def test_hooks_import_only_the_canonical_python_server_package(self) -> None:
        for hook in (HOOK, SPAWN_HOOK):
            source = hook.read_text(encoding="utf-8")
            self.assertIn("from the_hive.server import", source)
            self.assertNotIn("from codex_master.server import", source)

    def test_pretooluse_spawn_hook_denies_when_state_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            completed = self.run_spawn_hook(
                json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "spawn_agent",
                        "tool_input": {"task": "work"},
                        "session_id": "thr_parent",
                        "cwd": str(Path(tmpdir)),
                    }
                ),
                state_root=Path(tmpdir) / "state",
            )

        self.assertEqual(completed.returncode, 0)
        output = json.loads(completed.stdout)
        hook_output = output["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "PreToolUse")
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertIn("error_code=", hook_output["permissionDecisionReason"])

    def test_hooks_manifest_registers_blocking_spawn_pretooluse_matcher(self) -> None:
        payload = json.loads(HOOKS_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["hooks"]["PreToolUse"][0]["matcher"],
            "spawn_agent|multi_agent_v1__spawn_agent",
        )

    def test_session_start_initializes_empty_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            completed = self.run_hook(
                json.dumps({"hook_event_name": "SessionStart", "session_id": "thr_parent"}),
                state_root=state_root,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            state = json.loads((state_root / "native-agents.json").read_text(encoding="utf-8"))
            self.assertEqual(state["schema_version"], 2)
            self.assertEqual(state["agents"], [])
            self.assertEqual(len(state["sessions"]), 1)
            self.assertEqual(
                {key: value for key, value in state["sessions"][0].items() if key != "updated_at"},
                {"session_id": "thr_parent", "activity_state": "active"},
            )

    def test_registry_retains_all_managed_referenced_history_on_hook_server_roundtrip(self) -> None:
        from the_hive import server as server_module

        self.assertEqual(server_module.MAX_NATIVE_AGENT_RECORDS, 1024)
        self.assertEqual(server_module.MAX_NATIVE_SESSION_RECORDS, 1024)
        for original_count in (64, 1023, 1024):
            with self.subTest(original_count=original_count), tempfile.TemporaryDirectory() as tmpdir:
                state_root = Path(tmpdir) / "state"
                state_root.mkdir(mode=0o700)
                registry_path = state_root / "native-agents.json"
                rows = range(original_count)
                seed = {
                    "schema_version": 2,
                    "agents": [
                        {"session_id": f"parent_{i}", "agent_id": f"agent_{i}",
                         "agent_type": "worker", "activity_state": "completed", "updated_at": 1.0}
                        for i in rows
                    ],
                    "sessions": [
                        {"session_id": f"parent_{i}", "managed_session": f"managed_{i}",
                         "activity_state": "ended", "updated_at": 1.0}
                        for i in rows
                    ],
                    "reservations": [],
                }
                with patch.object(server_module, "NATIVE_AGENT_REGISTRY_FILE", registry_path):
                    server_module._write_native_agent_registry(seed)
                    completed = self.run_hook(json.dumps({
                        "hook_event_name": "SubagentStart", "session_id": "new_parent",
                        "agent_id": "new_agent", "agent_type": "worker",
                    }), state_root=state_root)
                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual(completed.stderr, "")
                    stored = json.loads(registry_path.read_text(encoding="utf-8"))
                    normalized, read_state = server_module._read_native_agent_registry_read_only()
                    if original_count == 1024:
                        overfull = {
                            **seed,
                            "agents": [*seed["agents"], stored["agents"][-1]],
                            "sessions": [*seed["sessions"], stored["sessions"][-1]],
                        }
                        server_module._write_native_agent_registry(overfull)
                        server_trimmed = json.loads(registry_path.read_text(encoding="utf-8"))
                        self.assertEqual(server_trimmed["agents"][0]["agent_id"], "agent_0")
                        self.assertEqual(server_trimmed["sessions"][0]["managed_session"], "managed_0")
                self.assertEqual(read_state, "ready")
                self.assertEqual(normalized, stored)
                self.assertEqual(len(stored["agents"]), original_count + 1)
                self.assertEqual(len(stored["sessions"]), original_count + 1)
                first_retained = 0
                self.assertEqual(stored["agents"][0]["agent_id"], f"agent_{first_retained}")
                self.assertEqual(stored["sessions"][0]["managed_session"], f"managed_{first_retained}")
                self.assertEqual(stored["agents"][-1]["agent_id"], "new_agent")
                self.assertEqual(stored["sessions"][-1]["session_id"], "new_parent")

        maximal = {
            "schema_version": 2,
            "agents": [{"session_id": f"{index:04x}" + "s" * 124,
                        "agent_id": f"{index:04x}" + "a" * 124,
                        "agent_type": "t" * 64, "activity_state": "unconfirmed",
                        "updated_at": -1.7976931348623157e308} for index in range(1024)],
            "sessions": [{"session_id": f"{index:04x}" + "s" * 124,
                          "managed_session": "m" * 128,
                          "activity_state": "active", "updated_at": -1.7976931348623157e308}
                         for index in range(1024)],
            "reservations": [{"reservation_id": f"{index:04x}" + "r" * 124,
                              "kind": "headless_inflight",
                              "created_at": -1.7976931348623157e308, "agent": "a" * 128,
                              "assignment_id": "i" * 128} for index in range(64)],
        }
        self.assertEqual(len(server_module._native_agent_normalize_registry(maximal)["sessions"]), 1024)
        self.assertLessEqual(len((json.dumps(maximal, sort_keys=True) + "\n").encode()), 1024 * 1024)

    def test_session_start_preserves_parallel_parent_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            first = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": "parent-one",
                        "agent_id": "worker-one",
                        "agent_type": "worker",
                    }
                ),
                state_root=state_root,
            )
            second = self.run_hook(
                json.dumps({"hook_event_name": "SessionStart", "session_id": "parent-two"}),
                state_root=state_root,
            )

            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
            state = json.loads((state_root / "native-agents.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {(record["session_id"], record["agent_id"]) for record in state["agents"]},
                {("parent-one", "worker-one")},
            )
            self.assertEqual(
                {record["session_id"] for record in state["sessions"]},
                {"parent-one", "parent-two"},
            )

    def test_subagent_start_stores_only_allowlisted_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            transcript_marker = "/tmp/SECRET_TRANSCRIPT_PATH.jsonl"
            message_marker = "SECRET_LAST_ASSISTANT_MESSAGE"
            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": "thr_parent",
                        "agent_id": "agent_1",
                        "agent_type": "worker",
                        "agent_transcript_path": transcript_marker,
                        "last_assistant_message": message_marker,
                    }
                ),
                state_root=state_root,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
            state = json.loads(state_text)
            self.assertEqual(state["schema_version"], 2)
            self.assertEqual(len(state["agents"]), 1)
            row = state["agents"][0]
            self.assertEqual(
                {key: value for key, value in row.items() if key != "updated_at"},
                {
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                    "agent_type": "worker",
                    "activity_state": "active",
                },
            )
            self.assertIsInstance(row["updated_at"], (int, float))
            self.assertNotIn("agent_transcript_path", row)
            self.assertNotIn("last_assistant_message", row)
            self.assertNotIn('"agent_transcript_path"', state_text)
            self.assertNotIn('"last_assistant_message"', state_text)
            self.assertNotIn(transcript_marker, state_text)
            self.assertNotIn(message_marker, state_text)

    def test_subagent_stop_returns_json_object_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "SubagentStop",
                        "session_id": "thr_parent",
                        "agent_id": "agent_1",
                    }
                ),
                state_root=Path(tmpdir) / "state",
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "{}\n")
            self.assertEqual(completed.stderr, "")

    def test_completed_subagent_is_counted_only_while_a_resumed_turn_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for payload in (
                {
                    "hook_event_name": "SubagentStart",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                    "agent_type": "explorer",
                },
                {
                    "hook_event_name": "SubagentStop",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                },
            ):
                completed = self.run_hook(json.dumps(payload), state_root=state_root)
                self.assertEqual(completed.returncode, 0)

            state_path = state_root / "native-agents.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["agents"][0]["activity_state"], "completed")

            resumed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": "agent_1",
                    }
                ),
                state_root=state_root,
            )
            self.assertEqual(resumed.returncode, 0)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["agents"][0]["activity_state"], "active")

            stopped = self.run_hook(
                json.dumps({"hook_event_name": "Stop", "session_id": "agent_1"}),
                state_root=state_root,
            )
            self.assertEqual(stopped.returncode, 0)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["agents"][0]["activity_state"], "completed")

    def test_parent_tool_hooks_count_a_resumed_subagent_turn(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for payload in (
                {
                    "hook_event_name": "SubagentStart",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                    "agent_type": "explorer",
                },
                {
                    "hook_event_name": "SubagentStop",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                },
            ):
                self.assertEqual(self.run_hook(json.dumps(payload), state_root=state_root).returncode, 0)

            resumed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "session_id": "thr_parent",
                        "tool_name": "multi_agent_v1__send_input",
                        "tool_input": {"target": "agent_1", "message": "SECRET_RESUME_PROMPT"},
                    }
                ),
                state_root=state_root,
            )
            state_path = state_root / "native-agents.json"
            state_text = state_path.read_text(encoding="utf-8")
            self.assertEqual(resumed.returncode, 0)
            self.assertEqual(resumed.stdout, "")
            self.assertEqual(json.loads(state_text)["agents"][0]["activity_state"], "active")
            self.assertNotIn("SECRET", state_text)

            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "thr_parent",
                        "tool_name": "multi_agent_v1__wait_agent",
                        "tool_input": {"ids": ["agent_1"]},
                        "tool_response": {
                            "status": {"agent_1": {"completed": "SECRET_AGENT_OUTPUT"}},
                            "timed_out": False,
                        },
                    }
                ),
                state_root=state_root,
            )
            state_text = state_path.read_text(encoding="utf-8")
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(json.loads(state_text)["agents"][0]["activity_state"], "completed")
            self.assertNotIn("SECRET", state_text)

    def test_parent_session_lifecycle_keeps_completed_subagent_noncounting(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for payload in (
                {
                    "hook_event_name": "SubagentStart",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                    "agent_type": "explorer",
                },
                {
                    "hook_event_name": "SubagentStop",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                },
                {"hook_event_name": "SessionEnd", "session_id": "thr_parent"},
                {"hook_event_name": "SessionStart", "session_id": "thr_parent"},
            ):
                self.assertEqual(self.run_hook(json.dumps(payload), state_root=state_root).returncode, 0)

            state = json.loads((state_root / "native-agents.json").read_text(encoding="utf-8"))
            self.assertEqual(state["agents"][0]["activity_state"], "completed")

    def test_resume_hook_rejects_unknown_missing_and_foreign_targets_without_leaking_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for payload in (
                {
                    "hook_event_name": "SubagentStart",
                    "session_id": "parent_a",
                    "agent_id": "agent_1",
                    "agent_type": "explorer",
                },
                {
                    "hook_event_name": "SubagentStop",
                    "session_id": "parent_a",
                    "agent_id": "agent_1",
                },
            ):
                self.assertEqual(self.run_hook(json.dumps(payload), state_root=state_root).returncode, 0)

            for payload in (
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "parent_a",
                    "tool_name": "send_input",
                    "tool_input": {"target": "unknown", "message": "SECRET_UNKNOWN"},
                },
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "parent_a",
                    "tool_name": "send_input",
                    "tool_input": {"message": "SECRET_MISSING"},
                },
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "parent_b",
                    "tool_name": "send_input",
                    "tool_input": {"target": "agent_1", "message": "SECRET_FOREIGN"},
                },
            ):
                with self.subTest(payload=payload):
                    completed = self.run_hook(json.dumps(payload), state_root=state_root)
                    output = json.loads(completed.stdout)["hookSpecificOutput"]
                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual(output["hookEventName"], "PreToolUse")
                    self.assertEqual(output["permissionDecision"], "deny")
                    self.assertNotIn("SECRET", completed.stdout)
                    state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
                    self.assertEqual(json.loads(state_text)["agents"][0]["activity_state"], "completed")
                    self.assertNotIn("SECRET", state_text)

    def test_resume_hook_rejects_oversized_valid_json_before_state_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for payload in (
                {
                    "hook_event_name": "SubagentStart",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                    "agent_type": "explorer",
                },
                {
                    "hook_event_name": "SubagentStop",
                    "session_id": "thr_parent",
                    "agent_id": "agent_1",
                },
            ):
                self.assertEqual(self.run_hook(json.dumps(payload), state_root=state_root).returncode, 0)
            payload = json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "thr_parent",
                    "tool_name": "send_input",
                    "tool_input": {"target": "agent_1", "message": "SECRET_OVERSIZED"},
                }
            )

            completed = self.run_hook(payload + " " * 70_000, state_root=state_root)

            state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(json.loads(state_text)["agents"][0]["activity_state"], "completed")
            self.assertNotIn("SECRET", state_text)

    def test_post_tool_close_completes_only_the_calling_parents_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            for parent in ("parent_a", "parent_b"):
                self.assertEqual(
                    self.run_hook(
                        json.dumps(
                            {
                                "hook_event_name": "SubagentStart",
                                "session_id": parent,
                                "agent_id": "agent_1",
                                "agent_type": "explorer",
                            }
                        ),
                        state_root=state_root,
                    ).returncode,
                    0,
                )

            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "parent_a",
                        "tool_name": "close_agent",
                        "tool_input": {"id": "agent_1"},
                        "tool_response": {"previous_status": {"completed": "SECRET_OUTPUT"}},
                    }
                ),
                state_root=state_root,
            )

            state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
            states = {
                row["session_id"]: row["activity_state"] for row in json.loads(state_text)["agents"]
            }
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(states, {"parent_a": "completed", "parent_b": "active"})
            self.assertNotIn("SECRET", state_text)

    def test_resumed_legacy_subagent_recovers_parent_from_its_bounded_transcript_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_root = root / "state"
            codex_home = root / "codex-home"
            transcript = codex_home / "sessions" / "2026" / "08" / "14" / "child.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {
                            "id": "agent_legacy",
                            "source": {
                                "subagent": {
                                    "thread_spawn": {
                                        "parent_thread_id": "thr_parent",
                                        "depth": 1,
                                    }
                                }
                            },
                        },
                    }
                )
                + "\nSECRET_TRANSCRIPT_BODY_MUST_NOT_BE_READ\n",
                encoding="utf-8",
            )

            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": "agent_legacy",
                        "transcript_path": str(transcript),
                        "prompt": "SECRET_PROMPT_MUST_NOT_BE_STORED",
                    }
                ),
                state_root=state_root,
                codex_home=codex_home,
            )

            self.assertEqual(completed.returncode, 0)
            state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
            state = json.loads(state_text)
            self.assertEqual(
                {key: value for key, value in state["agents"][0].items() if key != "updated_at"},
                {
                    "session_id": "thr_parent",
                    "agent_id": "agent_legacy",
                    "agent_type": "subagent",
                    "activity_state": "active",
                },
            )
            self.assertNotIn("SECRET", state_text)

    def test_session_end_marks_seeded_agent_unconfirmed_silently(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            started = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": "thr_parent",
                        "agent_id": "agent_1",
                        "agent_type": "worker",
                    }
                ),
                state_root=state_root,
            )
            completed = self.run_hook(
                json.dumps({"hook_event_name": "SessionEnd", "session_id": "thr_parent"}),
                state_root=state_root,
            )

            self.assertEqual(started.returncode, 0)
            self.assertEqual(started.stdout, "")
            self.assertEqual(started.stderr, "")
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            state = json.loads((state_root / "native-agents.json").read_text(encoding="utf-8"))
            self.assertEqual(len(state["agents"]), 1)
            self.assertEqual(state["agents"][0]["activity_state"], "unconfirmed")

    def test_invalid_and_oversized_json_are_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state-root"
            state_root.write_text("nope", encoding="utf-8")

            invalid = self.run_hook("{", state_root=state_root)
            self.assertEqual(invalid.returncode, 0)
            self.assertEqual(invalid.stdout, "")
            self.assertEqual(invalid.stderr, "")

            oversized_payload = {
                "hook_event_name": "SubagentStart",
                "session_id": "thr_parent",
                "agent_id": "agent_1",
                "agent_type": "worker",
                "padding": "",
            }
            prefix = json.dumps(oversized_payload, separators=(",", ":"))
            oversized_payload["padding"] = "x" * (65537 - len(prefix))
            oversized = json.dumps(oversized_payload, separators=(",", ":")) + "SECRET_TRAILING_BYTES"

            completed = self.run_hook(oversized, state_root=Path(tmpdir) / "state")
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")

    def test_state_errors_are_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            blocked_state = Path(tmpdir) / "blocked-state"
            blocked_state.write_text("not a directory", encoding="utf-8")
            completed = self.run_hook(
                json.dumps({"hook_event_name": "SessionStart", "session_id": "thr_parent"}),
                state_root=blocked_state,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")


class NativeRegistryCleanupTest(unittest.TestCase):
    def setUp(self):
        from the_hive import server

        self.server = server
        spec = importlib.util.spec_from_file_location("cleanup_hook", HOOK)
        self.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hook)

    @staticmethod
    def registry(agents=(), sessions=(), reservations=()):
        return {
            "schema_version": 2,
            "agents": list(agents),
            "sessions": list(sessions),
            "reservations": list(reservations),
        }

    @staticmethod
    def agent(index, state="completed", parent="ended"):
        return {
            "session_id": parent,
            "agent_id": f"child-{index}",
            "agent_type": "worker",
            "activity_state": state,
            "updated_at": float(index),
        }

    @staticmethod
    def session(index, state="ended", **extra):
        return {
            "session_id": f"session-{index}",
            "activity_state": state,
            "updated_at": float(index),
            **extra,
        }

    def cleanup(self, document, **kwargs):
        from the_hive.native_registry import cleanup_registry

        return cleanup_registry(
            document, now=2000, retained_session_ids=frozenset(), **kwargs
        )

    def test_normalizers_never_slice_protected_population(self):
        document = self.registry(
            [self.agent(i, "active") for i in range(1100)],
            [self.session(i, "active") for i in range(1100)],
        )
        for normalizer in (
            self.hook._normalized_registry,
            self.server._native_agent_normalize_registry,
        ):
            normalized = normalizer(document)
            self.assertEqual(len(normalized["agents"]), 1100)
            self.assertEqual(len(normalized["sessions"]), 1100)

    def test_mixed_overflow_preserves_active_and_uncertain_and_trims_oldest_history(
        self,
    ):
        protected = [self.agent(-2, "active"), self.agent(-1, "unconfirmed")]
        result = self.cleanup(
            self.registry(protected + [self.agent(i) for i in range(1100)])
        )
        self.assertEqual(result["agents"][:2], protected)
        self.assertEqual(len(result["agents"]), 1026)
        self.assertEqual(result["agents"][2]["agent_id"], "child-76")

    def test_terminal_parent_child_pin_and_reservation_references_are_protected(self):
        from the_hive.native_registry import cleanup_registry

        rows = [self.agent(i, parent="session-1") for i in range(1050)]
        for sessions, reservations, pins in (
            ([self.session(1, "active")], [], frozenset()),
            ([self.session(1, managed_session="managed")], [], frozenset()),
            (
                [],
                [
                    {
                        "reservation_id": "r",
                        "kind": "native_spawn",
                        "created_at": 2000,
                        "parent_session_id": "session-1",
                    }
                ],
                frozenset(),
            ),
            ([], [], frozenset({"session-1"})),
        ):
            result = cleanup_registry(
                self.registry(rows, sessions, reservations),
                now=2000,
                retained_session_ids=pins,
            )
            self.assertEqual(result["agents"], rows)
        child_rows = [self.agent(i) for i in range(1050)]
        sessions = [
            {
                "session_id": row["agent_id"],
                "activity_state": "active",
                "updated_at": 2000,
            }
            for row in child_rows
        ]
        self.assertEqual(
            self.cleanup(self.registry(child_rows, sessions))["agents"], child_rows
        )

    def test_unknown_orphan_survives_managed_shutdown_without_individual_proof(self):
        rows = [self.agent(i, "unconfirmed", parent="session-1") for i in range(1050)]
        document = self.registry(rows, [self.session(1, managed_session="managed")])
        result = self.cleanup(document, stopped_managed_sessions=frozenset({"managed"}))
        self.assertEqual(result["agents"], rows)
        self.assertEqual(len(result["sessions"]), 1)

    def test_fresh_terminal_child_event_releases_history_but_reopen_protects(self):
        rows = [self.agent(i, "unconfirmed") for i in range(1050)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "native-agents.json"
            path.write_text(json.dumps(self.registry(rows)))
            path.chmod(0o600)
            with (
                patch.object(self.server, "STATE_ROOT", root),
                patch.object(self.server, "LOCK_DIR", root / "locks"),
                patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                patch.object(
                    self.server,
                    "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                    root / "locks" / "native-agents.lock",
                ),
                patch(
                    "the_hive.native_registry.retained_pin_session_ids",
                    return_value=frozenset(),
                ),
            ):
                ids = [row["agent_id"] for row in rows]
                self.server.record_native_agent_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "ended",
                        "tool_name": "wait_agent",
                        "tool_input": {"ids": ids},
                        "tool_response": {
                            "status": {child: {"completed": "done"} for child in ids}
                        },
                    },
                    now=2000,
                )
                stored = json.loads(path.read_text())
                self.assertEqual(len(stored["agents"]), 1024)
                self.server.record_native_agent_event(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": stored["agents"][0]["agent_id"],
                    },
                    now=2001,
                )
                self.assertEqual(
                    json.loads(path.read_text())["agents"][0]["activity_state"],
                    "active",
                )

    def test_ttl_is_only_for_native_and_replacement_reservations(self):
        reservations = [
            {
                "reservation_id": "native",
                "kind": "native_spawn",
                "created_at": 1969,
                "parent_session_id": "parent",
            },
            {
                "reservation_id": "replacement",
                "kind": "managed_replacement",
                "created_at": 1969,
                "managed_session": "managed",
            },
            {
                "reservation_id": "headless",
                "kind": "headless_inflight",
                "created_at": 1,
                "agent": "agent",
                "assignment_id": "assignment",
            },
        ]
        self.assertEqual(
            self.cleanup(self.registry(reservations=reservations))["reservations"],
            reservations[2:],
        )
        self.assertEqual(
            self.hook._normalized_registry(self.registry(reservations=reservations)),
            self.server._native_agent_normalize_registry(
                self.registry(reservations=reservations)
            ),
        )

    def test_hook_writer_persists_lifecycle_reference_before_ttl_cleanup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            observed = []

            def record_reference(_store, *, reference_id, now):
                observed.append((reference_id, now))

            try:
                with (
                    patch.object(self.hook, "_hook_state_root", return_value=root),
                    patch(
                        "the_hive.native_registry.retained_pin_session_ids",
                        return_value=frozenset(),
                    ),
                    patch(
                        "the_hive.worktree_lifecycle.WorktreeLifecycleStore.reserve_native_reference",
                        autospec=True,
                        side_effect=record_reference,
                    ) as reserve,
                ):
                    self.assertTrue(
                        self.hook._write_registry(
                            root_fd,
                            self.registry(
                                reservations=[
                                    {
                                        "reservation_id": "expired",
                                        "kind": "native_spawn",
                                        "created_at": 1,
                                        "parent_session_id": "parent",
                                    }
                                ]
                            ),
                            now=2_000,
                        )
                    )
                reserve.assert_called_once()
                self.assertEqual(observed[0][0], "native-registry-cleanup")
                self.assertEqual(self.hook._read_registry(root_fd)["reservations"], [])
            finally:
                os.close(root_fd)

    def test_atomic_byte_rejection_preserves_file_and_protected_reservations(self):
        rows = [
            self.agent(i, "active", parent="p" * 128)
            | {"agent_id": f"{i:06d}" + "a" * 122, "agent_type": "t" * 64}
            for i in range(3000)
        ]
        document = self.registry(rows)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "native-agents.json"
            path.write_text(json.dumps(self.registry()))
            path.chmod(0o600)
            before = path.read_bytes()
            with patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path):
                with self.assertRaisesRegex(self.server.AgentError, "byte budget"):
                    self.server._write_native_agent_registry(document)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertFalse(self.hook._write_registry(fd, document))
            finally:
                os.close(fd)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(root.iterdir()), [path])

    def test_uncertain_pin_store_protects_terminal_history(self):
        from the_hive.native_registry import cleanup_registry

        document = self.registry([self.agent(i) for i in range(1100)])
        self.assertEqual(
            cleanup_registry(document, now=2000, retained_session_ids=None), document
        )

    def test_event_rejects_existing_invalid_or_oversized_registry_atomically(self):
        for raw in (b'{"broken":true}', b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "native-agents.json"
                path.write_bytes(raw)
                path.chmod(0o600)
                inode = path.stat().st_ino
                with (
                    patch.object(self.server, "STATE_ROOT", root),
                    patch.object(self.server, "LOCK_DIR", root / "locks"),
                    patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                    patch.object(
                        self.server,
                        "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                        root / "locks" / "native-agents.lock",
                    ),
                ):
                    with self.assertRaisesRegex(
                        self.server.AgentError, "event update rejected"
                    ):
                        self.server.record_native_agent_event(
                            {"hook_event_name": "SessionStart", "session_id": "new"},
                            now=2000,
                        )
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(path.stat().st_ino, inode)

    def test_managed_association_survives_hook_and_server_end_and_reopen(self):
        document = self.registry(
            [self.agent(1, "unconfirmed", parent="session-1")],
            [self.session(1, "active", managed_session="managed")],
        )
        for module in (self.hook, self.server):
            with (
                self.subTest(module=module.__name__),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                path = root / "native-agents.json"
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                with (
                    patch.dict(os.environ, {"CODEX_MASTER_MCP_STATE": str(root)}),
                    patch.object(self.server, "STATE_ROOT", root),
                    patch.object(self.server, "LOCK_DIR", root / "locks"),
                    patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                    patch.object(
                        self.server,
                        "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                        root / "locks" / "native-agents.lock",
                    ),
                    patch.object(
                        self.server,
                        "_trusted_managed_tmux_session_for_home",
                        return_value=None,
                    ),
                ):
                    for event in ("SessionEnd", "SessionStart"):
                        payload = {"hook_event_name": event, "session_id": "session-1"}
                        if module is self.hook:
                            module._record_native_event(payload)
                        else:
                            module.record_native_agent_event(payload, now=2000)
                        self.assertEqual(
                            json.loads(path.read_text())["sessions"][0][
                                "managed_session"
                            ],
                            "managed",
                        )

    def test_hook_and_server_writers_produce_identical_cleanup_and_one_reservation_consumption(
        self,
    ):
        document = self.registry(
            [self.agent(i) for i in range(1100)],
            reservations=[
                {
                    "reservation_id": f"r-{i}",
                    "kind": "native_spawn",
                    "created_at": 1999,
                    "parent_session_id": "new-parent",
                }
                for i in range(2)
            ],
        )
        stored = []
        for module in (self.hook, self.server):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "native-agents.json"
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                with (
                    patch.dict(os.environ, {"CODEX_MASTER_MCP_STATE": str(root)}),
                    patch.object(self.server, "STATE_ROOT", root),
                    patch.object(self.server, "LOCK_DIR", root / "locks"),
                    patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                    patch.object(
                        self.server,
                        "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                        root / "locks" / "native-agents.lock",
                    ),
                    patch.object(
                        self.server,
                        "_trusted_managed_tmux_session_for_home",
                        return_value=None,
                    ),
                    patch(
                        "the_hive.native_registry.retained_pin_session_ids",
                        return_value=frozenset(),
                    ),
                    patch.object(self.hook.time, "time", return_value=2000),
                ):
                    payload = {
                        "hook_event_name": "SubagentStart",
                        "session_id": "new-parent",
                        "agent_id": "new-child",
                        "agent_type": "worker",
                    }
                    if module is self.hook:
                        module._record_native_event(payload)
                    else:
                        module.record_native_agent_event(payload, now=2000)
                    stored.append(path.read_bytes())
        self.assertEqual(stored[0], stored[1])
        self.assertEqual(len(json.loads(stored[0])["reservations"]), 1)

    def test_hook_event_overflow_reports_bounded_reason_without_overwriting(self):
        document = self.registry([self.agent(i, "active") for i in range(4)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "native-agents.json"
            path.write_text(json.dumps(document))
            path.chmod(0o600)
            before = path.read_bytes()
            errors = io.StringIO()
            with (
                patch.dict(os.environ, {"CODEX_MASTER_MCP_STATE": str(root)}),
                patch.object(
                    self.hook, "MAX_NATIVE_AGENT_REGISTRY_BYTES", len(before) + 1
                ),
                patch.object(self.hook.sys, "stderr", errors),
            ):
                self.hook._record_native_event(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": "new-parent",
                        "agent_id": "new-child",
                        "agent_type": "worker",
                    }
                )
            self.assertEqual(
                errors.getvalue(), "error_code=native_registry_byte_budget_exceeded\n"
            )
            self.assertEqual(path.read_bytes(), before)

    def test_server_and_hook_share_lock_and_do_not_lose_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "native-agents.json"
            path.write_text(json.dumps(self.registry()))
            path.chmod(0o600)
            env = os.environ.copy() | {
                "PLUGIN_ROOT": str(REPO_ROOT),
                "CODEX_MASTER_MCP_STATE": str(root),
            }
            with (
                patch.object(self.server, "STATE_ROOT", root),
                patch.object(self.server, "LOCK_DIR", root / "locks"),
                patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                patch.object(
                    self.server,
                    "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                    root / "locks" / "native-agents.lock",
                ),
            ):
                with self.server.native_agent_registry_lock():
                    child = subprocess.Popen(
                        [sys.executable, str(HOOK)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                    )
                    try:
                        child.communicate(
                            json.dumps(
                                {
                                    "hook_event_name": "SessionStart",
                                    "session_id": "hook-parent",
                                }
                            ),
                            timeout=0.5,
                        )
                    except subprocess.TimeoutExpired:
                        pass
                    else:
                        self.fail("hook did not wait for the server registry lock")
                    self.server.record_native_agent_event(
                        {
                            "hook_event_name": "SessionStart",
                            "session_id": "server-parent",
                        },
                        now=2000,
                    )
                output, error = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, error)
                self.assertEqual(output, "")
                self.assertEqual(
                    {
                        row["session_id"]
                        for row in json.loads(path.read_text())["sessions"]
                    },
                    {"hook-parent", "server-parent"},
                )

    def test_canonical_pin_collection_retains_ended_grace_and_resume_and_fails_closed(
        self,
    ):
        from the_hive.hook_session_pin_store import HookSessionPinStoreV1
        from the_hive.native_registry import retained_pin_session_ids

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            root = home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
            store = HookSessionPinStoreV1.create_at(root)
            digest = "sha256:" + "a" * 64
            store.bind_session(
                session_id="pin-parent",
                generation="one",
                runtime_manifest_digest=digest,
                hooks={"native_bee_event": digest, "native_spawn_admission": digest},
                now_unix_ns=1_000_000_000,
            )
            store.end_session(session_id="pin-parent", now_unix_ns=2_000_000_000)
            with patch(
                "the_hive.native_registry.pwd.getpwuid",
                return_value=SimpleNamespace(pw_dir=str(home)),
            ):
                self.assertEqual(retained_pin_session_ids(3), frozenset({"pin-parent"}))
                self.assertEqual(
                    retained_pin_session_ids(86402), frozenset({"pin-parent"})
                )
                store.resume_session(
                    session_id="pin-parent",
                    generation="one",
                    runtime_manifest_digest=digest,
                    hooks={
                        "native_bee_event": digest,
                        "native_spawn_admission": digest,
                    },
                    now_unix_ns=86403_000_000_000,
                )
                self.assertEqual(
                    retained_pin_session_ids(86404), frozenset({"pin-parent"})
                )
                (root / "untrusted").write_text("bad")
                self.assertIsNone(retained_pin_session_ids(86405))
            with patch(
                "the_hive.native_registry.pwd.getpwuid",
                return_value=SimpleNamespace(pw_dir=str(home / "missing")),
            ):
                self.assertIsNone(retained_pin_session_ids(86405))

    def test_actual_managed_stop_releases_only_unreferenced_ended_parent_history(self):
        import contextlib

        sessions = [self.session(i, managed_session="managed") for i in range(1100)]
        sessions[1]["activity_state"] = "active"
        document = self.registry(
            [self.agent(0, "unconfirmed", parent="session-0")], sessions
        )
        for process_count, lease_state, expected in (
            (None, "unclaimed", None),
            (0, "held", 1100),
            (0, "unclaimed", 1027),
        ):
            with (
                self.subTest(process_count=process_count, lease_state=lease_state),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                path = root / "native-agents.json"
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                with contextlib.ExitStack() as stack:
                    for name, value in (
                        ("STATE_ROOT", root),
                        ("LOCK_DIR", root / "locks"),
                        ("NATIVE_AGENT_REGISTRY_FILE", path),
                        (
                            "NATIVE_AGENT_REGISTRY_LOCK_FILE",
                            root / "locks" / "native-agents.lock",
                        ),
                    ):
                        stack.enter_context(patch.object(self.server, name, value))
                    for name, value in (
                        ("canonical_agent_id", "agent"),
                        ("_headless_descriptor", None),
                        ("agent_config", {"session": "managed"}),
                        ("tmux_alive", True),
                        ("require_managed_tmux_session", None),
                        ("ensure_agent_lease_available", None),
                        ("_tmux_args_for_session", []),
                        ("run_tmux", SimpleNamespace(returncode=0)),
                        (
                            "agent_home_process_summary",
                            {"process_count": process_count},
                        ),
                        ("release_agent", {"lease": {"state": lease_state}}),
                        ("close_runner_execution_fd", None),
                    ):
                        stack.enter_context(
                            patch.object(self.server, name, return_value=value)
                        )
                    lifecycle = stack.enter_context(
                        patch.object(
                            self.server,
                            "agent_lifecycle_lock",
                            return_value=contextlib.nullcontext(),
                        )
                    )
                    stack.enter_context(
                        patch(
                            "the_hive.native_registry.retained_pin_session_ids",
                            return_value=frozenset({"session-2"}),
                        )
                    )
                    if expected is None:
                        with self.assertRaises(self.server.AgentError):
                            self.server.stop_agent("agent")
                        self.assertEqual(json.loads(path.read_text()), document)
                    else:
                        self.server.stop_agent("agent")
                        stored = json.loads(path.read_text())
                        self.assertEqual(len(stored["sessions"]), expected)
                        self.assertEqual(stored["agents"], document["agents"])
                        self.assertTrue(
                            {"session-0", "session-1", "session-2"}
                            <= {row["session_id"] for row in stored["sessions"]}
                        )
                    lifecycle.assert_called_once()

    def test_terminal_session_history_and_persistent_reservations_have_separate_limits(
        self,
    ):
        from the_hive.native_registry import cleanup_registry

        reservations = [
            {
                "reservation_id": f"r-{i}",
                "kind": "headless_inflight",
                "created_at": 1.0,
                "agent": f"child-{i}",
                "assignment_id": f"session-{i}",
            }
            for i in range(1100)
        ]
        rows = [self.agent(i) for i in range(1100)]
        sessions = [self.session(i) for i in range(1100)]
        result = self.cleanup(self.registry(rows, sessions, reservations))
        self.assertEqual(result["reservations"], reservations)
        self.assertEqual(result["agents"], rows)
        self.assertEqual(result["sessions"], sessions)
        history = self.cleanup(self.registry(sessions=sessions))
        self.assertEqual(len(history["sessions"]), 1024)
        self.assertEqual(history["sessions"][0]["session_id"], "session-76")
        replacement = {
            "reservation_id": "replacement",
            "kind": "managed_replacement",
            "created_at": 2000.0,
            "managed_session": "managed",
        }
        managed = [self.session(i, managed_session="managed") for i in range(1100)]
        kept = cleanup_registry(
            self.registry(sessions=managed, reservations=[replacement]),
            now=2000,
            retained_session_ids=frozenset(),
            stopped_managed_sessions=frozenset({"managed"}),
        )
        self.assertEqual(kept["sessions"], managed)

    def test_mixed_byte_pressure_trims_eligible_history_before_rejecting(self):
        protected = [
            self.agent(i, "active", parent="p" * 128)
            | {"agent_id": f"{i:06d}" + "a" * 122, "agent_type": "t" * 64}
            for i in range(2200)
        ]
        protected_document = self.registry(protected)
        protected_size = len(
            (json.dumps(protected_document, sort_keys=True) + "\n").encode()
        )
        budget = protected_size + 2048
        self.assertLess(budget, 1024 * 1024)
        history = [self.agent(i + 10000) for i in range(100)]
        ended = [self.session(i) for i in range(100)]
        document = self.registry(protected + history, ended)
        self.assertGreater(
            len((json.dumps(document, sort_keys=True) + "\n").encode()), budget
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "native-agents.json"
            path.write_text(json.dumps(self.registry()))
            path.chmod(0o600)
            with (
                patch(
                    "the_hive.native_registry.retained_pin_session_ids",
                    return_value=frozenset(),
                ),
                patch.object(self.server, "NATIVE_AGENT_REGISTRY_FILE", path),
                patch.object(self.server, "MAX_NATIVE_AGENT_REGISTRY_BYTES", budget),
            ):
                self.server._write_native_agent_registry(document, now=2000)
            stored = json.loads(path.read_bytes())
            self.assertLessEqual(path.stat().st_size, budget)
            self.assertEqual(stored["agents"][: len(protected)], protected)
            remaining = stored["agents"][len(protected) :]
            self.assertGreater(len(remaining), 0)
            self.assertLess(len(remaining), len(history))
            self.assertEqual(remaining, history[-len(remaining) :])
            self.assertEqual(stored["sessions"], [])
