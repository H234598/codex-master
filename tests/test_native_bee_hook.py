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
            timeout=2,
            check=False,
        )

    def run_spawn_hook(self, payload: str, *, state_root: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(REPO_ROOT)
        if state_root is not None:
            env["CODEX_MASTER_MCP_STATE"] = str(state_root)
        return subprocess.run(
            [sys.executable, str(SPAWN_HOOK)], input=payload, text=True, capture_output=True, env=env, timeout=2, check=False
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
                            "command": "python3 ${PLUGIN_ROOT}/hooks/native_spawn_admission.py",
                            "timeout": 1,
                        }
                    ],
                },
                {
                    "matcher": "send_input|multi_agent_v1__send_input",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python3 ${PLUGIN_ROOT}/hooks/native_bee_event.py",
                            "timeout": 1,
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
                            "command": "python3 ${PLUGIN_ROOT}/hooks/native_bee_event.py",
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
                    "command": "python3 ${PLUGIN_ROOT}/hooks/native_bee_event.py",
                    "timeout": 1,
                }
            ]
        }
        for event in events:
            with self.subTest(event=event):
                self.assertEqual(hooks[event], expected_by_event.get(event, [default]))

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
            patch("codex_master.server.reserve_native_agent_spawn", return_value={"allowed": True, "reservation_id": "res-token"}) as reserve,
        ):
            assert spec is not None and spec.loader is not None
            spec.loader.exec_module(module)
            result = module.main()

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        reserve.assert_called_once_with(payload)

    def test_plugin_manifest_points_at_hooks_manifest(self) -> None:
        payload = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(payload["hooks"], "./hooks/hooks.json")

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
