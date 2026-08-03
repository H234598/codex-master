import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "hooks" / "native_bee_event.py"
HOOKS_MANIFEST = REPO_ROOT / "hooks" / "hooks.json"
PLUGIN_MANIFEST = REPO_ROOT / ".codex-plugin" / "plugin.json"


class NativeBeeHookTest(unittest.TestCase):
    def run_hook(self, payload: str, *, state_root: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(REPO_ROOT)
        if state_root is not None:
            env["CODEX_MASTER_MCP_STATE"] = str(state_root)
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
            timeout=2,
            check=False,
        )

    def test_hooks_manifest_uses_official_event_group_schema(self) -> None:
        payload = json.loads(HOOKS_MANIFEST.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        events = ["SessionStart", "SubagentStart", "SubagentStop", "SessionEnd"]

        self.assertEqual(list(hooks), events)
        for event in events:
            with self.subTest(event=event):
                self.assertEqual(
                    hooks[event],
                    [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python3 ${PLUGIN_ROOT}/hooks/native_bee_event.py",
                                    "timeout": 1,
                                }
                            ]
                        }
                    ],
                )

    def test_plugin_manifest_points_at_hooks_manifest(self) -> None:
        payload = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(payload["hooks"], "./hooks/hooks.json")

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
            self.assertEqual(
                json.loads((state_root / "native-agents.json").read_text(encoding="utf-8")),
                {"schema_version": 1, "agents": []},
            )

    def test_subagent_start_stores_only_allowlisted_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = Path(tmpdir) / "state"
            transcript_secret = "/tmp/SECRET_TRANSCRIPT_PATH.jsonl"
            message_secret = "SECRET_LAST_ASSISTANT_MESSAGE"
            completed = self.run_hook(
                json.dumps(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": "thr_parent",
                        "agent_id": "agent_1",
                        "agent_type": "worker",
                        "agent_transcript_path": transcript_secret,
                        "last_assistant_message": message_secret,
                    }
                ),
                state_root=state_root,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            state_text = (state_root / "native-agents.json").read_text(encoding="utf-8")
            state = json.loads(state_text)
            self.assertEqual(state["schema_version"], 1)
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
            self.assertNotIn(transcript_secret, state_text)
            self.assertNotIn(message_secret, state_text)

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
