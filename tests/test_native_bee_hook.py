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

    def test_hooks_manifest_declares_four_command_hooks(self) -> None:
        payload = json.loads(HOOKS_MANIFEST.read_text(encoding="utf-8"))
        hooks = payload["hooks"]

        self.assertEqual([entry["event"] for entry in hooks], ["SessionStart", "SubagentStart", "SubagentStop", "SessionEnd"])
        for entry in hooks:
            with self.subTest(event=entry["event"]):
                self.assertEqual(entry["type"], "command")
                self.assertEqual(entry["timeout"], 1)
                self.assertEqual(entry["command"], "python3 $PLUGIN_ROOT/hooks/native_bee_event.py")

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

