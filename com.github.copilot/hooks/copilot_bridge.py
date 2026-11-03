#!/usr/bin/env python3
"""Route Copilot CLI hook events into the Codex-contract hooks of The Hive.

Copilot names its subagent tools differently from Codex. This bridge maps
them onto the names the existing hooks/native_*.py scripts expect and forwards
the payload unchanged otherwise. Spawn and resume checks stay fail-closed.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - only fixed-argv subprocess calls below, no shell
import sys
from pathlib import Path

MAX_STDIN_BYTES = 65537
HOOKS_DIR = Path(__file__).resolve().parents[2] / "hooks"
ADMISSION = "native_spawn_admission.py"
BEE_EVENT = "native_bee_event.py"
SPAWN_TOOLS = {"task": "spawn_agent", "Task": "spawn_agent", "Agent": "spawn_agent"}
SEND_TOOLS = {"write_agent": "send_input"}
WAIT_TOOLS = {"read_agent": "wait_agent"}
LIFECYCLE_EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
}


def route_for(payload: dict[str, object]) -> tuple[str, str | None] | None:
    """Return (hook script, rewritten tool name) or None when not ours."""
    event = payload.get("hook_event_name")
    tool = payload.get("tool_name")
    if event == "PreToolUse" and isinstance(tool, str):
        if tool in SPAWN_TOOLS:
            return ADMISSION, SPAWN_TOOLS[tool]
        if tool in SEND_TOOLS:
            return BEE_EVENT, SEND_TOOLS[tool]
        return None
    if event == "PostToolUse" and isinstance(tool, str):
        if tool in WAIT_TOOLS:
            return BEE_EVENT, WAIT_TOOLS[tool]
        return None
    if event in LIFECYCLE_EVENTS:
        return BEE_EVENT, None
    return None


def _deny_pretool() -> int:
    sys.stdout.write(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "error_code=reservation_unavailable reason_codes=hook_error",
                }
            },
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    try:
        if len(raw) > MAX_STDIN_BYTES:
            raise ValueError("input_too_large")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("invalid_input")
    except ValueError:
        return 0

    route = route_for(payload)
    if route is None:
        return 0
    script, tool_name = route
    is_pretool = payload.get("hook_event_name") == "PreToolUse"
    forwarded = dict(payload)
    if tool_name is not None:
        forwarded["tool_name"] = tool_name
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv to our own hook script, no shell
            [sys.executable, str(HOOKS_DIR / script)],
            input=json.dumps(forwarded).encode("utf-8"),
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _deny_pretool() if is_pretool else 0
    if proc.returncode != 0:
        return _deny_pretool() if is_pretool else 0
    sys.stdout.write(proc.stdout.decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
