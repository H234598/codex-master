#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

MAX_STDIN_BYTES = 65537
SPAWN_TOOL_NAMES = {"spawn_agent", "multi_agent_v1__spawn_agent"}
PLUGIN_ROOT = Path(os.environ.get("PLUGIN_ROOT") or Path(__file__).resolve().parents[1])
SRC_ROOT = PLUGIN_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _deny(error_code: str, reason_codes: list[str]) -> int:
    reason = f"error_code={error_code} reason_codes={','.join(reason_codes)}"
    sys.stdout.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, separators=(",", ":")) + "\n")
    return 0


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            return _deny("invalid_pretooluse_input", ["input_too_large"])
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            return _deny("invalid_pretooluse_input", ["invalid_input"])
        if payload.get("hook_event_name") != "PreToolUse" or payload.get("tool_name") not in SPAWN_TOOL_NAMES:
            return _deny("invalid_pretooluse_input", ["invalid_input"])
        if not isinstance(payload.get("session_id"), str) or not payload["session_id"]:
            return _deny("invalid_pretooluse_input", ["invalid_input"])
        if not isinstance(payload.get("tool_input"), dict) or not isinstance(payload.get("cwd"), str):
            return _deny("invalid_pretooluse_input", ["invalid_input"])
        from codex_master.server import reserve_native_agent_spawn
        result = reserve_native_agent_spawn(payload)
        if not isinstance(result, dict) or result.get("allowed") is not True:
            code = result.get("error_code", "spawn_capacity_unavailable") if isinstance(result, dict) else "reservation_unavailable"
            reasons = result.get("reason_codes", ["session_metrics_unavailable"]) if isinstance(result, dict) else ["reservation_error"]
            if not isinstance(code, str) or not code:
                code = "reservation_unavailable"
            if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
                reasons = ["reservation_error"]
            return _deny(code, reasons)
        return 0
    except Exception:
        return _deny("reservation_unavailable", ["hook_error"])


if __name__ == "__main__":
    raise SystemExit(main())
