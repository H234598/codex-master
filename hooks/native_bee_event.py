#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


MAX_STDIN_BYTES = 65537
PLUGIN_ROOT = Path(os.environ.get("PLUGIN_ROOT") or Path(__file__).resolve().parents[1])
SRC_ROOT = PLUGIN_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _read_payload() -> dict[str, object] | None:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    except Exception:
        return None
    if len(raw) > MAX_STDIN_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def main() -> int:
    payload = _read_payload()
    if payload is None:
        return 0

    event_name = payload.get("hook_event_name")
    if event_name == "PreToolUse":
        try:
            from codex_master.server import activate_native_agent_resume

            result = activate_native_agent_resume(payload)
        except Exception:
            result = {
                "allowed": False,
                "error_code": "reservation_unavailable",
                "reason_codes": ["hook_error"],
            }
        if result.get("allowed") is not True:
            code = result.get("error_code", "spawn_capacity_unavailable")
            reasons = result.get("reason_codes", ["session_metrics_unavailable"])
            reason = f"error_code={code} reason_codes={','.join(reasons)}"
            sys.stdout.write(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": reason,
                        }
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
        return 0

    try:
        from codex_master.server import record_native_agent_event
    except Exception:
        record_native_agent_event = None

    if callable(record_native_agent_event):
        try:
            record_native_agent_event(payload)
        except Exception:
            pass

    if event_name in {"SubagentStop", "Stop"}:
        try:
            sys.stdout.write("{}\n")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
