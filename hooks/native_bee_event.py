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
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES)
    except Exception:
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
    try:
        from codex_master.server import record_native_agent_event
    except Exception:
        record_native_agent_event = None

    if callable(record_native_agent_event):
        try:
            record_native_agent_event(payload)
        except Exception:
            pass

    if event_name == "SubagentStop":
        try:
            sys.stdout.write("{}\n")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
