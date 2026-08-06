"""Read-only Hive/Selection tool catalog."""

from __future__ import annotations

from collections.abc import Mapping

from codex_master.hive.status import godbee_status, hive_status, queen_list, selection_status


_NAMES = (
    "hive_status", "godbee_status", "queen_list", "queen_status", "hive_dispatch_status", "hive_queue_status",
    "hive_decisions", "hive_authority_check", "hive_plan_dispatch", "hive_admission_status", "agent_selection_preview", "agent_selection_status",
)


def hive_tool_definitions() -> list[dict[str, object]]:
    return [
        {"name": name, "description": "Read-only Hive diagnostic", "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}}}
        for name in _NAMES
    ]


def call_hive_tool(name: str, args: Mapping[str, object] | None = None) -> Mapping[str, object]:
    if name not in _NAMES or (args is not None and not isinstance(args, Mapping)):
        raise ValueError("unknown_hive_tool")
    args = args or {}
    if args:
        raise ValueError("hive_tool_arguments_not_allowed")
    if name == "hive_status":
        return hive_status()
    if name == "godbee_status":
        return godbee_status()
    if name == "queen_list":
        return queen_list(offset=0, limit=32)
    if name == "queen_status":
        return {"state": "requires_context", "raw_output": "not_returned"}
    if name == "agent_selection_status":
        return selection_status()
    return {"state": "read_only_context_required", "raw_output": "not_returned"}


__all__ = ["call_hive_tool", "hive_tool_definitions"]
