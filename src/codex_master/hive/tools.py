"""Hive/Selection tool catalog with injected test-evidence service."""

from __future__ import annotations

from collections.abc import Mapping
import time

from codex_master.hive.status import godbee_status, hive_status, queen_list, selection_status
from codex_master.hive.evidence_service import (
    HiveTestEvidenceService,
    build_local_test_service,
    probe_test_index,
)


_NAMES = (
    "hive_status", "godbee_status", "queen_list", "queen_status", "hive_dispatch_status", "hive_queue_status",
    "hive_decisions", "hive_authority_check", "hive_plan_dispatch", "hive_admission_status", "agent_selection_preview", "agent_selection_status",
)
_TEST_NAMES = (
    "hive_test_index_status",
    "hive_test_plan",
    "hive_test_run",
    "hive_test_status",
    "hive_test_invalidate",
)


def _test_tool_definitions() -> list[dict[str, object]]:
    digest = {"type": "string", "maxLength": 71}
    text = {"type": "string", "maxLength": 2048}
    empty = {"type": "object", "additionalProperties": False, "properties": {}}
    return [
        {"name": "hive_test_index_status", "description": "Validate canonical Hive test index", "inputSchema": empty},
        {
            "name": "hive_test_plan",
            "description": "Plan smallest required indexed test set",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "changed_paths": {"type": "array", "maxItems": 1000, "items": text},
                    "function_ids": {"type": "array", "maxItems": 1000, "items": text},
                    "phase": {"type": "string", "enum": ["change", "branch", "merge", "release"]},
                    "base_revision": {"type": "string", "maxLength": 256},
                    "target_revision": {"type": "string", "maxLength": 256},
                },
            },
        },
        {"name": "hive_test_status", "description": "Return bounded Hive test evidence status", "inputSchema": empty},
        {
            "name": "hive_test_run",
            "description": "Run one exact indexed local test node",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["test_id", "index_digest"],
                "properties": {"test_id": text, "index_digest": digest},
            },
        },
        {
            "name": "hive_test_invalidate",
            "description": "Invalidate one exact local evidence receipt",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["evidence_id", "index_digest"],
                "properties": {"evidence_id": digest, "index_digest": digest},
            },
        },
    ]


def hive_tool_definitions() -> list[dict[str, object]]:
    diagnostic = [
        {"name": name, "description": "Read-only Hive diagnostic", "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}}}
        for name in _NAMES
    ]
    return [*diagnostic, *_test_tool_definitions()]


def call_hive_tool(
    name: str,
    args: Mapping[str, object] | None = None,
    *,
    test_service: HiveTestEvidenceService | None = None,
) -> Mapping[str, object]:
    if name not in {*_NAMES, *_TEST_NAMES} or (args is not None and not isinstance(args, Mapping)):
        raise ValueError("unknown_hive_tool")
    args = args or {}
    if name in _NAMES and args:
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
    if name in _NAMES:
        return {"state": "read_only_context_required", "raw_output": "not_returned"}
    if name == "hive_test_index_status":
        if args:
            raise ValueError("hive_tool_arguments_not_allowed")
        return test_service.index_status() if test_service is not None else probe_test_index()
    service = test_service or build_local_test_service()
    if name == "hive_test_plan":
        request = service.request(
            changed_paths=_string_list(args.get("changed_paths", ()), "changed_paths"),
            function_ids=_string_list(args.get("function_ids", ()), "function_ids"),
            requested_phase=str(args.get("phase", "change")),
            base_revision=str(args.get("base_revision", "working-tree")),
            target_revision=str(args.get("target_revision", "working-tree")),
        )
        return service.plan(request, now_monotonic_ns=time.monotonic_ns()).public()
    if name == "hive_test_status":
        if args:
            raise ValueError("hive_tool_arguments_not_allowed")
        request = service.request()
        return service.status(request, now_monotonic_ns=time.monotonic_ns())
    if name == "hive_test_run":
        receipt = service.run(
            _required_text(args, "test_id"),
            expected_index_digest=_required_text(args, "index_digest"),
        )
        return {"evidence_id": receipt.evidence_id, "receipt": receipt.public()}
    service.invalidate(
        _required_text(args, "evidence_id"),
        expected_index_digest=_required_text(args, "index_digest"),
    )
    return {"invalidated": True, "evidence_id": args["evidence_id"]}


def _required_text(args: Mapping[str, object], field: str) -> str:
    value = args.get(field)
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("test.index_invalid")
    return value


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 1000:
        raise ValueError("test.index_invalid")
    values = tuple(value)
    if any(not isinstance(item, str) or not item or len(item) > 2048 for item in values):
        raise ValueError("test.index_invalid")
    if field == "changed_paths" and any(item.startswith("/") or ".." in item.split("/") for item in values):
        raise ValueError("test.index_invalid")
    return values


__all__ = ["call_hive_tool", "hive_tool_definitions"]
