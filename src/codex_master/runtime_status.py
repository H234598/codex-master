"""Autonomous runtime-image and direct MCP-surface status checks."""

from __future__ import annotations

import json
from pathlib import Path

from codex_master.runtime_layout import (
    LayoutError,
    RuntimeLayout,
    validate_runtime_metadata,
)
from codex_master.runtime_process import (
    BoundedProcessError,
    DEFAULT_STDERR_LIMIT,
    run_bounded,
)


_MCP_SERVER_NAME = "codex-master-mcp"
_MCP_PROTOCOL_VERSION = "2024-11-05"
_MAX_MCP_OUTPUT_BYTES = 256 * 1024
_MCP_TIMEOUT_SECONDS = 10
_REQUIRED_AUTONOMOUS_TOOL = "runtime_status"


def _probe_payload() -> bytes:
    messages = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "codex-master-runtime-status", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    return b"".join(
        json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        for message in messages
    )


def _run_direct_mcp(layout: RuntimeLayout) -> tuple[int, str]:
    try:
        result = run_bounded(
            [str(layout.mcp_entrypoint)],
            cwd=layout.root,
            home=Path.home(),
            timeout_seconds=_MCP_TIMEOUT_SECONDS,
            stdout_limit=_MAX_MCP_OUTPUT_BYTES,
            stderr_limit=DEFAULT_STDERR_LIMIT,
            input_data=_probe_payload(),
            runtime_layout=layout,
        )
    except BoundedProcessError as exc:
        if exc.code == "command_timeout":
            raise TimeoutError from exc
        raise RuntimeError from exc
    return result.returncode, result.stdout


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build one JSON object while rejecting duplicate member names."""

    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def _is_runtime_status_input_schema(schema: object) -> bool:
    """Require the closed, empty schema with exact JSON value types."""

    return (
        type(schema) is dict
        and set(schema) == {"type", "properties", "additionalProperties"}
        and schema.get("type") == "object"
        and type(schema.get("properties")) is dict
        and not schema["properties"]
        and type(schema.get("additionalProperties")) is bool
        and schema["additionalProperties"] is False
    )


def _mcp_surface(returncode: int, output: str) -> dict[str, object]:
    initialized = False
    tools_list = False
    tool_count = 0
    tools_contract_valid = False
    invalid = False
    lines = output.splitlines()
    if len(lines) != 2:
        invalid = True
    for expected_id, line in zip((1, 2), lines):
        try:
            payload = json.loads(line, object_pairs_hook=_unique_json_object)
        except (json.JSONDecodeError, ValueError):
            invalid = True
            break
        if (
            type(payload) is not dict
            or set(payload) != {"jsonrpc", "id", "result"}
            or payload.get("jsonrpc") != "2.0"
            or type(payload.get("id")) is not int
            or payload["id"] != expected_id
        ):
            invalid = True
            break
        response_id = payload["id"]
        if response_id == 1:
            result = payload.get("result")
            server_info = result.get("serverInfo") if isinstance(result, dict) else None
            if (
                type(result) is dict
                and set(result) == {"protocolVersion", "capabilities", "serverInfo"}
                and result.get("protocolVersion") == _MCP_PROTOCOL_VERSION
                and result.get("capabilities")
                == {"tools": {}, "resources": {}, "prompts": {}}
                and type(server_info) is dict
                and set(server_info) == {"name", "version"}
                and server_info.get("name") == _MCP_SERVER_NAME
                and isinstance(server_info.get("version"), str)
                and server_info["version"]
            ):
                initialized = True
            else:
                invalid = True
                break
        else:
            result = payload.get("result")
            tools = result.get("tools") if isinstance(result, dict) else None
            if (
                type(result) is dict
                and set(result) == {"tools"}
                and type(tools) is list
            ):
                tool_count = len(tools)
                tools_list = True
                tools_contract_valid = (
                    len(tools) == 1
                    and type(tools[0]) is dict
                    and set(tools[0]) == {"name", "description", "inputSchema"}
                    and tools[0].get("name") == _REQUIRED_AUTONOMOUS_TOOL
                    and isinstance(tools[0].get("description"), str)
                    and bool(tools[0]["description"])
                    and _is_runtime_status_input_schema(tools[0].get("inputSchema"))
                )
                if not tools_contract_valid:
                    invalid = True
            else:
                invalid = True
                break
    ok = (
        returncode == 0
        and initialized
        and tools_list
        and tools_contract_valid
        and len(lines) == 2
        and not invalid
    )
    return {
        "ok": ok,
        "initialize": initialized,
        "tools_list": tools_list,
        "tool_count": tool_count,
        "reason_code": "ok" if ok else "mcp_surface_invalid",
    }


def _blocked_surface(reason_code: str) -> dict[str, object]:
    return {
        "ok": False,
        "initialize": False,
        "tools_list": False,
        "tool_count": 0,
        "reason_code": reason_code,
    }


def runtime_status(*, layout: RuntimeLayout | None = None) -> dict[str, object]:
    """Check only the image metadata and its direct MCP initialize/tools surface."""

    try:
        active_layout = (
            RuntimeLayout.from_module_path(Path(__file__)) if layout is None else layout
        )
        validate_runtime_metadata(active_layout)
    except (LayoutError, TypeError, ValueError):
        return {
            "ok": False,
            "metadata": {"ok": False, "reason_code": "metadata_invalid"},
            "mcp_surface": _blocked_surface("metadata_invalid"),
            "raw_output": "not_returned",
        }
    try:
        returncode, output = _run_direct_mcp(active_layout)
    except TimeoutError:
        surface = _blocked_surface("mcp_timeout")
    except RuntimeError:
        surface = _blocked_surface("mcp_unavailable")
    else:
        surface = _mcp_surface(returncode, output)
    return {
        "ok": bool(surface["ok"]),
        "metadata": {"ok": True, "reason_code": "ok"},
        "mcp_surface": surface,
        "raw_output": "not_returned",
    }


__all__ = ["runtime_status"]
