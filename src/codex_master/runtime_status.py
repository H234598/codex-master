"""Autonomous runtime-image and direct MCP-surface status checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Any

from codex_master.runtime_layout import LayoutError, RuntimeLayout, validate_runtime_metadata


_MCP_SERVER_NAME = "codex-master-mcp"
_MCP_PROTOCOL_VERSION = "2024-11-05"
_MAX_MCP_OUTPUT_BYTES = 256 * 1024
_MCP_TIMEOUT_SECONDS = 10


class _McpProbeError(RuntimeError):
    pass


class _McpProbeTimeout(_McpProbeError):
    pass


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
    return b"".join(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n" for message in messages)


def _probe_environment() -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    home = os.environ.get("HOME")
    if home and Path(home).is_absolute():
        environment["HOME"] = home
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait()


def _run_direct_mcp(layout: RuntimeLayout) -> tuple[int, str]:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout: Any = None
    try:
        process = subprocess.Popen(
            [str(layout.mcp_entrypoint)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=layout.root,
            env=_probe_environment(),
            close_fds=True,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None:
            raise _McpProbeError("mcp_pipe_unavailable")
        try:
            process.stdin.write(_probe_payload())
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
        stdout = process.stdout
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + _MCP_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _McpProbeTimeout("mcp_timeout")
            ready = selector.select(remaining)
            if not ready:
                raise _McpProbeTimeout("mcp_timeout")
            for key, _ in ready:
                chunk = os.read(key.fileobj.fileno(), min(8192, _MAX_MCP_OUTPUT_BYTES + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > _MAX_MCP_OUTPUT_BYTES:
                    raise _McpProbeError("mcp_output_too_large")
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise _McpProbeTimeout("mcp_timeout") from exc
        return returncode, output.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise _McpProbeError("mcp_unavailable") from exc
    finally:
        if selector is not None:
            selector.close()
        if stdout is not None:
            stdout.close()
        if process is not None:
            _terminate(process)


def _mcp_surface(returncode: int, output: str) -> dict[str, object]:
    initialized = False
    tools_list = False
    tool_count = 0
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            continue
        if payload.get("id") == 1:
            result = payload.get("result")
            server_info = result.get("serverInfo") if isinstance(result, dict) else None
            if (
                isinstance(result, dict)
                and result.get("protocolVersion") == _MCP_PROTOCOL_VERSION
                and isinstance(result.get("capabilities"), dict)
                and isinstance(server_info, dict)
                and server_info.get("name") == _MCP_SERVER_NAME
            ):
                initialized = True
        if payload.get("id") == 2:
            result = payload.get("result")
            tools = result.get("tools") if isinstance(result, dict) else None
            if isinstance(tools, list):
                tool_count = sum(
                    1
                    for tool in tools
                    if isinstance(tool, dict) and isinstance(tool.get("name"), str) and tool["name"]
                )
                tools_list = True
    ok = returncode == 0 and initialized and tools_list
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
        active_layout = RuntimeLayout.from_module_path(Path(__file__)) if layout is None else layout
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
    except _McpProbeTimeout:
        surface = _blocked_surface("mcp_timeout")
    except _McpProbeError:
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
