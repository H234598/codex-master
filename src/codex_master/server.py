"""MCP server and CLI for controlling two local Codex instances via tmux.

The public tool surface is intentionally data-sparse. Raw terminal output is
written to local state files only; tool responses return structured status or
explicitly requested, size-limited, redacted excerpts.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import fcntl
import json
import os
import re
import shutil
import shlex
import stat as stat_module
import subprocess
import sys
import time
import tomllib
import uuid
from pathlib import Path
from typing import Any

from codex_master import __version__


STATE_ROOT = Path(
    os.environ.get("CODEX_MASTER_MCP_STATE")
    or os.environ.get("CODEX_AGENT_MCP_STATE")
    or "~/.local/state/codex-master-mcp"
).expanduser()
LEGACY_STATE_ROOT = Path("~/.local/state/codex-agent-mcp").expanduser()
RAW_DIR = STATE_ROOT / "raw"
META_DIR = STATE_ROOT / "meta"
LOCK_DIR = STATE_ROOT / "locks"
LEASE_DIR = STATE_ROOT / "leases"
ASSIGNMENT_LOG = STATE_ROOT / "assignments.jsonl"
LEGACY_META_DIR = LEGACY_STATE_ROOT / "meta"
DEFAULT_AGENT_MODEL = "gpt-5.4-mini"
DEFAULT_AGENT_MODEL_EFFORT = "medium"
WRITE_AGENT_MODEL = "gpt-5.3-codex-spark"
WRITE_AGENT_MODEL_EFFORT = "low"
BASE_ARGS = [
    "--model",
    DEFAULT_AGENT_MODEL,
    "-c",
    f'model="{DEFAULT_AGENT_MODEL}"',
    "-c",
    f'model_reasoning_effort="{DEFAULT_AGENT_MODEL_EFFORT}"',
    "--yolo",
    "-s",
    "danger-full-access",
    "--search",
]
MAX_TAIL_LINES = 80
MAX_TAIL_CHARS = 8192
MAX_RAW_LOG_BYTES = 5 * 1024 * 1024
MAX_RAW_LOG_FILES = 20
RAW_LOG_CHUNK_BYTES = 64 * 1024
MAX_LIMIT_STATUS_BYTES = 16 * 1024
IDLE_RESPONSE_SECONDS = 300
DEFAULT_WAIT_SECONDS = 120
MAX_WAIT_SECONDS = 600
DEFAULT_WAIT_POLL_SECONDS = 30
MAX_WAIT_POLL_SECONDS = 900
DEFAULT_AGENT_LEASE_SECONDS = 1800
MAX_AGENT_LEASE_SECONDS = 7200
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
MCP_SERVER_NAME = "codex-master-mcp"
DEFAULT_INSTALL_PATH = Path("~/.local/bin/codex-master-mcp").expanduser()
MAX_SKILL_NAMES = 200
MAX_CAPABILITY_PLUGINS = 20
MAX_ASSIGNMENT_RECORDS = 100
MAX_ASSIGNMENT_LOG_RECORDS = 500
MAX_ASSIGNMENT_LOG_BYTES = 1024 * 1024
MAX_ASSIGNMENT_TEXT = 12000
MAX_SEND_TEXT = 12000
MAX_TASK_TEXT = 4000
MAX_TEXT_FIELD = 1000
MAX_ASSIGNMENT_LIST_ITEMS = 50
MAX_AGENTIN_NAME = 80
MAX_SKILL_REF = 300
MAX_PATH_TEXT = 1000
MAX_ASSIGNMENT_ID = 200
MAX_RPC_MESSAGE_BYTES = 1024 * 1024
MAX_ERROR_CHARS = 1200
MAX_META_BYTES = 64 * 1024
MAX_CODEX_CONFIG_BYTES = 1024 * 1024
MAX_PLUGIN_MANIFEST_BYTES = 64 * 1024
MAX_PLUGIN_CACHE_VERSIONS = 20
MAX_PLUGIN_CACHE_RETAINED_VERSIONS = 5
PLUGIN_CACHE_ALLOWED_FILES = (".app.json", ".mcp.json", "README.md", "pyproject.toml")
PLUGIN_CACHE_ALLOWED_DIRS = (".codex-plugin", "bin", "skills", "src")
PLUGIN_CACHE_EXCLUDED_NAMES = (".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__")
PLUGIN_CACHE_EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".swp", ".swo", ".tmp", ".bak", ".orig", ".rej", "~")
COMMAND_TIMEOUT_RETURN_CODE = 124
DEFAULT_TMUX_TIMEOUT_SECONDS = 10
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS = 10
RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS = 120
DEFAULT_AGENTIN_NAMES = {"a": "Mila", "b": "Nora"}
RAW_LOG_TRUNCATION_MARKER = b"\n... codex-master-mcp retained the last raw log bytes ...\n"
MCP_SERVER_TABLE_HEADER = f"[mcp_servers.{MCP_SERVER_NAME}]"
APP_BRIDGE_NAME = "codex-master"
SERVER_INSTANCE_ID = os.environ.get("CODEX_MASTER_MCP_INSTANCE_ID") or uuid.uuid4().hex
APP_BRIDGE_ID_PREFIXES = ("connector_", "asdk_app_")
PLUGIN_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,199}$")
BRACKETED_PASTE_BEGIN = "\x1b[200~"
BRACKETED_PASTE_END = "\x1b[201~"
PATH_NOT_RETURNED = "not_returned"


AGENTS = {
    "a": {
        "label": "Codex Agentin A",
        "runner": Path(os.environ.get("CODEX_AGENT_A_RUNNER", "/home/teladi/.codex-agent-a/codex")),
        "home": Path(os.environ.get("CODEX_AGENT_A_HOME", "/home/teladi/.codex-agent-a")),
        "session": os.environ.get("CODEX_AGENT_A_SESSION", "codex_agent_a_mcp"),
    },
    "b": {
        "label": "Codex Agentin B",
        "runner": Path(os.environ.get("CODEX_AGENT_B_RUNNER", "/home/teladi/.codex-agent-b/codex")),
        "home": Path(os.environ.get("CODEX_AGENT_B_HOME", "/home/teladi/.codex-agent-b")),
        "session": os.environ.get("CODEX_AGENT_B_SESSION", "codex_agent_b_mcp"),
    },
}


ANSI_RE = re.compile(
    r"(?:\x1B[@-Z\\-_]|\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07]*(?:\x07|\x1B\\))"
)
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_\-]{12,})\b"),
    re.compile(r"(?i)\b(sess-[A-Za-z0-9_\-]{12,})\b"),
    re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9_]{12,})\b"),
    re.compile(r"(?i)\b(xox[baprs]-[A-Za-z0-9\-]{12,})\b"),
    re.compile(
        r"(?i)\b((?:api|access|auth|bearer|codex|openai)[_\- ]?(?:key|token|secret))\s*[:=]\s*['\"]?([^'\"\s]{8,})"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
]
ABSOLUTE_PATH_RE = re.compile(r"(?<![\w.-])(?:/[^\s\"'<>:;,)}\]]+)+")


class AgentError(RuntimeError):
    """Raised for expected agent-control failures."""


class AgentBusyError(AgentError):
    """Raised when an Agentin is leased by a different MCP client."""

    def __init__(self, message: str, payload: dict[str, Any]):
        super().__init__(message)
        self.payload = payload


def public_error_payload(exc: Exception) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": safe_error_text(exc)}
    if isinstance(exc, AgentBusyError):
        payload.update(exc.payload)
    return payload


def ensure_state() -> None:
    for path in (STATE_ROOT, RAW_DIR, META_DIR, LOCK_DIR, LEASE_DIR):
        ensure_private_dir(path)
    prune_raw_logs()


def ensure_private_dir(path: Path) -> None:
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.absolute()
    ensure_directory_chain_no_symlink(path.parent, "private state parent directories must be real directories")
    try:
        current = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            current = path.lstat()
        else:
            current = path.lstat()
    if stat_module.S_ISLNK(current.st_mode):
        raise AgentError("private state directory must not be a symlink")
    if not stat_module.S_ISDIR(current.st_mode):
        raise AgentError("private state path is not a directory")
    try:
        current = path.lstat()
    except FileNotFoundError as exc:
        raise AgentError("private state directory disappeared") from exc
    if stat_module.S_ISLNK(current.st_mode) or not stat_module.S_ISDIR(current.st_mode):
        raise AgentError("private state directory changed unexpectedly")
    try:
        path.chmod(0o700)
    except PermissionError:
        pass


def ensure_directory_chain_no_symlink(path: Path, error_text: str) -> None:
    if not path.is_absolute():
        raise AgentError(error_text)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir()
            except FileExistsError:
                current_stat = current.lstat()
            except OSError as exc:
                raise AgentError(error_text) from exc
            else:
                current_stat = current.lstat()
        except OSError as exc:
            raise AgentError(error_text) from exc
        if stat_module.S_ISLNK(current_stat.st_mode) or not stat_module.S_ISDIR(current_stat.st_mode):
            raise AgentError(error_text)


def directory_chain_is_real_no_symlink(path: Path) -> bool:
    if not path.is_absolute():
        return False
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            current_stat = current.lstat()
        except OSError:
            return False
        if stat_module.S_ISLNK(current_stat.st_mode) or not stat_module.S_ISDIR(current_stat.st_mode):
            return False
    return True


def now_id() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_wrapper_path() -> Path:
    return repo_root() / "bin" / "codex-master-mcp"


def normalized_compare_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    try:
        return expanded.resolve(strict=False)
    except (OSError, RuntimeError):
        return expanded.absolute()


def codex_home_context() -> dict[str, Any]:
    raw_codex_home = os.environ.get("CODEX_HOME")
    classification = classify_codex_home(raw_codex_home)

    return {
        "name": "codex_home_context",
        "ok": classification["ok"],
        "codex_home_env": "set" if raw_codex_home else "unset",
        "home_kind": classification["home_kind"],
        "matched_agent": classification["matched_agent"],
        "mcp_visibility": classification["mcp_visibility"],
        "active_home_path": "not_returned",
        "raw_output": "not_returned",
    }


def classify_codex_home(raw_codex_home: str | None) -> dict[str, Any]:
    active_home = Path(raw_codex_home).expanduser() if raw_codex_home else Path.home() / ".codex"
    active_home_cmp = normalized_compare_path(active_home)
    default_home_cmp = normalized_compare_path(Path.home() / ".codex")

    matched_agent = None
    for agent, cfg in AGENTS.items():
        if active_home_cmp == normalized_compare_path(cfg["home"]):
            matched_agent = agent
            break

    if matched_agent:
        return {
            "ok": False,
            "home_kind": "managed_agent_home",
            "matched_agent": matched_agent,
            "mcp_visibility": "not_expected_for_master_mcp",
        }
    if active_home_cmp == default_home_cmp:
        return {
            "ok": True,
            "home_kind": "main_default_home",
            "matched_agent": None,
            "mcp_visibility": "expected_if_registered",
        }
    return {
        "ok": True,
        "home_kind": "custom_home",
        "matched_agent": None,
        "mcp_visibility": "depends_on_custom_home_registration",
    }


def codex_config_path() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    root = Path(codex_home).expanduser() if codex_home else Path.home() / ".codex"
    if not root.is_absolute():
        root = Path.cwd() / root
    return root / "config.toml"


def updated_mcp_startup_timeout_config(text: str) -> tuple[str, bool, int | None]:
    lines = text.splitlines()
    previous: int | None = None
    section_start: int | None = None
    section_end = len(lines)

    for index, line in enumerate(lines):
        if line.strip() == MCP_SERVER_TABLE_HEADER:
            section_start = index
            break

    if section_start is None:
        prefix = lines[:]
        if prefix and prefix[-1].strip():
            prefix.append("")
        prefix.extend([MCP_SERVER_TABLE_HEADER, f"startup_timeout_sec = {RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS}"])
        return "\n".join(prefix) + "\n", True, previous

    for index in range(section_start + 1, len(lines)):
        stripped = lines[index].lstrip()
        if stripped.startswith("[") and not stripped.startswith("[["):
            section_end = index
            break

    timeout_line_re = re.compile(r"^(\s*startup_timeout_sec\s*=\s*)(\d+)(\s*(?:#.*)?)$")
    for index in range(section_start + 1, section_end):
        match = timeout_line_re.match(lines[index])
        if not match:
            continue
        previous = int(match.group(2))
        if previous >= RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS:
            return text if text.endswith("\n") else text + "\n", False, previous
        lines[index] = f"{match.group(1)}{RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS}{match.group(3)}"
        return "\n".join(lines) + "\n", True, previous

    insert_at = section_end
    while insert_at > section_start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, f"startup_timeout_sec = {RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS}")
    return "\n".join(lines) + "\n", True, previous


def ensure_mcp_startup_timeout_configured(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or codex_config_path()
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    ensure_directory_chain_no_symlink(path.parent, "codex config parent directories must be real directories")
    if path.exists() or path.is_symlink():
        if path.is_symlink():
            raise AgentError("codex config path must be a regular file")
        text = read_private_regular_text(path, MAX_CODEX_CONFIG_BYTES, "could not read codex config")
    else:
        text = ""
    new_text, changed, previous = updated_mcp_startup_timeout_config(text)
    if changed:
        replace_private_text(path, new_text)
    return {
        "status": "updated" if changed else "already_configured",
        "startup_timeout_sec": RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS,
        "previous_startup_timeout_sec": previous,
        "config_path": "not_returned",
        "raw_output": "not_returned",
    }


def codex_client_mcp_config_status(
    config_path: Path | None = None,
    command_path: Path = DEFAULT_INSTALL_PATH,
) -> dict[str, Any]:
    path = config_path or codex_config_path()
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    result: dict[str, Any] = {
        "name": "codex_client_mcp_config",
        "path": PATH_NOT_RETURNED,
        "path_state": "missing",
        "exists": False,
        "regular_file": False,
        "symlink": False,
        "server": MCP_SERVER_NAME,
        "server_declared": False,
        "command_configured": False,
        "command_matches_install_path": False,
        "startup_timeout_sec": None,
        "startup_timeout_ok": False,
        "startup_timeout_recommended_sec": RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS,
        "ok": False,
        "raw_output": "not_returned",
    }
    try:
        current = path.lstat()
    except FileNotFoundError:
        result["reason"] = "codex_config_missing"
        return result
    except OSError:
        result["path_state"] = "error"
        result["reason"] = "codex_config_unreadable"
        return result
    result.update(
        {
            "path_state": "set",
            "exists": True,
            "regular_file": stat_module.S_ISREG(current.st_mode),
            "symlink": stat_module.S_ISLNK(current.st_mode),
        }
    )
    if result["symlink"] or not result["regular_file"]:
        result["reason"] = "codex_config_not_regular_file"
        return result
    try:
        text = read_private_regular_text(path, MAX_CODEX_CONFIG_BYTES, "could not read codex config")
    except AgentError:
        result["reason"] = "codex_config_unreadable"
        return result
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        result["reason"] = "codex_config_invalid_toml"
        return result
    mcp_servers = payload.get("mcp_servers")
    server_config = mcp_servers.get(MCP_SERVER_NAME) if isinstance(mcp_servers, dict) else None
    if not isinstance(server_config, dict):
        result["reason"] = "mcp_server_not_declared"
        return result

    command = server_config.get("command")
    command_configured = isinstance(command, str) and bool(command.strip())
    startup_timeout = server_config.get("startup_timeout_sec")
    startup_timeout_sec = (
        startup_timeout if isinstance(startup_timeout, int) and not isinstance(startup_timeout, bool) else None
    )
    startup_timeout_ok = (
        startup_timeout_sec is not None and startup_timeout_sec >= RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS
    )
    command_matches = command_configured and command.strip() == str(command_path)
    result.update(
        {
            "server_declared": True,
            "command_configured": command_configured,
            "command_matches_install_path": command_matches,
            "startup_timeout_sec": startup_timeout_sec,
            "startup_timeout_ok": startup_timeout_ok,
            "ok": command_matches and startup_timeout_ok,
        }
    )
    if not result["ok"]:
        if not command_configured:
            result["reason"] = "mcp_command_missing"
        elif not command_matches:
            result["reason"] = "mcp_command_mismatch"
        else:
            result["reason"] = "mcp_startup_timeout_too_low"
    return result


def assert_install_context_allows_master_registration() -> None:
    context = codex_home_context()
    if context["home_kind"] == "managed_agent_home":
        raise AgentError("refusing to register Master MCP inside a managed Agentin home")


def agent_ids(agent: str) -> list[str]:
    if agent in ("all", "both"):
        return ["a", "b"]
    if agent not in AGENTS:
        raise AgentError(f"unknown agent: {agent!r}; expected a, b, both, or all")
    return [agent]


def timeout_output_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def timeout_completed_process(args: list[str], exc: subprocess.TimeoutExpired, label: str) -> subprocess.CompletedProcess[str]:
    stdout = timeout_output_text(exc.stdout)
    stderr = timeout_output_text(exc.stderr)
    if not stderr:
        stderr = f"{label} timed out after {exc.timeout} seconds"
    return subprocess.CompletedProcess(args, COMMAND_TIMEOUT_RETURN_CODE, stdout, stderr)


def run_tmux(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = DEFAULT_TMUX_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    command = ["tmux", *args]
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        cp = timeout_completed_process(command, exc, "tmux command")
        if check:
            raise subprocess.CalledProcessError(cp.returncode, cp.args, output=cp.stdout, stderr=cp.stderr) from exc
        return cp


def run_command(
    args: list[str],
    *,
    check: bool = False,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    timeout: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        cp = timeout_completed_process(args, exc, "command")
        if check:
            raise subprocess.CalledProcessError(cp.returncode, cp.args, output=cp.stdout, stderr=cp.stderr) from exc
        return cp


def mcp_initialize_probe_payload() -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "codex-master-install-probe", "version": "0"},
            },
        },
        separators=(",", ":"),
    ) + "\n"


def mcp_tools_list_probe_payload() -> str:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "codex-master-tools-probe", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    return "".join(json.dumps(message, separators=(",", ":")) + "\n" for message in messages)


def iter_json_objects(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    payloads: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            payload, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads


def mcp_probe_response_ok(output: str) -> bool:
    for payload in iter_json_objects(output):
        if not isinstance(payload, dict) or payload.get("id") != 1:
            continue
        if payload.get("jsonrpc") != "2.0":
            continue
        result = payload.get("result")
        if not isinstance(result, dict):
            continue
        if result.get("protocolVersion") not in SUPPORTED_PROTOCOL_VERSIONS:
            continue
        if not isinstance(result.get("capabilities"), dict):
            continue
        server_info = result.get("serverInfo")
        if isinstance(server_info, dict) and server_info.get("name") == MCP_SERVER_NAME:
            return True
    return False


def mcp_tools_list_probe_result(output: str, required_tool: str) -> dict[str, Any]:
    for payload in iter_json_objects(output):
        if payload.get("id") != 2 or payload.get("jsonrpc") != "2.0":
            continue
        result = payload.get("result")
        if not isinstance(result, dict):
            break
        tools = result.get("tools")
        if not isinstance(tools, list):
            break
        names = [tool.get("name") for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)]
        return {
            "response_found": True,
            "tool_count": len(names),
            "required_tool": required_tool,
            "required_tool_available": required_tool in names,
            "raw_output": "not_returned",
        }
    return {
        "response_found": False,
        "tool_count": 0,
        "required_tool": required_tool,
        "required_tool_available": False,
        "raw_output": "not_returned",
    }


def mcp_command_startup_self_test(
    command_path: Path,
    *,
    timeout: int = DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    command = [str(command_path)]
    try:
        cp = subprocess.run(
            command,
            input=mcp_initialize_probe_payload(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except OSError:
        return {
            "ok": False,
            "status": "unavailable",
            "timeout_seconds": timeout,
            "raw_output": "not_returned",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "timeout_seconds": timeout,
            "raw_output": "not_returned",
        }

    output = cp.stdout + cp.stderr
    ok = cp.returncode == 0 and mcp_probe_response_ok(output)
    return {
        "ok": ok,
        "status": "ok" if ok else "failed",
        "returncode": cp.returncode,
        "timeout_seconds": timeout,
        "raw_output": "not_returned",
    }


def mcp_command_tools_list_self_test(
    command_path: Path,
    *,
    required_tool: str = "master_app_bridge_status",
    timeout: int = DEFAULT_MCP_STARTUP_SELF_TEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    command = [str(command_path)]
    try:
        cp = subprocess.run(
            command,
            input=mcp_tools_list_probe_payload(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except OSError:
        return {
            "ok": False,
            "status": "unavailable",
            "timeout_seconds": timeout,
            "required_tool": required_tool,
            "required_tool_available": False,
            "raw_output": "not_returned",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "timeout_seconds": timeout,
            "required_tool": required_tool,
            "required_tool_available": False,
            "raw_output": "not_returned",
        }

    output = cp.stdout + cp.stderr
    tools_result = mcp_tools_list_probe_result(output, required_tool)
    ok = cp.returncode == 0 and tools_result["response_found"] and tools_result["required_tool_available"]
    return {
        "ok": ok,
        "status": "ok" if ok else "failed",
        "returncode": cp.returncode,
        "timeout_seconds": timeout,
        **tools_result,
        "raw_output": "not_returned",
    }


def tmux_alive(session: str) -> bool:
    return run_tmux(["has-session", "-t", session], check=False).returncode == 0


def meta_path(agent: str) -> Path:
    return META_DIR / f"{agent}.json"


def read_json_file(path: Path) -> dict[str, Any]:
    error = {"meta_error": "could_not_read"}
    try:
        current_stat = path.lstat()
    except OSError:
        return error
    if not stat_module.S_ISREG(current_stat.st_mode) or current_stat.st_size > MAX_META_BYTES:
        return error

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(path, flags)
        opened_stat = os.fstat(fd)
        if not stat_module.S_ISREG(opened_stat.st_mode) or opened_stat.st_size > MAX_META_BYTES:
            return error
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(MAX_META_BYTES + 1)
    except OSError:
        return error
    finally:
        if fd >= 0:
            os.close(fd)

    if len(raw) > MAX_META_BYTES:
        return error
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return error


def path_present_no_follow(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def resolve_path_no_throw(path: Path) -> Path | None:
    try:
        if path.is_symlink():
            path.stat()
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def read_meta(agent: str) -> dict[str, Any]:
    path = meta_path(agent)
    if not path_present_no_follow(path):
        legacy_path = LEGACY_META_DIR / f"{agent}.json"
        if legacy_path != path and path_present_no_follow(legacy_path):
            data = read_json_file(legacy_path)
            data.setdefault("meta_source", "legacy")
            return data
        return {}
    return read_json_file(path)


def public_agent_meta(meta: dict[str, Any]) -> dict[str, Any]:
    public = dict(meta)
    if "raw_log" in public:
        public["raw_log"] = "not_returned"
    return public


def write_meta(agent: str, data: dict[str, Any]) -> None:
    path = meta_path(agent)
    replace_private_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_private_text(path: Path, text: str) -> None:
    with open_private_regular_update(path) as fh:
        fh.seek(0, os.SEEK_END)
        fh.write(text.encode("utf-8"))


def replace_private_text(path: Path, text: str) -> None:
    replace_private_bytes(path, text.encode("utf-8"))


def read_private_regular_text(path: Path, max_bytes: int, error_text: str) -> str:
    max_bytes = max(1, int(max_bytes))
    try:
        current_stat = path.lstat()
    except OSError as exc:
        raise AgentError(error_text) from exc
    if not stat_module.S_ISREG(current_stat.st_mode) or current_stat.st_size > max_bytes:
        raise AgentError(error_text)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(path, flags)
        opened_stat = os.fstat(fd)
        if not stat_module.S_ISREG(opened_stat.st_mode) or opened_stat.st_size > max_bytes:
            raise AgentError(error_text)
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(max_bytes + 1)
    except AgentError:
        raise
    except OSError as exc:
        raise AgentError(error_text) from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > max_bytes:
        raise AgentError(error_text)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentError(error_text) from exc


def replace_private_bytes(path: Path, data: bytes) -> None:
    ensure_private_dir(path.parent)
    tmp_path = path.with_name(f".{path.name}.{now_id()}.tmp")
    tmp_created = False
    try:
        write_private_new_bytes(tmp_path, data)
        tmp_created = True
        tmp_path.replace(path)
        tmp_created = False
        try:
            path.chmod(0o600)
        except PermissionError:
            pass
    finally:
        if tmp_created:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


def write_private_new_bytes(path: Path, data: bytes) -> None:
    ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AgentError("could not create private state temp file without following symlinks") from exc
    try:
        current_stat = os.fstat(fd)
        if not stat_module.S_ISREG(current_stat.st_mode):
            raise AgentError("private state temp path is not a regular file")
        try:
            os.fchmod(fd, 0o600)
        except PermissionError:
            pass
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def open_private_regular_update(path: Path) -> Any:
    ensure_private_dir(path.parent)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AgentError("could not open private state file without following symlinks") from exc
    try:
        current_stat = os.fstat(fd)
        if not stat_module.S_ISREG(current_stat.st_mode):
            raise AgentError("private state path is not a regular file")
        try:
            os.fchmod(fd, 0o600)
        except PermissionError:
            pass
        return os.fdopen(fd, "r+b")
    except Exception:
        os.close(fd)
        raise


@contextlib.contextmanager
def agent_lifecycle_lock(agent: str) -> Any:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    ensure_private_dir(STATE_ROOT)
    ensure_private_dir(LOCK_DIR)
    lock_path = LOCK_DIR / f"agent-{agent}.lock"
    with open_private_regular_update(lock_path) as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise AgentError("could not acquire agent lifecycle lock") from exc
        finally:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


def agent_lease_path(agent: str) -> Path:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    return LEASE_DIR / f"{agent}.json"


def lease_utc(timestamp: float | int | None) -> str | None:
    if timestamp is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(timestamp), _dt.timezone.utc).isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def normalize_int_field(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise AgentError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise AgentError(f"{field} must be an integer") from exc
    if number < minimum:
        raise AgentError(f"{field} must be >= {minimum}")
    if number > maximum:
        raise AgentError(f"{field} must be <= {maximum}")
    return number


def normalize_lease_seconds(value: Any) -> int:
    return normalize_int_field(value, field="ttl_seconds", minimum=1, maximum=MAX_AGENT_LEASE_SECONDS)


def normalize_wait_seconds(value: Any) -> int:
    return normalize_int_field(value, field="wait_seconds", minimum=0, maximum=MAX_WAIT_SECONDS)


def normalize_poll_interval_seconds(value: Any) -> int:
    return normalize_int_field(
        value,
        field="poll_interval_seconds",
        minimum=1,
        maximum=MAX_WAIT_POLL_SECONDS,
    )


def read_agent_lease_record(agent: str) -> dict[str, Any] | None:
    path = agent_lease_path(agent)
    if not path_present_no_follow(path):
        return None
    data = read_json_file(path)
    if data.get("meta_error"):
        raise AgentError("could_not_read_agent_lease")
    if data.get("agent") != agent or not isinstance(data.get("owner"), str):
        raise AgentError("could_not_read_agent_lease")
    return data


def public_agent_lease(agent: str, record: dict[str, Any] | None = None) -> dict[str, Any]:
    now = time.time()
    if not record:
        return {
            "agent": agent,
            "state": "unclaimed",
            "holder": "none",
            "held_by_this_server": False,
            "expires_at_utc": None,
            "seconds_remaining": 0,
            "ttl_seconds": DEFAULT_AGENT_LEASE_SECONDS,
            "raw_output": "not_returned",
        }
    try:
        expires_at = float(record.get("expires_at_epoch", 0))
    except (TypeError, ValueError):
        expires_at = 0.0
    active = expires_at > now
    held_by_this_server = active and record.get("owner") == SERVER_INSTANCE_ID
    holder = "this_server" if held_by_this_server else "other_server" if active else "none"
    return {
        "agent": agent,
        "state": "held" if active else "expired",
        "holder": holder,
        "held_by_this_server": held_by_this_server,
        "expires_at_utc": lease_utc(expires_at),
        "seconds_remaining": max(0, int(expires_at - now)) if active else 0,
        "ttl_seconds": record.get("ttl_seconds") if isinstance(record.get("ttl_seconds"), int) else None,
        "raw_output": "not_returned",
    }


def agent_busy_error(agent: str, lease: dict[str, Any]) -> AgentBusyError:
    seconds_remaining = int(lease.get("seconds_remaining") or 0)
    retry_after = max(1, min(seconds_remaining or 1, 30))
    return AgentBusyError(
        f"agent {agent} is leased by another MCP client",
        {
            "error_code": "agent_lease_held_by_other_client",
            "agent": agent,
            "retryable": True,
            "retry_after_seconds": retry_after,
            "lease_seconds_remaining": seconds_remaining,
            "lease": lease,
            "raw_output": "not_returned",
        },
    )


def agent_lease_status(agent: str) -> dict[str, Any]:
    ensure_state()
    try:
        return public_agent_lease(agent, read_agent_lease_record(agent))
    except AgentError:
        return {
            "agent": agent,
            "state": "unreadable",
            "holder": "unknown",
            "held_by_this_server": False,
            "expires_at_utc": None,
            "seconds_remaining": 0,
            "ttl_seconds": None,
            "raw_output": "not_returned",
        }


def write_agent_lease(agent: str, ttl_seconds: int) -> dict[str, Any]:
    now = time.time()
    expires_at = now + ttl_seconds
    record = {
        "agent": agent,
        "owner": SERVER_INSTANCE_ID,
        "created_at_utc": _dt.datetime.fromtimestamp(now, _dt.timezone.utc).isoformat(),
        "updated_at_utc": _dt.datetime.fromtimestamp(now, _dt.timezone.utc).isoformat(),
        "expires_at_epoch": expires_at,
        "expires_at_utc": lease_utc(expires_at),
        "ttl_seconds": ttl_seconds,
    }
    replace_private_text(agent_lease_path(agent), json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def remove_agent_lease(agent: str) -> bool:
    path = agent_lease_path(agent)
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AgentError("could_not_read_agent_lease") from exc
    if not stat_module.S_ISREG(current.st_mode) or stat_module.S_ISLNK(current.st_mode):
        raise AgentError("agent lease path is not a regular file")
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def claim_agent(agent: str, ttl_seconds: int = DEFAULT_AGENT_LEASE_SECONDS, force: bool = False) -> dict[str, Any]:
    ensure_state()
    ttl_seconds = normalize_lease_seconds(ttl_seconds)
    current = read_agent_lease_record(agent)
    current_public = public_agent_lease(agent, current)
    if current_public["state"] == "held" and not current_public["held_by_this_server"] and not force:
        raise agent_busy_error(agent, current_public)
    if current_public["state"] == "held" and current_public["held_by_this_server"]:
        status = "renewed"
    elif current_public["state"] == "held" and force:
        status = "forced"
    elif current_public["state"] == "expired":
        status = "claimed_expired"
    else:
        status = "claimed"
    record = write_agent_lease(agent, ttl_seconds)
    return {
        "agent": agent,
        "status": status,
        "lease": public_agent_lease(agent, record),
        "previous_lease": current_public,
        "raw_output": "not_returned",
    }


def release_agent(agent: str, force: bool = False) -> dict[str, Any]:
    ensure_state()
    current = read_agent_lease_record(agent)
    current_public = public_agent_lease(agent, current)
    if current_public["state"] != "held":
        if current_public["state"] == "expired":
            remove_agent_lease(agent)
        return {
            "agent": agent,
            "status": "not_held",
            "previous_lease": current_public,
            "lease": public_agent_lease(agent),
            "raw_output": "not_returned",
        }
    if not current_public["held_by_this_server"] and not force:
        raise agent_busy_error(agent, current_public)
    remove_agent_lease(agent)
    return {
        "agent": agent,
        "status": "released",
        "previous_lease": current_public,
        "lease": public_agent_lease(agent),
        "raw_output": "not_returned",
    }


def claim_for_agent_mutation(agent: str) -> tuple[dict[str, Any], bool]:
    claim = claim_agent(agent)
    return claim["lease"], claim["status"] in {"claimed", "claimed_expired"}


def ensure_agent_lease_available(agent: str, *, force: bool = False) -> dict[str, Any]:
    current = read_agent_lease_record(agent)
    current_public = public_agent_lease(agent, current)
    if current_public["state"] == "held" and not current_public["held_by_this_server"] and not force:
        raise agent_busy_error(agent, current_public)
    return current_public


def claim_agent_with_wait(
    agent: str,
    ttl_seconds: int = DEFAULT_AGENT_LEASE_SECONDS,
    force: bool = False,
    wait_seconds: int = 0,
    poll_interval_seconds: int = DEFAULT_WAIT_POLL_SECONDS,
) -> dict[str, Any]:
    wait_seconds = normalize_wait_seconds(wait_seconds)
    poll_interval_seconds = normalize_poll_interval_seconds(poll_interval_seconds)
    started = time.monotonic()
    deadline = started + wait_seconds
    polls = 0
    while True:
        try:
            result = call_agent_lifecycle(
                agent,
                lambda: claim_agent(agent, ttl_seconds=ttl_seconds, force=force),
            )
            result["waited_seconds"] = max(0, int(time.monotonic() - started))
            result["poll_count"] = polls
            return result
        except AgentBusyError:
            if time.monotonic() >= deadline:
                raise
            remaining = max(0.0, deadline - time.monotonic())
            time.sleep(min(float(poll_interval_seconds), remaining))
            polls += 1


def is_real_directory_no_symlink(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat_module.S_ISDIR(mode)


def is_regular_executable_no_symlink(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    if not stat_module.S_ISREG(mode):
        return False
    return os.access(path, os.X_OK)


def managed_raw_dirs() -> tuple[Path, ...]:
    legacy_raw = LEGACY_STATE_ROOT / "raw"
    dirs = [RAW_DIR]
    if legacy_raw != RAW_DIR:
        dirs.append(legacy_raw)
    return tuple(dirs)


def allowed_raw_log_path(raw_log: Any) -> Path | None:
    if not isinstance(raw_log, str) or not raw_log.strip():
        return None
    try:
        candidate = Path(raw_log).expanduser().resolve(strict=False)
    except OSError:
        return None
    if candidate.suffix != ".log":
        return None
    for root in managed_raw_dirs():
        if not is_real_directory_no_symlink(root):
            continue
        try:
            candidate.relative_to(root.resolve(strict=False))
            return candidate
        except (OSError, ValueError):
            continue
    return None


def protected_raw_log_paths() -> set[Path]:
    protected: set[Path] = set()
    for agent in AGENTS:
        path = allowed_raw_log_path(read_meta(agent).get("raw_log"))
        if path is not None:
            protected.add(path)
    return protected


def bound_raw_log_file(path: Path, max_bytes: int = MAX_RAW_LOG_BYTES) -> bool:
    max_bytes = max(1, int(max_bytes))
    try:
        current_stat = path.lstat()
    except OSError:
        return False
    if not stat_module.S_ISREG(current_stat.st_mode):
        return False
    marker = RAW_LOG_TRUNCATION_MARKER[: max(0, max_bytes - 1)]
    with open_private_regular_update(path) as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size <= max_bytes:
            return False
        tail_limit = max(0, max_bytes - len(marker))
        fh.seek(max(0, size - tail_limit), os.SEEK_SET)
        tail = fh.read(tail_limit)
    replace_private_bytes(path, marker + tail)
    return True


def append_bounded_raw_log(path: Path, chunk: bytes, max_bytes: int = MAX_RAW_LOG_BYTES) -> None:
    max_bytes = max(1, int(max_bytes))
    if not chunk:
        return
    with open_private_regular_update(path) as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size + len(chunk) <= max_bytes:
            fh.write(chunk)
            return
        marker = RAW_LOG_TRUNCATION_MARKER[: max(0, max_bytes - 1)]
        tail_limit = max(0, max_bytes - len(marker) - len(chunk))
        preserved = b""
        if tail_limit:
            fh.seek(max(0, size - tail_limit), os.SEEK_SET)
            preserved = fh.read(tail_limit)
        payload_limit = max(0, max_bytes - len(marker) - len(preserved))
        payload = chunk[-payload_limit:] if payload_limit else b""
        new_content = marker + preserved + payload
        if len(new_content) > max_bytes:
            tail_limit = max(0, max_bytes - len(marker))
            new_content = marker + new_content[-tail_limit:]
        fh.seek(0)
        fh.truncate()
        fh.write(new_content)


def validate_raw_log_writer_max_bytes(max_bytes: Any) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise AgentError("raw log max_bytes must be an integer")
    if max_bytes < 1:
        raise AgentError("raw log max_bytes must be >= 1")
    if max_bytes > MAX_RAW_LOG_BYTES:
        raise AgentError(f"raw log max_bytes must be <= {MAX_RAW_LOG_BYTES}")
    return max_bytes


def write_bounded_raw_log(path: Path, max_bytes: int = MAX_RAW_LOG_BYTES) -> int:
    max_bytes = validate_raw_log_writer_max_bytes(max_bytes)
    ensure_state()
    allowed = allowed_raw_log_path(str(path))
    if allowed is None:
        raise AgentError("raw log path is outside managed raw log state")
    while True:
        chunk = sys.stdin.buffer.read(RAW_LOG_CHUNK_BYTES)
        if not chunk:
            return 0
        append_bounded_raw_log(allowed, chunk, max_bytes)


def prune_raw_logs(max_files: int = MAX_RAW_LOG_FILES, max_bytes: int = MAX_RAW_LOG_BYTES) -> dict[str, Any]:
    max_files = max(1, int(max_files))
    max_bytes = max(1, int(max_bytes))
    protected = protected_raw_log_paths()
    deleted = 0
    deleted_symlink = 0
    truncated = 0
    retained = 0
    for raw_dir in managed_raw_dirs():
        if not is_real_directory_no_symlink(raw_dir):
            continue
        logs: list[tuple[Path, os.stat_result]] = []
        for path in raw_dir.glob("*.log"):
            try:
                current_stat = path.lstat()
            except OSError:
                continue
            if stat_module.S_ISLNK(current_stat.st_mode):
                try:
                    path.unlink()
                    deleted += 1
                    deleted_symlink += 1
                except FileNotFoundError:
                    pass
                continue
            if stat_module.S_ISREG(current_stat.st_mode):
                logs.append((path, current_stat))
        logs = sorted(logs, key=lambda item: (item[1].st_mtime, item[0].name), reverse=True)
        keep: set[Path] = set(protected)
        for path, _current_stat in logs[:max_files]:
            keep.add(path.resolve(strict=False))
        for path, current_stat in logs:
            resolved = path.resolve(strict=False)
            try:
                path.chmod(0o600)
            except PermissionError:
                pass
            if resolved not in protected and current_stat.st_size > max_bytes:
                truncated += 1 if bound_raw_log_file(path, max_bytes) else 0
            if resolved in keep:
                retained += 1
                continue
            try:
                path.unlink()
                deleted += 1
            except FileNotFoundError:
                pass
    return {
        "max_files_per_dir": max_files,
        "max_bytes_per_file": max_bytes,
        "retained_count": retained,
        "deleted_count": deleted,
        "deleted_symlink_count": deleted_symlink,
        "truncated_count": truncated,
        "raw_output": "not_returned",
    }


def raw_log_retention_status() -> dict[str, Any]:
    file_count = 0
    total_bytes = 0
    oversized_count = 0
    for raw_dir in managed_raw_dirs():
        if not is_real_directory_no_symlink(raw_dir):
            continue
        for path in raw_dir.glob("*.log"):
            try:
                current_stat = path.lstat()
            except OSError:
                continue
            if not stat_module.S_ISREG(current_stat.st_mode):
                continue
            file_count += 1
            size = current_stat.st_size
            total_bytes += size
            oversized_count += int(size > MAX_RAW_LOG_BYTES)
    return {
        "managed_dirs": PATH_NOT_RETURNED,
        "managed_dir_count": len(managed_raw_dirs()),
        "max_files_per_dir": MAX_RAW_LOG_FILES,
        "max_bytes_per_file": MAX_RAW_LOG_BYTES,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "oversized_count": oversized_count,
        "raw_output": "not_returned",
    }


def raw_log_writer_command(raw_log: Path) -> str:
    wrapper = repo_wrapper_path()
    if wrapper.exists() and os.access(wrapper, os.X_OK):
        argv = [str(wrapper), "raw-log-writer", str(raw_log), "--max-bytes", str(MAX_RAW_LOG_BYTES)]
    else:
        argv = [sys.executable, "-m", "codex_master.server", "raw-log-writer", str(raw_log), "--max-bytes", str(MAX_RAW_LOG_BYTES)]
    return shlex.join(argv)


def read_proc_environ(pid_dir: Path) -> dict[str, str]:
    try:
        raw = (pid_dir / "environ").read_bytes()
    except OSError:
        return {}
    env: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return env


def read_proc_status(pid_dir: Path) -> dict[str, str]:
    try:
        lines = (pid_dir / "status").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    result: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"Name", "State", "PPid", "Tgid"}:
            result[key] = value.strip()
    return result


def read_proc_cmdline(pid_dir: Path) -> list[str]:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return []
    return [item.decode("utf-8", errors="replace") for item in raw.split(b"\0") if item]


def same_path_text(left: str, right: Path) -> bool:
    try:
        return Path(left).expanduser().resolve(strict=False) == right.expanduser().resolve(strict=False)
    except OSError:
        return False


def public_path(path: Any) -> str | None:
    if path is None or str(path) == "":
        return None
    return PATH_NOT_RETURNED


def public_path_state(path: Any) -> str:
    return "set" if public_path(path) is not None else "not_set"


def public_config_path_state(path: Any) -> str:
    return "configured" if public_path(path) is not None else "not_configured"


def agent_home_processes(agent: str, proc_root: Path = Path("/proc")) -> list[dict[str, Any]]:
    cfg = AGENTS[agent]
    home = cfg["home"]
    processes: list[dict[str, Any]] = []
    if not proc_root.exists():
        return processes
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        env = read_proc_environ(pid_dir)
        if not same_path_text(env.get("CODEX_HOME", ""), home):
            continue
        status = read_proc_status(pid_dir)
        managed = env.get("CODEX_AGENT_MCP") == "1" or env.get("CODEX_MASTER_MCP") == "1"
        ppid_parts = status.get("PPid", "0").split()
        ppid = int(ppid_parts[0]) if ppid_parts and ppid_parts[0].isdigit() else None
        processes.append(
            {
                "pid": int(pid_dir.name),
                "ppid": ppid,
                "name": status.get("Name") or "unknown",
                "state": status.get("State") or "unknown",
                "managed_by_masterjet": managed,
                "raw_output": "not_returned",
            }
        )
    return sorted(processes, key=lambda item: item["pid"])


def agent_home_process_summary(agent: str, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    processes = agent_home_processes(agent, proc_root)
    external = [item for item in processes if not item["managed_by_masterjet"]]
    return {
        "agent": agent,
        "home": PATH_NOT_RETURNED,
        "home_kind": "managed_agent_home",
        "process_count": len(processes),
        "external_process_count": len(external),
        "managed_process_count": len(processes) - len(external),
        "external_processes": external[:10],
        "external_processes_truncated": len(external) > 10,
        "raw_output": "not_returned",
    }


def codex_related_process_summary(proc_root: Path = Path("/proc")) -> dict[str, Any]:
    home_kind_counts = {
        "main_default_home": 0,
        "custom_home": 0,
        "managed_agent_home": 0,
        "unknown": 0,
    }
    client_count = 0
    mcp_server_count = 0
    if not proc_root.exists():
        return {
            "codex_client_process_count": 0,
            "mcp_server_process_count": 0,
            "home_kind_counts": home_kind_counts,
            "namespace_visibility": {
                "main_default_home_clients": 0,
                "custom_home_clients": 0,
                "managed_agent_home_clients": 0,
                "unknown_home_clients": 0,
                "custom_home_clients_need_own_mcp_config": False,
                "managed_agent_home_clients_expect_no_master_mcp": False,
                "unknown_home_clients_need_manual_check": False,
                "raw_output": "not_returned",
            },
            "raw_output": "not_returned",
        }

    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        status = read_proc_status(pid_dir)
        name = (status.get("Name") or "").lower()
        argv = read_proc_cmdline(pid_dir)
        joined = "\0".join(argv).lower()
        if "codex_master.server" in joined or "codex-master-mcp" in joined:
            mcp_server_count += 1
            continue

        argv_names = {Path(item).name.lower() for item in argv if item}
        codex_client = (
            name == "codex"
            or "codex" in argv_names
            or "@openai/codex" in joined
            or "node_modules/@openai/codex" in joined
        )
        if not codex_client:
            continue

        client_count += 1
        env = read_proc_environ(pid_dir)
        if env:
            home_kind = str(classify_codex_home(env.get("CODEX_HOME"))["home_kind"])
        else:
            home_kind = "unknown"
        home_kind_counts[home_kind if home_kind in home_kind_counts else "unknown"] += 1

    return {
        "codex_client_process_count": client_count,
        "mcp_server_process_count": mcp_server_count,
        "home_kind_counts": home_kind_counts,
        "namespace_visibility": {
            "main_default_home_clients": home_kind_counts["main_default_home"],
            "custom_home_clients": home_kind_counts["custom_home"],
            "managed_agent_home_clients": home_kind_counts["managed_agent_home"],
            "unknown_home_clients": home_kind_counts["unknown"],
            "custom_home_clients_need_own_mcp_config": home_kind_counts["custom_home"] > 0,
            "managed_agent_home_clients_expect_no_master_mcp": home_kind_counts["managed_agent_home"] > 0,
            "unknown_home_clients_need_manual_check": home_kind_counts["unknown"] > 0,
            "raw_output": "not_returned",
        },
        "raw_output": "not_returned",
    }


def pane_pid(session: str) -> int | None:
    if not tmux_alive(session):
        return None
    cp = run_tmux(["display-message", "-p", "-t", session, "#{pane_pid}"], check=False)
    if cp.returncode != 0:
        return None
    text = cp.stdout.strip()
    return int(text) if text.isdigit() else None


def cleanup_failed_start(session: str, raw_log: Path, *, kill_session: bool) -> None:
    if kill_session and tmux_alive(session):
        run_tmux(["kill-session", "-t", session], check=False)
    try:
        raw_log.unlink()
    except FileNotFoundError:
        pass


def start_agent(
    agent: str,
    cwd: str | None = None,
    prompt: str | None = None,
    lease: dict[str, Any] | None = None,
    release_lease_on_failure: bool = False,
) -> dict[str, Any]:
    ensure_state()
    cfg = AGENTS[agent]
    runner = cfg["runner"]
    session = cfg["session"]
    if not is_regular_executable_no_symlink(runner):
        raise AgentError(f"runner for agent {agent} must be a regular executable file")
    if tmux_alive(session):
        process_summary = agent_home_process_summary(agent)
        if process_summary["external_process_count"]:
            raise AgentError(
                f"agent {agent} is already running in tmux, but CODEX_HOME is also used by "
                f"{process_summary['external_process_count']} external process(es); stop the external process(es) first"
            )
        return {
            "agent": agent,
            "status": "already_running",
            "backend": "tmux",
            "session": session,
            "pid": pane_pid(session),
            "lease": agent_lease_status(agent),
            "meta": public_agent_meta(read_meta(agent)),
            "home_external_process_count": process_summary["external_process_count"],
            "raw_output": "not_returned",
        }

    process_summary = agent_home_process_summary(agent)
    if process_summary["external_process_count"]:
        raise AgentError(
            f"agent {agent} CODEX_HOME is already used by {process_summary['external_process_count']} external process(es); "
            "stop them or use a separate CODEX_HOME before starting through codex-master-mcp"
        )

    cwd = bounded_text(cwd, field="cwd", max_chars=MAX_PATH_TEXT) if cwd is not None else None
    prompt = bounded_text(prompt, field="prompt", max_chars=MAX_SEND_TEXT, strip=False) if prompt is not None else None
    start_cwd = Path(cwd or os.getcwd()).expanduser().resolve()
    if not start_cwd.exists() or not start_cwd.is_dir():
        raise AgentError(f"cwd is not a directory: {start_cwd}")

    run_id = f"{now_id()}-{agent}"
    raw_log = RAW_DIR / f"{run_id}.log"
    write_private_new_bytes(raw_log, b"")

    argv = [str(runner), *BASE_ARGS]
    if prompt:
        argv.append(prompt)

    command = "env CODEX_MASTER_MCP=1 CODEX_AGENT_MCP=1 " + shlex.join(argv)
    cp = run_tmux(["new-session", "-d", "-s", session, "-c", str(start_cwd), command], check=False)
    if cp.returncode != 0:
        cleanup_failed_start(session, raw_log, kill_session=False)
        if release_lease_on_failure and lease and lease.get("held_by_this_server"):
            release_agent(agent, force=True)
        raise AgentError(f"tmux start failed for agent {agent}: {command_error_text(cp.stderr)}")

    pipe_command = raw_log_writer_command(raw_log)
    pipe = run_tmux(["pipe-pane", "-o", "-t", session, pipe_command], check=False)
    if pipe.returncode != 0:
        cleanup_failed_start(session, raw_log, kill_session=True)
        if release_lease_on_failure and lease and lease.get("held_by_this_server"):
            release_agent(agent, force=True)
        raise AgentError(f"tmux pipe-pane failed for agent {agent}: {command_error_text(pipe.stderr)}")

    data = {
        "agent": agent,
        "backend": "tmux",
        "label": cfg["label"],
        "session": session,
        "home": str(cfg["home"]),
        "runner": str(runner),
        "cwd": str(start_cwd),
        "args": BASE_ARGS,
        "model": DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
        "started_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "run_id": run_id,
        "raw_log": str(raw_log),
        "raw_log_policy": "local_only_bounded_not_returned_by_default",
        "raw_log_max_bytes": MAX_RAW_LOG_BYTES,
    }
    write_meta(agent, data)
    return {
        "agent": agent,
        "status": "started",
        "backend": "tmux",
        "session": session,
        "pid": pane_pid(session),
        "cwd": PATH_NOT_RETURNED,
        "cwd_state": "set",
        "lease": lease or agent_lease_status(agent),
        "model": DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
        "raw_log": "not_returned",
        "raw_log_max_bytes": MAX_RAW_LOG_BYTES,
        "raw_output": "not_returned",
    }


def start_agent_with_lease(agent: str, cwd: Any = None, prompt: Any = None) -> dict[str, Any]:
    if tmux_alive(AGENTS[agent]["session"]):
        return start_agent(agent, cwd, prompt)
    claim = claim_agent(agent)
    lease = claim["lease"]
    release_on_completion = claim["status"] in {"claimed", "claimed_expired"}
    try:
        result = start_agent(
            agent,
            cwd,
            prompt,
            lease=lease,
            release_lease_on_failure=release_on_completion,
        )
    except Exception:
        if release_on_completion and agent_lease_status(agent).get("held_by_this_server"):
            release_agent(agent, force=True)
        raise
    if release_on_completion and agent_lease_status(agent).get("held_by_this_server"):
        release = release_agent(agent, force=True)
        result["lease"] = release["lease"]
    return result


def stop_agent(agent: str, force: bool = False) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    was_running = tmux_alive(session)
    if was_running:
        ensure_agent_lease_available(agent, force=force)
    if was_running:
        cp = run_tmux(["kill-session", "-t", session], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux stop failed for agent {agent}: {command_error_text(cp.stderr)}")
        release = release_agent(agent, force=True)
    else:
        release = {"status": "skipped", "lease": agent_lease_status(agent), "raw_output": "not_returned"}
    return {
        "agent": agent,
        "status": "stopped" if was_running else "not_running",
        "session": session,
        "lease": release["lease"],
        "raw_output": "not_returned",
    }


def require_running_agent(agent: str) -> None:
    if not tmux_alive(AGENTS[agent]["session"]):
        raise AgentError(f"agent {agent} is not running")


def run_with_agent_lease(agent: str, fn: Any) -> dict[str, Any]:
    lease, release_on_failure = claim_for_agent_mutation(agent)
    try:
        return fn(lease)
    except Exception:
        if release_on_failure:
            release_agent(agent, force=True)
        raise


def raw_log_metadata(raw_log_path: Path | None) -> dict[str, Any]:
    if raw_log_path is None:
        return {"bytes": None, "updated_at_utc": None, "idle_seconds": None}
    try:
        current_stat = raw_log_path.lstat()
    except OSError:
        return {"bytes": None, "updated_at_utc": None, "idle_seconds": None}
    if not stat_module.S_ISREG(current_stat.st_mode):
        return {"bytes": None, "updated_at_utc": None, "idle_seconds": None}
    updated = _dt.datetime.fromtimestamp(current_stat.st_mtime, _dt.timezone.utc)
    idle_seconds = max(0, int(time.time() - current_stat.st_mtime))
    return {
        "bytes": current_stat.st_size,
        "updated_at_utc": updated.isoformat(),
        "idle_seconds": idle_seconds,
    }


def latest_assignment_summary(agent: str) -> dict[str, Any] | None:
    try:
        result = list_assignments(agent, 1)
    except AgentError:
        return None
    records = result.get("records")
    if not isinstance(records, list) or not records:
        return None
    record = records[-1]
    if not isinstance(record, dict):
        return None
    return {
        "assignment_id": record.get("assignment_id"),
        "created_at_utc": record.get("created_at_utc"),
        "role": record.get("role"),
        "model": record.get("model"),
        "raw_output": "not_returned",
    }


def limit_model_pool(model: Any) -> str:
    text = str(model or "").lower()
    if "spark" in text or WRITE_AGENT_MODEL in text:
        return "spark_write_model"
    if DEFAULT_AGENT_MODEL in text or "5.4" in text:
        return "default_agent_model"
    return "unknown"


LIMIT_TEXT_PATTERNS = (
    r"\brate limit(?:ed|s)?\b",
    r"\busage limit\b",
    r"\blimit (?:reached|exceeded|hit)\b",
    r"\bquota (?:exceeded|reached)\b",
    r"\btoo many requests\b",
    r"\bout of tokens\b",
    r"\btoken (?:limit|budget|quota)\b",
    r"\bcontext (?:length|window).{0,80}\b(?:exceeded|full|limit)\b",
)


def model_from_status_text(text: str) -> str | None:
    lowered = text.lower()
    if re.search(r"\b(?:gpt[- ]?5\.3[- ]?codex[- ]?spark|codex[- ]?spark|spark)\b", lowered):
        return WRITE_AGENT_MODEL
    if re.search(r"\b(?:gpt[- ]?5\.4[- ]?mini|gpt[- ]?5\.4|5\.4[- ]?mini)\b", lowered):
        return DEFAULT_AGENT_MODEL
    return None


def first_limit_evidence(text: str) -> str:
    lowered = text.lower()
    for pattern in LIMIT_TEXT_PATTERNS:
        match = re.search(pattern, lowered)
        if match:
            line_start = text.rfind("\n", 0, match.start()) + 1
            next_line = text.find("\n", match.end())
            line_end = len(text) if next_line == -1 else next_line
            start = max(line_start, match.start() - 160)
            end = min(line_end, match.end() + 160)
            return text[start:end]
    return ""


def infer_limit_model_info(
    text: str,
    meta: dict[str, Any],
    latest_assignment: dict[str, Any] | None,
    *,
    detected: bool,
) -> tuple[str, str]:
    assignment_model = latest_assignment.get("model") if latest_assignment else None
    session_model = meta.get("model") if isinstance(meta.get("model"), str) else None

    if detected:
        evidence_model = model_from_status_text(first_limit_evidence(text))
        if evidence_model:
            return evidence_model, "limit_evidence_text"
        if isinstance(assignment_model, str):
            return assignment_model, "assignment_metadata"
        if isinstance(session_model, str):
            return session_model, "session_metadata"

    status_model = model_from_status_text(text)
    if status_model:
        return status_model, "status_text"
    if latest_assignment and isinstance(latest_assignment.get("model"), str):
        return latest_assignment["model"], "assignment_metadata"
    if isinstance(session_model, str):
        return session_model, "session_metadata"
    return "unknown", "unknown"


def infer_limit_model(text: str, meta: dict[str, Any], latest_assignment: dict[str, Any] | None) -> str:
    return infer_limit_model_info(text, meta, latest_assignment, detected=True)[0]


def classify_limit_text(text: str, meta: dict[str, Any] | None = None, latest_assignment: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or {}
    cleaned = strip_ansi(text)
    lowered = cleaned.lower()
    has_limit = any(
        re.search(pattern, lowered)
        for pattern in LIMIT_TEXT_PATTERNS
    )
    window = "unknown"
    if re.search(r"\b(?:daily|per day|today|24h|24 hours)\b", lowered):
        window = "daily"
    elif re.search(r"\b(?:weekly|per week|this week|7d|7 days)\b", lowered):
        window = "weekly"

    limit_kind = "unknown"
    if re.search(r"\b(?:token|context length|context window)\b", lowered):
        limit_kind = "token"
    elif re.search(r"\brate limit|too many requests\b", lowered):
        limit_kind = "rate"
    elif re.search(r"\bquota\b", lowered):
        limit_kind = "quota"
    elif has_limit:
        limit_kind = "usage"

    detected = has_limit or (window != "unknown" and "limit" in lowered)
    model, model_source = infer_limit_model_info(cleaned, meta, latest_assignment, detected=detected)
    session_model = meta.get("model") if isinstance(meta.get("model"), str) else "unknown"
    assignment_model = latest_assignment.get("model") if latest_assignment else None
    assignment_model_pool = limit_model_pool(assignment_model) if assignment_model else "none"
    role = latest_assignment.get("role") if latest_assignment else "unknown"
    if role not in {"exploriererin", "arbeitsbiene"}:
        role = "unknown"

    return {
        "limited": detected,
        "window": window if detected else "none",
        "kind": limit_kind if detected else "none",
        "model": model,
        "model_source": model_source,
        "model_pool": limit_model_pool(model),
        "session_model": session_model,
        "session_model_pool": limit_model_pool(session_model),
        "assignment_model": assignment_model,
        "assignment_model_pool": assignment_model_pool,
        "role": role,
        "source": "classified_from_bounded_status_text" if cleaned else "no_status_text",
        "evidence": "not_returned",
        "raw_output": "not_returned",
    }


def classify_tui_context(text: str, running: bool) -> dict[str, Any]:
    if not running:
        state = "not_running"
        source = "not_running"
    else:
        cleaned = strip_ansi(text)
        lowered = re.sub(r"\s+", " ", cleaned.lower())
        starter_patterns = (
            r"\bfind and fix a bug in @filename\b",
            r"\bwhat can i help(?: you)?(?: with)?\b",
            r"\bask me anything\b",
        )
        if any(re.search(pattern, lowered) for pattern in starter_patterns):
            state = "starter_placeholder"
            source = "classified_from_bounded_pane_text"
        elif cleaned.strip():
            state = "unknown"
            source = "classified_from_bounded_pane_text"
        else:
            state = "no_pane_text"
            source = "no_status_text"
    return {
        "state": state,
        "source": source,
        "evidence": "not_returned",
        "raw_output": "not_returned",
    }


def agent_limit_state(
    agent: str,
    *,
    running: bool,
    meta: dict[str, Any],
    raw_log_path: Path | None,
    latest_assignment: dict[str, Any] | None,
    pane_text: str | None = None,
) -> dict[str, Any]:
    samples: list[str] = []
    if running:
        samples.append(pane_text if pane_text is not None else pane_tail(agent, MAX_TAIL_LINES))
    if raw_log_path:
        samples.append(read_log_tail(raw_log_path, MAX_LIMIT_STATUS_BYTES))
    return classify_limit_text("\n".join(item for item in samples if item), meta, latest_assignment)


def agent_response_state(
    running: bool,
    limit_state: dict[str, Any],
    raw_log_info: dict[str, Any],
    tui_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if limit_state.get("limited"):
        state = "blocked_by_limit"
    elif not running:
        state = "not_running"
    elif (tui_context or {}).get("state") == "starter_placeholder":
        state = "running_tui_starter_context"
    elif raw_log_info.get("idle_seconds") is None:
        state = "running_no_output_observed"
    elif int(raw_log_info["idle_seconds"]) >= IDLE_RESPONSE_SECONDS:
        state = "running_idle"
    else:
        state = "running_recent_output"
    return {
        "state": state,
        "idle_threshold_seconds": IDLE_RESPONSE_SECONDS,
        "response_output": "not_returned",
        "raw_output": "not_returned",
    }


def activity_signature(status: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (
        status.get("raw_log_bytes"),
        status.get("raw_log_updated_at_utc"),
        (status.get("response_state") or {}).get("state"),
    )


def wait_terminal_status(status: dict[str, Any], initial: dict[str, Any]) -> str | None:
    if (status.get("limit_state") or {}).get("limited"):
        return "blocked_by_limit"
    if not status.get("running"):
        return "not_running"
    if ((status.get("response_state") or {}).get("state")) == "running_tui_starter_context":
        return "tui_starter_context"
    if activity_signature(status) != activity_signature(initial):
        return "activity_observed"
    return None


def wait_agent(agent: str, timeout_seconds: int = DEFAULT_WAIT_SECONDS, poll_interval_seconds: int = DEFAULT_WAIT_POLL_SECONDS) -> dict[str, Any]:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    timeout_seconds = normalize_int_field(
        timeout_seconds,
        field="timeout_seconds",
        minimum=0,
        maximum=MAX_WAIT_SECONDS,
    )
    poll_interval_seconds = normalize_poll_interval_seconds(poll_interval_seconds)
    started = time.monotonic()
    deadline = started + timeout_seconds
    initial = status_agent(agent)
    current = initial
    polls = 0
    status = wait_terminal_status(current, initial)
    while status is None and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        time.sleep(min(float(poll_interval_seconds), remaining))
        polls += 1
        current = status_agent(agent)
        status = wait_terminal_status(current, initial)
    if status is None:
        status = "timeout"
    return {
        "agent": agent,
        "status": status,
        "timeout_seconds": timeout_seconds,
        "poll_interval_seconds": poll_interval_seconds,
        "poll_count": polls,
        "elapsed_seconds": max(0, int(time.monotonic() - started)),
        "initial": initial,
        "current": current,
        "raw_output": "not_returned",
        "response_output": "not_returned",
    }


def status_agent(agent: str) -> dict[str, Any]:
    ensure_state()
    cfg = AGENTS[agent]
    session = cfg["session"]
    meta = read_meta(agent)
    raw_log = meta.get("raw_log")
    raw_log_path = allowed_raw_log_path(raw_log)
    process_summary = agent_home_process_summary(agent)
    running = tmux_alive(session)
    raw_log_info = raw_log_metadata(raw_log_path)
    latest_assignment = latest_assignment_summary(agent)
    pane_text = pane_tail(agent, MAX_TAIL_LINES) if running else ""
    tui_context = classify_tui_context(pane_text, running)
    limit_state = agent_limit_state(
        agent,
        running=running,
        meta=meta,
        raw_log_path=raw_log_path,
        latest_assignment=latest_assignment,
        pane_text=pane_text,
    )
    return {
        "agent": agent,
        "label": cfg["label"],
        "backend": "tmux",
        "running": running,
        "session": session,
        "pid": pane_pid(session),
        "home": PATH_NOT_RETURNED,
        "home_kind": "managed_agent_home",
        "runner": PATH_NOT_RETURNED,
        "runner_state": public_config_path_state(cfg["runner"]),
        "started_at_utc": meta.get("started_at_utc"),
        "cwd": public_path(meta.get("cwd")),
        "cwd_state": public_path_state(meta.get("cwd")),
        "model": meta.get("model") or DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": meta.get("model_reasoning_effort") or DEFAULT_AGENT_MODEL_EFFORT,
        "lease": agent_lease_status(agent),
        "last_assignment": latest_assignment,
        "tui_context": tui_context,
        "limit_state": limit_state,
        "response_state": agent_response_state(running, limit_state, raw_log_info, tui_context),
        "raw_log": "not_returned" if raw_log else None,
        "raw_log_bytes": raw_log_info["bytes"],
        "raw_log_updated_at_utc": raw_log_info["updated_at_utc"],
        "raw_log_idle_seconds": raw_log_info["idle_seconds"],
        "raw_log_max_bytes": MAX_RAW_LOG_BYTES,
        "raw_log_policy": "local_only_bounded_not_returned_by_default",
        "raw_log_path_valid": (raw_log_path is not None) if raw_log else True,
        "home_process_count": process_summary["process_count"],
        "home_external_process_count": process_summary["external_process_count"],
        "home_external_processes_truncated": process_summary["external_processes_truncated"],
        "raw_output": "not_returned",
    }


def skill_scan_roots(home: Path) -> list[tuple[str, Path]]:
    return [
        ("system", home / "skills"),
        ("plugin_cache", home / "plugins" / "cache"),
        ("tmp_plugin_cache", home / ".tmp" / "plugins"),
    ]


def safe_relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def parse_skill_path(home: Path, path: Path) -> dict[str, str]:
    rel = path.relative_to(home)
    parts = rel.parts
    info = {"name": path.parent.name, "source": "unknown", "plugin": ""}

    if len(parts) >= 4 and parts[0] == "skills" and parts[1] == ".system":
        return {"name": parts[2], "source": "system", "plugin": ""}

    if len(parts) >= 6 and parts[:3] == ("plugins", "cache", "openai-curated"):
        return {"name": path.parent.name, "source": "plugin_cache", "plugin": f"{parts[3]}@openai-curated"}

    if len(parts) >= 6 and parts[:3] == (".tmp", "plugins", "plugins"):
        return {"name": path.parent.name, "source": "tmp_plugin_cache", "plugin": f"{parts[3]}@tmp"}

    if len(parts) >= 6 and parts[:4] == (".tmp", "plugins", ".agents", "skills"):
        return {"name": parts[4], "source": "tmp_agent_skills", "plugin": "agents@tmp"}

    return info


def list_skill_files(root: Path) -> list[Path]:
    if not is_real_directory_no_symlink(root):
        return []
    return sorted(path for path in root.rglob("SKILL.md") if is_regular_file_no_symlink(path))


def is_regular_file_no_symlink(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat_module.S_ISREG(mode)


def paged_mapping(items: dict[str, int], offset: int, limit: int) -> tuple[dict[str, int], bool]:
    offset = max(0, int(offset))
    limit = max(0, int(limit))
    sorted_items = sorted(items.items())
    page = dict(sorted_items[offset : offset + limit])
    return page, offset + limit < len(sorted_items)


def skills_agent(
    agent: str,
    include_names: bool = False,
    limit: int = 80,
    names_offset: int = 0,
    plugins_offset: int = 0,
    plugins_limit: int = MAX_CAPABILITY_PLUGINS,
) -> dict[str, Any]:
    cfg = AGENTS[agent]
    home = cfg["home"]
    limit = max(0, min(int(limit), MAX_SKILL_NAMES))
    names_offset = max(0, int(names_offset))
    plugins_offset = max(0, int(plugins_offset))
    plugins_limit = max(0, min(int(plugins_limit), MAX_SKILL_NAMES))

    all_paths: list[Path] = []
    roots: list[dict[str, Any]] = []
    for kind, root in skill_scan_roots(home):
        paths = list_skill_files(root)
        roots.append(
            {
                "kind": kind,
                "path": PATH_NOT_RETURNED,
                "path_state": "configured",
                "exists": root.exists(),
                "skill_count": len(paths),
            }
        )
        all_paths.extend(paths)

    by_source: dict[str, int] = {}
    by_plugin: dict[str, int] = {}
    system_skills: list[str] = []
    names: list[dict[str, str]] = []

    unique_paths = sorted(set(all_paths))
    for index, path in enumerate(unique_paths):
        parsed = parse_skill_path(home, path)
        source = parsed["source"]
        by_source[source] = by_source.get(source, 0) + 1
        if parsed["plugin"]:
            by_plugin[parsed["plugin"]] = by_plugin.get(parsed["plugin"], 0) + 1
        if source == "system":
            system_skills.append(parsed["name"])
        if include_names and index >= names_offset and len(names) < limit:
            names.append(
                {
                    "name": parsed["name"],
                    "source": source,
                    "plugin": parsed["plugin"],
                    "path": safe_relative(path, home),
                }
            )

    plugins, plugins_truncated = paged_mapping(by_plugin, plugins_offset, plugins_limit)
    result: dict[str, Any] = {
        "agent": agent,
        "label": cfg["label"],
        "home": PATH_NOT_RETURNED,
        "home_kind": "managed_agent_home",
        "total": len(set(all_paths)),
        "roots": roots,
        "by_source": dict(sorted(by_source.items())),
        "system_skills": sorted(set(system_skills)),
        "plugin_count": len(by_plugin),
        "plugins_offset": plugins_offset,
        "plugins_limit": plugins_limit,
        "plugins": plugins,
        "plugins_truncated": plugins_truncated,
        "skill_file_contents": "not_returned",
        "raw_output": "not_returned",
    }
    if include_names:
        result["names_total"] = len(unique_paths)
        result["names_offset"] = names_offset
        result["names_limit"] = limit
        result["names"] = names
        result["names_truncated"] = names_offset + len(names) < len(unique_paths)
    return result


def bounded_text(
    value: Any,
    *,
    field: str,
    max_chars: int,
    required: bool = False,
    strip: bool = True,
) -> str | None:
    if value is None:
        if required:
            raise AgentError(f"{field} must be a non-empty string")
        return None
    if not isinstance(value, str):
        raise AgentError(f"{field} must be a string")
    text = value.strip() if strip else value
    if required and not text.strip():
        raise AgentError(f"{field} must be a non-empty string")
    if len(text) > max_chars:
        raise AgentError(f"{field} exceeds {max_chars} characters")
    return text


def as_string_list(
    value: Any,
    *,
    field: str,
    max_items: int = MAX_ASSIGNMENT_LIST_ITEMS,
    max_chars: int = MAX_TEXT_FIELD,
) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if len(text) > max_chars:
            raise AgentError(f"{field} items must not exceed {max_chars} characters")
        return [text] if text else []
    if not isinstance(value, list):
        raise AgentError(f"{field} must be a string or list of strings")
    if len(value) > max_items:
        raise AgentError(f"{field} must contain at most {max_items} items")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise AgentError(f"{field} must contain only strings")
        text = item.strip()
        if len(text) > max_chars:
            raise AgentError(f"{field} items must not exceed {max_chars} characters")
        if text:
            result.append(text)
    return result


def skill_matches(agent: str, skill_ref: str, limit: int = 8) -> list[dict[str, str]]:
    cfg = AGENTS[agent]
    home = cfg["home"]
    wanted = skill_ref.strip().lower()
    matches: list[dict[str, str]] = []

    for _kind, root in skill_scan_roots(home):
        for path in list_skill_files(root):
            parsed = parse_skill_path(home, path)
            name = parsed["name"].lower()
            plugin = parsed["plugin"].lower()
            plugin_base = plugin.split("@", 1)[0] if plugin else ""
            candidates = {name}
            if plugin_base:
                candidates.add(f"{plugin_base}:{name}")
                candidates.add(f"{plugin_base}/{name}")
            if plugin:
                candidates.add(f"{plugin}:{name}")
                candidates.add(f"{plugin}/{name}")
            if wanted in candidates:
                matches.append(
                    {
                        "name": parsed["name"],
                        "source": parsed["source"],
                        "plugin": parsed["plugin"],
                        "path": safe_relative(path, home),
                    }
                )
                if len(matches) >= limit:
                    return matches
    return matches


def skill_match_agent(agent: str, skill_ref: Any, limit: int = 8) -> dict[str, Any]:
    skill_ref = bounded_text(skill_ref, field="skill", max_chars=MAX_SKILL_REF, required=True) or ""
    limit = max(1, min(int(limit), MAX_SKILL_NAMES))
    matches = skill_matches(agent, skill_ref, limit)
    skill_safe, _changed = redact(skill_ref)
    return {
        "agent": agent,
        "skill": trim_chars(skill_safe, 300),
        "available": bool(matches),
        "match_count": len(matches),
        "matches": matches,
        "skill_file_contents": "not_returned",
        "raw_output": "not_returned",
    }

def capabilities_agent(agent: str) -> dict[str, Any]:
    inventory = skills_agent(agent, include_names=False)
    return {
        "agent": agent,
        "label": AGENTS[agent]["label"],
        "home": PATH_NOT_RETURNED,
        "home_kind": "managed_agent_home",
        "models": {
            "default": DEFAULT_AGENT_MODEL,
            "read_only": DEFAULT_AGENT_MODEL,
            "write": WRITE_AGENT_MODEL,
            "default_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
            "write_reasoning_effort": WRITE_AGENT_MODEL_EFFORT,
        },
        "skill_count": inventory["total"],
        "system_skills": inventory["system_skills"],
        "plugin_count": inventory["plugin_count"],
        "plugin_page_count": len(inventory["plugins"]),
        "plugins_offset": inventory["plugins_offset"],
        "plugins_limit": inventory["plugins_limit"],
        "plugins": inventory["plugins"],
        "plugins_truncated": inventory["plugins_truncated"],
        "master_mcp_tools": "not_configured_for_agent",
        "native_subagents": "assignment_gated",
        "write_policy": "explicit_paths_only",
        "raw_output": "not_returned",
    }


def normalize_scope_path(item: str, cwd: Path) -> Path | None:
    text = item.strip()
    if not text or "://" in text:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return path.resolve(strict=False)


def path_is_within(path: Path, scope: Path) -> bool:
    try:
        path.relative_to(scope)
        return True
    except ValueError:
        return False


def scope_check(scope: list[str], write_paths: list[str], cwd: Any = None) -> dict[str, Any]:
    cwd = bounded_text(cwd, field="cwd", max_chars=MAX_PATH_TEXT) if cwd is not None else None
    base = Path(cwd or os.getcwd()).expanduser().resolve(strict=False)
    scope_paths = [path for item in scope if (path := normalize_scope_path(item, base)) is not None]
    violations: list[str] = []

    if write_paths and not scope_paths:
        violations = redact_list(write_paths)
    else:
        for original in write_paths:
            write_path = normalize_scope_path(original, base)
            if write_path is None or not any(path_is_within(write_path, scope_path) for scope_path in scope_paths):
                violations.append(redact_list([original])[0])

    return {
        "cwd": PATH_NOT_RETURNED,
        "cwd_state": "set",
        "allowed": not violations,
        "scope": redact_list(scope),
        "write_paths": redact_list(write_paths),
        "violations": violations,
        "raw_output": "not_returned",
    }


def bullet_block(items: list[str], fallback: str = "-") -> str:
    if not items:
        return fallback
    return "\n".join(f"- {item}" for item in items)


def assignment_prompt(
    *,
    agent: str,
    role: str,
    task: str,
    scope: list[str],
    skill: str | None,
    write_paths: list[str],
    context: list[str],
    forbidden: list[str],
    name: str | None,
    allow_subagents: bool,
) -> str:
    display_name = (name or DEFAULT_AGENTIN_NAMES.get(agent) or "Arbeitsbiene").strip()
    skill_line = skill.strip() if skill else "kein spezieller Skill vorgegeben"
    model = assignment_model(role)

    if role == "exploriererin":
        return "\n".join(
            [
                "[EXPLORER_BEE_TASK]",
                f"Name: {display_name}",
                "Rolle: Exploriererin",
                f"Modell: {model}",
                f"Skill: {skill_line}",
                f"Scope:\n{bullet_block(scope)}",
                "Darf schreiben: nein",
                f"Darf eigene Subagentinnen starten: {'ja, nur lesend im Scope' if allow_subagents else 'nein'}",
                f"Stabiler Kontext:\n{bullet_block(context)}",
                f"Aufgabe: {task}",
                f"Grenzen:\n{bullet_block(forbidden)}",
                "Rueckgabe: knappe Fakten, relevante Dateien/Zeilen, Empfehlung",
            ]
        )

    return "\n".join(
        [
            "[WORK_BEE_TASK]",
            f"Name: {display_name}",
            "Rolle: Arbeitsbiene",
            f"Modell: {model}",
            f"Skill: {skill_line}",
            f"Scope:\n{bullet_block(scope)}",
            f"Darf schreiben: ja, nur:\n{bullet_block(write_paths)}",
            f"Darf eigene Subagentinnen starten: {'ja, nur innerhalb Scope und Schreibpfaden' if allow_subagents else 'nein'}",
            f"Stabiler Kontext:\n{bullet_block(context)}",
            f"Aktuelle Aufgabe: {task}",
            f"Grenzen:\n{bullet_block(forbidden)}",
            "Rueckgabe: Root Cause, Aenderung, Tests, offene Risiken",
        ]
    )


def assignment_model(role: str) -> str:
    if role == "arbeitsbiene":
        return WRITE_AGENT_MODEL
    return DEFAULT_AGENT_MODEL


def assign_agent(
    agent: str,
    *,
    role: str,
    task: Any,
    scope: Any,
    skill: str | None = None,
    write_paths: Any = None,
    context: Any = None,
    forbidden: Any = None,
    name: str | None = None,
    enter: bool = True,
    allow_missing_skill: bool = False,
    allow_subagents: bool = False,
    lease: dict[str, Any] | None = None,
) -> dict[str, Any]:
    role = role.strip().lower()
    if role not in {"exploriererin", "arbeitsbiene"}:
        raise AgentError("role must be 'exploriererin' or 'arbeitsbiene'")
    task = bounded_text(task, field="task", max_chars=MAX_TASK_TEXT, required=True) or ""
    skill = bounded_text(skill, field="skill", max_chars=MAX_SKILL_REF) if skill is not None else None
    name = bounded_text(name, field="name", max_chars=MAX_AGENTIN_NAME) if name is not None else None
    scope = as_string_list(scope, field="scope", max_chars=MAX_PATH_TEXT)
    write_paths = as_string_list(write_paths, field="write_paths", max_chars=MAX_PATH_TEXT)
    context = as_string_list(context, field="context")
    forbidden = as_string_list(forbidden, field="forbidden")
    if role == "exploriererin" and write_paths:
        raise AgentError("exploriererin assignments must not include write paths")
    if role == "arbeitsbiene" and not write_paths:
        raise AgentError("arbeitsbiene assignments require at least one explicit write path")
    scope_result = scope_check(scope, write_paths)
    if role == "arbeitsbiene" and not scope_result["allowed"]:
        raise AgentError(f"write paths must stay inside scope: {', '.join(scope_result['violations'])}")

    matches: list[dict[str, str]] = []
    if skill:
        matches = skill_matches(agent, skill)
        if not matches and not allow_missing_skill:
            raise AgentError(f"skill not found for agent {agent}: {skill}")

    model = assignment_model(role)
    prompt = assignment_prompt(
        agent=agent,
        role=role,
        task=task,
        scope=scope,
        skill=skill,
        write_paths=write_paths,
        context=context,
        forbidden=forbidden,
        name=name,
        allow_subagents=allow_subagents,
    )
    if len(prompt) > MAX_ASSIGNMENT_TEXT:
        raise AgentError(f"assignment prompt exceeds {MAX_ASSIGNMENT_TEXT} characters")

    release_on_failure = False
    if lease is None:
        lease, release_on_failure = claim_for_agent_mutation(agent)
    try:
        sent = send_agent(agent, prompt, enter)
    except Exception:
        if release_on_failure:
            release_agent(agent, force=True)
        raise
    assignment_id = f"{now_id()}-{agent}"
    record_assignment(
        {
            "assignment_id": assignment_id,
            "created_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "agent": agent,
            "role": role,
            "name": name or DEFAULT_AGENTIN_NAMES.get(agent),
            "model": model,
            "skill": {
                "requested": skill,
                "available": bool(matches) if skill else None,
                "match_count": len(matches),
            },
            "scope": redact_list(scope),
            "write_paths": redact_list(write_paths),
            "context_count": len(context),
            "forbidden_count": len(forbidden),
            "write_policy": "read_only" if role == "exploriererin" else "explicit_paths_only",
            "allow_subagents": allow_subagents,
            "lease": {
                "state": lease.get("state"),
                "holder": lease.get("holder"),
                "held_by_this_server": lease.get("held_by_this_server"),
                "expires_at_utc": lease.get("expires_at_utc"),
                "raw_output": "not_returned",
            },
            "submitted": enter,
            "prompt_chars": len(prompt),
            "prompt_output": "not_returned",
            "response_output": "not_returned",
        }
    )
    return {
        "assignment_id": assignment_id,
        "agent": agent,
        "status": "assigned",
        "role": role,
        "name": name or DEFAULT_AGENTIN_NAMES.get(agent),
        "model": model,
        "skill": {"requested": skill, "available": bool(matches) if skill else None, "matches": matches[:5]},
        "scope_count": len(scope),
        "write_policy": "read_only" if role == "exploriererin" else "explicit_paths_only",
        "write_path_count": len(write_paths),
        "subagents_allowed": allow_subagents,
        "lease": lease,
        "prompt_chars": len(prompt),
        "prompt_output": "not_returned",
        "response_output": "not_returned",
        "send": sent,
    }


def redact_list(items: list[str], max_items: int = 50) -> list[str]:
    safe_items = []
    for item in items[:max_items]:
        redacted, _changed = redact(item)
        safe_items.append(trim_chars(redacted, 300))
    return safe_items


def sanitize_assignment_record(record: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(record)
    for key in ("scope", "write_paths"):
        values = sanitized.get(key)
        if isinstance(values, list):
            sanitized[key] = redact_list([str(item) for item in values], max_items=MAX_ASSIGNMENT_LIST_ITEMS)
    skill = sanitized.get("skill")
    if isinstance(skill, dict):
        sanitized["skill"] = {
            key: redact(str(value))[0] if isinstance(value, str) else value
            for key, value in skill.items()
        }
    sanitized["prompt_output"] = "not_returned"
    sanitized["response_output"] = "not_returned"
    return sanitized


def record_assignment(record: dict[str, Any]) -> None:
    ensure_state()
    write_private_text(ASSIGNMENT_LOG, json.dumps(record, sort_keys=True) + "\n")
    prune_assignment_log()


def prune_assignment_log(max_records: int | None = None) -> None:
    max_records = max(1, int(max_records if max_records is not None else MAX_ASSIGNMENT_LOG_RECORDS))
    if not ASSIGNMENT_LOG.exists():
        return
    lines = read_private_regular_text(
        ASSIGNMENT_LOG,
        MAX_ASSIGNMENT_LOG_BYTES,
        "could_not_read_assignment_log",
    ).splitlines()

    valid_records: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        valid_records.append(json.dumps(parsed, sort_keys=True))

    kept = valid_records[-max_records:]
    text = "\n".join(kept) + ("\n" if kept else "")
    replace_private_text(ASSIGNMENT_LOG, text)


def list_assignments(agent: str = "all", limit: int = 20) -> dict[str, Any]:
    ensure_state()
    if agent not in {"a", "b", "all"}:
        raise AgentError("agent must be a, b, or all")
    limit = max(1, min(int(limit), MAX_ASSIGNMENT_RECORDS))
    records: list[dict[str, Any]] = []
    if ASSIGNMENT_LOG.exists():
        for line in read_private_regular_text(
            ASSIGNMENT_LOG, MAX_ASSIGNMENT_LOG_BYTES, "could_not_read_assignment_log"
        ).splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if agent == "all" or record.get("agent") == agent:
                records.append(sanitize_assignment_record(record))
    return {
        "agent": agent,
        "limit": limit,
        "records": records[-limit:],
        "record_count": len(records[-limit:]),
        "retained_count": len(records),
        "retention_limit": MAX_ASSIGNMENT_LOG_RECORDS,
        "records_truncated": len(records) > limit,
        "log_path": "not_returned",
        "prompt_output": "not_returned",
        "response_output": "not_returned",
        "raw_output": "not_returned",
    }


def command_excerpt(text: str, chars: int = 1200) -> tuple[str, bool]:
    cleaned = strip_ansi(text)
    cleaned, redacted = redact(cleaned)
    return trim_chars(cleaned, chars), redacted


def last_assignment_status(agent: str) -> dict[str, Any]:
    result = list_assignments(agent, 1)
    return {
        "agent": agent,
        "status": "found" if result["records"] else "none",
        "record": result["records"][0] if result["records"] else None,
        "prompt_output": "not_returned",
        "response_output": "not_returned",
        "raw_output": "not_returned",
    }


def request_agent_report(
    agent: str,
    assignment_id: Any = None,
    enter: bool = True,
    lease: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if assignment_id:
        assignment_id = bounded_text(assignment_id, field="assignment_id", max_chars=MAX_ASSIGNMENT_ID) or ""
        safe_id, _changed = redact(assignment_id)
        text = (
            "Bitte liefere einen knappen Bericht zum Assignment "
            f"{trim_chars(safe_id, 200)}: Status, relevante Dateien/Zeilen, Tests, offene Risiken. "
            "Keine Rohlogs und keine langen Ausgaben."
        )
    else:
        text = "Bitte liefere einen knappen Statusbericht: Aufgabe, Stand, Tests, offene Risiken. Keine Rohlogs."
    lease = lease or agent_lease_status(agent)
    sent = send_agent(agent, text, enter)
    return {
        "agent": agent,
        "status": "report_requested",
        "submitted": enter,
        "assignment_id": assignment_id,
        "lease": lease,
        "prompt_output": "not_returned",
        "response_output": "not_returned",
        "send": sent,
    }


def git_excerpt(args: list[str], *, cwd: Path | None = None, chars: int = 4000) -> dict[str, Any]:
    cp = run_command(["git", *args], cwd=cwd or repo_root())
    output, redacted = command_excerpt(cp.stdout + cp.stderr, chars)
    return {
        "ok": cp.returncode == 0,
        "returncode": cp.returncode,
        "output_excerpt": output,
        "redaction_applied": redacted,
    }


def repo_relative_public_path(path: Path, repo: Path) -> str | None:
    try:
        rel = path.relative_to(repo)
    except ValueError:
        return None
    text = rel.as_posix()
    return text or "."


def worktree_create_for_agent(agent: str, path: Any = None, base_ref: Any = None) -> dict[str, Any]:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    path = bounded_text(path, field="path", max_chars=MAX_PATH_TEXT) if path is not None else None
    base_ref = bounded_text(base_ref, field="base_ref", max_chars=MAX_PATH_TEXT) if base_ref is not None else None
    repo = repo_root().resolve(strict=False)
    target = Path(path).expanduser() if path else repo / ".codex-master-worktrees" / f"agent-{agent}-{now_id()}"
    if not target.is_absolute():
        target = repo / target
    target = target.absolute()
    scoped_target = target.resolve(strict=False)
    if not path_is_within(scoped_target, repo):
        raise AgentError("worktree path must stay inside repo")
    if path_present_no_follow(target):
        raise AgentError("worktree path already exists")
    ensure_directory_chain_no_symlink(target.parent, "worktree parent directories must be real directories")
    target = target.resolve(strict=False)
    if not path_is_within(target, repo):
        raise AgentError("worktree path must stay inside repo")
    args = ["worktree", "add", str(target)]
    if base_ref:
        args.append(base_ref)
    cp = run_command(["git", *args], cwd=repo)
    if cp.returncode != 0:
        output, redacted = command_excerpt(cp.stdout + cp.stderr)
        raise AgentError(f"git worktree add failed: {output if not redacted else '<redacted>'}")
    public_path = repo_relative_public_path(target, repo)
    return {
        "agent": agent,
        "path": public_path or PATH_NOT_RETURNED,
        "path_state": "set" if public_path else "not_returned",
        "path_kind": "repo_relative" if public_path else "not_returned",
        "base_ref": base_ref,
        "status": "created",
        "raw_output": "not_returned",
    }


def worktree_status(path: Any = None) -> dict[str, Any]:
    path = bounded_text(path, field="path", max_chars=MAX_PATH_TEXT) if path is not None else None
    repo = repo_root().resolve(strict=False)
    target = Path(path).expanduser() if path else repo
    if not target.is_absolute():
        target = repo / target
    target = target.absolute()
    scoped_target = target.resolve(strict=False)
    if not path_is_within(scoped_target, repo):
        raise AgentError("worktree status path must stay inside repo")
    if not directory_chain_is_real_no_symlink(target.parent):
        raise AgentError("worktree status parent directories must be real directories")
    if not is_real_directory_no_symlink(target):
        raise AgentError("worktree status path must be a real directory")
    target = target.resolve(strict=False)
    return {
        "path": PATH_NOT_RETURNED,
        "path_state": "set",
        "status": git_excerpt(["status", "--short"], cwd=target),
        "worktrees": git_excerpt(["worktree", "list", "--porcelain"], cwd=repo),
        "raw_output": "not_returned",
    }


def normalize_install_path(path: Path) -> Path:
    normalized = path.expanduser()
    if not normalized.is_absolute():
        normalized = Path.cwd() / normalized
    return normalized.absolute()


def repo_worktree_safety() -> dict[str, Any]:
    cp = run_command(["git", "status", "--porcelain=v1"], cwd=repo_root())
    if cp.returncode != 0:
        return {
            "name": "installed_source_worktree_state",
            "ok": False,
            "status": "unknown",
            "severity": "warning",
            "raw_output": "not_returned",
        }
    lines = [line for line in cp.stdout.splitlines() if line]
    untracked_count = sum(1 for line in lines if line.startswith("??"))
    tracked_change_count = len(lines) - untracked_count
    clean = not lines
    return {
        "name": "installed_source_worktree_state",
        "ok": True,
        "status": "clean" if clean else "dirty",
        "severity": "info" if clean else "warning",
        "tracked_change_count": tracked_change_count,
        "untracked_count": untracked_count,
        "raw_output": "not_returned",
    }


def installed_source_worktree_state(installed_target: Path | None, wrapper: Path) -> dict[str, Any]:
    if installed_target != wrapper:
        return {
            "name": "installed_source_worktree_state",
            "ok": True,
            "status": "not_applicable",
            "severity": "info",
            "raw_output": "not_returned",
        }
    return repo_worktree_safety()


def replace_install_symlink(install_path: Path, wrapper: Path) -> None:
    tmp_link = install_path.parent / f".{install_path.name}.tmp.{now_id()}.{uuid.uuid4().hex}"
    try:
        tmp_link.symlink_to(wrapper)
        os.replace(tmp_link, install_path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_link.unlink()
        raise AgentError("could_not_write_install_symlink") from exc


def integration_status() -> dict[str, Any]:
    return {
        "repo": PATH_NOT_RETURNED,
        "repo_state": "set",
        "status": git_excerpt(["status", "--short"]),
        "diff_stat": git_excerpt(["diff", "--stat"]),
        "assignments": list_assignments("all", 10),
        "raw_output": "not_returned",
    }


def commit_ready_check(run_tests: bool = True) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    repo = repo_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = "src" if not env.get("PYTHONPATH") else f"src{os.pathsep}{env['PYTHONPATH']}"
    commands = [
        ("diff_check", ["git", "diff", "--check"]),
        ("compileall", [sys.executable, "-m", "compileall", "-q", "src", "tests"]),
    ]
    if run_tests:
        commands.append(("unittest", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]))
    for name, command in commands:
        cp = run_command(command, cwd=repo, env=env)
        output, redacted = command_excerpt(cp.stdout + cp.stderr, 6000)
        checks.append(
            {
                "name": name,
                "ok": cp.returncode == 0,
                "returncode": cp.returncode,
                "output_excerpt": output,
                "redaction_applied": redacted,
            }
        )
    return {"ok": all(check["ok"] for check in checks), "checks": checks, "raw_output": "not_returned"}


def repo_file_status(path: Path) -> dict[str, Any]:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return {"path": PATH_NOT_RETURNED, "path_state": "missing", "exists": False, "regular_file": False}
    except OSError:
        return {"path": PATH_NOT_RETURNED, "path_state": "error", "exists": False, "regular_file": False}
    return {
        "path": PATH_NOT_RETURNED,
        "path_state": "set",
        "exists": True,
        "regular_file": stat_module.S_ISREG(current.st_mode),
        "symlink": stat_module.S_ISLNK(current.st_mode),
    }


def read_repo_json_object(path: Path, label: str) -> dict[str, Any]:
    text = read_private_regular_text(path, MAX_PLUGIN_MANIFEST_BYTES, f"{label} could not be read")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AgentError(f"{label} must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise AgentError(f"{label} must contain a JSON object")
    return payload


def public_plugin_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    version = value.strip()
    if not PLUGIN_VERSION_RE.fullmatch(version):
        return None
    return version


def plugin_manifest_version(root: Path | None = None) -> dict[str, Any]:
    manifest = (root or repo_root()) / ".codex-plugin" / "plugin.json"
    status = repo_file_status(manifest)
    result: dict[str, Any] = {
        "path": PATH_NOT_RETURNED,
        "path_state": status["path_state"],
        "exists": status["exists"],
        "version": "",
        "version_state": "missing",
        "name_matches": False,
        "ok": False,
        "raw_output": "not_returned",
    }
    if not status["regular_file"]:
        result["reason"] = "plugin_manifest_not_regular_file"
        return result
    try:
        payload = read_repo_json_object(manifest, "plugin manifest")
    except AgentError as exc:
        result["reason"] = safe_error_text(exc)
        return result
    version = public_plugin_version(payload.get("version"))
    name_matches = payload.get("name") == APP_BRIDGE_NAME
    result.update(
        {
            "version": version or "",
            "version_state": "set" if version else "invalid_or_missing",
            "name_matches": name_matches,
            "ok": bool(version) and name_matches,
        }
    )
    if not result["ok"]:
        result["reason"] = "plugin_manifest_name_or_version_invalid"
    return result


def normalize_plugin_contract_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    path = Path(value)
    if path.is_absolute():
        return None
    normalized = path.as_posix().rstrip("/")
    return normalized or None


def plugin_declares_app_manifest(root: Path) -> dict[str, Any]:
    manifest = root / ".codex-plugin" / "plugin.json"
    status = repo_file_status(manifest)
    result: dict[str, Any] = {
        "path": PATH_NOT_RETURNED,
        "path_state": status["path_state"],
        "exists": status["exists"],
        "declared": False,
        "ok": False,
        "raw_output": "not_returned",
    }
    if not status["regular_file"]:
        result["reason"] = "plugin_manifest_not_regular_file"
        return result
    try:
        payload = read_repo_json_object(manifest, "plugin manifest")
    except AgentError as exc:
        result["reason"] = safe_error_text(exc)
        return result
    normalized = normalize_plugin_contract_path(payload.get("apps"))
    result.update(
        {
            "declared": normalized is not None,
            "target": normalized or "",
            "ok": normalized == ".app.json",
        }
    )
    return result


def codex_plugin_cache_root() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    root = Path(codex_home).expanduser() if codex_home else Path.home() / ".codex"
    if not root.is_absolute():
        root = Path.cwd() / root
    return root / "plugins" / "cache" / "personal" / APP_BRIDGE_NAME


def normalize_plugin_cache_root(cache_root: Path | None = None) -> Path:
    target_cache = cache_root or codex_plugin_cache_root()
    target_cache = target_cache.expanduser()
    if not target_cache.is_absolute():
        target_cache = Path.cwd() / target_cache
    return target_cache.absolute()


def plugin_cache_status(root: Path | None = None, cache_root: Path | None = None) -> dict[str, Any]:
    repo_version = plugin_manifest_version(root)
    target_cache = normalize_plugin_cache_root(cache_root)
    result: dict[str, Any] = {
        "marketplace": "personal",
        "plugin_name": APP_BRIDGE_NAME,
        "path": PATH_NOT_RETURNED,
        "path_state": "missing",
        "exists": False,
        "directory": False,
        "symlink": False,
        "repo_manifest": repo_version,
        "repo_version_installed": False,
        "installed_version_count": 0,
        "installed_versions": [],
        "installed_versions_truncated": False,
        "symlink_entry_count": 0,
        "invalid_entry_count": 0,
        "unreadable_entry_count": 0,
        "ok": False,
        "raw_output": "not_returned",
    }
    try:
        current = target_cache.lstat()
    except FileNotFoundError:
        result["reason"] = "plugin_cache_missing"
        return result
    except OSError:
        result["path_state"] = "error"
        result["reason"] = "plugin_cache_unreadable"
        return result
    result.update(
        {
            "path_state": "set",
            "exists": True,
            "directory": stat_module.S_ISDIR(current.st_mode),
            "symlink": stat_module.S_ISLNK(current.st_mode),
        }
    )
    if result["symlink"] or not result["directory"]:
        result["reason"] = "plugin_cache_not_real_directory"
        return result

    versions: list[str] = []
    try:
        entries = list(target_cache.iterdir())
    except OSError:
        result["reason"] = "plugin_cache_unreadable"
        return result

    for entry in entries:
        try:
            entry_stat = entry.lstat()
        except OSError:
            result["unreadable_entry_count"] += 1
            continue
        if stat_module.S_ISLNK(entry_stat.st_mode):
            result["symlink_entry_count"] += 1
            continue
        if not stat_module.S_ISDIR(entry_stat.st_mode):
            result["invalid_entry_count"] += 1
            continue
        entry_version = public_plugin_version(entry.name)
        if not entry_version:
            result["invalid_entry_count"] += 1
            continue

        plugin_dir = entry / ".codex-plugin"
        try:
            plugin_dir_stat = plugin_dir.lstat()
        except OSError:
            result["unreadable_entry_count"] += 1
            continue
        if stat_module.S_ISLNK(plugin_dir_stat.st_mode) or not stat_module.S_ISDIR(plugin_dir_stat.st_mode):
            result["invalid_entry_count"] += 1
            continue
        try:
            payload = read_repo_json_object(plugin_dir / "plugin.json", "cached plugin manifest")
        except AgentError:
            result["unreadable_entry_count"] += 1
            continue
        cached_version = public_plugin_version(payload.get("version"))
        if payload.get("name") != APP_BRIDGE_NAME or cached_version != entry_version:
            result["invalid_entry_count"] += 1
            continue
        versions.append(entry_version)

    versions = sorted(set(versions))
    repo_version_text = repo_version.get("version") if repo_version.get("ok") else ""
    repo_version_installed = bool(repo_version_text) and repo_version_text in versions
    result.update(
        {
            "repo_version_installed": repo_version_installed,
            "installed_version_count": len(versions),
            "installed_versions": versions[-MAX_PLUGIN_CACHE_VERSIONS:],
            "installed_versions_truncated": len(versions) > MAX_PLUGIN_CACHE_VERSIONS,
            "ok": repo_version_installed,
        }
    )
    if not result["ok"]:
        result["reason"] = "repo_plugin_version_not_installed"
    return result


def copy_plugin_cache_path(src: Path, dst: Path) -> dict[str, int]:
    try:
        src_stat = src.lstat()
    except OSError as exc:
        raise AgentError("could_not_sync_plugin_cache") from exc
    if stat_module.S_ISLNK(src_stat.st_mode):
        raise AgentError("plugin source contains unsupported symlink")
    if stat_module.S_ISDIR(src_stat.st_mode):
        try:
            dst.mkdir(mode=0o755, exist_ok=False)
        except OSError as exc:
            raise AgentError("could_not_sync_plugin_cache") from exc
        counts = {"files": 0, "directories": 1}
        try:
            entries = sorted(src.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            raise AgentError("could_not_sync_plugin_cache") from exc
        for entry in entries:
            if plugin_cache_name_excluded(entry.name):
                continue
            child_counts = copy_plugin_cache_path(entry, dst / entry.name)
            counts["files"] += child_counts["files"]
            counts["directories"] += child_counts["directories"]
        return counts
    if stat_module.S_ISREG(src_stat.st_mode):
        if getattr(src_stat, "st_nlink", 1) > 1:
            raise AgentError("plugin source contains unsupported hardlink")
        try:
            shutil.copy2(src, dst)
        except OSError as exc:
            raise AgentError("could_not_sync_plugin_cache") from exc
        return {"files": 1, "directories": 0}
    raise AgentError("plugin source contains unsupported file type")


def plugin_cache_name_excluded(name: str) -> bool:
    return (
        name in PLUGIN_CACHE_EXCLUDED_NAMES
        or name.startswith(".")
        or name.startswith("#")
        or name.startswith(".#")
        or name.endswith(PLUGIN_CACHE_EXCLUDED_SUFFIXES)
    )


def remove_real_plugin_cache_dir(path: Path) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AgentError("could_not_sync_plugin_cache") from exc
    if stat_module.S_ISLNK(current.st_mode) or not stat_module.S_ISDIR(current.st_mode):
        raise AgentError("plugin cache entry is not a real directory")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise AgentError("safe plugin cache removal is unavailable")
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise AgentError("could_not_sync_plugin_cache") from exc


def valid_plugin_cache_entry_version(entry: Path) -> str | None:
    try:
        entry_stat = entry.lstat()
    except OSError:
        return None
    if stat_module.S_ISLNK(entry_stat.st_mode) or not stat_module.S_ISDIR(entry_stat.st_mode):
        return None
    entry_version = public_plugin_version(entry.name)
    if not entry_version:
        return None
    plugin_dir = entry / ".codex-plugin"
    try:
        plugin_dir_stat = plugin_dir.lstat()
    except OSError:
        return None
    if stat_module.S_ISLNK(plugin_dir_stat.st_mode) or not stat_module.S_ISDIR(plugin_dir_stat.st_mode):
        return None
    try:
        payload = read_repo_json_object(plugin_dir / "plugin.json", "cached plugin manifest")
    except AgentError:
        return None
    cached_version = public_plugin_version(payload.get("version"))
    if payload.get("name") != APP_BRIDGE_NAME or cached_version != entry_version:
        return None
    return entry_version


def prune_plugin_cache_versions(
    cache_root: Path,
    *,
    keep_version: str,
    max_versions: int = MAX_PLUGIN_CACHE_RETAINED_VERSIONS,
) -> dict[str, Any]:
    max_versions = normalize_int_field(max_versions, field="max_versions", minimum=1, maximum=MAX_PLUGIN_CACHE_VERSIONS)
    try:
        entries = list(cache_root.iterdir())
    except OSError as exc:
        raise AgentError("could_not_sync_plugin_cache") from exc
    candidates: list[tuple[float, str, Path]] = []
    for entry in entries:
        version = valid_plugin_cache_entry_version(entry)
        if not version or version == keep_version:
            continue
        try:
            modified = entry.lstat().st_mtime
        except OSError:
            continue
        candidates.append((modified, version, entry))
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    keep_slots = max(0, max_versions - 1)
    to_prune = candidates[keep_slots:]
    for _, _, entry in to_prune:
        remove_real_plugin_cache_dir(entry)
    retained_old_count = len(candidates) - len(to_prune)
    return {
        "max_versions": max_versions,
        "current_version_retained": True,
        "retained_old_version_count": retained_old_count,
        "pruned_version_count": len(to_prune),
        "raw_output": "not_returned",
    }


def sync_plugin_cache_from_repo(
    root: Path | None = None,
    cache_root: Path | None = None,
    retained_versions: int = MAX_PLUGIN_CACHE_RETAINED_VERSIONS,
) -> dict[str, Any]:
    context = codex_home_context()
    if not context.get("ok"):
        raise AgentError("plugin cache install is not allowed from a managed Agentin home")

    source_root = root or repo_root()
    source_root = source_root.expanduser()
    if not source_root.is_absolute():
        source_root = Path.cwd() / source_root
    source_root = source_root.absolute()
    if not is_real_directory_no_symlink(source_root):
        raise AgentError("plugin source root must be a real directory")

    manifest = plugin_manifest_version(source_root)
    if not manifest.get("ok"):
        raise AgentError("plugin manifest name or version is invalid")
    version = manifest["version"]
    target_cache = normalize_plugin_cache_root(cache_root)
    ensure_directory_chain_no_symlink(target_cache.parent, "plugin cache parent directories must be real directories")
    try:
        target_stat = target_cache.lstat()
    except FileNotFoundError:
        try:
            target_cache.mkdir(mode=0o755)
        except OSError as exc:
            raise AgentError("could_not_sync_plugin_cache") from exc
    except OSError as exc:
        raise AgentError("could_not_sync_plugin_cache") from exc
    else:
        if stat_module.S_ISLNK(target_stat.st_mode) or not stat_module.S_ISDIR(target_stat.st_mode):
            raise AgentError("plugin cache root must be a real directory")

    target_entry = target_cache / version
    tmp_entry = target_cache / f".{version}.tmp.{now_id()}"
    copied_files = 0
    copied_directories = 0
    try:
        tmp_entry.mkdir(mode=0o755, exist_ok=False)
        copied_directories += 1
        for name in PLUGIN_CACHE_ALLOWED_FILES:
            src = source_root / name
            if not path_present_no_follow(src):
                raise AgentError("plugin source is missing a required file")
            counts = copy_plugin_cache_path(src, tmp_entry / name)
            copied_files += counts["files"]
            copied_directories += counts["directories"]
        for name in PLUGIN_CACHE_ALLOWED_DIRS:
            src = source_root / name
            if not path_present_no_follow(src):
                raise AgentError("plugin source is missing a required directory")
            counts = copy_plugin_cache_path(src, tmp_entry / name)
            copied_files += counts["files"]
            copied_directories += counts["directories"]
        remove_real_plugin_cache_dir(target_entry)
        try:
            tmp_entry.rename(target_entry)
        except OSError as exc:
            raise AgentError("could_not_sync_plugin_cache") from exc
    except Exception:
        with contextlib.suppress(Exception):
            remove_real_plugin_cache_dir(tmp_entry)
        raise

    retention = prune_plugin_cache_versions(target_cache, keep_version=version, max_versions=retained_versions)
    status = plugin_cache_status(source_root, target_cache)
    return {
        "ok": bool(status.get("ok")),
        "status": "synced" if status.get("ok") else "sync_incomplete",
        "marketplace": "personal",
        "plugin_name": APP_BRIDGE_NAME,
        "version": version,
        "cache_entry": PATH_NOT_RETURNED,
        "cache_entry_state": "set",
        "copied_files": copied_files,
        "copied_directories": copied_directories,
        "excluded_artifacts": [
            "git",
            "bytecode",
            "test_cache",
            "repo_tests",
            "hidden_files",
            "editor_swap",
            "backup_artifacts",
            "hardlinks_rejected",
        ],
        "retention": retention,
        "plugin_cache": status,
        "raw_output": "not_returned",
    }


def app_id_kind(app_id: str) -> str:
    if app_id.startswith("connector_"):
        return "connector"
    if app_id.startswith("asdk_app_"):
        return "app"
    return "custom"


def master_app_bridge_status() -> dict[str, Any]:
    root = repo_root()
    manifest = root / ".app.json"
    app_manifest = repo_file_status(manifest)
    plugin_apps = plugin_declares_app_manifest(root)
    result: dict[str, Any] = {
        "ok": False,
        "app_name": APP_BRIDGE_NAME,
        "app_manifest": app_manifest,
        "plugin_apps": plugin_apps,
        "registration_mode": "local_plugin_app_manifest",
        "chatgpt_connector_registration": "create_or_refresh_in_chatgpt_developer_mode",
        "raw_output": "not_returned",
    }
    if not app_manifest["regular_file"]:
        result["reason"] = "app_manifest_not_regular_file"
        return result
    try:
        payload = read_repo_json_object(manifest, "app manifest")
    except AgentError as exc:
        result["reason"] = safe_error_text(exc)
        return result
    apps = payload.get("apps")
    if not isinstance(apps, dict):
        result["reason"] = "apps_not_object"
        return result
    app_entry = apps.get(APP_BRIDGE_NAME)
    if not isinstance(app_entry, dict):
        result["reason"] = "codex_master_app_missing"
        return result
    connector_id = app_entry.get("id")
    if not isinstance(connector_id, str) or not connector_id.strip():
        result["reason"] = "connector_id_missing"
        return result
    connector_id = connector_id.strip()
    id_prefix_ok = connector_id.startswith(APP_BRIDGE_ID_PREFIXES)
    result.update(
        {
            "connector_id": connector_id,
            "connector_id_kind": app_id_kind(connector_id),
            "connector_id_format_ok": id_prefix_ok,
            "ok": id_prefix_ok and bool(plugin_apps.get("ok")),
        }
    )
    if not result["ok"]:
        result["reason"] = "plugin_or_connector_id_not_ready"
    return result


def master_plugin_status() -> dict[str, Any]:
    root = repo_root()
    manifest = root / ".codex-plugin" / "plugin.json"
    mcp_manifest = root / ".mcp.json"
    app_manifest = root / ".app.json"
    skill = root / "skills" / "codex-master-fleet" / "SKILL.md"
    app_bridge = master_app_bridge_status()
    mcp_registration = check_mcp_registration(DEFAULT_INSTALL_PATH)
    startup_self_test = mcp_command_startup_self_test(DEFAULT_INSTALL_PATH)
    cache_status = plugin_cache_status(root)
    client_config = codex_client_mcp_config_status(command_path=DEFAULT_INSTALL_PATH)
    return {
        "ok": (
            bool(app_bridge.get("ok"))
            and bool(mcp_registration.get("ok"))
            and bool(startup_self_test.get("ok"))
            and bool(cache_status.get("ok"))
            and bool(client_config.get("ok"))
        ),
        "repo": PATH_NOT_RETURNED,
        "repo_state": "set",
        "plugin_manifest": repo_file_status(manifest),
        "plugin_manifest_version": plugin_manifest_version(root),
        "plugin_cache": cache_status,
        "mcp_manifest": repo_file_status(mcp_manifest),
        "app_manifest": repo_file_status(app_manifest),
        "skill": repo_file_status(skill),
        "app_bridge": app_bridge,
        "mcp_registration": mcp_registration,
        "client_config": client_config,
        "startup_self_test": startup_self_test,
        "installed_source_worktree_state": installed_source_worktree_state(
            resolve_path_no_throw(DEFAULT_INSTALL_PATH) if DEFAULT_INSTALL_PATH.is_symlink() else None,
            repo_wrapper_path(),
        ),
        "codex_home_context": codex_home_context(),
        "raw_output": "not_returned",
    }


def master_namespace_status() -> dict[str, Any]:
    registration = check_mcp_registration(DEFAULT_INSTALL_PATH)
    startup_self_test = mcp_command_startup_self_test(DEFAULT_INSTALL_PATH)
    tools_list_self_test = mcp_command_tools_list_self_test(DEFAULT_INSTALL_PATH)
    cache_status = plugin_cache_status(repo_root())
    client_config = codex_client_mcp_config_status(command_path=DEFAULT_INSTALL_PATH)
    home_context = codex_home_context()
    tool_names = {tool["name"] for tool in TOOLS if isinstance(tool.get("name"), str)}
    local_tool_contract = {
        "tool_count": len(tool_names),
        "master_app_bridge_status": "master_app_bridge_status" in tool_names,
        "master_plugin_status": "master_plugin_status" in tool_names,
        "master_namespace_status": "master_namespace_status" in tool_names,
        "raw_output": "not_returned",
    }
    server_ready = bool(registration.get("ok")) and bool(startup_self_test.get("ok")) and bool(
        tools_list_self_test.get("ok")
    )
    plugin_cache_ready = bool(cache_status.get("ok"))
    client_config_ready = bool(client_config.get("ok"))
    active_home_ready = bool(home_context.get("ok"))
    namespace_ready = server_ready and plugin_cache_ready and client_config_ready and active_home_ready
    return {
        "ok": namespace_ready,
        "server_name": MCP_SERVER_NAME,
        "expected_mcp_server": MCP_SERVER_NAME,
        "mcp_server_ready": server_ready,
        "plugin_cache_ready": plugin_cache_ready,
        "client_config_ready": client_config_ready,
        "active_home_ready": active_home_ready,
        "namespace_ready": namespace_ready,
        "expected_tools": {
            "master_app_bridge_status": local_tool_contract["master_app_bridge_status"],
            "master_plugin_status": local_tool_contract["master_plugin_status"],
            "master_namespace_status": local_tool_contract["master_namespace_status"],
        },
        "local_tool_contract": local_tool_contract,
        "mcp_registration": registration,
        "startup_self_test": startup_self_test,
        "tools_list_self_test": tools_list_self_test,
        "plugin_cache": cache_status,
        "client_config": client_config,
        "app_bridge": master_app_bridge_status(),
        "codex_home_context": home_context,
        "running_process_summary": codex_related_process_summary(),
        "tool_search": {
            "authoritative_for_local_stdio_mcp_tools": False,
            "note": "Use /mcp or this MCP tools/list probe for the local namespace.",
            "raw_output": "not_returned",
        },
        "client_refresh": {
            "existing_sessions_may_need_restart": True,
            "reason": "Codex clients can cache MCP tool metadata for a running session.",
            "recommended_action_if_missing_in_client": "run_install_force_then_restart_affected_codex_cli",
            "raw_output": "not_returned",
        },
        "raw_output": "not_returned",
    }


def mcp_get_field(output: str, field: str) -> str | None:
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == field:
            return value.strip()
    return None


def mcp_registration_command_matches(output: str, command_path: Path) -> bool:
    return mcp_get_field(output, "command") == str(command_path)


def mcp_startup_timeout_seconds(output: str) -> int | None:
    value = mcp_get_field(output, "startup_timeout_sec")
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def check_mcp_registration(command_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    codex_path = shutil.which("codex")
    if not codex_path:
        return {"registered": False, "ok": False, "reason": "codex command not found"}
    cp = run_command(["codex", "mcp", "get", MCP_SERVER_NAME])
    raw_output = cp.stdout + cp.stderr
    output, redacted = command_excerpt(raw_output)
    registered = cp.returncode == 0
    command_matches = mcp_registration_command_matches(raw_output, command_path) if registered else False
    startup_timeout_sec = mcp_startup_timeout_seconds(raw_output) if registered else None
    startup_timeout_ok = (
        startup_timeout_sec is not None and startup_timeout_sec >= RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS
    )
    return {
        "registered": registered,
        "command_matches": command_matches,
        "startup_timeout_sec": startup_timeout_sec,
        "startup_timeout_ok": startup_timeout_ok,
        "startup_timeout_recommended_sec": RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS,
        "ok": registered and command_matches,
        "redaction_applied": redacted,
        "output_excerpt": output if not registered or not command_matches else "",
    }


def doctor() -> dict[str, Any]:
    ensure_state()
    wrapper = repo_wrapper_path()
    install_path = DEFAULT_INSTALL_PATH
    installed_target = None
    installed_target_state = "not_symlink"
    if install_path.is_symlink():
        resolved_install_path = resolve_path_no_throw(install_path)
        installed_target_state = (
            "unreadable"
            if resolved_install_path is None
            else "matching_repo_wrapper"
            if resolved_install_path == wrapper
            else "different"
        )
        installed_target = PATH_NOT_RETURNED if resolved_install_path else "<unreadable>"
    else:
        resolved_install_path = None
    checks: list[dict[str, Any]] = [
        {"name": "tmux_available", "ok": shutil.which("tmux") is not None},
        {"name": "codex_available", "ok": shutil.which("codex") is not None},
        {
            "name": "repo_wrapper_exists",
            "ok": wrapper.exists(),
            "path": PATH_NOT_RETURNED,
            "path_state": "set",
        },
        {
            "name": "repo_wrapper_executable",
            "ok": os.access(wrapper, os.X_OK),
            "path": PATH_NOT_RETURNED,
            "path_state": "set",
        },
        {
            "name": "installed_symlink",
            "ok": install_path.is_symlink() and resolved_install_path == wrapper,
            "path": PATH_NOT_RETURNED,
            "path_state": "set",
            "target": installed_target,
            "target_state": installed_target_state,
        },
        installed_source_worktree_state(resolved_install_path, wrapper),
        {"name": "mcp_startup_self_test", **mcp_command_startup_self_test(install_path)},
    ]
    for agent, cfg in AGENTS.items():
        process_summary = agent_home_process_summary(agent)
        running = tmux_alive(cfg["session"])
        checks.extend(
            [
                {
                    "name": f"agent_{agent}_home_exists",
                    "ok": cfg["home"].is_dir(),
                    "path": PATH_NOT_RETURNED,
                    "path_state": "set",
                    "home_kind": "managed_agent_home",
                },
                {
                    "name": f"agent_{agent}_runner_executable",
                    "ok": is_regular_executable_no_symlink(cfg["runner"]),
                    "path": PATH_NOT_RETURNED,
                    "path_state": public_config_path_state(cfg["runner"]),
                    "symlink_allowed": False,
                },
                {
                    "name": f"agent_{agent}_tmux_session_state",
                    "ok": True,
                    "running": running,
                    "session": cfg["session"],
                    "severity": "info",
                },
                {
                    "name": f"agent_{agent}_home_not_used_externally",
                    "ok": process_summary["external_process_count"] == 0,
                    "home": process_summary["home"],
                    "home_kind": process_summary.get("home_kind", "managed_agent_home"),
                    "external_process_count": process_summary["external_process_count"],
                    "external_processes": process_summary["external_processes"],
                    "external_processes_truncated": process_summary["external_processes_truncated"],
                    "raw_output": "not_returned",
                },
            ]
        )
    registration = check_mcp_registration(install_path)
    checks.append({"name": "mcp_registered", **registration})
    checks.append(codex_client_mcp_config_status(command_path=install_path))
    checks.append(
        {
            "name": "mcp_startup_timeout_configured",
            "ok": bool(registration.get("startup_timeout_ok")),
            "startup_timeout_sec": registration.get("startup_timeout_sec"),
            "recommended_sec": RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS,
            "raw_output": "not_returned",
        }
    )
    checks.append(codex_home_context())
    checks.append({"name": "raw_log_retention_configured", "ok": True, **raw_log_retention_status()})
    return {"ok": all(check["ok"] for check in checks), "checks": checks, "raw_output": "not_returned"}


def install(
    register: bool = True,
    force: bool = False,
    install_path: Path = DEFAULT_INSTALL_PATH,
    sync_plugin_cache: bool = True,
) -> dict[str, Any]:
    if register:
        assert_install_context_allows_master_registration()
    wrapper = repo_wrapper_path()
    if not wrapper.exists():
        raise AgentError(f"repo wrapper missing: {wrapper}")
    if not os.access(wrapper, os.X_OK):
        raise AgentError(f"repo wrapper is not executable: {wrapper}")
    startup_self_test: dict[str, Any] = {"requested": register, "status": "skipped", "raw_output": "not_returned"}
    if register:
        wrapper_self_test = mcp_command_startup_self_test(wrapper)
        if not wrapper_self_test["ok"]:
            raise AgentError("repo wrapper failed MCP startup self-test")

    install_path = normalize_install_path(install_path)
    ensure_directory_chain_no_symlink(install_path.parent, "install parent directories must be real directories")
    if install_path.exists() or install_path.is_symlink():
        resolved_install_path = resolve_path_no_throw(install_path) if install_path.is_symlink() else None
        if install_path.is_symlink() and resolved_install_path == wrapper:
            symlink_status = "already_installed"
        elif force:
            replace_install_symlink(install_path, wrapper)
            symlink_status = "replaced"
        else:
            raise AgentError("install path exists and is not this wrapper symlink")
    else:
        replace_install_symlink(install_path, wrapper)
        symlink_status = "created"

    registration: dict[str, Any] = {"requested": register, "status": "skipped"}
    if register:
        startup_self_test = {"requested": True, **mcp_command_startup_self_test(install_path)}
        if not startup_self_test["ok"]:
            raise AgentError("install path failed MCP startup self-test")
        current = check_mcp_registration(install_path)
        startup_timeout_config = None
        if current.get("ok"):
            registration = {"requested": True, "status": "already_registered"}
        else:
            if current.get("registered") and force:
                remove = run_command(["codex", "mcp", "remove", MCP_SERVER_NAME])
                if remove.returncode != 0:
                    output, redacted = command_excerpt(remove.stdout + remove.stderr)
                    raise AgentError(f"codex mcp remove failed: {output if not redacted else '<redacted>'}")
            elif current.get("registered"):
                raise AgentError("MCP server is registered with a different command; rerun install with --force")
            add = run_command(["codex", "mcp", "add", MCP_SERVER_NAME, "--", str(install_path)])
            if add.returncode != 0:
                output, redacted = command_excerpt(add.stdout + add.stderr)
                raise AgentError(f"codex mcp add failed: {output if not redacted else '<redacted>'}")
            registration = {"requested": True, "status": "registered"}
        if not current.get("startup_timeout_ok"):
            startup_timeout_config = ensure_mcp_startup_timeout_configured()
        else:
            startup_timeout_config = {
                "status": "already_configured",
                "startup_timeout_sec": current.get(
                    "startup_timeout_sec", RECOMMENDED_MCP_STARTUP_TIMEOUT_SECONDS
                ),
                "previous_startup_timeout_sec": current.get("startup_timeout_sec"),
                "config_path": "not_returned",
                "raw_output": "not_returned",
            }
        registration["startup_timeout"] = startup_timeout_config
    plugin_cache_install = (
        sync_plugin_cache_from_repo()
        if sync_plugin_cache
        else {"requested": False, "status": "skipped", "raw_output": "not_returned"}
    )

    return {
        "ok": True,
        "install_path": PATH_NOT_RETURNED,
        "install_path_state": "set",
        "install_path_kind": "configured_install_path",
        "target": PATH_NOT_RETURNED,
        "target_state": "repo_wrapper",
        "symlink": symlink_status,
        "startup_self_test": startup_self_test,
        "mcp": registration,
        "plugin_cache_install": plugin_cache_install,
        "raw_output": "not_returned",
    }


def uninstall(unregister: bool = True, remove_symlink: bool = False, install_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    install_path = normalize_install_path(install_path)
    mcp_status = "skipped"
    if unregister:
        current = check_mcp_registration(install_path)
        if current.get("registered"):
            remove = run_command(["codex", "mcp", "remove", MCP_SERVER_NAME])
            if remove.returncode != 0:
                output, redacted = command_excerpt(remove.stdout + remove.stderr)
                raise AgentError(f"codex mcp remove failed: {output if not redacted else '<redacted>'}")
            mcp_status = "removed"
        else:
            mcp_status = "not_registered"

    symlink_status = "skipped"
    if remove_symlink:
        ensure_directory_chain_no_symlink(install_path.parent, "install parent directories must be real directories")
        wrapper = repo_wrapper_path()
        resolved_install_path = resolve_path_no_throw(install_path) if install_path.is_symlink() else None
        if install_path.is_symlink() and resolved_install_path == wrapper:
            install_path.unlink()
            symlink_status = "removed"
        elif install_path.exists() or install_path.is_symlink():
            symlink_status = "left_in_place_not_repo_wrapper"
        else:
            symlink_status = "missing"

    return {"ok": True, "mcp": mcp_status, "symlink": symlink_status, "raw_output": "not_returned"}


def send_agent(agent: str, text: str, enter: bool = True) -> dict[str, Any]:
    text = bounded_text(text, field="text", max_chars=MAX_SEND_TEXT, required=True, strip=False) or ""
    cfg = AGENTS[agent]
    session = cfg["session"]
    if not tmux_alive(session):
        raise AgentError(f"agent {agent} is not running")
    paste_mode = "bracketed_paste" if "\n" in text else "plain_paste"
    payload = f"{BRACKETED_PASTE_BEGIN}{text}{BRACKETED_PASTE_END}" if paste_mode == "bracketed_paste" else text
    buffer_name = f"codex-master-mcp-{agent}-{int(time.time() * 1000)}"
    cp = run_tmux(["load-buffer", "-b", buffer_name, "-"], input_text=payload, check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux load-buffer failed for agent {agent}: {command_error_text(cp.stderr)}")
    cp = run_tmux(["paste-buffer", "-d", "-b", buffer_name, "-t", session], check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux paste-buffer failed for agent {agent}: {command_error_text(cp.stderr)}")
    if enter:
        cp = run_tmux(["send-keys", "-t", session, "Enter"], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux send Enter failed for agent {agent}: {command_error_text(cp.stderr)}")
    return {
        "agent": agent,
        "status": "sent",
        "chars": len(text),
        "paste_mode": paste_mode,
        "submitted": enter,
        "response_output": "not_returned",
    }


def interrupt_agent(agent: str, force: bool = False) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    if not tmux_alive(session):
        raise AgentError(f"agent {agent} is not running")
    claim = claim_agent(agent, force=force)
    release_on_failure = claim["status"] in {"claimed", "claimed_expired", "forced"}
    lease = claim["lease"]
    try:
        cp = run_tmux(["send-keys", "-t", session, "C-c"], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux interrupt failed for agent {agent}: {command_error_text(cp.stderr)}")
    except Exception:
        if release_on_failure:
            release_agent(agent, force=True)
        raise
    return {"agent": agent, "status": "interrupt_sent", "lease": lease, "response_output": "not_returned"}


def strip_ansi(text: str) -> str:
    text = ANSI_RE.sub("", text)
    return text.replace("\r", "\n")


def redact(text: str) -> tuple[str, bool]:
    redacted = text
    changed = False
    for pattern in SECRET_PATTERNS:
        next_text = pattern.sub(
            lambda m: m.group(1) + "=<redacted>" if m.lastindex and m.lastindex >= 2 else "<redacted>",
            redacted,
        )
        changed = changed or next_text != redacted
        redacted = next_text
    path_redacted = ABSOLUTE_PATH_RE.sub("/<redacted>", redacted)
    changed = changed or path_redacted != redacted
    redacted = path_redacted
    return redacted, changed


def trim_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join([f"... truncated to last {max_lines} lines ...", *lines[-max_lines:]])


def trim_chars(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return "... truncated to last characters ...\n" + text[-max_chars:]


def safe_error_text(value: Any, max_chars: int = MAX_ERROR_CHARS) -> str:
    cleaned = strip_ansi(str(value))
    redacted, _changed = redact(cleaned)
    return trim_chars(redacted, max_chars)


def command_error_text(value: Any) -> str:
    text = safe_error_text(value).strip()
    return text or "no stderr"


def read_log_tail(path: Path, approx_bytes: int) -> str:
    approx_bytes = max(1, int(approx_bytes))
    try:
        current_stat = path.lstat()
    except OSError:
        return ""
    if not stat_module.S_ISREG(current_stat.st_mode):
        return ""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(path, flags)
        opened_stat = os.fstat(fd)
        if not stat_module.S_ISREG(opened_stat.st_mode):
            return ""
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - approx_bytes), os.SEEK_SET)
            return fh.read(approx_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""
    finally:
        if fd >= 0:
            os.close(fd)


def pane_tail(agent: str, lines: int) -> str:
    cfg = AGENTS[agent]
    session = cfg["session"]
    if not tmux_alive(session):
        return ""
    cp = run_tmux(["capture-pane", "-p", "-t", session, "-S", f"-{lines}"], check=False)
    if cp.returncode != 0:
        return ""
    return cp.stdout


def safe_tail(agent: str, lines: int = 40, chars: int = 4000, source: str = "pane") -> dict[str, Any]:
    ensure_state()
    lines = max(1, min(int(lines), MAX_TAIL_LINES))
    chars = max(1, min(int(chars), MAX_TAIL_CHARS))
    if source not in ("pane", "log"):
        raise AgentError("source must be 'pane' or 'log'")
    meta = read_meta(agent)
    if source == "pane":
        raw = pane_tail(agent, lines)
    else:
        raw_log = meta.get("raw_log")
        raw_log_path = allowed_raw_log_path(raw_log)
        if raw_log and raw_log_path is None:
            raise AgentError("raw_log path is outside managed raw log state")
        raw = read_log_tail(raw_log_path, chars * 4) if raw_log_path else ""
    cleaned = strip_ansi(raw)
    redacted, was_redacted = redact(cleaned)
    cleaned = trim_lines(redacted, lines)
    cleaned = trim_chars(cleaned, chars)
    return {
        "agent": agent,
        "source": source,
        "lines_limit": lines,
        "chars_limit": chars,
        "redaction_applied": was_redacted,
        "raw_log": "not_returned" if meta.get("raw_log") else None,
        "output": cleaned,
    }


def negotiate_protocol_version(requested: str | None) -> str:
    if requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    raise AgentError("Unsupported protocol version")


def multi_agent_result(selected: list[str], fn: Any) -> dict[str, Any]:
    results = []
    for agent in selected:
        try:
            results.append(fn(agent))
        except Exception as exc:
            results.append({"agent": agent, "error": safe_error_text(exc)})
    return {"results": results}


def call_agent_lifecycle(agent: str, fn: Any) -> dict[str, Any]:
    with agent_lifecycle_lock(agent):
        return fn()


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "agent_start":
        selected = agent_ids(str(args.get("agent", "both")))
        return multi_agent_result(
            selected,
            lambda agent: call_agent_lifecycle(agent, lambda: start_agent_with_lease(agent, args.get("cwd"), args.get("prompt"))),
        )
    if name == "agent_stop":
        selected = agent_ids(str(args.get("agent", "both")))
        return multi_agent_result(
            selected,
            lambda agent: call_agent_lifecycle(agent, lambda: stop_agent(agent, bool_arg(args, "force", False))),
        )
    if name == "agent_status":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(selected, status_agent)
    if name == "agent_wait":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_wait requires exactly one agent: a or b")
        return wait_agent(
            selected[0],
            int_arg(args, "timeout_seconds", DEFAULT_WAIT_SECONDS),
            int_arg(args, "poll_interval_seconds", DEFAULT_WAIT_POLL_SECONDS),
        )
    if name == "agent_skills":
        selected = agent_ids(str(args.get("agent", "all")))
        include_names = bool_arg(args, "include_names", False)
        limit = int_arg(args, "limit", 80)
        names_offset = int_arg(args, "names_offset", 0)
        plugins_offset = int_arg(args, "plugins_offset", 0)
        plugins_limit = int_arg(args, "plugins_limit", MAX_CAPABILITY_PLUGINS)
        return multi_agent_result(
            selected,
            lambda agent: skills_agent(agent, include_names, limit, names_offset, plugins_offset, plugins_limit),
        )
    if name == "agent_skill_match":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(
            selected,
            lambda agent: skill_match_agent(agent, args.get("skill"), int_arg(args, "limit", 8)),
        )
    if name == "agent_capabilities":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(selected, capabilities_agent)
    if name == "agent_scope_check":
        return scope_check(
            as_string_list(args.get("scope"), field="scope"),
            as_string_list(args.get("write_paths"), field="write_paths"),
            args.get("cwd"),
        )
    if name == "agent_assign":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign requires exactly one agent: a or b")
        return call_agent_lifecycle(
            selected[0],
            lambda: assign_agent(
                selected[0],
                role=str(args.get("role", "")),
                task=args.get("task"),
                scope=args.get("scope"),
                skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
                write_paths=args.get("write_paths"),
                context=args.get("context"),
                forbidden=args.get("forbidden"),
                name=args.get("name") if isinstance(args.get("name"), str) else None,
                enter=bool_arg(args, "enter", True),
                allow_missing_skill=bool_arg(args, "allow_missing_skill", False),
                allow_subagents=bool_arg(args, "allow_subagents", False),
            ),
        )
    if name == "agent_assign_readonly":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign_readonly requires exactly one agent: a or b")
        return call_agent_lifecycle(
            selected[0],
            lambda: assign_agent(
                selected[0],
                role="exploriererin",
                task=args.get("task"),
                scope=args.get("scope"),
                skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
                context=args.get("context"),
                forbidden=args.get("forbidden"),
                name=args.get("name") if isinstance(args.get("name"), str) else None,
                enter=bool_arg(args, "enter", True),
                allow_missing_skill=bool_arg(args, "allow_missing_skill", False),
                allow_subagents=bool_arg(args, "allow_subagents", False),
            ),
        )
    if name == "agent_assign_write":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign_write requires exactly one agent: a or b")
        return call_agent_lifecycle(
            selected[0],
            lambda: assign_agent(
                selected[0],
                role="arbeitsbiene",
                task=args.get("task"),
                scope=args.get("scope"),
                skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
                write_paths=args.get("write_paths"),
                context=args.get("context"),
                forbidden=args.get("forbidden"),
                name=args.get("name") if isinstance(args.get("name"), str) else None,
                enter=bool_arg(args, "enter", True),
                allow_missing_skill=bool_arg(args, "allow_missing_skill", False),
                allow_subagents=bool_arg(args, "allow_subagents", False),
            ),
        )
    if name == "agent_assignments":
        return list_assignments(str(args.get("agent", "all")), int_arg(args, "limit", 20))
    if name == "agent_last_assignment_status":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_last_assignment_status requires exactly one agent: a or b")
        return last_assignment_status(selected[0])
    if name == "agent_report_request":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_report_request requires exactly one agent: a or b")
        return call_agent_lifecycle(
            selected[0],
            lambda: run_with_agent_lease(
                selected[0],
                lambda lease: request_agent_report(
                    selected[0],
                    args.get("assignment_id"),
                    bool_arg(args, "enter", True),
                    lease=lease,
                ),
            ),
        )
    if name == "worktree_create_for_agent":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("worktree_create_for_agent requires exactly one agent: a or b")
        return worktree_create_for_agent(
            selected[0],
            args.get("path"),
            args.get("base_ref"),
        )
    if name == "worktree_status":
        return worktree_status(args.get("path"))
    if name == "integration_status":
        return integration_status()
    if name == "commit_ready_check":
        return commit_ready_check(bool_arg(args, "run_tests", True))
    if name == "master_app_bridge_status":
        return master_app_bridge_status()
    if name == "master_plugin_status":
        return master_plugin_status()
    if name == "master_namespace_status":
        return master_namespace_status()
    if name == "agent_doctor":
        return doctor()
    if name == "agent_send":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_send requires exactly one agent: a or b")
        text = args.get("text")
        if not isinstance(text, str) or text == "":
            raise AgentError("agent_send requires non-empty text")
        return call_agent_lifecycle(
            selected[0],
            lambda: run_with_agent_lease(
                selected[0],
                lambda lease: {
                    **send_agent(selected[0], text, bool_arg(args, "enter", True)),
                    "lease": lease,
                },
            ),
        )
    if name == "agent_interrupt":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_interrupt requires exactly one agent: a or b")
        return call_agent_lifecycle(
            selected[0],
            lambda: interrupt_agent(selected[0], bool_arg(args, "force", False)),
        )
    if name == "agent_claim":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_claim requires exactly one agent: a or b")
        return claim_agent_with_wait(
            selected[0],
            int_arg(args, "ttl_seconds", DEFAULT_AGENT_LEASE_SECONDS),
            bool_arg(args, "force", False),
            int_arg(args, "wait_seconds", 0),
            int_arg(args, "poll_interval_seconds", DEFAULT_WAIT_POLL_SECONDS),
        )
    if name == "agent_release":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_release requires exactly one agent: a or b")
        return call_agent_lifecycle(selected[0], lambda: release_agent(selected[0], bool_arg(args, "force", False)))
    if name == "agent_lease_status":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(selected, agent_lease_status)
    if name == "agent_safe_tail":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_safe_tail requires exactly one agent: a or b")
        return safe_tail(
            selected[0],
            int_arg(args, "lines", 40),
            int_arg(args, "chars", 4000),
            str(args.get("source", "pane")),
        )
    raise AgentError(f"unknown tool: {name}")


def bool_arg(args: dict[str, Any], name: str, default: bool) -> bool:
    value = args.get(name, default)
    if isinstance(value, bool):
        return value
    raise AgentError(f"{name} must be a boolean")


def int_arg(args: dict[str, Any], name: str, default: int) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentError(f"{name} must be an integer")
    return value


def text_schema(max_chars: int, **extra: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "maxLength": max_chars}
    schema.update(extra)
    return schema


def text_array_schema(
    *,
    max_items: int = MAX_ASSIGNMENT_LIST_ITEMS,
    max_chars: int = MAX_TEXT_FIELD,
    default: list[str] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "maxItems": max_items,
        "items": text_schema(max_chars),
    }
    if default is not None:
        schema["default"] = default
    return schema


TOOLS: list[dict[str, Any]] = [
    {
        "name": "agent_start",
        "description": "Start Codex Agentin A, B, or both in persistent tmux sessions with gpt-5.4-mini, --yolo -s danger-full-access --search. Does not return raw output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "both"], "default": "both"},
                "cwd": text_schema(MAX_PATH_TEXT, description="Working directory. Defaults to the MCP server cwd."),
                "prompt": text_schema(MAX_SEND_TEXT, description="Optional initial prompt passed to Codex."),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_status",
        "description": "Return structured status for Codex Agentin A, B, or all Agentinnen, including data-sparse response and limit classification. Does not return raw output.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_lease_status",
        "description": "Return data-sparse per-Agentin lease state for multi-client collision avoidance.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_claim",
        "description": "Claim or renew one Agentin for this MCP client before sending work. Does not return client identity.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "ttl_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_AGENT_LEASE_SECONDS,
                    "default": DEFAULT_AGENT_LEASE_SECONDS,
                },
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_WAIT_SECONDS,
                    "default": 0,
                },
                "poll_interval_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_WAIT_POLL_SECONDS,
                    "default": DEFAULT_WAIT_POLL_SECONDS,
                },
                "force": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_release",
        "description": "Release this MCP client's claim on one Agentin. Force only after checking status.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "force": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_wait",
        "description": "Wait briefly for one Agentin to show activity, stop, or hit a classified limit. Returns metadata and status only; does not return raw output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_WAIT_SECONDS,
                    "default": DEFAULT_WAIT_SECONDS,
                },
                "poll_interval_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_WAIT_POLL_SECONDS,
                    "default": DEFAULT_WAIT_POLL_SECONDS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_send",
        "description": "Send text to one running Agentin through its tmux PTY. The Agentin response is not returned automatically.",
        "inputSchema": {
            "type": "object",
            "required": ["agent", "text"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "text": text_schema(MAX_SEND_TEXT),
                "enter": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_interrupt",
        "description": "Send Ctrl-C to one running Agentin. Does not return raw output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "force": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_stop",
        "description": "Stop Codex Agentin A, B, or both by killing the managed tmux session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "both"], "default": "both"},
                "force": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_safe_tail",
        "description": "Explicitly request a small, ANSI-stripped, redacted output excerpt from one Agentin. Raw logs remain local.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "source": {"type": "string", "enum": ["pane", "log"], "default": "pane"},
                "lines": {"type": "integer", "minimum": 1, "maximum": MAX_TAIL_LINES, "default": 40},
                "chars": {"type": "integer", "minimum": 1, "maximum": MAX_TAIL_CHARS, "default": 4000},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_skills",
        "description": "Return data-sparse skill inventory for one or all Agentinnen. Does not return skill file contents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"},
                "include_names": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 0, "maximum": MAX_SKILL_NAMES, "default": 80},
                "names_offset": {"type": "integer", "minimum": 0, "default": 0},
                "plugins_offset": {"type": "integer", "minimum": 0, "default": 0},
                "plugins_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_SKILL_NAMES,
                    "default": MAX_CAPABILITY_PLUGINS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_skill_match",
        "description": "Check whether one or all Agentinnen have a named skill. Does not return skill file contents.",
        "inputSchema": {
            "type": "object",
            "required": ["skill"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"},
                "skill": text_schema(MAX_SKILL_REF),
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_SKILL_NAMES, "default": 8},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_capabilities",
        "description": "Return data-sparse capability summaries for one or all Agentinnen.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_scope_check",
        "description": "Check whether write paths stay inside declared assignment scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "write_paths": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "cwd": text_schema(MAX_PATH_TEXT),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_assign",
        "description": "Send a structured, skill-aware assignment to one Agentin with explicit scope, write boundaries, and model policy. Does not return the prompt or response output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent", "role", "task"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "role": {"type": "string", "enum": ["exploriererin", "arbeitsbiene"]},
                "task": text_schema(MAX_TASK_TEXT),
                "skill": text_schema(MAX_SKILL_REF),
                "scope": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "write_paths": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "context": text_array_schema(default=[]),
                "forbidden": text_array_schema(default=[]),
                "name": text_schema(MAX_AGENTIN_NAME),
                "enter": {"type": "boolean", "default": True},
                "allow_missing_skill": {"type": "boolean", "default": False},
                "allow_subagents": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_assign_readonly",
        "description": "Shortcut for a read-only Exploriererin assignment. Does not return the prompt or response output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent", "task"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "task": text_schema(MAX_TASK_TEXT),
                "skill": text_schema(MAX_SKILL_REF),
                "scope": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "context": text_array_schema(default=[]),
                "forbidden": text_array_schema(default=[]),
                "name": text_schema(MAX_AGENTIN_NAME),
                "enter": {"type": "boolean", "default": True},
                "allow_missing_skill": {"type": "boolean", "default": False},
                "allow_subagents": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_assign_write",
        "description": "Shortcut for an Arbeitsbiene write assignment with required explicit write paths. Does not return the prompt or response output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent", "task", "write_paths"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "task": text_schema(MAX_TASK_TEXT),
                "skill": text_schema(MAX_SKILL_REF),
                "scope": text_array_schema(max_chars=MAX_PATH_TEXT, default=[]),
                "write_paths": text_array_schema(max_chars=MAX_PATH_TEXT),
                "context": text_array_schema(default=[]),
                "forbidden": text_array_schema(default=[]),
                "name": text_schema(MAX_AGENTIN_NAME),
                "enter": {"type": "boolean", "default": True},
                "allow_missing_skill": {"type": "boolean", "default": False},
                "allow_subagents": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_assignments",
        "description": "Return data-sparse assignment audit records. Does not return prompt text or Agentin responses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ASSIGNMENT_RECORDS, "default": 20},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_last_assignment_status",
        "description": "Return the most recent assignment metadata for one Agentin. Does not return prompt text or Agentin responses.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {"agent": {"type": "string", "enum": ["a", "b"]}},
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_report_request",
        "description": "Ask one running Agentin for a concise report. The Agentin response is not returned automatically.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "assignment_id": text_schema(MAX_ASSIGNMENT_ID),
                "enter": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "worktree_create_for_agent",
        "description": "Create an isolated git worktree for one Agentin. Does not return command output.",
        "inputSchema": {
            "type": "object",
            "required": ["agent"],
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b"]},
                "path": text_schema(MAX_PATH_TEXT),
                "base_ref": text_schema(MAX_PATH_TEXT),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "worktree_status",
        "description": "Return capped git status and worktree metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": text_schema(MAX_PATH_TEXT)},
            "additionalProperties": False,
        },
    },
    {
        "name": "integration_status",
        "description": "Return repo integration metadata: git status, diff stat, and recent assignment records.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "commit_ready_check",
        "description": "Run fixed readiness checks: git diff --check, compileall, and optionally unittest.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_tests": {"type": "boolean", "default": True}},
            "additionalProperties": False,
        },
    },
    {
        "name": "master_app_bridge_status",
        "description": "Return codex-master App Bridge manifest and connector-ID status without local paths.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "master_plugin_status",
        "description": "Return plugin packaging, App Bridge, and MCP registration status for codex-master.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "master_namespace_status",
        "description": "Diagnose whether codex-master-mcp is registered, starts, and exposes its MCP tools to new clients. Does not return raw output.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "agent_doctor",
        "description": "Return structured diagnostics for installation, MCP registration, runners, and tmux sessions. Does not return raw output.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


TOOL_SCHEMAS = {tool["name"]: tool["inputSchema"] for tool in TOOLS}


def validate_tool_call(name: Any, args: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(name, str) or not name.strip():
        raise AgentError("tools/call requires a known tool name")
    if name not in TOOL_SCHEMAS:
        raise AgentError(f"unknown tool: {name}")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise AgentError("tools/call arguments must be an object")

    schema = TOOL_SCHEMAS[name]
    properties = schema.get("properties", {})
    if schema.get("additionalProperties") is False:
        extra = sorted(set(args) - set(properties))
        if extra:
            safe_extra = ", ".join(redact_list([str(item) for item in extra], max_items=10))
            raise AgentError(f"unknown argument(s) for {name}: {safe_extra}")

    missing = [field for field in schema.get("required", []) if field not in args or args[field] is None]
    if missing:
        raise AgentError(f"missing required argument(s) for {name}: {', '.join(missing)}")
    for field, value in args.items():
        validate_schema_value(field, value, properties[field])
    return name, args


def compact_optional_args(args: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in args.items() if value is not None}


def call_validated_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    validated_name, validated_args = validate_tool_call(name, compact_optional_args(args))
    return call_tool(validated_name, validated_args)


def validate_schema_value(field: str, value: Any, schema: dict[str, Any]) -> None:
    value_type = schema.get("type")
    if value_type == "string":
        if not isinstance(value, str):
            raise AgentError(f"{field} must be a string")
        allowed = schema.get("enum")
        if allowed and value not in allowed:
            raise AgentError(f"{field} must be one of: {', '.join(allowed)}")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(value) > max_length:
            raise AgentError(f"{field} must not exceed {max_length} characters")
        return
    if value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise AgentError(f"{field} must be an integer")
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            raise AgentError(f"{field} must be >= {minimum}")
        if isinstance(maximum, int) and value > maximum:
            raise AgentError(f"{field} must be <= {maximum}")
        return
    if value_type == "boolean":
        if not isinstance(value, bool):
            raise AgentError(f"{field} must be a boolean")
        return
    if value_type == "array":
        if not isinstance(value, list):
            raise AgentError(f"{field} must be an array")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(value) > max_items:
            raise AgentError(f"{field} must contain at most {max_items} items")
        item_schema = schema.get("items", {})
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema_value(f"{field}[{index}]", item, item_schema)


def rpc_result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def rpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": safe_error_text(message)}}


def handle_rpc(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method")
    message_id = msg.get("id")
    if method == "initialize":
        requested = (msg.get("params") or {}).get("protocolVersion")
        try:
            protocol_version = negotiate_protocol_version(requested)
        except AgentError:
            return rpc_error(
                message_id,
                -32602,
                "Unsupported protocol version",
            )
        return rpc_result(
            message_id,
            {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": MCP_SERVER_NAME, "version": __version__},
            },
        )
    if method == "tools/list":
        return rpc_result(message_id, {"tools": TOOLS})
    if method == "resources/list":
        return rpc_result(message_id, {"resources": []})
    if method == "prompts/list":
        return rpc_result(message_id, {"prompts": []})
    if method == "tools/call":
        try:
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                raise AgentError("tools/call params must be an object")
            name, args = validate_tool_call(params.get("name"), params.get("arguments", {}))
            payload = call_tool(name, args)
            text = json.dumps(payload, indent=2, sort_keys=True)
            return rpc_result(message_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:
            text = json.dumps(public_error_payload(exc), indent=2, sort_keys=True)
            return rpc_result(message_id, {"content": [{"type": "text", "text": text}], "isError": True})
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if message_id is None:
        return None
    return rpc_error(message_id, -32601, f"method not found: {method}")


def parse_content_length(line: bytes, max_bytes: int = MAX_RPC_MESSAGE_BYTES) -> int:
    try:
        length = int(line.decode("ascii").split(":", 1)[1].strip())
    except (IndexError, UnicodeDecodeError, ValueError) as exc:
        raise AgentError("invalid Content-Length header") from exc
    if length <= 0:
        raise AgentError("Content-Length must be positive")
    if length > max_bytes:
        raise AgentError(f"Content-Length exceeds {max_bytes} bytes")
    return length


def read_message() -> dict[str, Any] | None:
    first = sys.stdin.buffer.readline(MAX_RPC_MESSAGE_BYTES + 1)
    if len(first) > MAX_RPC_MESSAGE_BYTES:
        raise AgentError(f"RPC message line exceeds {MAX_RPC_MESSAGE_BYTES} bytes")
    if not first:
        return None
    if first.startswith(b"Content-Length:"):
        length = parse_content_length(first)
        while True:
            line = sys.stdin.buffer.readline(MAX_RPC_MESSAGE_BYTES + 1)
            if len(line) > MAX_RPC_MESSAGE_BYTES:
                raise AgentError(f"RPC header line exceeds {MAX_RPC_MESSAGE_BYTES} bytes")
            if line in (b"\r\n", b"\n", b""):
                break
        body = sys.stdin.buffer.read(length)
        if len(body) != length:
            raise AgentError("incomplete RPC message body")
        return json.loads(body.decode("utf-8"))
    stripped = first.strip()
    if stripped:
        return json.loads(stripped.decode("utf-8"))
    return None


def write_message(message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def serve_mcp() -> int:
    ensure_state()
    while True:
        try:
            msg = read_message()
            if msg is None:
                return 0
            response = handle_rpc(msg)
            if response is not None:
                write_message(response)
        except Exception as exc:
            try:
                write_message(rpc_error(None, -32000, safe_error_text(exc)))
            except Exception:
                return 1


def print_json(payload: Any) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Control local Codex Agentin A/B via tmux, or run as MCP stdio server.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start")
    p_start.add_argument("agent", choices=["a", "b", "both"], nargs="?", default="both")
    p_start.add_argument("--cwd")
    p_start.add_argument("--prompt")

    p_status = sub.add_parser("status")
    p_status.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")

    p_wait = sub.add_parser("wait")
    p_wait.add_argument("agent", choices=["a", "b"])
    p_wait.add_argument("--timeout-seconds", type=int, default=DEFAULT_WAIT_SECONDS)
    p_wait.add_argument("--poll-interval-seconds", type=int, default=DEFAULT_WAIT_POLL_SECONDS)

    p_send = sub.add_parser("send")
    p_send.add_argument("agent", choices=["a", "b"])
    p_send.add_argument("text")
    p_send.add_argument("--no-enter", action="store_true")

    p_interrupt = sub.add_parser("interrupt")
    p_interrupt.add_argument("agent", choices=["a", "b"])
    p_interrupt.add_argument("--force", action="store_true")

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("agent", choices=["a", "b", "both"], nargs="?", default="both")
    p_stop.add_argument("--force", action="store_true")

    p_lease_status = sub.add_parser("lease-status")
    p_lease_status.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")

    p_claim = sub.add_parser("claim")
    p_claim.add_argument("agent", choices=["a", "b"])
    p_claim.add_argument("--ttl-seconds", type=int, default=DEFAULT_AGENT_LEASE_SECONDS)
    p_claim.add_argument("--wait-seconds", type=int, default=0)
    p_claim.add_argument("--poll-interval-seconds", type=int, default=DEFAULT_WAIT_POLL_SECONDS)
    p_claim.add_argument("--force", action="store_true")

    p_release = sub.add_parser("release")
    p_release.add_argument("agent", choices=["a", "b"])
    p_release.add_argument("--force", action="store_true")

    p_tail = sub.add_parser("tail")
    p_tail.add_argument("agent", choices=["a", "b"])
    p_tail.add_argument("--source", choices=["pane", "log"], default="pane")
    p_tail.add_argument("--lines", type=int, default=20)
    p_tail.add_argument("--chars", type=int, default=2000)

    p_skills = sub.add_parser("skills")
    p_skills.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")
    p_skills.add_argument("--include-names", action="store_true")
    p_skills.add_argument("--limit", type=int, default=80)
    p_skills.add_argument("--names-offset", type=int, default=0)
    p_skills.add_argument("--plugins-offset", type=int, default=0)
    p_skills.add_argument("--plugins-limit", type=int, default=MAX_CAPABILITY_PLUGINS)

    p_skill_match = sub.add_parser("skill-match")
    p_skill_match.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")
    p_skill_match.add_argument("skill")
    p_skill_match.add_argument("--limit", type=int, default=8)

    p_capabilities = sub.add_parser("capabilities")
    p_capabilities.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")

    p_scope_check = sub.add_parser("scope-check")
    p_scope_check.add_argument("--scope", action="append", default=[])
    p_scope_check.add_argument("--write-path", dest="write_paths", action="append", default=[])
    p_scope_check.add_argument("--cwd")

    p_assign = sub.add_parser("assign")
    p_assign.add_argument("agent", choices=["a", "b"])
    p_assign.add_argument("--role", choices=["exploriererin", "arbeitsbiene"], required=True)
    p_assign.add_argument("--task", required=True)
    p_assign.add_argument("--skill")
    p_assign.add_argument("--scope", action="append", default=[])
    p_assign.add_argument("--write-path", dest="write_paths", action="append", default=[])
    p_assign.add_argument("--context", action="append", default=[])
    p_assign.add_argument("--forbid", dest="forbidden", action="append", default=[])
    p_assign.add_argument("--name")
    p_assign.add_argument("--no-enter", action="store_true")
    p_assign.add_argument("--allow-missing-skill", action="store_true")
    p_assign.add_argument("--allow-subagents", action="store_true")

    p_assign_readonly = sub.add_parser("assign-readonly")
    p_assign_readonly.add_argument("agent", choices=["a", "b"])
    p_assign_readonly.add_argument("--task", required=True)
    p_assign_readonly.add_argument("--skill")
    p_assign_readonly.add_argument("--scope", action="append", default=[])
    p_assign_readonly.add_argument("--context", action="append", default=[])
    p_assign_readonly.add_argument("--forbid", dest="forbidden", action="append", default=[])
    p_assign_readonly.add_argument("--name")
    p_assign_readonly.add_argument("--no-enter", action="store_true")
    p_assign_readonly.add_argument("--allow-missing-skill", action="store_true")
    p_assign_readonly.add_argument("--allow-subagents", action="store_true")

    p_assign_write = sub.add_parser("assign-write")
    p_assign_write.add_argument("agent", choices=["a", "b"])
    p_assign_write.add_argument("--task", required=True)
    p_assign_write.add_argument("--skill")
    p_assign_write.add_argument("--scope", action="append", default=[])
    p_assign_write.add_argument("--write-path", dest="write_paths", action="append", default=[])
    p_assign_write.add_argument("--context", action="append", default=[])
    p_assign_write.add_argument("--forbid", dest="forbidden", action="append", default=[])
    p_assign_write.add_argument("--name")
    p_assign_write.add_argument("--no-enter", action="store_true")
    p_assign_write.add_argument("--allow-missing-skill", action="store_true")
    p_assign_write.add_argument("--allow-subagents", action="store_true")

    p_assignments = sub.add_parser("assignments")
    p_assignments.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")
    p_assignments.add_argument("--limit", type=int, default=20)

    p_last_assignment = sub.add_parser("last-assignment")
    p_last_assignment.add_argument("agent", choices=["a", "b"])

    p_report = sub.add_parser("report-request")
    p_report.add_argument("agent", choices=["a", "b"])
    p_report.add_argument("--assignment-id")
    p_report.add_argument("--no-enter", action="store_true")

    p_worktree_create = sub.add_parser("worktree-create")
    p_worktree_create.add_argument("agent", choices=["a", "b"])
    p_worktree_create.add_argument("--path")
    p_worktree_create.add_argument("--base-ref")

    p_worktree_status = sub.add_parser("worktree-status")
    p_worktree_status.add_argument("--path")

    sub.add_parser("integration-status")

    p_commit_ready = sub.add_parser("commit-ready-check")
    p_commit_ready.add_argument("--no-tests", action="store_true")

    sub.add_parser("app-bridge-status")
    sub.add_parser("plugin-status")
    sub.add_parser("namespace-status")

    p_install = sub.add_parser("install")
    p_install.add_argument("--no-register", action="store_true")
    p_install.add_argument("--no-plugin-cache", action="store_true")
    p_install.add_argument("--force", action="store_true")
    p_install.add_argument("--path", default=str(DEFAULT_INSTALL_PATH))

    p_uninstall = sub.add_parser("uninstall")
    p_uninstall.add_argument("--keep-registration", action="store_true")
    p_uninstall.add_argument("--remove-symlink", action="store_true")
    p_uninstall.add_argument("--path", default=str(DEFAULT_INSTALL_PATH))

    sub.add_parser("doctor")
    sub.add_parser("tools")

    p_raw_log_writer = sub.add_parser("raw-log-writer", help=argparse.SUPPRESS)
    p_raw_log_writer.add_argument("path")
    p_raw_log_writer.add_argument("--max-bytes", type=int, default=MAX_RAW_LOG_BYTES)

    args = parser.parse_args(argv)
    try:
        if args.command == "raw-log-writer":
            return write_bounded_raw_log(Path(args.path), args.max_bytes)
        if args.command == "start":
            return print_json(call_validated_tool("agent_start", {"agent": args.agent, "cwd": args.cwd, "prompt": args.prompt}))
        if args.command == "status":
            return print_json(call_validated_tool("agent_status", {"agent": args.agent}))
        if args.command == "wait":
            return print_json(
                call_validated_tool(
                    "agent_wait",
                    {
                        "agent": args.agent,
                        "timeout_seconds": args.timeout_seconds,
                        "poll_interval_seconds": args.poll_interval_seconds,
                    },
                )
            )
        if args.command == "send":
            return print_json(call_validated_tool("agent_send", {"agent": args.agent, "text": args.text, "enter": not args.no_enter}))
        if args.command == "interrupt":
            return print_json(call_validated_tool("agent_interrupt", {"agent": args.agent, "force": args.force}))
        if args.command == "stop":
            return print_json(call_validated_tool("agent_stop", {"agent": args.agent, "force": args.force}))
        if args.command == "lease-status":
            return print_json(call_validated_tool("agent_lease_status", {"agent": args.agent}))
        if args.command == "claim":
            return print_json(
                call_validated_tool(
                    "agent_claim",
                    {
                        "agent": args.agent,
                        "ttl_seconds": args.ttl_seconds,
                        "wait_seconds": args.wait_seconds,
                        "poll_interval_seconds": args.poll_interval_seconds,
                        "force": args.force,
                    },
                )
            )
        if args.command == "release":
            return print_json(call_validated_tool("agent_release", {"agent": args.agent, "force": args.force}))
        if args.command == "tail":
            return print_json(
                call_validated_tool(
                    "agent_safe_tail",
                    {"agent": args.agent, "source": args.source, "lines": args.lines, "chars": args.chars},
                )
            )
        if args.command == "skills":
            return print_json(
                call_validated_tool(
                    "agent_skills",
                    {
                        "agent": args.agent,
                        "include_names": args.include_names,
                        "limit": args.limit,
                        "names_offset": args.names_offset,
                        "plugins_offset": args.plugins_offset,
                        "plugins_limit": args.plugins_limit,
                    },
                )
            )
        if args.command == "skill-match":
            return print_json(call_validated_tool("agent_skill_match", {"agent": args.agent, "skill": args.skill, "limit": args.limit}))
        if args.command == "capabilities":
            return print_json(call_validated_tool("agent_capabilities", {"agent": args.agent}))
        if args.command == "scope-check":
            return print_json(
                call_validated_tool(
                    "agent_scope_check",
                    {"scope": args.scope, "write_paths": args.write_paths, "cwd": args.cwd},
                )
            )
        if args.command == "assign":
            return print_json(
                call_validated_tool(
                    "agent_assign",
                    {
                        "agent": args.agent,
                        "role": args.role,
                        "task": args.task,
                        "skill": args.skill,
                        "scope": args.scope,
                        "write_paths": args.write_paths,
                        "context": args.context,
                        "forbidden": args.forbidden,
                        "name": args.name,
                        "enter": not args.no_enter,
                        "allow_missing_skill": args.allow_missing_skill,
                        "allow_subagents": args.allow_subagents,
                    },
                )
            )
        if args.command == "assign-readonly":
            return print_json(
                call_validated_tool(
                    "agent_assign_readonly",
                    {
                        "agent": args.agent,
                        "task": args.task,
                        "skill": args.skill,
                        "scope": args.scope,
                        "context": args.context,
                        "forbidden": args.forbidden,
                        "name": args.name,
                        "enter": not args.no_enter,
                        "allow_missing_skill": args.allow_missing_skill,
                        "allow_subagents": args.allow_subagents,
                    },
                )
            )
        if args.command == "assign-write":
            return print_json(
                call_validated_tool(
                    "agent_assign_write",
                    {
                        "agent": args.agent,
                        "task": args.task,
                        "skill": args.skill,
                        "scope": args.scope,
                        "write_paths": args.write_paths,
                        "context": args.context,
                        "forbidden": args.forbidden,
                        "name": args.name,
                        "enter": not args.no_enter,
                        "allow_missing_skill": args.allow_missing_skill,
                        "allow_subagents": args.allow_subagents,
                    },
                )
            )
        if args.command == "assignments":
            return print_json(call_validated_tool("agent_assignments", {"agent": args.agent, "limit": args.limit}))
        if args.command == "last-assignment":
            return print_json(call_validated_tool("agent_last_assignment_status", {"agent": args.agent}))
        if args.command == "report-request":
            return print_json(
                call_validated_tool(
                    "agent_report_request",
                    {"agent": args.agent, "assignment_id": args.assignment_id, "enter": not args.no_enter},
                )
            )
        if args.command == "worktree-create":
            return print_json(
                call_validated_tool(
                    "worktree_create_for_agent",
                    {"agent": args.agent, "path": args.path, "base_ref": args.base_ref},
                )
            )
        if args.command == "worktree-status":
            return print_json(call_validated_tool("worktree_status", {"path": args.path}))
        if args.command == "integration-status":
            return print_json(call_validated_tool("integration_status", {}))
        if args.command == "commit-ready-check":
            return print_json(call_validated_tool("commit_ready_check", {"run_tests": not args.no_tests}))
        if args.command == "app-bridge-status":
            return print_json(call_validated_tool("master_app_bridge_status", {}))
        if args.command == "plugin-status":
            return print_json(call_validated_tool("master_plugin_status", {}))
        if args.command == "namespace-status":
            return print_json(call_validated_tool("master_namespace_status", {}))
        if args.command == "install":
            return print_json(
                install(
                    register=not args.no_register,
                    force=args.force,
                    install_path=Path(args.path),
                    sync_plugin_cache=not args.no_plugin_cache,
                )
            )
        if args.command == "uninstall":
            return print_json(
                uninstall(
                    unregister=not args.keep_registration,
                    remove_symlink=args.remove_symlink,
                    install_path=Path(args.path),
                )
            )
        if args.command == "doctor":
            return print_json(doctor())
        if args.command == "tools":
            return print_json({"tools": TOOLS})
    except Exception as exc:
        print(json.dumps(public_error_payload(exc), indent=2, sort_keys=True))
        return 1
    return 2


def main() -> int:
    if len(sys.argv) > 1:
        return main_cli(sys.argv[1:])
    return serve_mcp()


if __name__ == "__main__":
    raise SystemExit(main())
