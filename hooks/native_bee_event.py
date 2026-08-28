#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import fcntl
import stat
import sys
import time
from pathlib import Path


MAX_STDIN_BYTES = 65537
MAX_NATIVE_AGENT_REGISTRY_BYTES = 64 * 1024
_NATIVE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_NATIVE_TYPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_NATIVE_RECORDS = 64
_MAX_NATIVE_SESSIONS = 64
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


def _hook_state_root() -> Path:
    return Path(
        os.environ.get("CODEX_MASTER_MCP_STATE")
        or os.environ.get("CODEX_AGENT_MCP_STATE")
        or "~/.local/state/codex-master-mcp"
    ).expanduser()


def _native_id(value: object) -> bool:
    return isinstance(value, str) and _NATIVE_ID_RE.fullmatch(value) is not None


def _native_type(value: object) -> bool:
    return isinstance(value, str) and _NATIVE_TYPE_RE.fullmatch(value) is not None


def _empty_registry() -> dict[str, object]:
    return {"schema_version": 2, "agents": [], "sessions": [], "reservations": []}


def _normalized_registry(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2}:
        return None
    raw_agents = value.get("agents")
    if not isinstance(raw_agents, list):
        return None
    agents: list[dict[str, object]] = []
    for item in raw_agents[-_MAX_NATIVE_RECORDS:]:
        if not isinstance(item, dict):
            continue
        session_id = item.get("session_id")
        agent_id = item.get("agent_id")
        agent_type = item.get("agent_type")
        activity_state = item.get("activity_state")
        updated_at = item.get("updated_at")
        if (
            not _native_id(session_id)
            or not _native_id(agent_id)
            or not _native_type(agent_type)
            or activity_state not in {"active", "unconfirmed", "completed"}
            or isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float))
        ):
            continue
        agents.append(
            {
                "session_id": session_id,
                "agent_id": agent_id,
                "agent_type": agent_type,
                "activity_state": activity_state,
                "updated_at": float(updated_at),
            }
        )
    raw_sessions = value.get("sessions", [])
    if not isinstance(raw_sessions, list):
        return None
    sessions: list[dict[str, object]] = []
    for item in raw_sessions[-_MAX_NATIVE_SESSIONS:]:
        if not isinstance(item, dict):
            continue
        session_id = item.get("session_id")
        activity_state = item.get("activity_state")
        updated_at = item.get("updated_at")
        if (
            not _native_id(session_id)
            or activity_state not in {"active", "ended"}
            or isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float))
        ):
            continue
        sessions.append(
            {
                "session_id": session_id,
                "activity_state": activity_state,
                "updated_at": float(updated_at),
            }
        )
    reservations = value.get("reservations", [])
    return {
        "schema_version": 2,
        "agents": agents,
        "sessions": sessions,
        "reservations": reservations if isinstance(reservations, list) else [],
    }


def _read_registry(root_fd: int) -> dict[str, object] | None:
    try:
        info = os.stat("native-agents.json", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return _empty_registry()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > MAX_NATIVE_AGENT_REGISTRY_BYTES
    ):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open("native-agents.json", flags, dir_fd=root_fd)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != info.st_size
        ):
            return None
        raw = os.read(fd, MAX_NATIVE_AGENT_REGISTRY_BYTES + 1)
        if len(raw) > MAX_NATIVE_AGENT_REGISTRY_BYTES:
            return None
        return _normalized_registry(json.loads(raw.decode("utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _write_registry(root_fd: int, registry: dict[str, object]) -> bool:
    encoded = (json.dumps(registry, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_NATIVE_AGENT_REGISTRY_BYTES:
        return False
    temporary = f".native-agents.{os.getpid()}.{os.urandom(8).hex()}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = -1
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                return False
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(
            temporary,
            "native-agents.json",
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        os.fsync(root_fd)
        return True
    except OSError:
        return False
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass


def _update_registry(mutator) -> bool:
    root = _hook_state_root()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root_info = root.lstat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_IMODE(root_info.st_mode) & 0o077
            or root_info.st_uid != os.geteuid()
        ):
            return False
        root_fd = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        return False
    lock_fd = -1
    try:
        lock_fd = os.open(
            ".native-agents.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=root_fd,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        registry = _read_registry(root_fd)
        if registry is None:
            return False
        mutator(registry)
        return _write_registry(root_fd, registry)
    except OSError:
        return False
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(root_fd)


def _terminal_agent_ids(payload: dict[str, object]) -> set[str]:
    tool_input = payload.get("tool_input")
    name = payload.get("tool_name")
    if not isinstance(tool_input, dict):
        return set()
    if name in {"close_agent", "multi_agent_v1__close_agent"}:
        target = tool_input.get("id", tool_input.get("target"))
        return {target} if _native_id(target) else set()
    if name not in {"wait_agent", "multi_agent_v1__wait_agent"}:
        return set()
    ids = tool_input.get("ids")
    response = payload.get("tool_response")
    if not isinstance(ids, list) or not isinstance(response, dict):
        return set()
    statuses = response.get("status")
    if not isinstance(statuses, dict) or response.get("timed_out") is True:
        return set()
    return {
        agent_id
        for agent_id in ids
        if _native_id(agent_id)
        and (
            (isinstance(statuses.get(agent_id), dict) and any(
                key in statuses[agent_id] for key in {"completed", "errored"}
            ))
            or statuses.get(agent_id) in {"interrupted", "shutdown", "not_found"}
        )
    }


def _legacy_parent_from_transcript(payload: dict[str, object], agent_id: str) -> str | None:
    raw_path = payload.get("transcript_path")
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096:
        return None
    sessions_root = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser() / "sessions"
    try:
        path = Path(raw_path).resolve(strict=True)
        sessions = sessions_root.resolve(strict=True)
        path.relative_to(sessions)
        with path.open("rb") as handle:
            header = handle.readline(64 * 1024 + 1)
        if len(header) > 64 * 1024:
            return None
        document = json.loads(header.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    try:
        parent = document["payload"]["source"]["subagent"]["thread_spawn"]["parent_thread_id"]
    except (KeyError, TypeError):
        return None
    return parent if _native_id(parent) else None


def _record_native_event(payload: dict[str, object]) -> None:
    event = payload.get("hook_event_name")
    session_id = payload.get("session_id")
    agent_id = payload.get("agent_id")
    agent_type = payload.get("agent_type")
    if event not in {
        "SessionStart", "UserPromptSubmit", "PostToolUse", "SubagentStart",
        "SubagentStop", "Stop", "SessionEnd",
    } or not _native_id(session_id):
        return
    if event in {"SubagentStart", "SubagentStop"} and not _native_id(agent_id):
        return
    if event == "SubagentStart" and not _native_type(agent_type):
        return
    timestamp = time.time()

    def mutate(registry: dict[str, object]) -> None:
        agents = registry["agents"]
        sessions = registry["sessions"]
        assert isinstance(agents, list) and isinstance(sessions, list)
        if event == "PostToolUse":
            completed = _terminal_agent_ids(payload)
            for row in agents:
                if isinstance(row, dict) and row.get("session_id") == session_id and row.get("agent_id") in completed:
                    row.update(activity_state="completed", updated_at=timestamp)
            return
        if event in {"UserPromptSubmit", "Stop"}:
            desired = "active" if event == "UserPromptSubmit" else "completed"
            matched = False
            for row in agents:
                if isinstance(row, dict) and row.get("agent_id") == session_id:
                    row.update(activity_state=desired, updated_at=timestamp)
                    matched = True
            if event == "UserPromptSubmit" and not matched:
                parent = _legacy_parent_from_transcript(payload, session_id)
                if parent is not None:
                    agents.append({"session_id": parent, "agent_id": session_id, "agent_type": "subagent", "activity_state": "active", "updated_at": timestamp})
            registry["agents"] = agents[-_MAX_NATIVE_RECORDS:]
            return
        sessions[:] = [row for row in sessions if not isinstance(row, dict) or row.get("session_id") != session_id]
        sessions.append({"session_id": session_id, "activity_state": "ended" if event == "SessionEnd" else "active", "updated_at": timestamp})
        registry["sessions"] = sessions[-_MAX_NATIVE_SESSIONS:]
        if event == "SessionStart":
            for row in agents:
                if isinstance(row, dict) and row.get("session_id") == session_id and row.get("activity_state") != "completed":
                    row.update(activity_state="unconfirmed", updated_at=timestamp)
            return
        if event == "SubagentStart":
            registry["reservations"] = [row for row in registry["reservations"] if not isinstance(row, dict) or not (row.get("kind") == "native_spawn" and row.get("parent_session_id") == session_id)]
            for row in agents:
                if isinstance(row, dict) and row.get("session_id") == session_id and row.get("agent_id") == agent_id:
                    row.update(agent_type=agent_type, activity_state="active", updated_at=timestamp)
                    break
            else:
                agents.append({"session_id": session_id, "agent_id": agent_id, "agent_type": agent_type, "activity_state": "active", "updated_at": timestamp})
            registry["agents"] = agents[-_MAX_NATIVE_RECORDS:]
            return
        if event == "SubagentStop":
            for row in agents:
                if isinstance(row, dict) and row.get("session_id") == session_id and row.get("agent_id") == agent_id:
                    row.update(activity_state="completed", updated_at=timestamp)
            return
        if event == "SessionEnd":
            for row in agents:
                if isinstance(row, dict) and row.get("session_id") == session_id and row.get("activity_state") != "completed":
                    row.update(activity_state="unconfirmed", updated_at=timestamp)

    _update_registry(mutate)


def _resume_association_is_known(payload: dict[str, object]) -> bool:
    """Reject malformed, unknown, and foreign resumes before importing server."""

    tool_input = payload.get("tool_input")
    session_id = payload.get("session_id")
    target = tool_input.get("target") if isinstance(tool_input, dict) else None
    if (
        payload.get("hook_event_name") != "PreToolUse"
        or payload.get("tool_name") not in {"send_input", "multi_agent_v1__send_input"}
        or not isinstance(session_id, str)
        or _NATIVE_ID_RE.fullmatch(session_id) is None
        or not isinstance(target, str)
        or _NATIVE_ID_RE.fullmatch(target) is None
    ):
        return False
    state_root = Path(
        os.environ.get("CODEX_MASTER_MCP_STATE")
        or os.environ.get("CODEX_AGENT_MCP_STATE")
        or "~/.local/state/codex-master-mcp"
    ).expanduser()
    registry = state_root / "native-agents.json"
    try:
        info = registry.lstat()
        if not registry.is_file() or registry.is_symlink() or info.st_size > MAX_NATIVE_AGENT_REGISTRY_BYTES:
            return False
        document = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    agents = document.get("agents") if isinstance(document, dict) else None
    if not isinstance(agents, list):
        return False
    matches = [
        item
        for item in agents
        if isinstance(item, dict)
        and item.get("session_id") == session_id
        and item.get("agent_id") == target
    ]
    return len(matches) == 1


def _deny_pretool(result: dict[str, object]) -> None:
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


def main() -> int:
    payload = _read_payload()
    if payload is None:
        return 0

    event_name = payload.get("hook_event_name")
    if event_name == "PreToolUse":
        if not _resume_association_is_known(payload):
            _deny_pretool(
                {
                    "error_code": "spawn_capacity_unavailable",
                    "reason_codes": ["session_metrics_unavailable"],
                }
            )
            return 0
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
            _deny_pretool(result)
        return 0

    _record_native_event(payload)

    if event_name in {"SubagentStop", "Stop"}:
        try:
            sys.stdout.write("{}\n")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
