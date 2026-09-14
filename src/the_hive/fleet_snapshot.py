"""Immutable process and tmux state for one fleet-watchdog run.

The snapshot module deliberately contains observation only.  Watchdog policy,
leases, and lifecycle actions remain in :mod:`codex_master.server`.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any


_PROC_VANISHED = object()


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """Bounded metadata for one process observed in a managed Codex home."""

    pid: int
    ppid: int | None
    name: str
    state: str
    codex_home: str
    managed_by_masterjet: bool


@dataclass(frozen=True, slots=True)
class TmuxSessionSnapshot:
    """The observed state of one tmux session."""

    alive: bool
    pane_pid: int | None


@dataclass(frozen=True, slots=True)
class AgentProcessSnapshot:
    """Processes associated with one managed Agentin home."""

    available: bool
    processes: tuple[ProcessSnapshot, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "processes", tuple(self.processes))


@dataclass(frozen=True, slots=True)
class FleetSnapshot:
    """One immutable observation used by a single watchdog run."""

    created_at: datetime
    processes: tuple[ProcessSnapshot, ...]
    processes_by_codex_home: Mapping[str, tuple[ProcessSnapshot, ...]]
    tmux_sessions: Mapping[str, TmuxSessionSnapshot]
    agent_process_map: Mapping[str, AgentProcessSnapshot]
    process_scan_available: bool
    tmux_scan_available: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.created_at, datetime)
            or self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
        ):
            raise ValueError("FleetSnapshot.created_at must be timezone-aware")
        object.__setattr__(self, "processes", tuple(self.processes))
        object.__setattr__(
            self,
            "processes_by_codex_home",
            MappingProxyType(
                {
                    key: tuple(processes)
                    for key, processes in self.processes_by_codex_home.items()
                }
            ),
        )
        object.__setattr__(self, "tmux_sessions", MappingProxyType(dict(self.tmux_sessions)))
        object.__setattr__(self, "agent_process_map", MappingProxyType(dict(self.agent_process_map)))


def _read_proc_environ(pid_dir: Path) -> dict[str, str] | None:
    try:
        raw = (pid_dir / "environ").read_bytes()
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    env: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return env


def _read_proc_status(pid_dir: Path) -> dict[str, str] | object | None:
    try:
        lines = (pid_dir / "status").read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return _PROC_VANISHED
    except OSError:
        return None
    result: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"Name", "State", "PPid", "Uid"}:
            result[key] = value.strip()
    return result


def _read_proc_cmdline(pid_dir: Path) -> list[str]:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return []
    return [item.decode("utf-8", errors="replace") for item in raw.split(b"\0") if item]


def _proc_is_codex_like(status: Mapping[str, str], argv: list[str]) -> bool:
    name = (status.get("Name") or "").lower()
    argv_names = {Path(item).name.lower() for item in argv if item}
    joined = "\0".join(argv).lower()
    return (
        name in {"codex", "codex-code-mode-host", "codex-code-mode"}
        or "codex" in argv_names
        or "@openai/codex" in joined
        or "node_modules/@openai/codex" in joined
    )


def _resolve_proc_cwd(pid_dir: Path) -> tuple[Path | None, bool]:
    try:
        return (pid_dir / "cwd").resolve(strict=True), False
    except FileNotFoundError:
        return None, False
    except (OSError, RuntimeError):
        return None, True


def _resolve_configured_home(configured: str, cwd: Path | None) -> Path | None:
    try:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            if cwd is None:
                return None
            path = cwd / path
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _resolved_home_map(agent_homes: Mapping[str, Path]) -> dict[str, str] | None:
    try:
        return {
            agent: str(home.expanduser().resolve(strict=False))
            for agent, home in agent_homes.items()
        }
    except (OSError, RuntimeError, ValueError):
        return None


def _process_snapshot(
    pid_dir: Path,
    status: Mapping[str, str],
    env: Mapping[str, str] | None,
    argv: list[str],
    home_by_path: Mapping[str, str],
) -> tuple[ProcessSnapshot | None, bool]:
    codex_like = _proc_is_codex_like(status, argv)
    cwd, unavailable = _resolve_proc_cwd(pid_dir)

    if env is None:
        # An unreadable foreign process outside a managed home is normal on a
        # multi-user host.  Only an unreadable process that could belong to a
        # managed home makes the complete observation unsafe.
        if unavailable:
            return None, not codex_like
        resolved_home = cwd
        if codex_like and resolved_home is not None and str(resolved_home) in home_by_path:
            return None, False
    else:
        configured_home = env.get("CODEX_HOME", "")
        if configured_home:
            configured_path = Path(configured_home).expanduser()
            if not configured_path.is_absolute() and unavailable:
                return None, not codex_like
            resolved_home = _resolve_configured_home(configured_home, cwd)
        else:
            if unavailable:
                return None, not codex_like
            resolved_home = cwd
    if resolved_home is None:
        return None, True
    home_key = home_by_path.get(str(resolved_home))
    if home_key is None:
        return None, True

    ppid_parts = status.get("PPid", "0").split()
    pid_text = pid_dir.name
    if not pid_text.isdigit():
        return None, True
    pid = int(pid_text)
    ppid = int(ppid_parts[0]) if ppid_parts and ppid_parts[0].isdigit() else None
    managed = bool(env) and (
        env.get("CODEX_AGENT_MCP") == "1" or env.get("CODEX_MASTER_MCP") == "1"
    ) and codex_like
    return (
        ProcessSnapshot(
            pid=pid,
            ppid=ppid,
            name=status.get("Name") or "unknown",
            state=status.get("State") or "unknown",
            codex_home=home_key,
            managed_by_masterjet=managed,
        ),
        True,
    )


def _scan_processes(
    agent_homes: Mapping[str, Path],
    proc_root: Path,
) -> tuple[tuple[ProcessSnapshot, ...], dict[str, tuple[ProcessSnapshot, ...]], bool]:
    try:
        if not proc_root.exists():
            return (), {}, False
        pid_dirs = list(proc_root.iterdir())
    except OSError:
        return (), {}, False

    resolved_homes = _resolved_home_map(agent_homes)
    if resolved_homes is None:
        return (), {}, False
    home_by_path = {path: path for path in resolved_homes.values()}
    processes: list[ProcessSnapshot] = []
    for pid_dir in pid_dirs:
        if not pid_dir.name.isdigit():
            continue
        status = _read_proc_status(pid_dir)
        if status is _PROC_VANISHED:
            continue
        if status is None or not {"Name", "State", "PPid", "Uid"}.issubset(status):
            # Process identity is security-sensitive.  A process can disappear
            # or become unreadable while /proc is being walked; a partial
            # snapshot must never authorize a watchdog action.
            return (), {}, False
        if status.get("State", "").startswith("Z"):
            continue
        uid_parts = status.get("Uid", "").split()
        foreign_uid = bool(uid_parts and uid_parts[0].isdigit() and int(uid_parts[0]) != os.getuid())
        env = _read_proc_environ(pid_dir)
        argv = _read_proc_cmdline(pid_dir)
        snapshot, readable = _process_snapshot(
            pid_dir,
            status,
            env,
            argv,
            home_by_path,
        )
        if not readable:
            if foreign_uid:
                # An unreadable foreign Codex process whose cwd resolves to a
                # managed home is relevant and must fail closed.  Other
                # unreadable foreign processes are outside this service's
                # control boundary and may be ignored.
                cwd, cwd_unavailable = _resolve_proc_cwd(pid_dir)
                if (
                    env is None
                    and _proc_is_codex_like(status, argv)
                    and not cwd_unavailable
                    and cwd is not None
                    and str(cwd) in home_by_path
                ):
                    return (), {}, False
                continue
            # Preserve the legacy fail-closed behavior for unreadable process
            # identity data without making a partial snapshot actionable.
            return (), {}, False
        if foreign_uid and snapshot is not None:
            # Never expose a foreign process in a managed home as a harmless
            # empty observation; callers must not act on a partial snapshot.
            return (), {}, False
        if snapshot is not None:
            processes.append(snapshot)

    processes.sort(key=lambda item: item.pid)
    by_home: dict[str, tuple[ProcessSnapshot, ...]] = {}
    for home in resolved_homes.values():
        by_home[home] = tuple(item for item in processes if item.codex_home == home)
    return tuple(processes), by_home, True


def _scan_tmux(
    sessions: Mapping[str, str],
    runner: Callable[..., Any] | None,
) -> tuple[dict[str, TmuxSessionSnapshot], bool]:
    if runner is None:
        return {name: TmuxSessionSnapshot(alive=False, pane_pid=None) for name in sessions.values()}, False
    try:
        result = runner(
            ["list-panes", "-a", "-F", "#{session_name}\t#{pane_active}\t#{pane_pid}"],
            check=False,
        )
    except (OSError, TypeError):
        result = None
    if result is None or getattr(result, "returncode", 1) != 0:
        return {name: TmuxSessionSnapshot(alive=False, pane_pid=None) for name in sessions.values()}, False

    observed: dict[str, tuple[bool, int | None]] = {}
    for line in str(getattr(result, "stdout", "") or "").splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0]:
            continue
        session, active, pane_pid_text = parts
        pane_pid = int(pane_pid_text) if pane_pid_text.isdigit() else None
        current = observed.get(session)
        candidate = (active == "1", pane_pid)
        if current is None or candidate[0] and not current[0]:
            observed[session] = candidate
    snapshot = {
        session: TmuxSessionSnapshot(
            alive=session in observed,
            pane_pid=observed.get(session, (False, None))[1],
        )
        for session in sessions.values()
    }
    return snapshot, True


def create_fleet_snapshot(
    *,
    agent_homes: Mapping[str, Path],
    agent_sessions: Mapping[str, str],
    proc_root: Path = Path("/proc"),
    tmux_runner: Callable[..., Any] | None = None,
    created_at: datetime | None = None,
) -> FleetSnapshot:
    """Observe all managed homes and tmux sessions exactly once."""

    resolved_homes = _resolved_home_map(agent_homes)
    if resolved_homes is None:
        resolved_homes = {}
        processes, processes_by_home, process_available = (), {}, False
    else:
        processes, processes_by_home, process_available = _scan_processes(agent_homes, proc_root)
    tmux_sessions, tmux_available = _scan_tmux(agent_sessions, tmux_runner)
    agent_process_map = {
        agent: AgentProcessSnapshot(
            available=process_available,
            processes=processes_by_home.get(
                resolved_homes.get(agent, ""),
                (),
            ),
        )
        for agent in agent_homes
    }
    return FleetSnapshot(
        created_at=created_at or datetime.now(timezone.utc),
        processes=processes,
        processes_by_codex_home=processes_by_home,
        tmux_sessions=tmux_sessions,
        agent_process_map=agent_process_map,
        process_scan_available=process_available,
        tmux_scan_available=tmux_available,
    )


def summarize_agent_processes(snapshot: FleetSnapshot, agent: str) -> dict[str, Any]:
    """Render one snapshot entry in the server's existing status shape."""

    entry = snapshot.agent_process_map.get(agent)
    if entry is None or not entry.available:
        return {
            "agent": agent,
            "home": "not_returned",
            "home_kind": "managed_agent_home",
            "process_count": None,
            "external_process_count": None,
            "managed_process_count": None,
            "managed_process_ids": [],
            "managed_root_process_ids": [],
            "external_processes": [],
            "external_processes_truncated": False,
            "raw_output": "not_returned",
        }

    processes = list(entry.processes)
    managed = [item for item in processes if item.managed_by_masterjet]
    managed_ids = {item.pid for item in managed}
    managed_root_ids = [item.pid for item in managed if item.ppid not in managed_ids]
    by_pid = {item.pid: item for item in processes}

    def has_managed_ancestor(item: ProcessSnapshot) -> bool:
        parent_id = item.ppid
        visited: set[int] = set()
        while isinstance(parent_id, int) and parent_id not in visited:
            if parent_id in managed_ids:
                return True
            visited.add(parent_id)
            parent = by_pid.get(parent_id)
            if parent is None:
                break
            parent_id = parent.ppid
        return False

    external = [
        item
        for item in processes
        if not item.managed_by_masterjet and not has_managed_ancestor(item)
    ]

    def public_process(item: ProcessSnapshot) -> dict[str, Any]:
        return {
            "pid": item.pid,
            "ppid": item.ppid,
            "name": item.name,
            "state": item.state,
            "managed_by_masterjet": item.managed_by_masterjet,
            "raw_output": "not_returned",
        }

    return {
        "agent": agent,
        "home": "not_returned",
        "home_kind": "managed_agent_home",
        "process_count": len(processes),
        "external_process_count": len(external),
        "managed_process_count": len(managed_ids),
        "managed_process_ids": sorted(managed_ids),
        "managed_root_process_ids": managed_root_ids,
        "external_processes": [public_process(item) for item in external[:10]],
        "external_processes_truncated": len(external) > 10,
        "raw_output": "not_returned",
    }
