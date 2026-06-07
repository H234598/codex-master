"""MCP server and CLI for controlling two local Codex instances via tmux.

The public tool surface is intentionally data-sparse. Raw terminal output is
written to local state files only; tool responses return structured status or
explicitly requested, size-limited, redacted excerpts.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import time
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
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
MCP_SERVER_NAME = "codex-master-mcp"
DEFAULT_INSTALL_PATH = Path("~/.local/bin/codex-master-mcp").expanduser()
MAX_SKILL_NAMES = 200
MAX_CAPABILITY_PLUGINS = 20
MAX_ASSIGNMENT_RECORDS = 100
MAX_ASSIGNMENT_LOG_RECORDS = 500
MAX_ASSIGNMENT_TEXT = 12000
DEFAULT_AGENTIN_NAMES = {"a": "Mila", "b": "Nora"}


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


class AgentError(RuntimeError):
    """Raised for expected agent-control failures."""


def ensure_state() -> None:
    for path in (STATE_ROOT, RAW_DIR, META_DIR):
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except PermissionError:
            pass


def now_id() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_wrapper_path() -> Path:
    return repo_root() / "bin" / "codex-master-mcp"


def agent_ids(agent: str) -> list[str]:
    if agent in ("all", "both"):
        return ["a", "b"]
    if agent not in AGENTS:
        raise AgentError(f"unknown agent: {agent!r}; expected a, b, both, or all")
    return [agent]


def run_tmux(args: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["tmux", *args],
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def run_command(
    args: list[str],
    *,
    check: bool = False,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, cwd=cwd, env=env)


def tmux_alive(session: str) -> bool:
    return run_tmux(["has-session", "-t", session], check=False).returncode == 0


def meta_path(agent: str) -> Path:
    return META_DIR / f"{agent}.json"


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"meta_error": f"could not read {path}"}


def read_meta(agent: str) -> dict[str, Any]:
    path = meta_path(agent)
    if not path.exists():
        legacy_path = LEGACY_META_DIR / f"{agent}.json"
        if legacy_path.exists() and legacy_path != path:
            data = read_json_file(legacy_path)
            data.setdefault("meta_source", str(legacy_path))
            return data
        return {}
    return read_json_file(path)


def write_meta(agent: str, data: dict[str, Any]) -> None:
    path = meta_path(agent)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except PermissionError:
        pass


def write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)
    try:
        path.chmod(0o600)
    except PermissionError:
        pass


def replace_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{now_id()}.tmp")
    try:
        tmp_path.write_text(text, encoding="utf-8")
        try:
            tmp_path.chmod(0o600)
        except PermissionError:
            pass
        tmp_path.replace(path)
        try:
            path.chmod(0o600)
        except PermissionError:
            pass
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def pane_pid(session: str) -> int | None:
    if not tmux_alive(session):
        return None
    cp = run_tmux(["display-message", "-p", "-t", session, "#{pane_pid}"], check=False)
    if cp.returncode != 0:
        return None
    text = cp.stdout.strip()
    return int(text) if text.isdigit() else None


def cleanup_failed_start(session: str, raw_log: Path) -> None:
    if tmux_alive(session):
        run_tmux(["kill-session", "-t", session], check=False)
    try:
        raw_log.unlink()
    except FileNotFoundError:
        pass


def start_agent(agent: str, cwd: str | None = None, prompt: str | None = None) -> dict[str, Any]:
    ensure_state()
    cfg = AGENTS[agent]
    runner = cfg["runner"]
    session = cfg["session"]
    if not runner.exists():
        raise AgentError(f"runner missing for agent {agent}: {runner}")
    if tmux_alive(session):
        return {
            "agent": agent,
            "status": "already_running",
            "backend": "tmux",
            "session": session,
            "pid": pane_pid(session),
            "meta": read_meta(agent),
            "raw_output": "not_returned",
        }

    start_cwd = Path(cwd or os.getcwd()).expanduser().resolve()
    if not start_cwd.exists() or not start_cwd.is_dir():
        raise AgentError(f"cwd is not a directory: {start_cwd}")

    run_id = f"{now_id()}-{agent}"
    raw_log = RAW_DIR / f"{run_id}.log"
    raw_log.touch(mode=0o600, exist_ok=False)
    try:
        raw_log.chmod(0o600)
    except PermissionError:
        pass

    argv = [str(runner), *BASE_ARGS]
    if prompt:
        argv.append(prompt)

    command = "env CODEX_MASTER_MCP=1 CODEX_AGENT_MCP=1 " + shlex.join(argv)
    cp = run_tmux(["new-session", "-d", "-s", session, "-c", str(start_cwd), command], check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux start failed for agent {agent}: {cp.stderr.strip()}")

    pipe_command = "cat >> " + shlex.quote(str(raw_log))
    pipe = run_tmux(["pipe-pane", "-o", "-t", session, pipe_command], check=False)
    if pipe.returncode != 0:
        cleanup_failed_start(session, raw_log)
        raise AgentError(f"tmux pipe-pane failed for agent {agent}: {pipe.stderr.strip()}")

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
        "raw_log_policy": "local_only_not_returned_by_default",
    }
    write_meta(agent, data)
    return {
        "agent": agent,
        "status": "started",
        "backend": "tmux",
        "session": session,
        "pid": pane_pid(session),
        "cwd": str(start_cwd),
        "model": DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
        "raw_log": str(raw_log),
        "raw_output": "not_returned",
    }


def stop_agent(agent: str) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    was_running = tmux_alive(session)
    if was_running:
        cp = run_tmux(["kill-session", "-t", session], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux stop failed for agent {agent}: {cp.stderr.strip()}")
    return {"agent": agent, "status": "stopped" if was_running else "not_running", "session": session}


def status_agent(agent: str) -> dict[str, Any]:
    ensure_state()
    cfg = AGENTS[agent]
    session = cfg["session"]
    meta = read_meta(agent)
    raw_log = meta.get("raw_log")
    raw_size = None
    if raw_log:
        try:
            raw_size = Path(raw_log).stat().st_size
        except OSError:
            raw_size = None
    return {
        "agent": agent,
        "label": cfg["label"],
        "backend": "tmux",
        "running": tmux_alive(session),
        "session": session,
        "pid": pane_pid(session),
        "home": str(cfg["home"]),
        "runner": str(cfg["runner"]),
        "started_at_utc": meta.get("started_at_utc"),
        "cwd": meta.get("cwd"),
        "model": meta.get("model") or DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": meta.get("model_reasoning_effort") or DEFAULT_AGENT_MODEL_EFFORT,
        "raw_log": raw_log,
        "raw_log_bytes": raw_size,
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
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("SKILL.md") if path.is_file())


def skills_agent(agent: str, include_names: bool = False, limit: int = 80) -> dict[str, Any]:
    cfg = AGENTS[agent]
    home = cfg["home"]
    limit = max(0, min(int(limit), MAX_SKILL_NAMES))

    all_paths: list[Path] = []
    roots: list[dict[str, Any]] = []
    for kind, root in skill_scan_roots(home):
        paths = list_skill_files(root)
        roots.append({"kind": kind, "path": str(root), "exists": root.exists(), "skill_count": len(paths)})
        all_paths.extend(paths)

    by_source: dict[str, int] = {}
    by_plugin: dict[str, int] = {}
    system_skills: list[str] = []
    names: list[dict[str, str]] = []

    for path in sorted(set(all_paths)):
        parsed = parse_skill_path(home, path)
        source = parsed["source"]
        by_source[source] = by_source.get(source, 0) + 1
        if parsed["plugin"]:
            by_plugin[parsed["plugin"]] = by_plugin.get(parsed["plugin"], 0) + 1
        if source == "system":
            system_skills.append(parsed["name"])
        if include_names and len(names) < limit:
            names.append(
                {
                    "name": parsed["name"],
                    "source": source,
                    "plugin": parsed["plugin"],
                    "path": safe_relative(path, home),
                }
            )

    result: dict[str, Any] = {
        "agent": agent,
        "label": cfg["label"],
        "home": str(home),
        "total": len(set(all_paths)),
        "roots": roots,
        "by_source": dict(sorted(by_source.items())),
        "system_skills": sorted(set(system_skills)),
        "plugins": dict(sorted(by_plugin.items())),
        "skill_file_contents": "not_returned",
        "raw_output": "not_returned",
    }
    if include_names:
        result["names_limit"] = limit
        result["names"] = names
        result["names_truncated"] = len(set(all_paths)) > len(names)
    return result


def as_string_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise AgentError(f"{field} must be a string or list of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise AgentError(f"{field} must contain only strings")
        text = item.strip()
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


def skill_match_agent(agent: str, skill_ref: str, limit: int = 8) -> dict[str, Any]:
    if not isinstance(skill_ref, str) or not skill_ref.strip():
        raise AgentError("skill must be a non-empty string")
    limit = max(1, min(int(limit), MAX_SKILL_NAMES))
    matches = skill_matches(agent, skill_ref, limit)
    skill_safe, _changed = redact(skill_ref.strip())
    return {
        "agent": agent,
        "skill": trim_chars(skill_safe, 300),
        "available": bool(matches),
        "match_count": len(matches),
        "matches": matches,
        "skill_file_contents": "not_returned",
        "raw_output": "not_returned",
    }


def capped_mapping(items: dict[str, int], limit: int) -> tuple[dict[str, int], bool]:
    sorted_items = sorted(items.items())
    capped = dict(sorted_items[:limit])
    return capped, len(sorted_items) > limit


def capabilities_agent(agent: str) -> dict[str, Any]:
    inventory = skills_agent(agent, include_names=False)
    plugins, plugins_truncated = capped_mapping(inventory["plugins"], MAX_CAPABILITY_PLUGINS)
    return {
        "agent": agent,
        "label": AGENTS[agent]["label"],
        "home": str(AGENTS[agent]["home"]),
        "models": {
            "default": DEFAULT_AGENT_MODEL,
            "read_only": DEFAULT_AGENT_MODEL,
            "write": WRITE_AGENT_MODEL,
            "default_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
            "write_reasoning_effort": WRITE_AGENT_MODEL_EFFORT,
        },
        "skill_count": inventory["total"],
        "system_skills": inventory["system_skills"],
        "plugin_count": len(inventory["plugins"]),
        "plugins_limit": MAX_CAPABILITY_PLUGINS,
        "plugins": plugins,
        "plugins_truncated": plugins_truncated,
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


def scope_check(scope: list[str], write_paths: list[str], cwd: str | None = None) -> dict[str, Any]:
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
        "cwd": str(base),
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
    task: str,
    scope: list[str],
    skill: str | None = None,
    write_paths: list[str] | None = None,
    context: list[str] | None = None,
    forbidden: list[str] | None = None,
    name: str | None = None,
    enter: bool = True,
    allow_missing_skill: bool = False,
    allow_subagents: bool = False,
) -> dict[str, Any]:
    role = role.strip().lower()
    if role not in {"exploriererin", "arbeitsbiene"}:
        raise AgentError("role must be 'exploriererin' or 'arbeitsbiene'")
    if not isinstance(task, str) or not task.strip():
        raise AgentError("task must be a non-empty string")

    write_paths = write_paths or []
    context = context or []
    forbidden = forbidden or []
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
        task=task.strip(),
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

    sent = send_agent(agent, prompt, enter)
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


def record_assignment(record: dict[str, Any]) -> None:
    ensure_state()
    write_private_text(ASSIGNMENT_LOG, json.dumps(record, sort_keys=True) + "\n")
    prune_assignment_log()


def prune_assignment_log(max_records: int | None = None) -> None:
    max_records = max(1, int(max_records if max_records is not None else MAX_ASSIGNMENT_LOG_RECORDS))
    if not ASSIGNMENT_LOG.exists():
        return
    try:
        lines = ASSIGNMENT_LOG.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AgentError(f"could not read assignment log for pruning: {exc}") from exc

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
        try:
            for line in ASSIGNMENT_LOG.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if agent == "all" or record.get("agent") == agent:
                    records.append(record)
        except OSError as exc:
            raise AgentError(f"could not read assignment log: {exc}") from exc
    return {
        "agent": agent,
        "limit": limit,
        "records": records[-limit:],
        "record_count": len(records[-limit:]),
        "retained_count": len(records),
        "retention_limit": MAX_ASSIGNMENT_LOG_RECORDS,
        "records_truncated": len(records) > limit,
        "log_path": str(ASSIGNMENT_LOG),
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


def request_agent_report(agent: str, assignment_id: str | None = None, enter: bool = True) -> dict[str, Any]:
    if assignment_id:
        safe_id, _changed = redact(assignment_id)
        text = (
            "Bitte liefere einen knappen Bericht zum Assignment "
            f"{trim_chars(safe_id, 200)}: Status, relevante Dateien/Zeilen, Tests, offene Risiken. "
            "Keine Rohlogs und keine langen Ausgaben."
        )
    else:
        text = "Bitte liefere einen knappen Statusbericht: Aufgabe, Stand, Tests, offene Risiken. Keine Rohlogs."
    sent = send_agent(agent, text, enter)
    return {
        "agent": agent,
        "status": "report_requested",
        "submitted": enter,
        "assignment_id": assignment_id,
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


def worktree_create_for_agent(agent: str, path: str | None = None, base_ref: str | None = None) -> dict[str, Any]:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    target = Path(path).expanduser() if path else repo_root() / ".codex-master-worktrees" / f"agent-{agent}-{now_id()}"
    target = target.resolve(strict=False)
    if target.exists():
        raise AgentError(f"worktree path already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    args = ["worktree", "add", str(target)]
    if base_ref:
        args.append(base_ref)
    cp = run_command(["git", *args], cwd=repo_root())
    if cp.returncode != 0:
        output, redacted = command_excerpt(cp.stdout + cp.stderr)
        raise AgentError(f"git worktree add failed: {output if not redacted else '<redacted>'}")
    return {
        "agent": agent,
        "path": str(target),
        "base_ref": base_ref,
        "status": "created",
        "raw_output": "not_returned",
    }


def worktree_status(path: str | None = None) -> dict[str, Any]:
    target = Path(path).expanduser().resolve(strict=False) if path else repo_root()
    return {
        "path": str(target),
        "status": git_excerpt(["status", "--short"], cwd=target),
        "worktrees": git_excerpt(["worktree", "list", "--porcelain"], cwd=repo_root()),
        "raw_output": "not_returned",
    }


def integration_status() -> dict[str, Any]:
    return {
        "repo": str(repo_root()),
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


def master_plugin_status() -> dict[str, Any]:
    root = repo_root()
    manifest = root / ".codex-plugin" / "plugin.json"
    mcp_manifest = root / ".mcp.json"
    skill = root / "skills" / "codex-master-fleet" / "SKILL.md"
    return {
        "repo": str(root),
        "plugin_manifest": {"path": str(manifest), "exists": manifest.is_file()},
        "mcp_manifest": {"path": str(mcp_manifest), "exists": mcp_manifest.is_file()},
        "skill": {"path": str(skill), "exists": skill.is_file()},
        "mcp_registration": check_mcp_registration(DEFAULT_INSTALL_PATH),
        "raw_output": "not_returned",
    }


def check_mcp_registration(command_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    codex_path = shutil.which("codex")
    if not codex_path:
        return {"registered": False, "ok": False, "reason": "codex command not found"}
    cp = run_command(["codex", "mcp", "get", MCP_SERVER_NAME])
    output, redacted = command_excerpt(cp.stdout + cp.stderr)
    registered = cp.returncode == 0
    command_matches = str(command_path) in output if registered else False
    return {
        "registered": registered,
        "command_matches": command_matches,
        "ok": registered and command_matches,
        "redaction_applied": redacted,
        "output_excerpt": output if not registered or not command_matches else "",
    }


def doctor() -> dict[str, Any]:
    wrapper = repo_wrapper_path()
    install_path = DEFAULT_INSTALL_PATH
    installed_target = None
    if install_path.is_symlink():
        try:
            installed_target = str(install_path.resolve())
        except OSError:
            installed_target = "<unreadable>"
    checks: list[dict[str, Any]] = [
        {"name": "tmux_available", "ok": shutil.which("tmux") is not None},
        {"name": "codex_available", "ok": shutil.which("codex") is not None},
        {"name": "repo_wrapper_exists", "ok": wrapper.exists(), "path": str(wrapper)},
        {"name": "repo_wrapper_executable", "ok": os.access(wrapper, os.X_OK), "path": str(wrapper)},
        {
            "name": "installed_symlink",
            "ok": install_path.is_symlink() and install_path.resolve() == wrapper,
            "path": str(install_path),
            "target": installed_target,
        },
    ]
    for agent, cfg in AGENTS.items():
        checks.extend(
            [
                {"name": f"agent_{agent}_home_exists", "ok": cfg["home"].is_dir(), "path": str(cfg["home"])},
                {
                    "name": f"agent_{agent}_runner_executable",
                    "ok": cfg["runner"].exists() and os.access(cfg["runner"], os.X_OK),
                    "path": str(cfg["runner"]),
                },
                {"name": f"agent_{agent}_tmux_running", "ok": tmux_alive(cfg["session"]), "session": cfg["session"]},
            ]
        )
    registration = check_mcp_registration(install_path)
    checks.append({"name": "mcp_registered", **registration})
    return {"ok": all(check["ok"] for check in checks), "checks": checks, "raw_output": "not_returned"}


def install(register: bool = True, force: bool = False, install_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    wrapper = repo_wrapper_path()
    if not wrapper.exists():
        raise AgentError(f"repo wrapper missing: {wrapper}")
    if not os.access(wrapper, os.X_OK):
        raise AgentError(f"repo wrapper is not executable: {wrapper}")

    install_path = install_path.expanduser()
    install_path.parent.mkdir(parents=True, exist_ok=True)
    if install_path.exists() or install_path.is_symlink():
        if install_path.is_symlink() and install_path.resolve() == wrapper:
            symlink_status = "already_installed"
        elif force:
            install_path.unlink()
            install_path.symlink_to(wrapper)
            symlink_status = "replaced"
        else:
            raise AgentError(f"install path exists and is not this wrapper symlink: {install_path}")
    else:
        install_path.symlink_to(wrapper)
        symlink_status = "created"

    registration: dict[str, Any] = {"requested": register, "status": "skipped"}
    if register:
        current = check_mcp_registration(install_path)
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

    return {
        "ok": True,
        "install_path": str(install_path),
        "target": str(wrapper),
        "symlink": symlink_status,
        "mcp": registration,
        "raw_output": "not_returned",
    }


def uninstall(unregister: bool = True, remove_symlink: bool = False, install_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    install_path = install_path.expanduser()
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
        wrapper = repo_wrapper_path()
        if install_path.is_symlink() and install_path.resolve() == wrapper:
            install_path.unlink()
            symlink_status = "removed"
        elif install_path.exists() or install_path.is_symlink():
            symlink_status = "left_in_place_not_repo_wrapper"
        else:
            symlink_status = "missing"

    return {"ok": True, "mcp": mcp_status, "symlink": symlink_status, "raw_output": "not_returned"}


def send_agent(agent: str, text: str, enter: bool = True) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    if not tmux_alive(session):
        raise AgentError(f"agent {agent} is not running")
    buffer_name = f"codex-master-mcp-{agent}-{int(time.time() * 1000)}"
    cp = run_tmux(["load-buffer", "-b", buffer_name, "-"], input_text=text, check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux load-buffer failed for agent {agent}: {cp.stderr.strip()}")
    cp = run_tmux(["paste-buffer", "-d", "-b", buffer_name, "-t", session], check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux paste-buffer failed for agent {agent}: {cp.stderr.strip()}")
    if enter:
        cp = run_tmux(["send-keys", "-t", session, "Enter"], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux send Enter failed for agent {agent}: {cp.stderr.strip()}")
    return {
        "agent": agent,
        "status": "sent",
        "chars": len(text),
        "submitted": enter,
        "response_output": "not_returned",
    }


def interrupt_agent(agent: str) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    if not tmux_alive(session):
        raise AgentError(f"agent {agent} is not running")
    cp = run_tmux(["send-keys", "-t", session, "C-c"], check=False)
    if cp.returncode != 0:
        raise AgentError(f"tmux interrupt failed for agent {agent}: {cp.stderr.strip()}")
    return {"agent": agent, "status": "interrupt_sent", "response_output": "not_returned"}


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


def read_log_tail(path: Path, approx_bytes: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - approx_bytes), os.SEEK_SET)
        return fh.read().decode("utf-8", errors="replace")


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
        raw = read_log_tail(Path(raw_log), chars * 4) if raw_log else ""
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
        "raw_log": meta.get("raw_log"),
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
            results.append({"agent": agent, "error": str(exc)})
    return {"results": results}


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "agent_start":
        selected = agent_ids(str(args.get("agent", "both")))
        return multi_agent_result(selected, lambda agent: start_agent(agent, args.get("cwd"), args.get("prompt")))
    if name == "agent_stop":
        selected = agent_ids(str(args.get("agent", "both")))
        return multi_agent_result(selected, stop_agent)
    if name == "agent_status":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(selected, status_agent)
    if name == "agent_skills":
        selected = agent_ids(str(args.get("agent", "all")))
        include_names = bool(args.get("include_names", False))
        limit = int(args.get("limit", 80))
        return multi_agent_result(selected, lambda agent: skills_agent(agent, include_names, limit))
    if name == "agent_skill_match":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(
            selected,
            lambda agent: skill_match_agent(agent, str(args.get("skill", "")), int(args.get("limit", 8))),
        )
    if name == "agent_capabilities":
        selected = agent_ids(str(args.get("agent", "all")))
        return multi_agent_result(selected, capabilities_agent)
    if name == "agent_scope_check":
        return scope_check(
            as_string_list(args.get("scope"), field="scope"),
            as_string_list(args.get("write_paths"), field="write_paths"),
            args.get("cwd") if isinstance(args.get("cwd"), str) else None,
        )
    if name == "agent_assign":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign requires exactly one agent: a or b")
        return assign_agent(
            selected[0],
            role=str(args.get("role", "")),
            task=str(args.get("task", "")),
            scope=as_string_list(args.get("scope"), field="scope"),
            skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
            write_paths=as_string_list(args.get("write_paths"), field="write_paths"),
            context=as_string_list(args.get("context"), field="context"),
            forbidden=as_string_list(args.get("forbidden"), field="forbidden"),
            name=args.get("name") if isinstance(args.get("name"), str) else None,
            enter=bool(args.get("enter", True)),
            allow_missing_skill=bool(args.get("allow_missing_skill", False)),
            allow_subagents=bool(args.get("allow_subagents", False)),
        )
    if name == "agent_assign_readonly":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign_readonly requires exactly one agent: a or b")
        return assign_agent(
            selected[0],
            role="exploriererin",
            task=str(args.get("task", "")),
            scope=as_string_list(args.get("scope"), field="scope"),
            skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
            context=as_string_list(args.get("context"), field="context"),
            forbidden=as_string_list(args.get("forbidden"), field="forbidden"),
            name=args.get("name") if isinstance(args.get("name"), str) else None,
            enter=bool(args.get("enter", True)),
            allow_missing_skill=bool(args.get("allow_missing_skill", False)),
            allow_subagents=bool(args.get("allow_subagents", False)),
        )
    if name == "agent_assign_write":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_assign_write requires exactly one agent: a or b")
        return assign_agent(
            selected[0],
            role="arbeitsbiene",
            task=str(args.get("task", "")),
            scope=as_string_list(args.get("scope"), field="scope"),
            skill=args.get("skill") if isinstance(args.get("skill"), str) else None,
            write_paths=as_string_list(args.get("write_paths"), field="write_paths"),
            context=as_string_list(args.get("context"), field="context"),
            forbidden=as_string_list(args.get("forbidden"), field="forbidden"),
            name=args.get("name") if isinstance(args.get("name"), str) else None,
            enter=bool(args.get("enter", True)),
            allow_missing_skill=bool(args.get("allow_missing_skill", False)),
            allow_subagents=bool(args.get("allow_subagents", False)),
        )
    if name == "agent_assignments":
        return list_assignments(str(args.get("agent", "all")), int(args.get("limit", 20)))
    if name == "agent_last_assignment_status":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_last_assignment_status requires exactly one agent: a or b")
        return last_assignment_status(selected[0])
    if name == "agent_report_request":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_report_request requires exactly one agent: a or b")
        return request_agent_report(
            selected[0],
            args.get("assignment_id") if isinstance(args.get("assignment_id"), str) else None,
            bool(args.get("enter", True)),
        )
    if name == "worktree_create_for_agent":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("worktree_create_for_agent requires exactly one agent: a or b")
        return worktree_create_for_agent(
            selected[0],
            args.get("path") if isinstance(args.get("path"), str) else None,
            args.get("base_ref") if isinstance(args.get("base_ref"), str) else None,
        )
    if name == "worktree_status":
        return worktree_status(args.get("path") if isinstance(args.get("path"), str) else None)
    if name == "integration_status":
        return integration_status()
    if name == "commit_ready_check":
        return commit_ready_check(bool(args.get("run_tests", True)))
    if name == "master_plugin_status":
        return master_plugin_status()
    if name == "agent_doctor":
        return doctor()
    if name == "agent_send":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_send requires exactly one agent: a or b")
        text = args.get("text")
        if not isinstance(text, str) or text == "":
            raise AgentError("agent_send requires non-empty text")
        return send_agent(selected[0], text, bool(args.get("enter", True)))
    if name == "agent_interrupt":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_interrupt requires exactly one agent: a or b")
        return interrupt_agent(selected[0])
    if name == "agent_safe_tail":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_safe_tail requires exactly one agent: a or b")
        return safe_tail(
            selected[0],
            int(args.get("lines", 40)),
            int(args.get("chars", 4000)),
            str(args.get("source", "pane")),
        )
    raise AgentError(f"unknown tool: {name}")


TOOLS: list[dict[str, Any]] = [
    {
        "name": "agent_start",
        "description": "Start Codex Agentin A, B, or both in persistent tmux sessions with gpt-5.4-mini, --yolo -s danger-full-access --search. Does not return raw output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["a", "b", "both"], "default": "both"},
                "cwd": {"type": "string", "description": "Working directory. Defaults to the MCP server cwd."},
                "prompt": {"type": "string", "description": "Optional initial prompt passed to Codex."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_status",
        "description": "Return structured status for Codex Agentin A, B, or all Agentinnen. Does not return raw output.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent": {"type": "string", "enum": ["a", "b", "all"], "default": "all"}},
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
                "text": {"type": "string"},
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
            "properties": {"agent": {"type": "string", "enum": ["a", "b"]}},
            "additionalProperties": False,
        },
    },
    {
        "name": "agent_stop",
        "description": "Stop Codex Agentin A, B, or both by killing the managed tmux session.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent": {"type": "string", "enum": ["a", "b", "both"], "default": "both"}},
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
                "skill": {"type": "string"},
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
                "scope": {"type": "array", "items": {"type": "string"}, "default": []},
                "write_paths": {"type": "array", "items": {"type": "string"}, "default": []},
                "cwd": {"type": "string"},
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
                "task": {"type": "string"},
                "skill": {"type": "string"},
                "scope": {"type": "array", "items": {"type": "string"}, "default": []},
                "write_paths": {"type": "array", "items": {"type": "string"}, "default": []},
                "context": {"type": "array", "items": {"type": "string"}, "default": []},
                "forbidden": {"type": "array", "items": {"type": "string"}, "default": []},
                "name": {"type": "string"},
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
                "task": {"type": "string"},
                "skill": {"type": "string"},
                "scope": {"type": "array", "items": {"type": "string"}, "default": []},
                "context": {"type": "array", "items": {"type": "string"}, "default": []},
                "forbidden": {"type": "array", "items": {"type": "string"}, "default": []},
                "name": {"type": "string"},
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
                "task": {"type": "string"},
                "skill": {"type": "string"},
                "scope": {"type": "array", "items": {"type": "string"}, "default": []},
                "write_paths": {"type": "array", "items": {"type": "string"}},
                "context": {"type": "array", "items": {"type": "string"}, "default": []},
                "forbidden": {"type": "array", "items": {"type": "string"}, "default": []},
                "name": {"type": "string"},
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
                "assignment_id": {"type": "string"},
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
                "path": {"type": "string"},
                "base_ref": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "worktree_status",
        "description": "Return capped git status and worktree metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
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
        "name": "master_plugin_status",
        "description": "Return plugin packaging and MCP registration status for codex-master.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "agent_doctor",
        "description": "Return structured diagnostics for installation, MCP registration, runners, and tmux sessions. Does not return raw output.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def rpc_result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def rpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


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
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            payload = call_tool(str(name), args if isinstance(args, dict) else {})
            text = json.dumps(payload, indent=2, sort_keys=True)
            return rpc_result(message_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:
            text = json.dumps({"error": str(exc)}, indent=2, sort_keys=True)
            return rpc_result(message_id, {"content": [{"type": "text", "text": text}], "isError": True})
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if message_id is None:
        return None
    return rpc_error(message_id, -32601, f"method not found: {method}")


def read_message() -> dict[str, Any] | None:
    first = sys.stdin.buffer.readline()
    if not first:
        return None
    if first.startswith(b"Content-Length:"):
        length = int(first.decode("ascii").split(":", 1)[1].strip())
        while True:
            line = sys.stdin.buffer.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        body = sys.stdin.buffer.read(length)
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
                write_message(rpc_error(None, -32000, str(exc)))
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

    p_send = sub.add_parser("send")
    p_send.add_argument("agent", choices=["a", "b"])
    p_send.add_argument("text")
    p_send.add_argument("--no-enter", action="store_true")

    p_interrupt = sub.add_parser("interrupt")
    p_interrupt.add_argument("agent", choices=["a", "b"])

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("agent", choices=["a", "b", "both"], nargs="?", default="both")

    p_tail = sub.add_parser("tail")
    p_tail.add_argument("agent", choices=["a", "b"])
    p_tail.add_argument("--source", choices=["pane", "log"], default="pane")
    p_tail.add_argument("--lines", type=int, default=20)
    p_tail.add_argument("--chars", type=int, default=2000)

    p_skills = sub.add_parser("skills")
    p_skills.add_argument("agent", choices=["a", "b", "all"], nargs="?", default="all")
    p_skills.add_argument("--include-names", action="store_true")
    p_skills.add_argument("--limit", type=int, default=80)

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

    sub.add_parser("plugin-status")

    p_install = sub.add_parser("install")
    p_install.add_argument("--no-register", action="store_true")
    p_install.add_argument("--force", action="store_true")
    p_install.add_argument("--path", default=str(DEFAULT_INSTALL_PATH))

    p_uninstall = sub.add_parser("uninstall")
    p_uninstall.add_argument("--keep-registration", action="store_true")
    p_uninstall.add_argument("--remove-symlink", action="store_true")
    p_uninstall.add_argument("--path", default=str(DEFAULT_INSTALL_PATH))

    sub.add_parser("doctor")
    sub.add_parser("tools")

    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            return print_json(call_tool("agent_start", {"agent": args.agent, "cwd": args.cwd, "prompt": args.prompt}))
        if args.command == "status":
            return print_json(call_tool("agent_status", {"agent": args.agent}))
        if args.command == "send":
            return print_json(call_tool("agent_send", {"agent": args.agent, "text": args.text, "enter": not args.no_enter}))
        if args.command == "interrupt":
            return print_json(call_tool("agent_interrupt", {"agent": args.agent}))
        if args.command == "stop":
            return print_json(call_tool("agent_stop", {"agent": args.agent}))
        if args.command == "tail":
            return print_json(
                call_tool(
                    "agent_safe_tail",
                    {"agent": args.agent, "source": args.source, "lines": args.lines, "chars": args.chars},
                )
            )
        if args.command == "skills":
            return print_json(
                call_tool(
                    "agent_skills",
                    {"agent": args.agent, "include_names": args.include_names, "limit": args.limit},
                )
            )
        if args.command == "skill-match":
            return print_json(call_tool("agent_skill_match", {"agent": args.agent, "skill": args.skill, "limit": args.limit}))
        if args.command == "capabilities":
            return print_json(call_tool("agent_capabilities", {"agent": args.agent}))
        if args.command == "scope-check":
            return print_json(
                call_tool(
                    "agent_scope_check",
                    {"scope": args.scope, "write_paths": args.write_paths, "cwd": args.cwd},
                )
            )
        if args.command == "assign":
            return print_json(
                call_tool(
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
                call_tool(
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
                call_tool(
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
            return print_json(call_tool("agent_assignments", {"agent": args.agent, "limit": args.limit}))
        if args.command == "last-assignment":
            return print_json(call_tool("agent_last_assignment_status", {"agent": args.agent}))
        if args.command == "report-request":
            return print_json(
                call_tool(
                    "agent_report_request",
                    {"agent": args.agent, "assignment_id": args.assignment_id, "enter": not args.no_enter},
                )
            )
        if args.command == "worktree-create":
            return print_json(
                call_tool(
                    "worktree_create_for_agent",
                    {"agent": args.agent, "path": args.path, "base_ref": args.base_ref},
                )
            )
        if args.command == "worktree-status":
            return print_json(call_tool("worktree_status", {"path": args.path}))
        if args.command == "integration-status":
            return print_json(call_tool("integration_status", {}))
        if args.command == "commit-ready-check":
            return print_json(call_tool("commit_ready_check", {"run_tests": not args.no_tests}))
        if args.command == "plugin-status":
            return print_json(call_tool("master_plugin_status", {}))
        if args.command == "install":
            return print_json(
                install(
                    register=not args.no_register,
                    force=args.force,
                    install_path=Path(args.path),
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
        print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True))
        return 1
    return 2


def main() -> int:
    if len(sys.argv) > 1:
        return main_cli(sys.argv[1:])
    return serve_mcp()


if __name__ == "__main__":
    raise SystemExit(main())
