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
DEFAULT_WAIT_SECONDS = 30
MAX_WAIT_SECONDS = 600
DEFAULT_WAIT_POLL_SECONDS = 2
MAX_WAIT_POLL_SECONDS = 10
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
COMMAND_TIMEOUT_RETURN_CODE = 124
DEFAULT_TMUX_TIMEOUT_SECONDS = 10
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
DEFAULT_AGENTIN_NAMES = {"a": "Mila", "b": "Nora"}
RAW_LOG_TRUNCATION_MARKER = b"\n... codex-master-mcp retained the last raw log bytes ...\n"


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
    for path in (STATE_ROOT, RAW_DIR, META_DIR, LOCK_DIR):
        ensure_private_dir(path)
    prune_raw_logs()


def ensure_private_dir(path: Path) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, exist_ok=False)
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
        "managed_dirs": [str(path) for path in managed_raw_dirs()],
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


def same_path_text(left: str, right: Path) -> bool:
    try:
        return Path(left).expanduser().resolve(strict=False) == right.expanduser().resolve(strict=False)
    except OSError:
        return False


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
        "home": str(AGENTS[agent]["home"]),
        "process_count": len(processes),
        "external_process_count": len(external),
        "managed_process_count": len(processes) - len(external),
        "external_processes": external[:10],
        "external_processes_truncated": len(external) > 10,
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


def start_agent(agent: str, cwd: str | None = None, prompt: str | None = None) -> dict[str, Any]:
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
        raise AgentError(f"tmux start failed for agent {agent}: {command_error_text(cp.stderr)}")

    pipe_command = raw_log_writer_command(raw_log)
    pipe = run_tmux(["pipe-pane", "-o", "-t", session, pipe_command], check=False)
    if pipe.returncode != 0:
        cleanup_failed_start(session, raw_log, kill_session=True)
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
        "cwd": str(start_cwd),
        "model": DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": DEFAULT_AGENT_MODEL_EFFORT,
        "raw_log": "not_returned",
        "raw_log_max_bytes": MAX_RAW_LOG_BYTES,
        "raw_output": "not_returned",
    }


def stop_agent(agent: str) -> dict[str, Any]:
    cfg = AGENTS[agent]
    session = cfg["session"]
    was_running = tmux_alive(session)
    if was_running:
        cp = run_tmux(["kill-session", "-t", session], check=False)
        if cp.returncode != 0:
            raise AgentError(f"tmux stop failed for agent {agent}: {command_error_text(cp.stderr)}")
    return {"agent": agent, "status": "stopped" if was_running else "not_running", "session": session}


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


def infer_limit_model(text: str, meta: dict[str, Any], latest_assignment: dict[str, Any] | None) -> str:
    lowered = text.lower()
    if re.search(r"\b(?:gpt[- ]?5\.3[- ]?codex[- ]?spark|codex[- ]?spark|spark)\b", lowered):
        return WRITE_AGENT_MODEL
    if re.search(r"\b(?:gpt[- ]?5\.4[- ]?mini|gpt[- ]?5\.4|5\.4[- ]?mini)\b", lowered):
        return DEFAULT_AGENT_MODEL
    if latest_assignment and isinstance(latest_assignment.get("model"), str):
        return latest_assignment["model"]
    if isinstance(meta.get("model"), str):
        return meta["model"]
    return "unknown"


def classify_limit_text(text: str, meta: dict[str, Any] | None = None, latest_assignment: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or {}
    cleaned = strip_ansi(text)
    lowered = cleaned.lower()
    has_limit = any(
        re.search(pattern, lowered)
        for pattern in (
            r"\brate limit(?:ed|s)?\b",
            r"\busage limit\b",
            r"\blimit (?:reached|exceeded|hit)\b",
            r"\bquota (?:exceeded|reached)\b",
            r"\btoo many requests\b",
            r"\bout of tokens\b",
            r"\btoken (?:limit|budget|quota)\b",
            r"\bcontext (?:length|window).{0,80}\b(?:exceeded|full|limit)\b",
        )
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
    model = infer_limit_model(cleaned, meta, latest_assignment)
    role = latest_assignment.get("role") if latest_assignment else "unknown"
    if role not in {"exploriererin", "arbeitsbiene"}:
        role = "unknown"

    return {
        "limited": detected,
        "window": window if detected else "none",
        "kind": limit_kind if detected else "none",
        "model": model,
        "model_pool": limit_model_pool(model),
        "role": role,
        "source": "classified_from_bounded_status_text" if cleaned else "no_status_text",
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
) -> dict[str, Any]:
    samples: list[str] = []
    if running:
        samples.append(pane_tail(agent, MAX_TAIL_LINES))
    if raw_log_path:
        samples.append(read_log_tail(raw_log_path, MAX_LIMIT_STATUS_BYTES))
    return classify_limit_text("\n".join(item for item in samples if item), meta, latest_assignment)


def agent_response_state(running: bool, limit_state: dict[str, Any], raw_log_info: dict[str, Any]) -> dict[str, Any]:
    if limit_state.get("limited"):
        state = "blocked_by_limit"
    elif not running:
        state = "not_running"
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
    if activity_signature(status) != activity_signature(initial):
        return "activity_observed"
    return None


def wait_agent(agent: str, timeout_seconds: int = DEFAULT_WAIT_SECONDS, poll_interval_seconds: int = DEFAULT_WAIT_POLL_SECONDS) -> dict[str, Any]:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    timeout_seconds = max(0, min(int(timeout_seconds), MAX_WAIT_SECONDS))
    poll_interval_seconds = max(1, min(int(poll_interval_seconds), MAX_WAIT_POLL_SECONDS))
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
    limit_state = agent_limit_state(
        agent,
        running=running,
        meta=meta,
        raw_log_path=raw_log_path,
        latest_assignment=latest_assignment,
    )
    return {
        "agent": agent,
        "label": cfg["label"],
        "backend": "tmux",
        "running": running,
        "session": session,
        "pid": pane_pid(session),
        "home": str(cfg["home"]),
        "runner": str(cfg["runner"]),
        "started_at_utc": meta.get("started_at_utc"),
        "cwd": meta.get("cwd"),
        "model": meta.get("model") or DEFAULT_AGENT_MODEL,
        "model_reasoning_effort": meta.get("model_reasoning_effort") or DEFAULT_AGENT_MODEL_EFFORT,
        "last_assignment": latest_assignment,
        "limit_state": limit_state,
        "response_state": agent_response_state(running, limit_state, raw_log_info),
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
        roots.append({"kind": kind, "path": str(root), "exists": root.exists(), "skill_count": len(paths)})
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
        "home": str(home),
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
                records.append(record)
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


def request_agent_report(agent: str, assignment_id: Any = None, enter: bool = True) -> dict[str, Any]:
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


def worktree_create_for_agent(agent: str, path: Any = None, base_ref: Any = None) -> dict[str, Any]:
    if agent not in {"a", "b"}:
        raise AgentError("agent must be a or b")
    path = bounded_text(path, field="path", max_chars=MAX_PATH_TEXT) if path is not None else None
    base_ref = bounded_text(base_ref, field="base_ref", max_chars=MAX_PATH_TEXT) if base_ref is not None else None
    target = Path(path).expanduser() if path else repo_root() / ".codex-master-worktrees" / f"agent-{agent}-{now_id()}"
    if not target.is_absolute():
        target = repo_root() / target
    target = target.absolute()
    if path_present_no_follow(target):
        raise AgentError("worktree path already exists")
    ensure_directory_chain_no_symlink(target.parent, "worktree parent directories must be real directories")
    target = target.resolve(strict=False)
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


def worktree_status(path: Any = None) -> dict[str, Any]:
    path = bounded_text(path, field="path", max_chars=MAX_PATH_TEXT) if path is not None else None
    target = Path(path).expanduser() if path else repo_root()
    if not target.is_absolute():
        target = repo_root() / target
    target = target.absolute()
    if not is_real_directory_no_symlink(target):
        raise AgentError("worktree status path must be a real directory")
    target = target.resolve(strict=False)
    return {
        "path": str(target),
        "status": git_excerpt(["status", "--short"], cwd=target),
        "worktrees": git_excerpt(["worktree", "list", "--porcelain"], cwd=repo_root()),
        "raw_output": "not_returned",
    }


def normalize_install_path(path: Path) -> Path:
    normalized = path.expanduser()
    if not normalized.is_absolute():
        normalized = Path.cwd() / normalized
    return normalized.absolute()


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


def mcp_registration_command_matches(output: str, command_path: Path) -> bool:
    expected = str(command_path)
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "command":
            return value.strip() == expected
    return False


def check_mcp_registration(command_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    codex_path = shutil.which("codex")
    if not codex_path:
        return {"registered": False, "ok": False, "reason": "codex command not found"}
    cp = run_command(["codex", "mcp", "get", MCP_SERVER_NAME])
    raw_output = cp.stdout + cp.stderr
    output, redacted = command_excerpt(raw_output)
    registered = cp.returncode == 0
    command_matches = mcp_registration_command_matches(raw_output, command_path) if registered else False
    return {
        "registered": registered,
        "command_matches": command_matches,
        "ok": registered and command_matches,
        "redaction_applied": redacted,
        "output_excerpt": output if not registered or not command_matches else "",
    }


def doctor() -> dict[str, Any]:
    ensure_state()
    wrapper = repo_wrapper_path()
    install_path = DEFAULT_INSTALL_PATH
    installed_target = None
    if install_path.is_symlink():
        resolved_install_path = resolve_path_no_throw(install_path)
        installed_target = str(resolved_install_path) if resolved_install_path else "<unreadable>"
    else:
        resolved_install_path = None
    checks: list[dict[str, Any]] = [
        {"name": "tmux_available", "ok": shutil.which("tmux") is not None},
        {"name": "codex_available", "ok": shutil.which("codex") is not None},
        {"name": "repo_wrapper_exists", "ok": wrapper.exists(), "path": str(wrapper)},
        {"name": "repo_wrapper_executable", "ok": os.access(wrapper, os.X_OK), "path": str(wrapper)},
        {
            "name": "installed_symlink",
            "ok": install_path.is_symlink() and resolved_install_path == wrapper,
            "path": str(install_path),
            "target": installed_target,
        },
    ]
    for agent, cfg in AGENTS.items():
        process_summary = agent_home_process_summary(agent)
        running = tmux_alive(cfg["session"])
        checks.extend(
            [
                {"name": f"agent_{agent}_home_exists", "ok": cfg["home"].is_dir(), "path": str(cfg["home"])},
                {
                    "name": f"agent_{agent}_runner_executable",
                    "ok": is_regular_executable_no_symlink(cfg["runner"]),
                    "path": str(cfg["runner"]),
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
                    "external_process_count": process_summary["external_process_count"],
                    "external_processes": process_summary["external_processes"],
                    "external_processes_truncated": process_summary["external_processes_truncated"],
                    "raw_output": "not_returned",
                },
            ]
        )
    registration = check_mcp_registration(install_path)
    checks.append({"name": "mcp_registered", **registration})
    checks.append({"name": "raw_log_retention_configured", "ok": True, **raw_log_retention_status()})
    return {"ok": all(check["ok"] for check in checks), "checks": checks, "raw_output": "not_returned"}


def install(register: bool = True, force: bool = False, install_path: Path = DEFAULT_INSTALL_PATH) -> dict[str, Any]:
    wrapper = repo_wrapper_path()
    if not wrapper.exists():
        raise AgentError(f"repo wrapper missing: {wrapper}")
    if not os.access(wrapper, os.X_OK):
        raise AgentError(f"repo wrapper is not executable: {wrapper}")

    install_path = normalize_install_path(install_path)
    ensure_directory_chain_no_symlink(install_path.parent, "install parent directories must be real directories")
    if install_path.exists() or install_path.is_symlink():
        resolved_install_path = resolve_path_no_throw(install_path) if install_path.is_symlink() else None
        if install_path.is_symlink() and resolved_install_path == wrapper:
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
    buffer_name = f"codex-master-mcp-{agent}-{int(time.time() * 1000)}"
    cp = run_tmux(["load-buffer", "-b", buffer_name, "-"], input_text=text, check=False)
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
        raise AgentError(f"tmux interrupt failed for agent {agent}: {command_error_text(cp.stderr)}")
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
            lambda agent: call_agent_lifecycle(agent, lambda: start_agent(agent, args.get("cwd"), args.get("prompt"))),
        )
    if name == "agent_stop":
        selected = agent_ids(str(args.get("agent", "both")))
        return multi_agent_result(selected, lambda agent: call_agent_lifecycle(agent, lambda: stop_agent(agent)))
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
            lambda: request_agent_report(
                selected[0],
                args.get("assignment_id"),
                bool_arg(args, "enter", True),
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
        return call_agent_lifecycle(selected[0], lambda: send_agent(selected[0], text, bool_arg(args, "enter", True)))
    if name == "agent_interrupt":
        selected = agent_ids(str(args.get("agent", "")))
        if len(selected) != 1:
            raise AgentError("agent_interrupt requires exactly one agent: a or b")
        return call_agent_lifecycle(selected[0], lambda: interrupt_agent(selected[0]))
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
            text = json.dumps({"error": safe_error_text(exc)}, indent=2, sort_keys=True)
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
            return print_json(call_validated_tool("agent_interrupt", {"agent": args.agent}))
        if args.command == "stop":
            return print_json(call_validated_tool("agent_stop", {"agent": args.agent}))
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
        if args.command == "plugin-status":
            return print_json(call_validated_tool("master_plugin_status", {}))
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
        print(json.dumps({"error": safe_error_text(exc)}, indent=2, sort_keys=True))
        return 1
    return 2


def main() -> int:
    if len(sys.argv) > 1:
        return main_cli(sys.argv[1:])
    return serve_mcp()


if __name__ == "__main__":
    raise SystemExit(main())
