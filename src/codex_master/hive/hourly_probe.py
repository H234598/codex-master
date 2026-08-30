"""Deterministic, fail-closed Hive hourly Runtime Image probe (record v2)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import contextlib
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any

from codex_master.runtime_layout import LayoutError, RuntimeLayout
from codex_master.runtime_process import BoundedProcessError, DEFAULT_STDERR_LIMIT, DEFAULT_STDOUT_LIMIT, run_bounded


DETERMINISTIC_PROBE_HOURS_UTC = (0, 3, 6, 9, 12, 15, 18, 21)
STATE_FILE_NAME = "hive-hourly-health.json"
PROBE_GATE_LOCK_NAME = ".hive-hourly-probe.lock"
MAX_PROBE_STATE_BYTES = 64 * 1024
MAX_PROBE_AGE_SECONDS = 4 * 60 * 60
_PROBE_RECORD_KEYS = frozenset({"schema_version", "checked_at", "checks", "commands"})
_PROBE_CHECK_KEYS = frozenset({"runtime_layout", "hive_runtime", "hive_doctor"})
_PROBE_COMMAND_KEYS = frozenset({"runtime_status", "hive_status", "hive_doctor"})
_HIVE_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "counts",
        "checks",
        "config_digest",
        "catalog_digest",
        "repository",
        "principal",
        "authority",
        "state",
        "pilot",
        "reason_codes",
        "mutation_performed",
        "raw_output",
    }
)


def _ready_state(value: object) -> bool:
    return value == "ready"


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _green_hive_runtime(value: object) -> bool:
    if not isinstance(value, Mapping) or frozenset(value) != _HIVE_STATUS_KEYS:
        return False
    counts = value.get("counts")
    checks = value.get("checks")
    reasons = value.get("reason_codes")
    return (
        type(value.get("schema_version")) is int
        and value.get("schema_version") == 1
        and value.get("mode") == "enforced"
        and _digest(value.get("config_digest"))
        and _digest(value.get("catalog_digest"))
        and type(counts) is dict
        and frozenset(counts) == {"principals", "repositories"}
        and all(type(item) is int and item >= 0 for item in counts.values())
        and type(checks) is dict
        and frozenset(checks) == {"authority", "repository", "state"}
        and all(_ready_state(checks.get(key)) for key in checks)
        and all(_ready_state(value.get(key)) for key in ("authority", "repository", "principal", "state", "pilot"))
        and type(reasons) is list
        and not reasons
        and value.get("mutation_performed") is False
        and value.get("raw_output") == "not_returned"
    )


def _green_runtime_status(value: object) -> bool:
    if not isinstance(value, Mapping) or value.get("ok") is not True:
        return False
    metadata = value.get("metadata")
    surface = value.get("mcp_surface")
    return (
        isinstance(metadata, Mapping)
        and metadata.get("ok") is True
        and metadata.get("reason_code") == "ok"
        and isinstance(surface, Mapping)
        and surface.get("ok") is True
        and surface.get("initialize") is True
        and surface.get("tools_list") is True
        and type(surface.get("tool_count")) is int
        and surface.get("tool_count") >= 1
        and surface.get("reason_code") == "ok"
        and value.get("raw_output") == "not_returned"
    )


def evaluate(
    runtime_status: Mapping[str, Any],
    hive: Mapping[str, Any],
    doctor: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce direct Runtime Image and Hive diagnostics to v2 booleans."""

    runtime_status = runtime_status if isinstance(runtime_status, Mapping) else {}
    hive = hive if isinstance(hive, Mapping) else {}
    doctor = doctor if isinstance(doctor, Mapping) else {}
    doctor_checks = doctor.get("checks")
    doctor_ready = isinstance(doctor_checks, Mapping) and all(
        _ready_state(doctor_checks.get(key)) for key in ("authority", "repository", "state")
    )
    checks = {
        "runtime_layout": _green_runtime_status(runtime_status),
        "hive_runtime": _green_hive_runtime(hive),
        "hive_doctor": doctor.get("healthy") is True and doctor_ready,
    }
    return {"checks": checks}


def probe_spawn_gate(
    payload: Mapping[str, Any],
    *,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Accept only one fresh, complete and green v2 result for Hive spawning."""

    if not isinstance(payload, Mapping) or frozenset(payload) != _PROBE_RECORD_KEYS:
        return {"allowed": False, "reason_code": "probe_ambiguous", "raw_output": "not_returned"}
    checks = payload.get("checks")
    commands = payload.get("commands")
    if (
        payload.get("schema_version") != 2
        or not isinstance(checks, Mapping)
        or frozenset(checks) != _PROBE_CHECK_KEYS
        or any(value is not True for value in checks.values())
        or not isinstance(commands, Mapping)
        or frozenset(commands) != _PROBE_COMMAND_KEYS
        or any(value is not True for value in commands.values())
    ):
        return {"allowed": False, "reason_code": "probe_red", "raw_output": "not_returned"}
    checked_at = payload.get("checked_at")
    if not isinstance(checked_at, str) or not 1 <= len(checked_at) <= 40:
        return {"allowed": False, "reason_code": "probe_invalid", "raw_output": "not_returned"}
    try:
        observed = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        reference = now() if callable(now) else (now or datetime.now(UTC))
        if observed.tzinfo is None or observed.utcoffset() is None or reference.tzinfo is None or reference.utcoffset() is None:
            raise ValueError
        age = (reference.astimezone(UTC) - observed.astimezone(UTC)).total_seconds()
    except (TypeError, ValueError, OverflowError):
        return {"allowed": False, "reason_code": "probe_invalid", "raw_output": "not_returned"}
    if age < 0 or age > MAX_PROBE_AGE_SECONDS:
        return {"allowed": False, "reason_code": "probe_stale", "raw_output": "not_returned"}
    return {"allowed": True, "reason_code": "probe_ready", "raw_output": "not_returned"}


def _read_private_probe_state(path: Path) -> Mapping[str, Any]:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ValueError("probe_state_invalid")
    try:
        parent = path.parent
        parent_stat = parent.lstat()
        path_stat = path.lstat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
            or stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_nlink != 1
            or path_stat.st_uid != os.geteuid()
            or stat.S_IMODE(path_stat.st_mode) != 0o600
            or path_stat.st_size > MAX_PROBE_STATE_BYTES
        ):
            raise ValueError("probe_state_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as exc:
        raise FileNotFoundError from exc
    except OSError as exc:
        raise ValueError("probe_state_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != path_stat.st_dev
            or opened.st_ino != path_stat.st_ino
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise ValueError("probe_state_invalid")
        raw = os.read(descriptor, MAX_PROBE_STATE_BYTES + 1)
    except OSError as exc:
        raise ValueError("probe_state_unavailable") from exc
    finally:
        os.close(descriptor)
    if len(raw) > MAX_PROBE_STATE_BYTES:
        raise ValueError("probe_state_invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("probe_state_invalid") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("probe_state_invalid")
    return payload


def _probe_state_root() -> Path:
    return Path.home() / ".local" / "state" / "codex-master-mcp"


def read_probe_gate(
    *,
    state_file: Path | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Read the private v2 record without creating or changing state."""

    if state_file is None:
        state_file = _probe_state_root() / STATE_FILE_NAME
    try:
        payload = _read_private_probe_state(state_file)
    except FileNotFoundError:
        return {"allowed": False, "reason_code": "probe_missing", "raw_output": "not_returned"}
    except (OSError, ValueError):
        return {"allowed": False, "reason_code": "probe_invalid", "raw_output": "not_returned"}
    return probe_spawn_gate(payload, now=now)


def _probe_gate_lock_path(state_file: Path) -> Path:
    if not isinstance(state_file, Path) or not state_file.is_absolute():
        raise ValueError("probe_gate_lock_invalid")
    return state_file.parent / PROBE_GATE_LOCK_NAME


def _open_probe_gate_lock(state_file: Path, *, create: bool) -> int:
    lock_path = _probe_gate_lock_path(state_file)
    try:
        parent = lock_path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ValueError("probe_gate_lock_invalid")
        if create:
            try:
                descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                descriptor = -1
            else:
                os.close(descriptor)
        item = lock_path.lstat()
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISREG(item.st_mode)
            or item.st_nlink != 1
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o600
        ):
            raise ValueError("probe_gate_lock_invalid")
        descriptor = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("probe_gate_lock_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != item.st_dev
            or opened.st_ino != item.st_ino
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("probe_gate_lock_invalid")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


@contextlib.contextmanager
def _probe_gate_lock(state_file: Path, *, exclusive: bool, create: bool) -> object:
    descriptor = _open_probe_gate_lock(state_file, create=create)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    except OSError as exc:
        os.close(descriptor)
        raise ValueError("probe_gate_lock_unavailable") from exc
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def probe_capacity_lock(*, state_file: Path | None = None) -> object:
    """Hold the shared state lock across one capacity-creating sink."""

    if state_file is None:
        state_file = _probe_state_root() / STATE_FILE_NAME
    with _probe_gate_lock(state_file, exclusive=False, create=False):
        yield


@contextlib.contextmanager
def probe_capacity_guard(
    *,
    state_file: Path | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> object:
    """Read a canonical v2 record while holding the shared publication lock."""

    capacity_lock = probe_capacity_lock(state_file=state_file)
    try:
        capacity_lock.__enter__()
    except (OSError, ValueError):
        yield {"allowed": False, "reason_code": "probe_invalid", "raw_output": "not_returned"}
        return
    try:
        yield read_probe_gate(state_file=state_file, now=now)
    finally:
        capacity_lock.__exit__(*sys.exc_info())


def _state_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("unsafe_probe_state_directory")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            try:
                item = current.lstat()
            except FileNotFoundError:
                current.mkdir(mode=0o700)
                item = current.lstat()
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
                raise ValueError("unsafe_probe_state_directory")
            if current == path and (item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700):
                raise ValueError("unsafe_probe_state_directory")
    except (OSError, ValueError) as exc:
        raise ValueError("unsafe_probe_state_directory") from exc
    if path == Path(path.anchor):
        raise ValueError("unsafe_probe_state_directory")
    return path


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise ValueError("probe_state_write_failed")
    try:
        encoded = (json.dumps(dict(payload), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("probe_state_encode_failed") from exc
    if len(encoded) > MAX_PROBE_STATE_BYTES:
        raise ValueError("probe_state_oversize")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = Path()
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.name:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _run_json(command: Path, *arguments: str) -> tuple[dict[str, Any], bool]:
    try:
        completed = run_bounded(
            [os.fspath(command), *arguments],
            cwd=command.parent.parent,
            home=Path.home(),
            timeout_seconds=45,
            stdout_limit=DEFAULT_STDOUT_LIMIT,
            stderr_limit=DEFAULT_STDERR_LIMIT,
        )
        if completed.returncode != 0:
            return {}, False
        value = json.loads(completed.stdout)
        return (value, True) if isinstance(value, dict) else ({}, False)
    except (BoundedProcessError, json.JSONDecodeError, TypeError):
        return {}, False


def run_probe(
    *,
    layout: RuntimeLayout | None = None,
    state_directory: Path | None = None,
    now: Callable[[], datetime] | None = None,
    runner: Callable[..., tuple[dict[str, Any], bool]] | None = None,
) -> dict[str, Any]:
    """Run direct v2 checks and atomically publish exactly one v2 record."""

    try:
        active_layout = RuntimeLayout.from_module_path(Path(__file__)) if layout is None else layout
    except LayoutError as exc:
        raise ValueError("probe_runtime_layout_unavailable") from exc
    if not isinstance(active_layout, RuntimeLayout):
        raise ValueError("probe_runtime_layout_unavailable")
    state_directory = _state_directory(state_directory or _probe_state_root())
    execute = runner or _run_json
    runtime, runtime_command = execute(active_layout.mcp_entrypoint, "hive", "runtime-status")
    hive, hive_command = execute(active_layout.mcp_entrypoint, "hive", "status")
    doctor, doctor_command = execute(active_layout.mcp_entrypoint, "hive", "doctor")
    result = evaluate(runtime, hive, doctor)
    moment = (now or (lambda: datetime.now(UTC)))()
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("probe_clock_invalid")
    result.update(
        {
            "schema_version": 2,
            "checked_at": moment.astimezone(UTC).isoformat(),
            "commands": {
                "runtime_status": runtime_command,
                "hive_status": hive_command,
                "hive_doctor": doctor_command,
            },
        }
    )
    state_file = state_directory / STATE_FILE_NAME
    with _probe_gate_lock(state_file, exclusive=True, create=True):
        _atomic_write(state_file, result)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    if tuple(arguments or ()) != ("--json",):
        return 2
    result = run_probe()
    print(json.dumps({"checks": result["checks"]}, sort_keys=True))
    return 0 if all(result["checks"].values()) else 1


__all__ = [
    "DETERMINISTIC_PROBE_HOURS_UTC",
    "MAX_PROBE_AGE_SECONDS",
    "MAX_PROBE_STATE_BYTES",
    "PROBE_GATE_LOCK_NAME",
    "STATE_FILE_NAME",
    "evaluate",
    "main",
    "probe_capacity_guard",
    "probe_capacity_lock",
    "probe_spawn_gate",
    "read_probe_gate",
    "run_probe",
]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
