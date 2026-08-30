"""Deterministic, data-sparse Hive hourly self-test contract."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any


DETERMINISTIC_PROBE_HOURS_UTC = (0, 3, 6, 9, 12, 15, 18, 21)
STATE_FILE_NAME = "hive-hourly-health.json"
ALARM_FILE_NAME = "hive-hourly-alarm.json"
FUNCTIONAL_MARKER_NAME = "hive-functional"
MAX_PROBE_STATE_BYTES = 64 * 1024
MAX_PROBE_AGE_SECONDS = 4 * 60 * 60
_BLOCKED_STATES = frozenset({"", "disabled", "fail_closed", "invalid", "missing", "not_configured", "unknown", "unavailable"})
_ALARM_ROUTE = ("queen-codex-master", "active_queen", "native_recovery_queen")
_PROBE_RECORD_KEYS = frozenset({"alarm", "checked_at", "checks", "commands", "functional"})
_PROBE_CHECK_KEYS = frozenset({"namespace", "plugin", "hive_doctor", "hive_runtime"})
_PROBE_COMMAND_KEYS = frozenset({"namespace", "plugin", "hive_status", "hive_doctor"})


def _ready_state(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _BLOCKED_STATES


def _safe_reason(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 96:
        return None
    if not all(character.islower() or character.isdigit() or character in "_-" for character in value):
        return None
    return value


def build_hive_probe_alarm(reason_codes: tuple[str, ...] | list[str]) -> dict[str, object]:
    """Build the bounded Hive-wide alarm envelope for a failed self-test."""

    if not isinstance(reason_codes, (tuple, list)):
        raise ValueError("invalid_probe_alarm_reasons")
    reasons = tuple(_safe_reason(value) for value in reason_codes)
    if not reasons or any(value is None for value in reasons):
        raise ValueError("invalid_probe_alarm_reasons")
    unique = tuple(dict.fromkeys(value for value in reasons if value is not None))
    if len(unique) > 8:
        raise ValueError("invalid_probe_alarm_reasons")
    return {
        "schema_version": 1,
        "scope": "hive",
        "event": "hourly_probe_failed",
        "reason_codes": list(unique),
        "route": list(_ALARM_ROUTE),
        "token_telemetry": "unknown",
        "raw_output": "not_returned",
    }


def evaluate(
    namespace: Mapping[str, Any],
    plugin: Mapping[str, Any],
    hive: Mapping[str, Any],
    doctor: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate public probe inputs without copying arbitrary input values."""

    if not all(isinstance(value, Mapping) for value in (namespace, plugin, hive, doctor)):
        namespace = namespace if isinstance(namespace, Mapping) else {}
        plugin = plugin if isinstance(plugin, Mapping) else {}
        hive = hive if isinstance(hive, Mapping) else {}
        doctor = doctor if isinstance(doctor, Mapping) else {}
    doctor_checks = doctor.get("checks")
    doctor_ready = isinstance(doctor_checks, Mapping) and all(
        _ready_state(doctor_checks.get(key)) for key in ("authority", "repository", "state")
    )
    hive_runtime = hive.get("mode") == "enforced" and _ready_state(hive.get("authority"))
    for key in ("repository", "principal", "state", "pilot"):
        if key in hive and not _ready_state(hive.get(key)):
            hive_runtime = False
    checks = {
        "namespace": namespace.get("ok") is True and namespace.get("namespace_ready") is True,
        "plugin": plugin.get("ok") is True,
        "hive_runtime": hive_runtime,
        "hive_doctor": doctor.get("healthy") is True and doctor_ready,
    }
    functional = all(checks.values())
    result: dict[str, Any] = {"functional": functional, "checks": checks}
    if not functional:
        failed = tuple(f"{name}_unavailable" for name, value in checks.items() if not value)
        result["alarm"] = build_hive_probe_alarm(failed)
    else:
        result["alarm"] = None
    return result


def probe_spawn_gate(
    payload: Mapping[str, Any],
    *,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Accept only one fresh, unambiguous green result for Hive spawning."""

    if not isinstance(payload, Mapping) or frozenset(payload) != _PROBE_RECORD_KEYS:
        return {"allowed": False, "reason_code": "probe_ambiguous", "raw_output": "not_returned"}
    checks = payload.get("checks")
    commands = payload.get("commands")
    if (
        not isinstance(checks, Mapping)
        or frozenset(checks) != _PROBE_CHECK_KEYS
        or any(value is not True for value in checks.values())
        or not isinstance(commands, Mapping)
        or frozenset(commands) != _PROBE_COMMAND_KEYS
        or any(value is not True for value in commands.values())
        or payload.get("functional") is not True
        or payload.get("alarm") is not None
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
    configured = os.environ.get("CODEX_MASTER_MCP_STATE") or os.environ.get("CODEX_AGENT_MCP_STATE")
    return Path(configured or "~/.local/state/codex-master-mcp").expanduser()


def read_probe_gate(
    *,
    state_file: Path | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Read the private probe record without creating or changing any state."""

    if state_file is None:
        state_file = _probe_state_root() / STATE_FILE_NAME
    try:
        payload = _read_private_probe_state(state_file)
    except FileNotFoundError:
        return {"allowed": False, "reason_code": "probe_missing", "raw_output": "not_returned"}
    except (OSError, ValueError):
        return {"allowed": False, "reason_code": "probe_invalid", "raw_output": "not_returned"}
    return probe_spawn_gate(payload, now=now)


def _repository_from_source() -> Path:
    configured = os.environ.get("CODEX_MASTER_PROBE_REPOSITORY")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute():
            return candidate
    return Path(__file__).resolve().parents[3]


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


def _atomic_write(path: Path, payload: Mapping[str, object] | str) -> None:
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
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    else:
        try:
            encoded = (json.dumps(dict(payload), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("probe_state_encode_failed") from exc
    if len(encoded) > 64 * 1024:
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


def _remove_probe_file(path: Path) -> None:
    try:
        item = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
        raise ValueError("probe_state_write_failed")
    try:
        path.unlink()
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc


def _run_json(command: Path, *arguments: str) -> tuple[dict[str, Any], bool]:
    try:
        completed = subprocess.run(
            [os.fspath(command), *arguments],
            cwd=command.parent.parent,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        if completed.returncode != 0:
            return {}, False
        value = json.loads(completed.stdout)
        return (value, True) if isinstance(value, dict) else ({}, False)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError):
        return {}, False


def run_probe(
    *,
    repository: Path | None = None,
    command: Path | None = None,
    state_directory: Path | None = None,
    now: Callable[[], datetime] | None = None,
    runner: Callable[..., tuple[dict[str, Any], bool]] | None = None,
) -> dict[str, Any]:
    """Run the probe and persist only bounded health/alarm metadata."""

    repository = repository or _repository_from_source()
    command = command or repository / "bin" / "codex-master-mcp"
    state_directory = state_directory or _probe_state_root()
    if not isinstance(repository, Path) or not repository.is_absolute() or not isinstance(command, Path) or not command.is_absolute():
        raise ValueError("probe_repository_unavailable")
    state_directory = _state_directory(state_directory)
    execute = runner or _run_json
    namespace, namespace_command = execute(command, "namespace-status")
    plugin, plugin_command = execute(command, "plugin-status")
    hive, hive_command = execute(command, "hive", "status")
    doctor, doctor_command = execute(command, "hive", "doctor")
    result = evaluate(namespace, plugin, hive, doctor)
    moment = (now or (lambda: datetime.now(UTC)))()
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("probe_clock_invalid")
    checked_at = moment.astimezone(UTC).isoformat()
    result.update(
        {
            "checked_at": checked_at,
            "commands": {
                "namespace": namespace_command,
                "plugin": plugin_command,
                "hive_status": hive_command,
                "hive_doctor": doctor_command,
            },
        }
    )
    _atomic_write(state_directory / STATE_FILE_NAME, result)
    alarm = result.get("alarm")
    if isinstance(alarm, Mapping):
        _atomic_write(state_directory / ALARM_FILE_NAME, alarm)
        _remove_probe_file(state_directory / FUNCTIONAL_MARKER_NAME)
    else:
        _remove_probe_file(state_directory / ALARM_FILE_NAME)
        _remove_probe_file(state_directory / FUNCTIONAL_MARKER_NAME)
        _atomic_write(state_directory / FUNCTIONAL_MARKER_NAME, checked_at + "\n")
    return result


def main() -> int:
    result = run_probe()
    print(json.dumps({"functional": result["functional"], "checks": result["checks"], "alarm": result["alarm"]}, sort_keys=True))
    return 0 if result["functional"] else 1


__all__ = [
    "ALARM_FILE_NAME",
    "DETERMINISTIC_PROBE_HOURS_UTC",
    "FUNCTIONAL_MARKER_NAME",
    "MAX_PROBE_AGE_SECONDS",
    "MAX_PROBE_STATE_BYTES",
    "STATE_FILE_NAME",
    "build_hive_probe_alarm",
    "evaluate",
    "main",
    "probe_spawn_gate",
    "read_probe_gate",
    "run_probe",
]
