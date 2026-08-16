"""Pure, fail-closed consumer for the account-usage-v1 snapshot contract."""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, TypeAlias


_MAX_ACTIVE_BYTES = 128 * 1024
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
_MAX_STDERR_BYTES = 4096
_LIVE_MAX_AGE = timedelta(minutes=15)
_CACHE_MAX_AGE = timedelta(minutes=60)
_MAX_ACCOUNTS = 100
_MAX_LIMITS = 32
_MAX_COST_WINDOWS = 64
_MAX_WINDOW_SECONDS = 2_592_000
_MAX_LOOKBACK_SECONDS = 86_400
_MAX_SAMPLE_COUNT = 10_000
_STAT_ID = tuple[int, int, int]
_ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ASCII_TOKEN_RE = re.compile(r"^[!-~]{1,128}$")
_SCHEMA_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SECRET_NAMES = frozenset(
    {
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "secret",
        "clientsecret",
        "password",
        "passphrase",
        "authorization",
        "cookie",
        "cookies",
        "session",
        "sessionid",
        "csrf",
        "devicecode",
        "auth",
        "authjson",
        "privatekey",
        "credential",
        "credentials",
        "credentialfingerprint",
        "email",
        "emailaddress",
        "responsebody",
        "raw",
        "rawoutput",
        "headers",
        "profile",
        "profilepath",
        "authjsonpath",
        "sourceurls",
        "backenduserid",
        "backendaccountid",
    }
)
_SECRET_SUFFIXES = ("token", "secret", "key", "cookie", "password", "path", "url", "header")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


@dataclass(frozen=True, slots=True)
class LauncherSpec:
    launcher_path: Path

    def __repr__(self) -> str:
        return "LauncherSpec(launcher_path=<redacted>)"


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes

    def __repr__(self) -> str:
        return "ProcessResult(exit_code=<redacted>, stdout=<redacted>, stderr=<redacted>)"


@dataclass(frozen=True, slots=True)
class UsageLimit:
    pool: str
    window_seconds: int
    used_percent: float | None
    remaining_percent: float | None
    reset_at: datetime | None


@dataclass(frozen=True, slots=True)
class UsageCostWindow:
    lookback_seconds: int
    pool: str
    limit_window_seconds: int
    consumed_percentage_points: float
    coverage: str
    sample_count: int


@dataclass(frozen=True, slots=True)
class UsageReset:
    available: int
    known: bool
    redeem_capability: bool


@dataclass(frozen=True, slots=True)
class AccountUsage:
    account_id: str
    status: str
    captured_at: datetime
    stale: bool
    limits: tuple[UsageLimit, ...]
    cost_windows: tuple[UsageCostWindow, ...]
    usage_resets: tuple[UsageReset, ...]


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    accounts: tuple[AccountUsage, ...]
    source: Literal["live", "cache", "unavailable"]
    stale: bool
    warnings: tuple[str, ...]


class UsageSnapshotUnavailable(Exception):
    """Redacted signal for an unusable active pointer or usage document."""

    def __repr__(self) -> str:
        return "UsageSnapshotUnavailable()"


ActiveReleaseReader: TypeAlias = Callable[[], LauncherSpec]
SnapshotRunner: TypeAlias = Callable[[tuple[str, ...], float, int, int], ProcessResult]
CacheReader: TypeAlias = Callable[[int], bytes]


class _Invalid(Exception):
    pass


def _unavailable() -> None:
    raise UsageSnapshotUnavailable() from None


def _directory_identity(path: Path) -> _STAT_ID:
    item = path.lstat()
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.getuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise _Invalid()
    return item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode)


def _file_identity(path: Path) -> _STAT_ID:
    item = path.lstat()
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.getuid()
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_nlink != 1
    ):
        raise _Invalid()
    return item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode)


def _launcher_identity(path: Path) -> _STAT_ID:
    item = path.lstat()
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.getuid()
        or stat.S_IMODE(item.st_mode) != 0o700
        or item.st_nlink != 1
    ):
        raise _Invalid()
    return item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode)


def _reject_symlink_ancestors(path: Path) -> None:
    if not path.is_absolute():
        raise _Invalid()
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if stat.S_ISLNK(current.lstat().st_mode):
            raise _Invalid()


def _capture_active_layout(state_home: Path) -> tuple[tuple[Path, _STAT_ID], ...]:
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise _Invalid()
    integration = state_home / "codex-usage" / "integration"
    active = integration / "active.json"
    directories = (state_home, state_home / "codex-usage", integration)
    _reject_symlink_ancestors(active)
    identities: list[tuple[Path, _STAT_ID]] = [
        (directory, _directory_identity(directory)) for directory in directories
    ]
    active_item = active.lstat()
    if active_item.st_size > _MAX_ACTIVE_BYTES:
        raise _Invalid()
    identities.append((active, _file_identity(active)))
    return tuple(identities)


def _capture_cache_layout(state_home: Path) -> tuple[tuple[Path, _STAT_ID], ...]:
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise _Invalid()
    integration = state_home / "codex-usage" / "integration"
    cache = integration / "account-usage-v1.json"
    directories = (state_home, state_home / "codex-usage", integration)
    _reject_symlink_ancestors(cache)
    identities: list[tuple[Path, _STAT_ID]] = [
        (directory, _directory_identity(directory)) for directory in directories
    ]
    identities.append((cache, _file_identity(cache)))
    return tuple(identities)


def _revalidate_layout(layout: tuple[tuple[Path, _STAT_ID], ...]) -> None:
    for path, identity in layout:
        item = path.lstat()
        if stat.S_ISDIR(item.st_mode):
            if _directory_identity(path) != identity:
                raise _Invalid()
        elif identity[2] == 0o700:
            if _launcher_identity(path) != identity:
                raise _Invalid()
        elif _file_identity(path) != identity:
            raise _Invalid()


def _read_bounded_bytes(
    path: Path, maximum: int, expected_identity: _STAT_ID | None = None
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        item = os.fstat(descriptor)
        identity = (item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode))
        if expected_identity is not None and identity != expected_identity:
            raise _Invalid()
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise _Invalid()
        chunks: list[bytes] = []
        size = 0
        while size <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > maximum:
            raise _Invalid()
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _canonical_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _Invalid()
    path = Path(value)
    if not path.is_absolute() or str(path) != value or any(
        component in {".", ".."} for component in path.parts
    ):
        raise _Invalid()
    return path


def _strict_json(payload: bytes, maximum: int) -> object:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise _Invalid()

    def reject_constant(_value: str) -> None:
        raise _Invalid()

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _Invalid()
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, _Invalid):
        raise _Invalid() from None


def _secret_key(value: str) -> bool:
    normalized = "".join(character for character in value.casefold() if character.isalnum())
    return normalized in _SECRET_NAMES or normalized.endswith(_SECRET_SUFFIXES)


def _scan_secrets(value: object, depth: int = 0) -> None:
    if depth > 64:
        raise _Invalid()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or not _SCHEMA_KEY_RE.fullmatch(key):
                raise _Invalid()
            if _secret_key(key):
                raise _Invalid()
            _scan_secrets(nested, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _scan_secrets(nested, depth + 1)
        return
    if isinstance(value, str):
        if value.startswith("Bearer ") or _JWT_RE.fullmatch(value) or _PEM_RE.search(value):
            raise _Invalid()
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise _Invalid()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or "T" not in value:
        raise _Invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = parsed.utcoffset()
    except (TypeError, ValueError, OverflowError):
        raise _Invalid() from None
    if parsed.tzinfo is None or offset is None or offset != timedelta(0):
        raise _Invalid()
    try:
        return parsed.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        raise _Invalid() from None


def _token(value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) < 1
        or len(value) > maximum
        or not value.isascii()
        or not _ASCII_TOKEN_RE.fullmatch(value)
    ):
        raise _Invalid()
    return value


def _integer(value: object, maximum: int, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _Invalid()
    return value


def _percent(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Invalid()
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 100:
        raise _Invalid()
    return result


def _canonical_limit(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or "pool" not in value or "window_seconds" not in value:
        raise _Invalid()
    result: dict[str, object] = {
        "pool": _token(value["pool"], 64),
        "window_seconds": _integer(value["window_seconds"], _MAX_WINDOW_SECONDS),
    }
    for name in ("used_percent", "remaining_percent"):
        if name in value:
            result[name] = _percent(value[name])
    if "reset_at" in value:
        result["reset_at"] = _timestamp(value["reset_at"])
    return result


def _canonical_cost_window(value: object) -> dict[str, object]:
    required = (
        "lookback_seconds",
        "pool",
        "limit_window_seconds",
        "consumed_percentage_points",
        "coverage",
        "sample_count",
    )
    if not isinstance(value, Mapping) or any(name not in value for name in required):
        raise _Invalid()
    coverage = value["coverage"]
    if coverage not in {"complete", "partial", "unknown"}:
        raise _Invalid()
    return {
        "lookback_seconds": _integer(value["lookback_seconds"], _MAX_LOOKBACK_SECONDS),
        "pool": _token(value["pool"], 64),
        "limit_window_seconds": _integer(value["limit_window_seconds"], _MAX_WINDOW_SECONDS),
        "consumed_percentage_points": _percent(value["consumed_percentage_points"]),
        "coverage": coverage,
        "sample_count": _integer(value["sample_count"], _MAX_SAMPLE_COUNT, allow_zero=True),
    }


def _canonical_document(value: object) -> dict[str, object]:
    _scan_secrets(value)
    if not isinstance(value, Mapping):
        raise _Invalid()
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise _Invalid()
    generated_at = _timestamp(value.get("generated_at"))
    accounts_value = value.get("accounts")
    if not isinstance(accounts_value, list) or len(accounts_value) > _MAX_ACCOUNTS:
        raise _Invalid()
    accounts: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw_account in accounts_value:
        if not isinstance(raw_account, Mapping):
            raise _Invalid()
        if not all(name in raw_account for name in ("account_id", "status", "freshness")):
            raise _Invalid()
        account_id = _token(raw_account["account_id"], 64)
        if not _ACCOUNT_ID_RE.fullmatch(account_id) or account_id in seen:
            raise _Invalid()
        status = raw_account["status"]
        if not isinstance(status, str) or status not in {
            "ok",
            "partial",
            "error",
            "login_required",
            "unknown",
        }:
            raise _Invalid()
        freshness = raw_account["freshness"]
        if not isinstance(freshness, Mapping):
            raise _Invalid()
        captured_at = _timestamp(freshness.get("captured_at"))
        stale = freshness.get("stale")
        if not isinstance(stale, bool):
            raise _Invalid()
        raw_limits = raw_account.get("limits", [])
        if not isinstance(raw_limits, list) or len(raw_limits) > _MAX_LIMITS:
            raise _Invalid()
        limits = [_canonical_limit(item) for item in raw_limits]
        identities = {
            (item["pool"], item["window_seconds"], item.get("reset_at")) for item in limits
        }
        if len(identities) != len(limits):
            raise _Invalid()
        limits.sort(
            key=lambda item: (
                item["pool"],
                item["window_seconds"],
                item.get("reset_at") is not None,
                item.get("reset_at") or datetime.min.replace(tzinfo=UTC),
            )
        )
        raw_cost_windows = raw_account.get("cost_windows", [])
        if not isinstance(raw_cost_windows, list) or len(raw_cost_windows) > _MAX_COST_WINDOWS:
            raise _Invalid()
        cost_windows = [_canonical_cost_window(item) for item in raw_cost_windows]
        cost_windows.sort(
            key=lambda item: (item["pool"], item["lookback_seconds"], item["limit_window_seconds"])
        )
        raw_resets = raw_account.get("usage_resets")
        resets: dict[str, object] | None = None
        if "usage_resets" in raw_account:
            if not isinstance(raw_resets, Mapping) or not all(
                name in raw_resets for name in ("available", "known", "redeem_capability")
            ):
                raise _Invalid()
            available = _integer(raw_resets["available"], 10_000, allow_zero=True)
            known = raw_resets["known"]
            redeem_capability = raw_resets["redeem_capability"]
            if not isinstance(known, bool) or not isinstance(redeem_capability, bool):
                raise _Invalid()
            resets = {
                "available": available,
                "known": known,
                "redeem_capability": redeem_capability,
            }
        accounts.append(
            {
                "account_id": account_id,
                "status": status,
                "captured_at": captured_at,
                "stale": stale,
                "limits": tuple(limits),
                "cost_windows": tuple(cost_windows),
                "usage_resets": resets,
            }
        )
        seen.add(account_id)
    if "source_commit" in value:
        _token(value["source_commit"], 128)
    accounts.sort(key=lambda account: account["account_id"])
    return {"generated_at": generated_at, "accounts": tuple(accounts)}


def _build_snapshot(
    document: dict[str, object], *, source: Literal["live", "cache"], stale: bool, known: frozenset[str]
) -> UsageSnapshot:
    accounts: list[AccountUsage] = []
    for raw in document["accounts"]:
        if raw["account_id"] not in known:
            continue
        if source == "live" and raw["stale"]:
            continue
        limits = tuple(
            UsageLimit(
                pool=item["pool"],
                window_seconds=item["window_seconds"],
                used_percent=item.get("used_percent"),
                remaining_percent=item.get("remaining_percent"),
                reset_at=item.get("reset_at"),
            )
            for item in raw["limits"]
        )
        cost_windows = tuple(UsageCostWindow(**item) for item in raw["cost_windows"])
        raw_reset = raw["usage_resets"]
        resets = () if raw_reset is None else (UsageReset(**raw_reset),)
        accounts.append(
            AccountUsage(
                account_id=raw["account_id"],
                status=raw["status"],
                captured_at=raw["captured_at"],
                stale=True if source == "cache" else raw["stale"],
                limits=limits,
                cost_windows=cost_windows,
                usage_resets=resets,
            )
        )
    return UsageSnapshot(tuple(accounts), source, stale, ())


def _clock_utc(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime):
        raise _Invalid()
    try:
        offset = value.utcoffset()
    except Exception:
        raise _Invalid() from None
    if value.tzinfo is None or offset is None:
        raise _Invalid()
    try:
        return value.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        raise _Invalid() from None


def _validate_live_result(result: object) -> bytes:
    if not isinstance(result, ProcessResult):
        raise _Invalid()
    if type(result.exit_code) is not int or result.exit_code != 0:
        raise _Invalid()
    if not isinstance(result.stdout, bytes) or len(result.stdout) > _MAX_SNAPSHOT_BYTES:
        raise _Invalid()
    if not isinstance(result.stderr, bytes) or len(result.stderr) > _MAX_STDERR_BYTES:
        raise _Invalid()
    if result.stderr:
        raise _Invalid()
    return result.stdout


def _valid_age(now: datetime, generated_at: datetime, maximum: timedelta) -> bool:
    age = now - generated_at
    return timedelta(0) <= age <= maximum


def _terminate_process_group(process: object) -> None:
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int):
        raise _Invalid()
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        killer = getattr(process, "kill", None)
        if not callable(killer):
            raise _Invalid()
        killer()


def _bounded_process_exchange(
    process: object, *, timeout: float, stdout_limit: int, stderr_limit: int
) -> tuple[bytes, bytes]:
    stdout = getattr(process, "stdout", None)
    stderr = getattr(process, "stderr", None)
    if stdout is None or stderr is None:
        raise _Invalid()
    streams = {stdout: stdout_limit, stderr: stderr_limit}
    buffers: dict[object, bytearray] = {stdout: bytearray(), stderr: bytearray()}
    selector = selectors.DefaultSelector()
    terminated = False

    def register_stream(stream: object) -> None:
        fileno = getattr(stream, "fileno", None)
        if not callable(fileno):
            raise _Invalid()
        descriptor = fileno()
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ)

    def drain_streams(deadline: float) -> None:
        while selector.get_map() and time.monotonic() < deadline:
            events = selector.select(max(0.0, deadline - time.monotonic()))
            if not events:
                break
            for key, _ in events:
                stream = key.fileobj
                data = os.read(stream.fileno(), 64 * 1024)
                if not data:
                    selector.unregister(stream)

    def stop_process() -> None:
        nonlocal terminated
        if terminated:
            return
        terminated = True
        try:
            _terminate_process_group(process)
        except Exception:
            pass
        try:
            drain_streams(time.monotonic() + 1.0)
        except Exception:
            pass

    try:
        register_stream(stdout)
        register_stream(stderr)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_process()
                raise TimeoutError()
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                read_size = min(64 * 1024, streams[stream] + 1 - len(buffers[stream]))
                data = os.read(stream.fileno(), read_size)
                if not data:
                    selector.unregister(stream)
                    continue
                buffer = buffers[stream]
                buffer.extend(data)
                if len(buffer) > streams[stream]:
                    stop_process()
                    raise _Invalid()
        waiter = getattr(process, "wait", None)
        if not callable(waiter):
            raise _Invalid()
        waiter(timeout=max(0.0, deadline - time.monotonic()))
        return bytes(buffers[stdout]), bytes(buffers[stderr])
    except Exception:
        stop_process()
        raise
    finally:
        if terminated:
            waiter = getattr(process, "wait", None)
            if callable(waiter):
                try:
                    waiter(timeout=1.0)
                except Exception:
                    pass
        selector.close()
        for stream in (stdout, stderr):
            try:
                stream.close()
            except Exception:
                pass


def _default_runner(
    argv: tuple[str, ...], timeout: float, stdout_limit: int, stderr_limit: int
) -> ProcessResult:
    process = subprocess.Popen(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        env={"LANG": "C.UTF-8", "TZ": "UTC"},
    )
    stdout, stderr = _bounded_process_exchange(
        process,
        timeout=timeout,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )
    return ProcessResult(process.returncode, stdout, stderr)


default_runner = _default_runner


def read_active_launcher_v1(*, state_home: Path) -> LauncherSpec:
    try:
        layout = _capture_active_layout(state_home)
        active = state_home / "codex-usage" / "integration" / "active.json"
        payload = _read_bounded_bytes(active, _MAX_ACTIVE_BYTES, layout[-1][1])
        _revalidate_layout(layout)
        manifest = _strict_json(payload, _MAX_ACTIVE_BYTES)
        if not isinstance(manifest, Mapping) or type(manifest.get("schema_version")) is not int:
            raise _Invalid()
        if manifest["schema_version"] != 1:
            raise _Invalid()
        release_dir = _canonical_path(manifest.get("release_dir"))
        launcher_path = _canonical_path(manifest.get("launcher_path"))
        integration = state_home / "codex-usage" / "integration"
        releases = integration / "releases"
        if release_dir.parent != releases:
            raise _Invalid()
        expected_launcher = release_dir / "venv" / "bin" / "codex-usage"
        if launcher_path != expected_launcher:
            raise _Invalid()
        _reject_symlink_ancestors(expected_launcher)
        target_layout = tuple(
            (directory, _directory_identity(directory))
            for directory in (
                releases,
                release_dir,
                release_dir / "venv",
                release_dir / "venv" / "bin",
            )
        ) + ((expected_launcher, _launcher_identity(expected_launcher)),)
        _revalidate_layout(layout + target_layout)
        return LauncherSpec(expected_launcher)
    except UsageSnapshotUnavailable:
        raise
    except Exception:
        raise UsageSnapshotUnavailable() from None


def read_account_usage_cache_v1(maximum: int, *, state_home: Path) -> bytes:
    try:
        if type(maximum) is not int or not 0 < maximum <= _MAX_SNAPSHOT_BYTES:
            raise _Invalid()
        layout = _capture_cache_layout(state_home)
        cache = state_home / "codex-usage" / "integration" / "account-usage-v1.json"
        payload = _read_bounded_bytes(cache, maximum, layout[-1][1])
        _revalidate_layout(layout)
        return payload
    except Exception:
        raise UsageSnapshotUnavailable() from None


def _live_document(
    active_release_reader: ActiveReleaseReader,
    runner: SnapshotRunner,
) -> dict[str, object] | None:
    try:
        spec = active_release_reader()
        if not isinstance(spec, LauncherSpec) or not isinstance(spec.launcher_path, Path):
            raise _Invalid()
        launcher_path = str(spec.launcher_path)
        if not spec.launcher_path.is_absolute() or "\x00" in launcher_path:
            raise _Invalid()
        argv = (launcher_path, "integration-snapshot", "--schema", "1", "--format", "json")
        payload = _validate_live_result(runner(argv, 5.0, _MAX_SNAPSHOT_BYTES, _MAX_STDERR_BYTES))
        return _canonical_document(_strict_json(payload, _MAX_SNAPSHOT_BYTES))
    except Exception:
        return None


def _cache_document(cache_reader: CacheReader) -> dict[str, object] | None:
    try:
        payload = cache_reader(_MAX_SNAPSHOT_BYTES)
        return _canonical_document(_strict_json(payload, _MAX_SNAPSHOT_BYTES))
    except Exception:
        return None


def load_account_usage_v1(
    *,
    active_release_reader: ActiveReleaseReader,
    runner: SnapshotRunner,
    cache_reader: CacheReader,
    known_account_ids: frozenset[str],
    clock: Callable[[], datetime],
) -> UsageSnapshot:
    try:
        if not isinstance(known_account_ids, frozenset) or any(
            not isinstance(account_id, str) for account_id in known_account_ids
        ):
            raise _Invalid()
        live = _live_document(active_release_reader, runner)
        if live is not None:
            now = _clock_utc(clock)
            if _valid_age(now, live["generated_at"], _LIVE_MAX_AGE):
                return _build_snapshot(live, source="live", stale=False, known=known_account_ids)
            cache = _cache_document(cache_reader)
            if cache is not None and _valid_age(now, cache["generated_at"], _CACHE_MAX_AGE):
                return _build_snapshot(cache, source="cache", stale=True, known=known_account_ids)
            return UsageSnapshot((), "unavailable", True, ("usage_unavailable",))
        cache = _cache_document(cache_reader)
        if cache is None:
            raise _Invalid()
        now = _clock_utc(clock)
        if not _valid_age(now, cache["generated_at"], _CACHE_MAX_AGE):
            raise _Invalid()
        return _build_snapshot(cache, source="cache", stale=True, known=known_account_ids)
    except Exception:
        return UsageSnapshot((), "unavailable", True, ("usage_unavailable",))


__all__ = [
    "AccountUsage",
    "ActiveReleaseReader",
    "CacheReader",
    "LauncherSpec",
    "ProcessResult",
    "SnapshotRunner",
    "UsageCostWindow",
    "UsageLimit",
    "UsageReset",
    "UsageSnapshot",
    "UsageSnapshotUnavailable",
    "default_runner",
    "load_account_usage_v1",
    "read_account_usage_cache_v1",
    "read_active_launcher_v1",
]
