"""Read-only, fail-closed consumer for attested account-usage schema 2."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import pwd
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal


_MAX_POINTER_BYTES = 4096
_MAX_BINDING_BYTES = 32768
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_LOCK_BYTES = 4096
_MAX_ACCOUNTS = 100
_MAX_LIMITS = 32
_MAX_TRENDS = 32
_MAX_TOTAL_TRENDS = 3200
_WINDOWS = frozenset({18000, 604800, 2592000})
_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_POOL_RE = re.compile(r"^(?:main|spark)$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


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


ReaderStatus = Literal["complete", "stale", "partial", "busy", "unavailable", "invalid"]


@dataclass(frozen=True, slots=True)
class UsageLimitV2:
    pool: Literal["main", "spark"]
    window_seconds: int
    reset_generation: str
    used_percent: float
    remaining_percent: float
    reset_at: datetime


@dataclass(frozen=True, slots=True)
class UsageTrendV2:
    pool: Literal["main", "spark"]
    window_seconds: int
    reset_generation: str
    coverage: Literal["complete", "partial", "insufficient"]
    last_sample_at: datetime
    projected_exhaustion_at: datetime


@dataclass(frozen=True, slots=True)
class TrackerEvidenceV2:
    pool: Literal["main", "spark"]
    window_seconds: int
    reset_generation: str
    coverage: Literal["complete", "partial", "insufficient"]
    last_sample_at: datetime


@dataclass(frozen=True, slots=True)
class AccountUsageEvidenceV2:
    account_id: str
    limits: tuple[UsageLimitV2, ...]
    trends: tuple[UsageTrendV2, ...]
    tracker_evidence: tuple[TrackerEvidenceV2, ...]


@dataclass(frozen=True, slots=True)
class UsageEvidenceV2:
    accounts: tuple[AccountUsageEvidenceV2, ...]
    status: ReaderStatus
    captured_at: datetime | None
    generated_at: datetime | None


@dataclass(frozen=True, slots=True)
class _ActiveManifest:
    digest: str
    producer_version: str
    release_id: str
    source_manifest_sha256: str


class _Invalid(Exception):
    pass


class _Unavailable(Exception):
    pass


class _Busy(Exception):
    pass


_Metadata = tuple[int, int, int, int, int, int, int, int]


def _metadata(item: os.stat_result) -> _Metadata:
    return (
        item.st_dev,
        item.st_ino,
        stat.S_IMODE(item.st_mode),
        item.st_uid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _same(item: os.stat_result, expected: _Metadata) -> bool:
    return _metadata(item) == expected


def _check_directory(item: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise _Invalid()


def _check_regular(item: os.stat_result, *, minimum: int, maximum: int) -> None:
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_nlink != 1
        or not minimum <= item.st_size <= maximum
    ):
        raise _Invalid()


class _FdGuard:
    def __init__(self) -> None:
        self._directories: list[tuple[int, int | None, str | None, _Metadata]] = []
        self._files: list[tuple[int, str, _Metadata]] = []
        self._close: list[int] = []

    def _open_directory(
        self, parent_fd: int, name: str, *, controlled: bool = True
    ) -> int:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if controlled:
                _check_directory(before)
            elif not stat.S_ISDIR(before.st_mode):
                raise _Invalid()
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError as exc:
            raise _Unavailable() from exc
        except OSError as exc:
            raise _Invalid() from exc
        try:
            opened = os.fstat(descriptor)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if controlled:
                _check_directory(opened)
            elif not stat.S_ISDIR(opened.st_mode):
                raise _Invalid()
            if not _same(before, _metadata(opened)) or not _same(
                after, _metadata(opened)
            ):
                raise _Invalid()
        except Exception:
            os.close(descriptor)
            raise
        self._directories.append((descriptor, parent_fd, name, _metadata(opened)))
        self._close.append(descriptor)
        return descriptor

    def absolute_directory(self, path: Path) -> int:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts[1:])
        ):
            raise _Invalid()
        try:
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as exc:
            raise _Unavailable() from exc
        self._directories.append(
            (descriptor, None, None, _metadata(os.fstat(descriptor)))
        )
        self._close.append(descriptor)
        components = path.parts[1:]
        for index, component in enumerate(components):
            descriptor = self._open_directory(
                descriptor,
                component,
                controlled=index == len(components) - 1,
            )
        return descriptor

    def directory(self, parent_fd: int, name: str) -> int:
        if name in {"", ".", ".."} or "/" in name:
            raise _Invalid()
        return self._open_directory(parent_fd, name)

    def _open_regular(
        self, parent_fd: int, name: str, *, minimum: int, maximum: int
    ) -> int:
        if name in {"", ".", ".."} or "/" in name:
            raise _Invalid()
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _check_regular(before, minimum=minimum, maximum=maximum)
            descriptor = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
            )
        except FileNotFoundError as exc:
            raise _Unavailable() from exc
        except OSError as exc:
            raise _Invalid() from exc
        try:
            opened = os.fstat(descriptor)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _check_regular(opened, minimum=minimum, maximum=maximum)
            if not _same(before, _metadata(opened)) or not _same(
                after, _metadata(opened)
            ):
                raise _Invalid()
        except Exception:
            os.close(descriptor)
            raise
        self._files.append((parent_fd, name, _metadata(opened)))
        self._close.append(descriptor)
        return descriptor

    def lock(self, parent_fd: int, name: str) -> int:
        return self._open_regular(parent_fd, name, minimum=0, maximum=_MAX_LOCK_BYTES)

    def read_file(self, parent_fd: int, name: str, maximum: int) -> bytes:
        descriptor = self._open_regular(parent_fd, name, minimum=1, maximum=maximum)
        chunks: list[bytes] = []
        total = 0
        try:
            while total <= maximum:
                block = os.read(descriptor, min(65536, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            if not 1 <= total <= maximum:
                raise _Invalid()
            expected = next(
                metadata
                for _parent, file_name, metadata in self._files
                if file_name == name
            )
            if not _same(os.fstat(descriptor), expected) or not _same(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False), expected
            ):
                raise _Invalid()
            return b"".join(chunks)
        finally:
            os.close(descriptor)
            self._close.remove(descriptor)

    def revalidate(self) -> None:
        for descriptor, parent_fd, name, expected in self._directories:
            if not _same(os.fstat(descriptor), expected):
                raise _Invalid()
            if (
                parent_fd is not None
                and name is not None
                and not _same(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False), expected
                )
            ):
                raise _Invalid()
        for parent_fd, name, expected in self._files:
            if not _same(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False), expected
            ):
                raise _Invalid()

    def close(self) -> None:
        while self._close:
            os.close(self._close.pop())


def _canonical_json(payload: bytes, maximum: int) -> dict[str, object]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= maximum:
        raise _Invalid()

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if not isinstance(key, str) or key in result:
                raise _Invalid()
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(_Invalid()),
        )
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
        _Invalid,
    ):
        raise _Invalid() from None
    if not isinstance(value, dict) or payload != canonical:
        raise _Invalid()
    return value


def _exact(value: Mapping[str, object], names: set[str]) -> None:
    if set(value) != names:
        raise _Invalid()


def _hex(value: object) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise _Invalid()
    return value


def _token(value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _TOKEN_RE.fullmatch(value) is None
    ):
        raise _Invalid()
    return value


def _timestamp(value: object) -> datetime:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or not value.endswith("Z")
    ):
        raise _Invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError, OverflowError):
        raise _Invalid() from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise _Invalid()
    return parsed.astimezone(UTC)


def _clock(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception as exc:
        raise _Invalid() from exc
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise _Invalid()
    return value.astimezone(UTC)


def _percent(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Invalid()
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 100:
        raise _Invalid()
    return result


def _active_manifest(payload: bytes) -> _ActiveManifest:
    value = _canonical_json(payload, _MAX_BINDING_BYTES)
    _exact(
        value,
        {
            "active_manifest_schema_version",
            "entry_point",
            "launcher_sha256",
            "producer_version",
            "record_sha256",
            "release_id",
            "release_tree_sha256",
            "source_manifest_sha256",
            "wheel_sha256",
        },
    )
    if (
        value["active_manifest_schema_version"] != 2
        or _token(value["producer_version"], 64) != "0.6.536"
    ):
        raise _Invalid()
    if value["entry_point"] != "codex_usage.cli:main":
        raise _Invalid()
    for name in (
        "launcher_sha256",
        "record_sha256",
        "release_tree_sha256",
        "source_manifest_sha256",
        "wheel_sha256",
    ):
        _hex(value[name])
    return _ActiveManifest(
        digest=hashlib.sha256(payload).hexdigest(),
        producer_version="0.6.536",
        release_id=_token(value["release_id"], 64),
        source_manifest_sha256=_hex(value["source_manifest_sha256"]),
    )


def _pointer(value: dict[str, object]) -> tuple[str, str]:
    _exact(
        value,
        {
            "pointer_schema_version",
            "current_generation_id",
            "current_binding_sha256",
            "previous_generation_id",
            "previous_binding_sha256",
        },
    )
    if value["pointer_schema_version"] != 2:
        raise _Invalid()
    generation = value["current_generation_id"]
    if not isinstance(generation, str) or _GENERATION_RE.fullmatch(generation) is None:
        raise _Invalid()
    current_digest = _hex(value["current_binding_sha256"])
    previous_generation = value["previous_generation_id"]
    previous_digest = value["previous_binding_sha256"]
    if (previous_generation is None) != (previous_digest is None):
        raise _Invalid()
    if previous_generation is not None:
        if (
            not isinstance(previous_generation, str)
            or _GENERATION_RE.fullmatch(previous_generation) is None
            or previous_generation == generation
            or _hex(previous_digest) == current_digest
        ):
            raise _Invalid()
    return generation, current_digest


def _binding(
    value: dict[str, object],
    active: _ActiveManifest,
    generation: str,
    pointer_digest: str,
    payload: bytes,
    now: datetime,
) -> None:
    _exact(
        value,
        {
            "active_manifest_sha256",
            "binding_schema_version",
            "generation_id",
            "payload_filename",
            "payload_sha256",
            "payload_size_bytes",
            "published_at",
            "producer_version",
            "release_id",
            "source_manifest_sha256",
        },
    )
    if (
        value["binding_schema_version"] != 2
        or value["generation_id"] != generation
        or value["payload_filename"] != "account-usage-v2.json"
        or value["active_manifest_sha256"] != active.digest
        or value["producer_version"] != active.producer_version
        or value["release_id"] != active.release_id
        or value["source_manifest_sha256"] != active.source_manifest_sha256
        or value["payload_sha256"] != hashlib.sha256(payload).hexdigest()
        or value["payload_size_bytes"] != len(payload)
    ):
        raise _Invalid()
    if (
        hashlib.sha256(
            json.dumps(
                value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        ).hexdigest()
        != pointer_digest
    ):
        raise _Invalid()
    if _timestamp(value["published_at"]) > now:
        raise _Invalid()


def _coverage(value: object) -> Literal["complete", "partial", "insufficient"]:
    if value not in {"complete", "partial", "insufficient"}:
        raise _Invalid()
    return value


def _pool(value: object) -> Literal["main", "spark"]:
    if not isinstance(value, str) or _POOL_RE.fullmatch(value) is None:
        raise _Invalid()
    return value


def _window(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in _WINDOWS:
        raise _Invalid()
    return value


def _reset_generation(value: object) -> str:
    return _token(value, 128)


def _payload(
    value: dict[str, object], now: datetime
) -> tuple[tuple[AccountUsageEvidenceV2, ...], ReaderStatus, datetime, datetime]:
    _exact(
        value,
        {
            "accounts",
            "captured_at",
            "fresh_until",
            "generated_at",
            "schema_version",
            "status",
        },
    )
    if value["schema_version"] != 2 or value["status"] not in {"complete", "partial"}:
        raise _Invalid()
    captured_at = _timestamp(value["captured_at"])
    generated_at = _timestamp(value["generated_at"])
    fresh_until = _timestamp(value["fresh_until"])
    if (
        captured_at > generated_at
        or fresh_until != captured_at + timedelta(seconds=900)
        or generated_at > now
    ):
        raise _Invalid()
    raw_accounts = value["accounts"]
    if not isinstance(raw_accounts, list) or len(raw_accounts) > _MAX_ACCOUNTS:
        raise _Invalid()
    accounts: list[AccountUsageEvidenceV2] = []
    account_ids: set[str] = set()
    total_trends = 0
    stale = now > fresh_until
    for raw_account in raw_accounts:
        if not isinstance(raw_account, dict):
            raise _Invalid()
        _exact(raw_account, {"account_id", "limits", "tracker_evidence", "trends"})
        account_id = raw_account["account_id"]
        if (
            not isinstance(account_id, str)
            or _ACCOUNT_RE.fullmatch(account_id) is None
            or account_id in account_ids
        ):
            raise _Invalid()
        account_ids.add(account_id)
        raw_limits = raw_account["limits"]
        raw_trends = raw_account["trends"]
        raw_evidence = raw_account["tracker_evidence"]
        if (
            not isinstance(raw_limits, list)
            or not isinstance(raw_trends, list)
            or not isinstance(raw_evidence, list)
            or len(raw_limits) > _MAX_LIMITS
            or len(raw_trends) > _MAX_TRENDS
            or len(raw_evidence) > _MAX_TRENDS
        ):
            raise _Invalid()
        limits: list[UsageLimitV2] = []
        limit_keys: set[tuple[str, int, str]] = set()
        for raw_limit in raw_limits:
            if not isinstance(raw_limit, dict):
                raise _Invalid()
            _exact(
                raw_limit,
                {
                    "pool",
                    "remaining_percent",
                    "reset_at",
                    "reset_generation",
                    "used_percent",
                    "window_seconds",
                },
            )
            pool = _pool(raw_limit["pool"])
            window = _window(raw_limit["window_seconds"])
            reset_generation = _reset_generation(raw_limit["reset_generation"])
            used = _percent(raw_limit["used_percent"])
            remaining = _percent(raw_limit["remaining_percent"])
            reset_at = _timestamp(raw_limit["reset_at"])
            key = (pool, window, reset_generation)
            if (
                key in limit_keys
                or abs(used + remaining - 100) > 1e-9
                or reset_at <= generated_at
            ):
                raise _Invalid()
            limit_keys.add(key)
            limits.append(
                UsageLimitV2(pool, window, reset_generation, used, remaining, reset_at)
            )
        trends: list[UsageTrendV2] = []
        trend_keys: set[tuple[str, int, str]] = set()
        for raw_trend in raw_trends:
            if not isinstance(raw_trend, dict):
                raise _Invalid()
            _exact(
                raw_trend,
                {
                    "coverage",
                    "last_sample_at",
                    "pool",
                    "projected_exhaustion_at",
                    "reset_generation",
                    "window_seconds",
                },
            )
            pool = _pool(raw_trend["pool"])
            window = _window(raw_trend["window_seconds"])
            reset_generation = _reset_generation(raw_trend["reset_generation"])
            key = (pool, window, reset_generation)
            last_sample_at = _timestamp(raw_trend["last_sample_at"])
            projected = _timestamp(raw_trend["projected_exhaustion_at"])
            if (
                key not in limit_keys
                or key in trend_keys
                or last_sample_at > generated_at
                or projected <= generated_at
            ):
                raise _Invalid()
            if generated_at - last_sample_at > timedelta(seconds=900):
                stale = True
            trend_keys.add(key)
            trends.append(
                UsageTrendV2(
                    pool,
                    window,
                    reset_generation,
                    _coverage(raw_trend["coverage"]),
                    last_sample_at,
                    projected,
                )
            )
        evidence: list[TrackerEvidenceV2] = []
        evidence_keys: set[tuple[str, int, str]] = set()
        for raw_item in raw_evidence:
            if not isinstance(raw_item, dict):
                raise _Invalid()
            _exact(
                raw_item,
                {
                    "coverage",
                    "last_sample_at",
                    "pool",
                    "reset_generation",
                    "window_seconds",
                },
            )
            pool = _pool(raw_item["pool"])
            window = _window(raw_item["window_seconds"])
            reset_generation = _reset_generation(raw_item["reset_generation"])
            key = (pool, window, reset_generation)
            last_sample_at = _timestamp(raw_item["last_sample_at"])
            if (
                key not in limit_keys
                or key in evidence_keys
                or last_sample_at > generated_at
            ):
                raise _Invalid()
            if generated_at - last_sample_at > timedelta(seconds=900):
                stale = True
            evidence_keys.add(key)
            evidence.append(
                TrackerEvidenceV2(
                    pool,
                    window,
                    reset_generation,
                    _coverage(raw_item["coverage"]),
                    last_sample_at,
                )
            )
        total_trends += len(trends)
        if total_trends > _MAX_TOTAL_TRENDS:
            raise _Invalid()
        accounts.append(
            AccountUsageEvidenceV2(
                account_id,
                tuple(
                    sorted(
                        limits,
                        key=lambda item: (
                            item.pool,
                            item.window_seconds,
                            item.reset_generation,
                        ),
                    )
                ),
                tuple(
                    sorted(
                        trends,
                        key=lambda item: (
                            item.pool,
                            item.window_seconds,
                            item.reset_generation,
                        ),
                    )
                ),
                tuple(
                    sorted(
                        evidence,
                        key=lambda item: (
                            item.pool,
                            item.window_seconds,
                            item.reset_generation,
                        ),
                    )
                ),
            )
        )
    status: ReaderStatus = "stale" if stale else value["status"]
    return (
        tuple(sorted(accounts, key=lambda item: item.account_id)),
        status,
        captured_at,
        generated_at,
    )


def _lock_root() -> Path:
    try:
        home = pwd.getpwuid(os.geteuid()).pw_dir
    except Exception as exc:
        raise _Unavailable() from exc
    if not isinstance(home, str):
        raise _Invalid()
    return Path(home) / ".local" / "state" / "codex-usage" / "locks"


def _default_state_home() -> Path:
    try:
        home = pwd.getpwuid(os.geteuid()).pw_dir
    except Exception as exc:
        raise _Unavailable() from exc
    if not isinstance(home, str):
        raise _Invalid()
    return Path(home) / ".local" / "state"


def _acquire_shared(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise _Busy() from exc
    except OSError as exc:
        raise _Invalid() from exc


def _read_chain(
    state_home: Path, now: datetime
) -> tuple[tuple[AccountUsageEvidenceV2, ...], ReaderStatus, datetime, datetime]:
    guard = _FdGuard()
    locked: list[int] = []
    try:
        lock_fd = guard.absolute_directory(_lock_root())
        for name in ("release.lock", "current.lock"):
            descriptor = guard.lock(lock_fd, name)
            _acquire_shared(descriptor)
            locked.append(descriptor)
        state_fd = guard.absolute_directory(state_home)
        usage_fd = guard.directory(state_fd, "codex-usage")
        integration_fd = guard.directory(usage_fd, "integration")
        generations_fd = guard.directory(integration_fd, "generations")
        staging_fd = guard.directory(integration_fd, "staging")
        try:
            generation_names = os.listdir(generations_fd)
            staging_names = os.listdir(staging_fd)
        except OSError as exc:
            raise _Invalid() from exc
        if (
            len(generation_names) > 257
            or len(staging_names) > 16
            or any(_GENERATION_RE.fullmatch(name) is None for name in generation_names)
            or any(_GENERATION_RE.fullmatch(name) is None for name in staging_names)
        ):
            raise _Invalid()
        active = _active_manifest(
            guard.read_file(integration_fd, "active.json", _MAX_BINDING_BYTES)
        )
        generation, pointer_digest = _pointer(
            _canonical_json(
                guard.read_file(integration_fd, "current.json", _MAX_POINTER_BYTES),
                _MAX_POINTER_BYTES,
            )
        )
        if generation not in generation_names:
            raise _Unavailable()
        generation_fd = guard.directory(generations_fd, generation)
        payload = guard.read_file(
            generation_fd, "account-usage-v2.json", _MAX_PAYLOAD_BYTES
        )
        binding = _canonical_json(
            guard.read_file(
                generation_fd, "account-usage-v2.binding.json", _MAX_BINDING_BYTES
            ),
            _MAX_BINDING_BYTES,
        )
        _binding(binding, active, generation, pointer_digest, payload, now)
        result = _payload(_canonical_json(payload, _MAX_PAYLOAD_BYTES), now)
        guard.revalidate()
        return result
    finally:
        for descriptor in reversed(locked):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except Exception:
                pass
        guard.close()


def read_usage_evidence_v2(
    *, state_home: Path | None = None, clock: Callable[[], datetime] | None = None
) -> UsageEvidenceV2:
    """Read one V2 generation; no retry, fallback, cache, process, or mutation."""
    try:
        now = _clock(clock or (lambda: datetime.now(UTC)))
        accounts, status, captured_at, generated_at = _read_chain(
            state_home or _default_state_home(), now
        )
        return UsageEvidenceV2(accounts, status, captured_at, generated_at)
    except _Busy:
        return UsageEvidenceV2((), "busy", None, None)
    except _Unavailable:
        return UsageEvidenceV2((), "unavailable", None, None)
    except Exception:
        return UsageEvidenceV2((), "invalid", None, None)


def display_snapshot_from_evidence(
    evidence: UsageEvidenceV2, *, known_account_ids: frozenset[str]
) -> UsageSnapshot:
    """One-way, side-effect-free display projection from verified V2 evidence."""
    if (
        type(evidence) is not UsageEvidenceV2
        or evidence.status != "complete"
        or evidence.captured_at is None
    ):
        return UsageSnapshot((), "unavailable", True, ("usage_unavailable",))
    if not isinstance(known_account_ids, frozenset) or any(
        type(item) is not str for item in known_account_ids
    ):
        return UsageSnapshot((), "unavailable", True, ("usage_unavailable",))
    accounts = tuple(
        AccountUsage(
            account_id=account.account_id,
            status="ok",
            captured_at=evidence.captured_at,
            stale=False,
            limits=tuple(
                UsageLimit(
                    limit.pool,
                    limit.window_seconds,
                    limit.used_percent,
                    limit.remaining_percent,
                    limit.reset_at,
                )
                for limit in account.limits
            ),
            cost_windows=(),
            usage_resets=(),
        )
        for account in evidence.accounts
        if account.account_id in known_account_ids
    )
    return UsageSnapshot(accounts, "live", False, ())


__all__ = [
    "AccountUsage",
    "AccountUsageEvidenceV2",
    "ReaderStatus",
    "TrackerEvidenceV2",
    "UsageCostWindow",
    "UsageEvidenceV2",
    "UsageLimit",
    "UsageLimitV2",
    "UsageReset",
    "UsageSnapshot",
    "UsageTrendV2",
    "display_snapshot_from_evidence",
    "read_usage_evidence_v2",
]
