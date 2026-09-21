"""Read-only, fail-closed consumer for attested account-usage schema 2."""

from __future__ import annotations

import base64
import csv
import fcntl
import hashlib
import io
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
_MAX_POOL_AUTHORITY_BYTES = 256 * 1024
_MAX_SOURCE_INPUT_BYTES = 512 * 1024
_MAX_MANIFEST_BYTES = 128 * 1024
_MAX_LOCK_BYTES = 4096
_MAX_ACCOUNTS = 100
_MAX_LIMITS = 32
_MAX_TRENDS = 32
_MAX_TOTAL_TRENDS = 3200
_MAX_POOL_AUTHORITIES = 256
_MAX_MODEL_CAPABILITIES = 512
_MAX_ATTESTATION_FILE_BYTES = 4 * 1024 * 1024
_MAX_RELEASE_TREE_ENTRIES = 4096
_MAX_RELEASE_TREE_BYTES = 128 * 1024 * 1024
_MAX_HISTORY_SAMPLES = 500_000
_WINDOWS = frozenset({18000, 604800, 2592000})
_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_POOL_RE = re.compile(r"^(?:main|spark)$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_PRODUCER_VERSION = "0.6.539"
_PRODUCER_SOURCE_MANIFEST_SHA256 = (
    "45803c0f270971e7b8ea41104e461a80020d36187222889894f68c25304dbf14"
)
_PRODUCER_RELEASE_ID = "0.6.539-45803c0f270971e7"
_RELEASE_RE = re.compile(r"^0\.6\.539-45803c0f270971e7$")
_RETIRED_SPARK_SOURCE_POOL = "gpt-5.3-codex-spark"
_AUTHORITY_POOL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_MODEL_FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_REASONING_LEVELS = ("low", "medium", "high", "xhigh", "max", "ultra")
_MODEL_INVOCABILITY_SOURCE = "pool_authority-v3.model_capabilities"
_LIFECYCLES = frozenset(("ephemeral", "session", "persistent"))
_PAYLOAD_STATUSES = frozenset(("ok", "partial", "error", "login_required", "unknown"))
_TRACKER_COVERAGES = frozenset(("complete", "partial", "insufficient", "stale"))
_ASCII_TOKEN_RE = re.compile(r"^[!-~]{1,128}$")
_LOCAL_PATH_RE = re.compile(r"(?:^|[^A-Za-z0-9/])(?:/+|~/|[A-Za-z]:[\\/]|\\\\)")
_PAYLOAD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PAYLOAD_SECRET_NAMES = frozenset(
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
_PAYLOAD_SECRET_SUFFIXES = (
    "token",
    "secret",
    "key",
    "cookie",
    "password",
    "path",
    "url",
    "header",
)


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
    pool: str
    window_seconds: int
    reset_generation: str
    used_percent: float
    remaining_percent: float
    reset_at: datetime


@dataclass(frozen=True, slots=True)
class UsageTrendV2:
    pool: str
    window_seconds: int
    reset_generation: str
    coverage: str
    last_sample_at: datetime
    projected_exhaustion_at: datetime


@dataclass(frozen=True, slots=True)
class TrackerEvidenceV2:
    pool: str
    window_seconds: int
    reset_generation: str
    coverage: str
    last_sample_at: datetime


@dataclass(frozen=True, slots=True)
class AccountUsageEvidenceV2:
    account_id: str
    limits: tuple[UsageLimitV2, ...]
    trends: tuple[UsageTrendV2, ...]
    tracker_evidence: tuple[TrackerEvidenceV2, ...]


ModelInvocabilityStatus = Literal["complete", "unattested", "invalid", "stale"]


@dataclass(frozen=True, slots=True)
class ModelInvocabilityV1:
    """One account/model/runner capability from a bound catalog projection."""

    account_id: str
    model_id: str
    runner_id: str
    meter_visible: bool
    catalog_visible: bool
    supported_in_api: bool
    runner_invocable: bool


@dataclass(frozen=True, slots=True)
class ModelInvocabilityProjectionV1:
    """Bound model capability evidence, kept separate from usage display evidence."""

    status: ModelInvocabilityStatus
    source: str
    capabilities: tuple[ModelInvocabilityV1, ...]


_UNATTESTED_MODEL_INVOCABILITY = ModelInvocabilityProjectionV1(
    "unattested", _MODEL_INVOCABILITY_SOURCE, ()
)


@dataclass(frozen=True, slots=True)
class UsageEvidenceV2:
    accounts: tuple[AccountUsageEvidenceV2, ...]
    status: ReaderStatus
    captured_at: datetime | None
    generated_at: datetime | None
    pool_authorities: tuple["PoolAuthorityV2", ...] = ()
    model_invocability: ModelInvocabilityProjectionV1 = (
        _UNATTESTED_MODEL_INVOCABILITY
    )
    generation_id: str | None = None


@dataclass(frozen=True, slots=True)
class PoolAuthorityV2:
    account_id: str
    pool_id: str
    provider: str
    allowed_lifecycles: tuple[str, ...]
    allowed_model_families: tuple[str, ...]
    hive_available: bool
    persistent_leadership_eligible: bool
    long_running_leadership_eligible: bool
    reasoning_minimum: str
    reasoning_maximum: str


@dataclass(frozen=True, slots=True)
class _EvidenceBindingV2:
    active_manifest_sha256: str
    generation_id: str
    payload_sha256: str
    payload_size_bytes: int
    published_at: datetime
    release_id: str
    source_manifest_sha256: str
    pool_authority_sha256: str
    pool_authority_size_bytes: int
    source_inputs_sha256: str
    source_inputs_size_bytes: int


@dataclass(frozen=True, slots=True)
class _PoolAuthorityProjectionV2:
    authorities: tuple[PoolAuthorityV2, ...]
    expires_at: datetime
    generation_id: str
    issued_at: datetime
    release_id: str
    usage_binding_sha256: str
    usage_payload_sha256: str
    model_invocability: ModelInvocabilityProjectionV1


@dataclass(frozen=True, slots=True)
class _ValidatedGenerationV2:
    accounts: tuple[AccountUsageEvidenceV2, ...]
    status: ReaderStatus
    captured_at: datetime | None
    generated_at: datetime
    authorities: tuple[PoolAuthorityV2, ...]
    model_invocability: ModelInvocabilityProjectionV1
    binding: _EvidenceBindingV2


@dataclass(frozen=True, slots=True)
class _ActiveManifest:
    digest: str
    producer_version: str
    release_id: str
    source_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _ActiveAttestationV2:
    manifest: _ActiveManifest
    data_home: Path
    release_dir: Path
    entrypoint_path: Path
    entrypoint_sha256: str
    launcher_path: Path
    launcher_sha256: str
    record_path: Path
    record_sha256: str
    release_tree_sha256: str
    wheel_path: Path
    wheel_sha256: str


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

    def private_lock_directory(self, path: Path) -> int:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts[1:])
        ):
            raise _Invalid()
        try:
            passwd_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise _Unavailable() from exc
        enforce_from = len(path.parts) - 1
        if path.parts[: len(passwd_home.parts)] == passwd_home.parts:
            enforce_from = len(passwd_home.parts) - 1
        try:
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as exc:
            raise _Unavailable() from exc
        self._directories.append(
            (descriptor, None, None, _metadata(os.fstat(descriptor)))
        )
        self._close.append(descriptor)
        for index, component in enumerate(path.parts[1:], start=1):
            descriptor = self._open_directory(descriptor, component, controlled=False)
            if index >= enforce_from:
                _check_directory(os.fstat(descriptor))
        return descriptor

    def directory(self, parent_fd: int, name: str) -> int:
        if name in {"", ".", ".."} or "/" in name:
            raise _Invalid()
        return self._open_directory(parent_fd, name)

    def _open_regular(
        self,
        parent_fd: int,
        name: str,
        *,
        minimum: int,
        maximum: int,
        missing_is_unavailable: bool = False,
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
            if missing_is_unavailable:
                raise _Unavailable() from exc
            raise _Invalid() from exc
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
        return self._open_regular(
            parent_fd,
            name,
            minimum=0,
            maximum=_MAX_LOCK_BYTES,
            missing_is_unavailable=True,
        )

    def read_file(
        self,
        parent_fd: int,
        name: str,
        maximum: int,
        *,
        missing_is_unavailable: bool = False,
    ) -> bytes:
        descriptor = self._open_regular(
            parent_fd,
            name,
            minimum=1,
            maximum=maximum,
            missing_is_unavailable=missing_is_unavailable,
        )
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
                for stored_parent, file_name, metadata in self._files
                if stored_parent == parent_fd and file_name == name
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


def _release_id(value: object) -> str:
    if type(value) is not str or _RELEASE_RE.fullmatch(value) is None:
        raise _Invalid()
    return value


def _source_manifest_digest(value: object) -> str:
    digest = _hex(value)
    if digest != _PRODUCER_SOURCE_MANIFEST_SHA256:
        raise _Invalid()
    return digest


def _generation_id(value: object) -> str:
    if type(value) is not str or _GENERATION_RE.fullmatch(value) is None:
        raise _Invalid()
    return value


def _canonical_timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise _Invalid()
    parsed = _timestamp(value)
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise _Invalid()
    return parsed


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _Invalid() from None


def _closed_strings(
    value: object,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
    allowed: frozenset[str] | None = None,
) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= maximum:
        raise _Invalid()
    values = tuple(value)
    if any(type(item) is not str for item in values):
        raise _Invalid()
    strings = tuple(values)
    if len(set(strings)) != len(strings) or strings != tuple(sorted(strings)):
        raise _Invalid()
    if pattern is not None and any(pattern.fullmatch(item) is None for item in strings):
        raise _Invalid()
    if allowed is not None and any(item not in allowed for item in strings):
        raise _Invalid()
    return strings


def _usage_binding_bytes(binding: _EvidenceBindingV2) -> bytes:
    return _canonical_bytes(
        {
            "active_manifest_sha256": binding.active_manifest_sha256,
            "generation_id": binding.generation_id,
            "payload_filename": "account-usage-v2.json",
            "payload_sha256": binding.payload_sha256,
            "payload_size_bytes": binding.payload_size_bytes,
            "published_at": binding.published_at.isoformat().replace("+00:00", "Z"),
            "producer_version": _PRODUCER_VERSION,
            "release_id": binding.release_id,
            "source_manifest_sha256": binding.source_manifest_sha256,
            "usage_binding_schema_version": 2,
        }
    )


def _binding_v2(payload: bytes) -> _EvidenceBindingV2:
    value = _canonical_json(payload, _MAX_BINDING_BYTES)
    _exact(
        value,
        {
            "binding_schema_version",
            "pool_authority_filename",
            "pool_authority_sha256",
            "pool_authority_size_bytes",
            "source_inputs_filename",
            "source_inputs_sha256",
            "source_inputs_size_bytes",
            "usage_binding",
        },
    )
    usage = value["usage_binding"]
    if type(usage) is not dict:
        raise _Invalid()
    _exact(
        usage,
        {
            "active_manifest_sha256",
            "generation_id",
            "payload_filename",
            "payload_sha256",
            "payload_size_bytes",
            "published_at",
            "producer_version",
            "release_id",
            "source_manifest_sha256",
            "usage_binding_schema_version",
        },
    )
    if (
        type(value["binding_schema_version"]) is not int
        or value["binding_schema_version"] != 3
        or value["pool_authority_filename"] != "pool-authority-v2.json"
        or type(value["pool_authority_size_bytes"]) is not int
        or not 1 <= value["pool_authority_size_bytes"] <= _MAX_POOL_AUTHORITY_BYTES
        or value["source_inputs_filename"] != "source-inputs-v2.json"
        or type(value["source_inputs_size_bytes"]) is not int
        or not 1 <= value["source_inputs_size_bytes"] <= _MAX_SOURCE_INPUT_BYTES
        or type(usage["usage_binding_schema_version"]) is not int
        or usage["usage_binding_schema_version"] != 2
        or usage["payload_filename"] != "account-usage-v2.json"
        or usage["producer_version"] != _PRODUCER_VERSION
        or type(usage["payload_size_bytes"]) is not int
        or not 1 <= usage["payload_size_bytes"] <= _MAX_PAYLOAD_BYTES
    ):
        raise _Invalid()
    return _EvidenceBindingV2(
        active_manifest_sha256=_hex(usage["active_manifest_sha256"]),
        generation_id=_generation_id(usage["generation_id"]),
        payload_sha256=_hex(usage["payload_sha256"]),
        payload_size_bytes=usage["payload_size_bytes"],
        published_at=_canonical_timestamp(usage["published_at"]),
        release_id=_release_id(usage["release_id"]),
        source_manifest_sha256=_source_manifest_digest(
            usage["source_manifest_sha256"]
        ),
        pool_authority_sha256=_hex(value["pool_authority_sha256"]),
        pool_authority_size_bytes=value["pool_authority_size_bytes"],
        source_inputs_sha256=_hex(value["source_inputs_sha256"]),
        source_inputs_size_bytes=value["source_inputs_size_bytes"],
    )


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise _Invalid()
    return value


def _source_file_binding(value: object) -> dict[str, int | str]:
    if type(value) is not dict:
        raise _Invalid()
    _exact(
        value,
        {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "sha256",
            "size_bytes",
            "uid",
        },
    )
    result: dict[str, int | str] = {
        name: _nonnegative_int(value[name])
        for name in {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "size_bytes",
            "uid",
        }
    }
    result["sha256"] = _hex(value["sha256"])
    if result["mode"] != 0o600 or result["size_bytes"] > _MAX_SOURCE_INPUT_BYTES:
        raise _Invalid()
    return result


def _source_directory_binding(value: object) -> dict[str, int]:
    if type(value) is not dict:
        raise _Invalid()
    _exact(value, {"device", "gid", "inode", "mode", "uid"})
    result = {
        name: _nonnegative_int(value[name])
        for name in {"device", "gid", "inode", "mode", "uid"}
    }
    if result["mode"] != 0o700:
        raise _Invalid()
    return result


def _source_inputs_v2(payload: bytes) -> None:
    value = _canonical_json(payload, _MAX_SOURCE_INPUT_BYTES)
    _exact(
        value,
        {
            "current_directory",
            "history",
            "owner_source",
            "records",
            "source_input_binding_schema_version",
        },
    )
    if value["source_input_binding_schema_version"] != 1:
        raise _Invalid()
    _source_directory_binding(value["current_directory"])
    _source_file_binding(value["owner_source"])

    records = value["records"]
    if type(records) is not list or len(records) > _MAX_ACCOUNTS:
        raise _Invalid()
    record_ids: list[str] = []
    for record in records:
        if type(record) is not dict:
            raise _Invalid()
        _exact(
            record,
            {
                "account_id",
                "current_file",
                "state_generation",
                "state_generation_file",
            },
        )
        account_id = record["account_id"]
        if type(account_id) is not str or _ACCOUNT_RE.fullmatch(account_id) is None:
            raise _Invalid()
        record_ids.append(account_id)
        _source_file_binding(record["current_file"])
        _nonnegative_int(record["state_generation"])
        sidecar = record["state_generation_file"]
        if sidecar is not None:
            _source_file_binding(sidecar)
    if record_ids != sorted(record_ids) or len(record_ids) != len(set(record_ids)):
        raise _Invalid()

    history = value["history"]
    if type(history) is not dict:
        raise _Invalid()
    _exact(history, {"consumed_rows", "database", "shm", "wal"})
    for name in ("database", "shm", "wal"):
        if history[name] is not None:
            _source_file_binding(history[name])
    rows = history["consumed_rows"]
    if type(rows) is not list or len(rows) > _MAX_TOTAL_TRENDS:
        raise _Invalid()
    row_keys: list[tuple[str, str, int]] = []
    source_pool = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")
    for row in rows:
        if type(row) is not dict:
            raise _Invalid()
        _exact(
            row,
            {"account_id", "pool", "rows_sha256", "sample_count", "window_seconds"},
        )
        account_id = row["account_id"]
        pool = row["pool"]
        if (
            type(account_id) is not str
            or _ACCOUNT_RE.fullmatch(account_id) is None
            or type(pool) is not str
            or source_pool.fullmatch(pool) is None
            or pool.casefold() == _RETIRED_SPARK_SOURCE_POOL
        ):
            raise _Invalid()
        row_keys.append((account_id, pool, _nonnegative_int(row["window_seconds"])))
        _hex(row["rows_sha256"])
        _nonnegative_int(row["sample_count"])
    if row_keys != sorted(row_keys) or len(row_keys) != len(set(row_keys)):
        raise _Invalid()


def _invalid_model_invocability() -> ModelInvocabilityProjectionV1:
    return ModelInvocabilityProjectionV1(
        "invalid", _MODEL_INVOCABILITY_SOURCE, ()
    )


def _model_invocability_v1(
    value: object, *, issued_at: datetime, now: datetime
) -> ModelInvocabilityProjectionV1:
    """Parse only a bound V3 capability projection; never infer a capability."""
    try:
        if type(value) is not dict:
            raise _Invalid()
        _exact(value, {"capability_schema_version", "entries"})
        if (
            type(value["capability_schema_version"]) is not int
            or value["capability_schema_version"] != 1
            or type(value["entries"]) is not list
            or len(value["entries"]) > _MAX_MODEL_CAPABILITIES
        ):
            raise _Invalid()
        capabilities: list[ModelInvocabilityV1] = []
        canonical_entries: list[dict[str, object]] = []
        keys: list[tuple[str, str, str]] = []
        stale = False
        for raw in value["entries"]:
            if type(raw) is not dict:
                raise _Invalid()
            _exact(
                raw,
                {
                    "account_id",
                    "catalog_fresh_until",
                    "catalog_observed_at",
                    "catalog_visible",
                    "meter_visible",
                    "model_id",
                    "runner_id",
                    "runner_invocable",
                    "supported_in_api",
                },
            )
            account_id = raw["account_id"]
            if (
                type(account_id) is not str
                or account_id in {".", ".."}
                or _ACCOUNT_RE.fullmatch(account_id) is None
                or any(
                    type(raw[field]) is not bool
                    for field in (
                        "meter_visible",
                        "catalog_visible",
                        "supported_in_api",
                        "runner_invocable",
                    )
                )
            ):
                raise _Invalid()
            model_id = _payload_token(raw["model_id"], 128)
            runner_id = _payload_token(raw["runner_id"], 64)
            observed_at = _canonical_timestamp(raw["catalog_observed_at"])
            fresh_until = _canonical_timestamp(raw["catalog_fresh_until"])
            try:
                expected_fresh_until = observed_at + timedelta(minutes=15)
            except OverflowError:
                return _invalid_model_invocability()
            if (
                observed_at > issued_at
                or fresh_until != expected_fresh_until
                or issued_at >= fresh_until
            ):
                raise _Invalid()
            catalog_visible = raw["catalog_visible"]
            supported_in_api = raw["supported_in_api"]
            runner_invocable = raw["runner_invocable"]
            if not catalog_visible and (supported_in_api or runner_invocable):
                raise _Invalid()
            key = (account_id, model_id, runner_id)
            keys.append(key)
            canonical_entries.append(
                {
                    "account_id": account_id,
                    "catalog_fresh_until": fresh_until.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "catalog_observed_at": observed_at.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "catalog_visible": catalog_visible,
                    "meter_visible": raw["meter_visible"],
                    "model_id": model_id,
                    "runner_id": runner_id,
                    "runner_invocable": runner_invocable,
                    "supported_in_api": supported_in_api,
                }
            )
            capabilities.append(
                ModelInvocabilityV1(
                    account_id,
                    model_id,
                    runner_id,
                    raw["meter_visible"],
                    catalog_visible,
                    supported_in_api,
                    runner_invocable,
                )
            )
            if now >= fresh_until:
                stale = True
        if len(set(keys)) != len(keys) or keys != sorted(keys):
            raise _Invalid()
        _scan_payload_secrets(
            {
                "capability_schema_version": 1,
                "entries": canonical_entries,
            }
        )
    except _Invalid:
        return _invalid_model_invocability()
    return ModelInvocabilityProjectionV1(
        "stale" if stale else "complete",
        _MODEL_INVOCABILITY_SOURCE,
        () if stale else tuple(capabilities),
    )


def _pool_authority_v2(
    payload: bytes, *, now: datetime
) -> _PoolAuthorityProjectionV2:
    value = _canonical_json(payload, _MAX_POOL_AUTHORITY_BYTES)
    schema_version = value.get("pool_authority_schema_version")
    if schema_version == 2:
        _exact(
            value,
            {
                "authorities",
                "expires_at",
                "generation_id",
                "issued_at",
                "pool_authority_schema_version",
                "producer_version",
                "release_id",
                "usage_binding_sha256",
                "usage_payload_sha256",
            },
        )
    elif schema_version == 3:
        v3_names = {
            "authorities",
            "expires_at",
            "generation_id",
            "issued_at",
            "pool_authority_schema_version",
            "producer_version",
            "release_id",
            "usage_binding_sha256",
            "usage_payload_sha256",
        }
        if set(value) not in (v3_names, v3_names | {"model_capabilities"}):
            raise _Invalid()
    else:
        raise _Invalid()
    if (
        type(value["pool_authority_schema_version"]) is not int
        or value["pool_authority_schema_version"] not in {2, 3}
        or value["producer_version"] != _PRODUCER_VERSION
        or type(value["authorities"]) is not list
        or len(value["authorities"]) > _MAX_POOL_AUTHORITIES
    ):
        raise _Invalid()
    authorities: list[PoolAuthorityV2] = []
    canonical_authorities: list[dict[str, object]] = []
    keys: list[tuple[str, str, str]] = []
    for raw in value["authorities"]:
        if type(raw) is not dict:
            raise _Invalid()
        _exact(
            raw,
            {
                "account_id",
                "allowed_lifecycles",
                "allowed_model_families",
                "hive_available",
                "long_running_leadership_eligible",
                "persistent_leadership_eligible",
                "pool_id",
                "provider",
                "reasoning_maximum",
                "reasoning_minimum",
            },
        )
        account_id = raw["account_id"]
        pool_id = raw["pool_id"]
        provider = raw["provider"]
        minimum = raw["reasoning_minimum"]
        maximum = raw["reasoning_maximum"]
        if (
            type(account_id) is not str
            or account_id in {".", ".."}
            or _ACCOUNT_RE.fullmatch(account_id) is None
            or type(pool_id) is not str
            or _AUTHORITY_POOL_RE.fullmatch(pool_id) is None
            or type(provider) is not str
            or _PROVIDER_RE.fullmatch(provider) is None
            or type(minimum) is not str
            or type(maximum) is not str
            or minimum not in _REASONING_LEVELS
            or maximum not in _REASONING_LEVELS
            or _REASONING_LEVELS.index(minimum) > _REASONING_LEVELS.index(maximum)
            or any(
                type(raw[field]) is not bool
                for field in (
                    "hive_available",
                    "persistent_leadership_eligible",
                    "long_running_leadership_eligible",
                )
            )
        ):
            raise _Invalid()
        key = (account_id, provider, pool_id)
        keys.append(key)
        allowed_lifecycles = _closed_strings(
            raw["allowed_lifecycles"], maximum=32, allowed=_LIFECYCLES
        )
        allowed_model_families = _closed_strings(
            raw["allowed_model_families"], maximum=32, pattern=_MODEL_FAMILY_RE
        )
        canonical_authorities.append(
            {
                "account_id": account_id,
                "allowed_lifecycles": list(allowed_lifecycles),
                "allowed_model_families": list(allowed_model_families),
                "hive_available": raw["hive_available"],
                "long_running_leadership_eligible": raw[
                    "long_running_leadership_eligible"
                ],
                "persistent_leadership_eligible": raw[
                    "persistent_leadership_eligible"
                ],
                "pool_id": pool_id,
                "provider": provider,
                "reasoning_maximum": maximum,
                "reasoning_minimum": minimum,
            }
        )
        authorities.append(
            PoolAuthorityV2(
                account_id=account_id,
                pool_id=pool_id,
                provider=provider,
                allowed_lifecycles=allowed_lifecycles,
                allowed_model_families=allowed_model_families,
                hive_available=raw["hive_available"],
                persistent_leadership_eligible=raw[
                    "persistent_leadership_eligible"
                ],
                long_running_leadership_eligible=raw[
                    "long_running_leadership_eligible"
                ],
                reasoning_minimum=minimum,
                reasoning_maximum=maximum,
            )
        )
    if len(set(keys)) != len(keys) or keys != sorted(keys):
        raise _Invalid()
    issued_at = _canonical_timestamp(value["issued_at"])
    expires_at = _canonical_timestamp(value["expires_at"])
    if not issued_at < expires_at <= issued_at + timedelta(minutes=15):
        raise _Invalid()
    _scan_payload_secrets(
        {
            "authorities": canonical_authorities,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "generation_id": value["generation_id"],
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "pool_authority_schema_version": schema_version,
            "producer_version": _PRODUCER_VERSION,
            "release_id": value["release_id"],
            "usage_binding_sha256": value["usage_binding_sha256"],
            "usage_payload_sha256": value["usage_payload_sha256"],
        }
    )
    model_invocability = (
        _UNATTESTED_MODEL_INVOCABILITY
        if schema_version == 2
        or "model_capabilities" not in value
        else _model_invocability_v1(
            value["model_capabilities"], issued_at=issued_at, now=now
        )
    )
    return _PoolAuthorityProjectionV2(
        authorities=tuple(authorities),
        expires_at=expires_at,
        generation_id=_generation_id(value["generation_id"]),
        issued_at=issued_at,
        release_id=_release_id(value["release_id"]),
        usage_binding_sha256=_hex(value["usage_binding_sha256"]),
        usage_payload_sha256=_hex(value["usage_payload_sha256"]),
        model_invocability=model_invocability,
    )


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
        or _token(value["producer_version"], 64) != _PRODUCER_VERSION
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
        producer_version=_PRODUCER_VERSION,
        release_id=_release_id(value["release_id"]),
        source_manifest_sha256=_source_manifest_digest(
            value["source_manifest_sha256"]
        ),
    )


def _canonical_manifest(payload: bytes) -> dict[str, object]:
    if not isinstance(payload, bytes) or not payload.endswith(b"\n"):
        raise _Invalid()
    value = _canonical_json(payload[:-1], _MAX_MANIFEST_BYTES)
    if _canonical_bytes(value) + b"\n" != payload:
        raise _Invalid()
    return value


def _manifest_path(value: object) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise _Invalid()
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} or "\\" in part for part in path.parts[1:])
    ):
        raise _Invalid()
    return path


def _active_manifest_v2(payload: bytes, state_home: Path) -> _ActiveAttestationV2:
    value = _canonical_manifest(payload)
    _exact(
        value,
        {
            "data_home",
            "entrypoint_path",
            "entrypoint_sha256",
            "launcher_path",
            "launcher_sha256",
            "record_path",
            "record_sha256",
            "release_dir",
            "release_id",
            "release_tree_sha256",
            "schema_version",
            "source_manifest_sha256",
            "state_home",
            "version",
            "wheel_path",
            "wheel_sha256",
        },
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["version"] != _PRODUCER_VERSION
        or _manifest_path(value["state_home"]) != state_home
    ):
        raise _Invalid()
    release_id = _release_id(value["release_id"])
    source_manifest_sha256 = _source_manifest_digest(value["source_manifest_sha256"])
    if release_id != _PRODUCER_RELEASE_ID:
        raise _Invalid()
    integration = state_home / "codex-usage" / "integration"
    release_dir = _manifest_path(value["release_dir"])
    if release_dir != integration / "releases" / release_id:
        raise _Invalid()
    data_home = _manifest_path(value["data_home"])
    entrypoint = _manifest_path(value["entrypoint_path"])
    launcher = _manifest_path(value["launcher_path"])
    record = _manifest_path(value["record_path"])
    wheel = _manifest_path(value["wheel_path"])
    try:
        site_packages = record.parent.parent
        python_directory = site_packages.relative_to(release_dir).parts
    except ValueError as exc:
        raise _Invalid() from exc
    if (
        not data_home.is_absolute()
        or len(python_directory) != 4
        or python_directory[:2] != ("venv", "lib")
        or python_directory[3] != "site-packages"
        or python_directory[2] != "python3.14"
        or entrypoint != site_packages / "codex_usage" / "integration_entrypoint.py"
        or launcher != release_dir / "venv" / "bin" / "codex-usage"
        or wheel != release_dir / "producer.whl"
        or record
        != site_packages
        / "codex_usage_integration_producer-0.6.539.dist-info"
        / "RECORD"
    ):
        raise _Invalid()
    for name in (
        "entrypoint_sha256",
        "launcher_sha256",
        "record_sha256",
        "release_tree_sha256",
        "wheel_sha256",
    ):
        _hex(value[name])
    return _ActiveAttestationV2(
        manifest=_ActiveManifest(
            digest=hashlib.sha256(payload).hexdigest(),
            producer_version=_PRODUCER_VERSION,
            release_id=release_id,
            source_manifest_sha256=source_manifest_sha256,
        ),
        data_home=data_home,
        release_dir=release_dir,
        entrypoint_path=entrypoint,
        entrypoint_sha256=_hex(value["entrypoint_sha256"]),
        launcher_path=launcher,
        launcher_sha256=_hex(value["launcher_sha256"]),
        record_path=record,
        record_sha256=_hex(value["record_sha256"]),
        release_tree_sha256=_hex(value["release_tree_sha256"]),
        wheel_path=wheel,
        wheel_sha256=_hex(value["wheel_sha256"]),
    )


def _pointer_v1(value: dict[str, object]) -> tuple[str, str, str | None, str | None]:
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
    if type(value["pointer_schema_version"]) is not int or value[
        "pointer_schema_version"
    ] != 1:
        raise _Invalid()
    generation = _generation_id(value["current_generation_id"])
    digest = _hex(value["current_binding_sha256"])
    previous_generation = value["previous_generation_id"]
    previous_digest = value["previous_binding_sha256"]
    if (previous_generation is None) != (previous_digest is None):
        raise _Invalid()
    if previous_generation is not None:
        previous_generation = _generation_id(previous_generation)
        previous_digest = _hex(previous_digest)
        if previous_generation == generation:
            raise _Invalid()
    return generation, digest, previous_generation, previous_digest


def _evidence_lock_name(path: Path) -> str:
    return hashlib.sha256(os.fsencode(os.path.abspath(path))).hexdigest() + ".lock"


def _read_attestation_fd(descriptor: int, expected: _Metadata) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= _MAX_ATTESTATION_FILE_BYTES:
        block = os.read(
            descriptor, min(65536, _MAX_ATTESTATION_FILE_BYTES + 1 - total)
        )
        if not block:
            break
        chunks.append(block)
        total += len(block)
    if total > _MAX_ATTESTATION_FILE_BYTES or not _same(
        os.fstat(descriptor), expected
    ):
        raise _Invalid()
    return b"".join(chunks)


def _release_tree(
    release_fd: int,
) -> tuple[tuple[tuple[str, bool, _Metadata], ...], tuple[bytes, ...]]:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    root_fd = os.dup(release_fd)
    stack: list[tuple[int, str, os.stat_result]] = [(root_fd, ".", os.fstat(root_fd))]
    entries: list[tuple[str, bool, _Metadata]] = []
    rows: list[bytes] = []
    entry_count = 1
    file_bytes = 0
    try:
        while stack:
            descriptor, relative, initial = stack.pop()
            try:
                initial_metadata = _metadata(initial)
                mode = stat.S_IMODE(initial.st_mode)
                if stat.S_ISDIR(initial.st_mode):
                    if initial.st_uid != os.geteuid():
                        raise _Invalid()
                    entries.append((relative, True, initial_metadata))
                    rows.append(f"D {relative}\0{mode:04o}\n".encode())
                    children: list[tuple[str, int, os.stat_result]] = []
                    try:
                        with os.scandir(descriptor) as scanned:
                            for entry in scanned:
                                if entry_count >= _MAX_RELEASE_TREE_ENTRIES:
                                    raise _Invalid()
                                entry_count += 1
                                name = entry.name
                                child = entry.stat(follow_symlinks=False)
                                if (
                                    not name
                                    or name in {".", ".."}
                                    or "/" in name
                                    or "\\" in name
                                    or "\x00" in name
                                    or (stat.S_ISDIR(child.st_mode) and name == "__pycache__")
                                    or (stat.S_ISREG(child.st_mode) and name.endswith(".pyc"))
                                    or not (
                                        stat.S_ISDIR(child.st_mode)
                                        or stat.S_ISREG(child.st_mode)
                                    )
                                    or child.st_uid != os.geteuid()
                                ):
                                    raise _Invalid()
                                child_fd = -1
                                try:
                                    child_fd = os.open(
                                        name,
                                        directory_flags
                                        if stat.S_ISDIR(child.st_mode)
                                        else file_flags,
                                        dir_fd=descriptor,
                                    )
                                    opened = os.fstat(child_fd)
                                    if (
                                        stat.S_IFMT(opened.st_mode)
                                        != stat.S_IFMT(child.st_mode)
                                        or not _same(opened, _metadata(child))
                                        or opened.st_uid != os.geteuid()
                                        or (
                                            stat.S_ISREG(opened.st_mode)
                                            and (
                                                opened.st_nlink != 1
                                                or opened.st_size
                                                > _MAX_ATTESTATION_FILE_BYTES
                                            )
                                        )
                                    ):
                                        raise _Invalid()
                                    children.append((name, child_fd, opened))
                                    child_fd = -1
                                finally:
                                    if child_fd >= 0:
                                        os.close(child_fd)
                        children.sort(key=lambda item: item[0], reverse=True)
                        stack.extend(
                            (child_fd, f"{relative}/{name}", child)
                            for name, child_fd, child in children
                        )
                        children.clear()
                    finally:
                        for _name, child_fd, _child in children:
                            os.close(child_fd)
                    if not _same(os.fstat(descriptor), initial_metadata):
                        raise _Invalid()
                    continue
                if (
                    not stat.S_ISREG(initial.st_mode)
                    or initial.st_uid != os.geteuid()
                    or initial.st_nlink != 1
                    or initial.st_size > _MAX_ATTESTATION_FILE_BYTES
                    or file_bytes + initial.st_size > _MAX_RELEASE_TREE_BYTES
                ):
                    raise _Invalid()
                entries.append((relative, False, initial_metadata))
                payload = _read_attestation_fd(descriptor, initial_metadata)
                file_bytes += len(payload)
                if file_bytes > _MAX_RELEASE_TREE_BYTES:
                    raise _Invalid()
                rows.append(
                    f"F {relative}\0{mode:04o}\0{len(payload)}\0".encode()
                    + hashlib.sha256(payload).hexdigest().encode("ascii")
                    + b"\n"
                )
            finally:
                os.close(descriptor)
        return tuple(entries), tuple(rows)
    finally:
        for descriptor, _relative, _item in stack:
            os.close(descriptor)


def _open_release_file(
    release_fd: int, relative: Path, *, mode: int
) -> bytes:
    if not relative.parts or relative.is_absolute() or any(
        part in {"", ".", ".."} or "\\" in part for part in relative.parts
    ):
        raise _Invalid()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.dup(release_fd)
    try:
        for index, component in enumerate(relative.parts):
            next_descriptor = os.open(
                component,
                file_flags if index == len(relative.parts) - 1 else directory_flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.geteuid()
            or item.st_nlink != 1
            or stat.S_IMODE(item.st_mode) != mode
            or not 1 <= item.st_size <= _MAX_ATTESTATION_FILE_BYTES
        ):
            raise _Invalid()
        return _read_attestation_fd(descriptor, _metadata(item))
    finally:
        os.close(descriptor)


def _record_digest(value: object, payload: bytes) -> bool:
    if type(value) is not str or not value.startswith("sha256="):
        return False
    encoded = value[7:]
    if len(encoded) != 43 or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in encoded
    ):
        return False
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=")
    except (ValueError, TypeError):
        return False
    expected = hashlib.sha256(payload).digest()
    return (
        decoded == expected
        and encoded
        == base64.urlsafe_b64encode(expected).decode("ascii").rstrip("=")
    )


def _verify_record(
    release_fd: int, attestation: _ActiveAttestationV2, record_payload: bytes
) -> None:
    try:
        site_packages = attestation.record_path.parent.parent.relative_to(
            attestation.release_dir
        )
        record_relative = attestation.record_path.relative_to(
            attestation.record_path.parent.parent
        ).as_posix()
        entrypoint_relative = attestation.entrypoint_path.relative_to(
            attestation.record_path.parent.parent
        ).as_posix()
        rows = csv.reader(io.StringIO(record_payload.decode("utf-8")))
    except (UnicodeDecodeError, ValueError, csv.Error) as exc:
        raise _Invalid() from exc
    seen: set[str] = set()
    entrypoint_valid = False
    count = 0
    try:
        for row in rows:
            count += 1
            if count > _MAX_RELEASE_TREE_ENTRIES or len(row) != 3:
                raise _Invalid()
            relative, digest, size_text = row
            if (
                not relative
                or relative in seen
                or relative.startswith("/")
                or "\\" in relative
                or "\x00" in relative
            ):
                raise _Invalid()
            pieces = relative.split("/")
            if any(piece in {"", ".", ".."} for piece in pieces):
                raise _Invalid()
            seen.add(relative)
            payload = _open_release_file(
                release_fd, site_packages.joinpath(*pieces), mode=0o600
            )
            if digest or size_text:
                if (
                    not digest
                    or not size_text
                    or not size_text.isdecimal()
                    or not _record_digest(digest, payload)
                    or int(size_text) != len(payload)
                ):
                    raise _Invalid()
                if relative == entrypoint_relative:
                    entrypoint_valid = True
            elif relative != record_relative:
                raise _Invalid()
    except (csv.Error, ValueError, OverflowError) as exc:
        raise _Invalid() from exc
    if not seen or record_relative not in seen or not entrypoint_valid:
        raise _Invalid()


def _attest_active_release(
    guard: _FdGuard, integration_fd: int, state_home: Path, active_payload: bytes
) -> _ActiveManifest:
    attestation = _active_manifest_v2(active_payload, state_home)
    guard.absolute_directory(attestation.data_home)
    releases_fd = guard.directory(integration_fd, "releases")
    release_fd = guard.directory(releases_fd, attestation.manifest.release_id)
    initial_entries, initial_rows = _release_tree(release_fd)
    if hashlib.sha256(b"".join(initial_rows)).hexdigest() != attestation.release_tree_sha256:
        raise _Invalid()
    def relative(path: Path) -> Path:
        return path.relative_to(attestation.release_dir)

    entrypoint = _open_release_file(
        release_fd, relative(attestation.entrypoint_path), mode=0o600
    )
    launcher = _open_release_file(
        release_fd, relative(attestation.launcher_path), mode=0o700
    )
    record = _open_release_file(release_fd, relative(attestation.record_path), mode=0o600)
    wheel = _open_release_file(release_fd, relative(attestation.wheel_path), mode=0o600)
    if (
        hashlib.sha256(entrypoint).hexdigest() != attestation.entrypoint_sha256
        or hashlib.sha256(launcher).hexdigest() != attestation.launcher_sha256
        or hashlib.sha256(record).hexdigest() != attestation.record_sha256
        or hashlib.sha256(wheel).hexdigest() != attestation.wheel_sha256
        or b" -B -I -m codex_usage.integration_entrypoint" not in launcher
        or b" PYTHONDONTWRITEBYTECODE=1 XDG_DATA_HOME=" not in launcher
    ):
        raise _Invalid()
    _verify_record(release_fd, attestation, record)
    metadata = _open_release_file(
        release_fd,
        relative(attestation.record_path.parent / "METADATA"),
        mode=0o600,
    )
    try:
        metadata_text = metadata.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Invalid() from exc
    if (
        "Name: codex-usage-integration-producer\n" not in metadata_text
        or f"Version: {_PRODUCER_VERSION}\n" not in metadata_text
    ):
        raise _Invalid()
    repeated_entries, repeated_rows = _release_tree(release_fd)
    if repeated_entries != initial_entries or repeated_rows != initial_rows:
        raise _Invalid()
    return attestation.manifest


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


def _payload_token(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or not value.isascii()
        or _ASCII_TOKEN_RE.fullmatch(value) is None
        or _LOCAL_PATH_RE.search(value) is not None
    ):
        raise _Invalid()
    return value


def _payload_secret_key(key: str) -> bool:
    normalized = key.casefold().replace("_", "")
    return normalized in _PAYLOAD_SECRET_NAMES or normalized.endswith(
        _PAYLOAD_SECRET_SUFFIXES
    )


def _scan_payload_secrets(value: object, *, depth: int = 0) -> None:
    if depth > 64:
        raise _Invalid()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if (
                type(key) is not str
                or _PAYLOAD_KEY_RE.fullmatch(key) is None
                or _payload_secret_key(key)
            ):
                raise _Invalid()
            _scan_payload_secrets(nested, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _scan_payload_secrets(nested, depth=depth + 1)
        return
    if isinstance(value, str):
        if (
            value.startswith("Bearer ")
            or _JWT_RE.fullmatch(value)
            or _PEM_PRIVATE_KEY_RE.search(value)
            or _LOCAL_PATH_RE.search(value)
        ):
            raise _Invalid()
        return
    if value is None or type(value) in (bool, int, float):
        return
    raise _Invalid()


def _payload_timestamp_text(value: object) -> str:
    if type(value) is not str or len(value) > 64 or "T" not in value:
        raise _Invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        raise _Invalid() from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise _Invalid()
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _payload_percent(value: object) -> float:
    if type(value) not in (int, float):
        raise _Invalid()
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        raise _Invalid() from None
    if not math.isfinite(result) or not 0 <= result <= 100:
        raise _Invalid()
    return result


def _payload_rate(value: object) -> float:
    if type(value) not in (int, float):
        raise _Invalid()
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        raise _Invalid() from None
    if not math.isfinite(result) or not 0 <= result <= 100.0:
        raise _Invalid()
    return result


def _serialize_payload_v2(value: object) -> bytes:
    """Mirror the producer's schema-2 serializer before accepting its bytes."""
    if type(value) is not dict:
        raise _Invalid()
    _exact(value, {"accounts", "generated_at", "schema_version"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise _Invalid()
    generated_at = _payload_timestamp_text(value["generated_at"])
    generated_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    raw_accounts = value["accounts"]
    if type(raw_accounts) is not list or len(raw_accounts) > _MAX_ACCOUNTS:
        raise _Invalid()
    accounts: list[dict[str, object]] = []
    account_ids: set[str] = set()
    for raw_account in raw_accounts:
        if type(raw_account) is not dict:
            raise _Invalid()
        _exact(
            raw_account,
            {"account_id", "freshness", "limits", "status", "tracker_evidence"},
        )
        account_id = _payload_token(raw_account["account_id"], 64)
        if _ACCOUNT_RE.fullmatch(account_id) is None or account_id in account_ids:
            raise _Invalid()
        status = raw_account["status"]
        if type(status) is not str or status not in _PAYLOAD_STATUSES:
            raise _Invalid()
        freshness = raw_account["freshness"]
        if type(freshness) is not dict:
            raise _Invalid()
        _exact(freshness, {"captured_at", "fresh_until", "stale"})
        if type(freshness["stale"]) is not bool:
            raise _Invalid()
        captured_at = _payload_timestamp_text(freshness["captured_at"])
        fresh_until = _payload_timestamp_text(freshness["fresh_until"])
        captured_time = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
        fresh_until_time = datetime.fromisoformat(fresh_until.replace("Z", "+00:00"))
        if (
            captured_time > generated_time
            or fresh_until_time != captured_time + timedelta(minutes=15)
            or (generated_time > fresh_until_time and freshness["stale"] is not True)
        ):
            raise _Invalid()
        raw_limits = raw_account["limits"]
        if type(raw_limits) is not list or len(raw_limits) > _MAX_LIMITS:
            raise _Invalid()
        limits: list[dict[str, object]] = []
        limit_ids: set[tuple[str, int]] = set()
        for raw_limit in raw_limits:
            if type(raw_limit) is not dict:
                raise _Invalid()
            if not {"pool", "window_seconds", "used_percent", "remaining_percent"} <= set(
                raw_limit
            ) or set(raw_limit) - {
                "pool",
                "window_seconds",
                "used_percent",
                "remaining_percent",
                "reset_at",
            }:
                raise _Invalid()
            window_seconds = raw_limit["window_seconds"]
            if type(window_seconds) is not int or window_seconds not in _WINDOWS:
                raise _Invalid()
            used_percent = _payload_percent(raw_limit["used_percent"])
            remaining_percent = _payload_percent(raw_limit["remaining_percent"])
            if not math.isclose(
                used_percent + remaining_percent,
                100.0,
                rel_tol=0.0,
                abs_tol=1e-9,
            ):
                raise _Invalid()
            pool = _payload_token(raw_limit["pool"], 64)
            identity = (pool, window_seconds)
            if identity in limit_ids:
                raise _Invalid()
            limit_ids.add(identity)
            limit: dict[str, object] = {
                "pool": pool,
                "remaining_percent": remaining_percent,
                "used_percent": used_percent,
                "window_seconds": window_seconds,
            }
            if "reset_at" in raw_limit:
                limit["reset_at"] = _payload_timestamp_text(raw_limit["reset_at"])
            limits.append(limit)
        raw_evidence = raw_account["tracker_evidence"]
        if type(raw_evidence) is not list or len(raw_evidence) > _MAX_TRENDS:
            raise _Invalid()
        evidence: list[dict[str, object]] = []
        evidence_ids: set[tuple[str, int]] = set()
        for raw_tracker in raw_evidence:
            if type(raw_tracker) is not dict:
                raise _Invalid()
            _exact(
                raw_tracker,
                {
                    "coverage",
                    "ema_time_constant_seconds",
                    "first_sample_at",
                    "last_sample_at",
                    "limit_window_seconds",
                    "pool",
                    "projected_used_percent_at_reset",
                    "rate_percentage_points_per_second",
                    "reset_generation",
                    "sample_count",
                },
            )
            coverage = raw_tracker["coverage"]
            sample_count = raw_tracker["sample_count"]
            window_seconds = raw_tracker["limit_window_seconds"]
            if (
                type(coverage) is not str
                or coverage not in _TRACKER_COVERAGES
                or type(raw_tracker["ema_time_constant_seconds"]) is not int
                or raw_tracker["ema_time_constant_seconds"] != 3600
                or type(window_seconds) is not int
                or window_seconds not in _WINDOWS
                or type(sample_count) is not int
                or not 1 <= sample_count <= _MAX_HISTORY_SAMPLES
                or (coverage == "insufficient") != (sample_count == 1)
            ):
                raise _Invalid()
            pool = _payload_token(raw_tracker["pool"], 64)
            identity = (pool, window_seconds)
            if identity in evidence_ids:
                raise _Invalid()
            evidence_ids.add(identity)
            first_sample_at = _payload_timestamp_text(raw_tracker["first_sample_at"])
            last_sample_at = _payload_timestamp_text(raw_tracker["last_sample_at"])
            first_sample_time = datetime.fromisoformat(first_sample_at.replace("Z", "+00:00"))
            last_sample_time = datetime.fromisoformat(last_sample_at.replace("Z", "+00:00"))
            if (
                first_sample_time > last_sample_time
                or (sample_count == 1 and first_sample_time != last_sample_time)
                or (sample_count > 1 and first_sample_time >= last_sample_time)
            ):
                raise _Invalid()
            evidence.append(
                {
                    "coverage": coverage,
                    "ema_time_constant_seconds": 3600,
                    "first_sample_at": first_sample_at,
                    "last_sample_at": last_sample_at,
                    "limit_window_seconds": window_seconds,
                    "pool": pool,
                    "projected_used_percent_at_reset": _payload_percent(
                        raw_tracker["projected_used_percent_at_reset"]
                    ),
                    "rate_percentage_points_per_second": _payload_rate(
                        raw_tracker["rate_percentage_points_per_second"]
                    ),
                    "reset_generation": _payload_token(
                        raw_tracker["reset_generation"], 128
                    ),
                    "sample_count": sample_count,
                }
            )
        limits_with_reset = {
            (item["pool"], item["window_seconds"]): datetime.fromisoformat(
                item["reset_at"].replace("Z", "+00:00")
            )
            for item in limits
            if "reset_at" in item
        }
        if not evidence_ids.issubset(limits_with_reset):
            raise _Invalid()
        if status not in {"ok", "partial"} and (limits or evidence):
            raise _Invalid()
        for item in evidence:
            last_sample_time = datetime.fromisoformat(
                item["last_sample_at"].replace("Z", "+00:00")
            )
            identity = (item["pool"], item["limit_window_seconds"])
            sample_age = generated_time - last_sample_time
            if (
                last_sample_time > captured_time
                or limits_with_reset[identity] <= last_sample_time
                or limits_with_reset[identity] <= generated_time
                or (
                    item["coverage"] in {"complete", "partial"}
                    and sample_age > timedelta(minutes=15)
                )
                or (
                    item["coverage"] == "stale"
                    and sample_age <= timedelta(minutes=15)
                )
            ):
                raise _Invalid()
        account_ids.add(account_id)
        accounts.append(
            {
                "account_id": account_id,
                "freshness": {
                    "captured_at": captured_at,
                    "fresh_until": fresh_until,
                    "stale": freshness["stale"],
                },
                "limits": sorted(
                    limits, key=lambda item: (item["pool"], item["window_seconds"])
                ),
                "status": status,
                "tracker_evidence": sorted(
                    evidence,
                    key=lambda item: (item["pool"], item["limit_window_seconds"]),
                ),
            }
        )
    document: dict[str, object] = {
        "accounts": sorted(accounts, key=lambda item: item["account_id"]),
        "generated_at": generated_at,
        "schema_version": 2,
    }
    _scan_payload_secrets(document)
    try:
        return json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _Invalid() from None


def _payload_v2(
    payload: bytes, now: datetime
) -> tuple[tuple[AccountUsageEvidenceV2, ...], ReaderStatus, datetime | None, datetime]:
    value = _canonical_json(payload, _MAX_PAYLOAD_BYTES)
    if _serialize_payload_v2(value) != payload:
        raise _Invalid()
    _exact(value, {"accounts", "generated_at", "schema_version"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise _Invalid()
    generated_at = _canonical_timestamp(value["generated_at"])
    raw_accounts = value["accounts"]
    if type(raw_accounts) is not list or len(raw_accounts) > _MAX_ACCOUNTS:
        raise _Invalid()
    accounts: list[AccountUsageEvidenceV2] = []
    account_ids: set[str] = set()
    captured_values: set[datetime] = set()
    stale = False
    partial = False
    for raw_account in raw_accounts:
        if type(raw_account) is not dict:
            raise _Invalid()
        _exact(raw_account, {"account_id", "freshness", "limits", "status", "tracker_evidence"})
        account_id = _payload_token(raw_account["account_id"], 64)
        if account_id in {".", ".."} or _ACCOUNT_RE.fullmatch(account_id) is None:
            raise _Invalid()
        if account_id in account_ids:
            raise _Invalid()
        account_ids.add(account_id)
        status = raw_account["status"]
        if type(status) is not str or status not in _PAYLOAD_STATUSES:
            raise _Invalid()
        freshness = raw_account["freshness"]
        if type(freshness) is not dict:
            raise _Invalid()
        _exact(freshness, {"captured_at", "fresh_until", "stale"})
        if type(freshness["stale"]) is not bool:
            raise _Invalid()
        captured_at = _canonical_timestamp(freshness["captured_at"])
        fresh_until = _canonical_timestamp(freshness["fresh_until"])
        if (
            captured_at > generated_at
            or fresh_until != captured_at + timedelta(minutes=15)
            or (generated_at > fresh_until and freshness["stale"] is not True)
        ):
            raise _Invalid()
        captured_values.add(captured_at)
        raw_limits = raw_account["limits"]
        if type(raw_limits) is not list or len(raw_limits) > _MAX_LIMITS:
            raise _Invalid()
        limits: dict[tuple[str, int], tuple[float, float, datetime | None]] = {}
        for raw_limit in raw_limits:
            if type(raw_limit) is not dict:
                raise _Invalid()
            if not {"pool", "window_seconds", "used_percent", "remaining_percent"} <= set(
                raw_limit
            ) or set(raw_limit) - {
                "pool",
                "window_seconds",
                "used_percent",
                "remaining_percent",
                "reset_at",
            }:
                raise _Invalid()
            pool = _payload_token(raw_limit["pool"], 64)
            window = raw_limit["window_seconds"]
            if type(window) is not int or window not in _WINDOWS:
                raise _Invalid()
            used = _percent(raw_limit["used_percent"])
            remaining = _percent(raw_limit["remaining_percent"])
            if abs(used + remaining - 100.0) > 1e-9:
                raise _Invalid()
            reset_at = (
                _canonical_timestamp(raw_limit["reset_at"])
                if "reset_at" in raw_limit
                else None
            )
            key = (pool, window)
            if key in limits:
                raise _Invalid()
            limits[key] = (used, remaining, reset_at)
        raw_trackers = raw_account["tracker_evidence"]
        if type(raw_trackers) is not list or len(raw_trackers) > _MAX_TRENDS:
            raise _Invalid()
        trackers: dict[tuple[str, int], TrackerEvidenceV2] = {}
        for raw_tracker in raw_trackers:
            if type(raw_tracker) is not dict:
                raise _Invalid()
            _exact(
                raw_tracker,
                {
                    "coverage",
                    "ema_time_constant_seconds",
                    "first_sample_at",
                    "last_sample_at",
                    "limit_window_seconds",
                    "pool",
                    "projected_used_percent_at_reset",
                    "rate_percentage_points_per_second",
                    "reset_generation",
                    "sample_count",
                },
            )
            coverage = raw_tracker["coverage"]
            window = raw_tracker["limit_window_seconds"]
            samples = raw_tracker["sample_count"]
            if (
                type(coverage) is not str
                or coverage not in _TRACKER_COVERAGES
                or type(raw_tracker["ema_time_constant_seconds"]) is not int
                or raw_tracker["ema_time_constant_seconds"] != 3600
                or type(window) is not int
                or window not in _WINDOWS
                or type(samples) is not int
                or not 1 <= samples <= _MAX_HISTORY_SAMPLES
                or (coverage == "insufficient") != (samples == 1)
            ):
                raise _Invalid()
            pool = _payload_token(raw_tracker["pool"], 64)
            first_sample = _canonical_timestamp(raw_tracker["first_sample_at"])
            last_sample = _canonical_timestamp(raw_tracker["last_sample_at"])
            reset_generation = _payload_token(raw_tracker["reset_generation"], 128)
            if (
                first_sample > last_sample
                or (samples == 1 and first_sample != last_sample)
                or (samples > 1 and first_sample >= last_sample)
                or (pool, window) not in limits
                or limits[(pool, window)][2] is None
                or last_sample > captured_at
                or limits[(pool, window)][2] <= last_sample
                or limits[(pool, window)][2] <= generated_at
                or (
                    coverage in {"complete", "partial"}
                    and generated_at - last_sample > timedelta(minutes=15)
                )
                or (
                    coverage == "stale"
                    and generated_at - last_sample <= timedelta(minutes=15)
                )
            ):
                raise _Invalid()
            _percent(raw_tracker["projected_used_percent_at_reset"])
            rate = raw_tracker["rate_percentage_points_per_second"]
            if (
                isinstance(rate, bool)
                or not isinstance(rate, (int, float))
                or not math.isfinite(float(rate))
                or not 0 <= float(rate) <= 100.0
                or (pool, window) in trackers
            ):
                raise _Invalid()
            trackers[(pool, window)] = TrackerEvidenceV2(
                pool, window, reset_generation, coverage, last_sample
            )
        if status not in {"ok", "partial"} and (limits or trackers):
            raise _Invalid()
        if freshness["stale"] is True or now > fresh_until:
            stale = True
        if status != "ok" or any(
            key not in trackers or trackers[key].coverage != "complete"
            for key in limits
        ):
            partial = True
        evidence_limits = tuple(
            UsageLimitV2(
                pool,
                window,
                trackers[(pool, window)].reset_generation,
                used,
                remaining,
                reset_at,
            )
            for (pool, window), (used, remaining, reset_at) in sorted(limits.items())
            if (pool, window) in trackers and reset_at is not None
        )
        accounts.append(
            AccountUsageEvidenceV2(
                account_id,
                evidence_limits,
                (),
                tuple(trackers[key] for key in sorted(trackers)),
            )
        )
    status: ReaderStatus = "stale" if stale else "partial" if partial else "complete"
    return (
        tuple(sorted(accounts, key=lambda account: account.account_id)),
        status,
        next(iter(captured_values)) if len(captured_values) == 1 else None,
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


def _validate_generation_v2(
    guard: _FdGuard,
    generations_fd: int,
    generation_id: str,
    binding_sha256: str,
    active: _ActiveManifest | None,
    now: datetime,
) -> _ValidatedGenerationV2:
    generation_fd = guard.directory(generations_fd, generation_id)
    try:
        names = os.listdir(generation_fd)
    except OSError as exc:
        raise _Invalid() from exc
    required_names = {
        "account-usage-v2.binding.json",
        "account-usage-v2.json",
        "pool-authority-v2.json",
        "source-inputs-v2.json",
    }
    if not required_names.issubset(names):
        raise _Unavailable()
    if set(names) != required_names:
        raise _Invalid()
    binding_bytes = guard.read_file(
        generation_fd,
        "account-usage-v2.binding.json",
        _MAX_BINDING_BYTES,
        missing_is_unavailable=True,
    )
    binding = _binding_v2(binding_bytes)
    if (
        binding.generation_id != generation_id
        or hashlib.sha256(binding_bytes).hexdigest() != binding_sha256
    ):
        raise _Invalid()
    payload = guard.read_file(
        generation_fd,
        "account-usage-v2.json",
        _MAX_PAYLOAD_BYTES,
        missing_is_unavailable=True,
    )
    if (
        len(payload) != binding.payload_size_bytes
        or hashlib.sha256(payload).hexdigest() != binding.payload_sha256
    ):
        raise _Invalid()
    accounts, status, captured_at, generated_at = _payload_v2(payload, now)
    if binding.published_at != generated_at:
        raise _Invalid()
    source_inputs = guard.read_file(
        generation_fd,
        "source-inputs-v2.json",
        _MAX_SOURCE_INPUT_BYTES,
        missing_is_unavailable=True,
    )
    if (
        len(source_inputs) != binding.source_inputs_size_bytes
        or hashlib.sha256(source_inputs).hexdigest() != binding.source_inputs_sha256
    ):
        raise _Invalid()
    _source_inputs_v2(source_inputs)
    authority_bytes = guard.read_file(
        generation_fd,
        "pool-authority-v2.json",
        _MAX_POOL_AUTHORITY_BYTES,
        missing_is_unavailable=True,
    )
    authority = _pool_authority_v2(authority_bytes, now=now)
    if (
        len(authority_bytes) != binding.pool_authority_size_bytes
        or hashlib.sha256(authority_bytes).hexdigest() != binding.pool_authority_sha256
        or authority.generation_id != binding.generation_id
        or authority.release_id != binding.release_id
        or authority.issued_at != binding.published_at
        or authority.usage_payload_sha256 != binding.payload_sha256
        or authority.usage_binding_sha256
        != hashlib.sha256(_usage_binding_bytes(binding)).hexdigest()
        or {account.account_id for account in accounts}
        != {entry.account_id for entry in authority.authorities}
    ):
        raise _Invalid()
    if active is not None and (
        binding.active_manifest_sha256 != active.digest
        or binding.release_id != active.release_id
        or binding.source_manifest_sha256 != active.source_manifest_sha256
    ):
        raise _Invalid()
    if now >= authority.expires_at:
        status = "stale"
    model_invocability = authority.model_invocability
    if model_invocability.status == "complete" and any(
        capability.account_id not in {account.account_id for account in accounts}
        for capability in model_invocability.capabilities
    ):
        model_invocability = _invalid_model_invocability()
    return _ValidatedGenerationV2(
        accounts,
        status,
        captured_at,
        generated_at,
        authority.authorities,
        model_invocability,
        binding,
    )


def _read_chain_v2(
    state_home: Path, now: datetime
) -> tuple[
    tuple[AccountUsageEvidenceV2, ...],
    ReaderStatus,
    datetime | None,
    datetime,
    tuple[PoolAuthorityV2, ...],
    ModelInvocabilityProjectionV1,
    str,
]:
    if type(state_home) is not type(Path()) or not state_home.is_absolute():
        raise _Invalid()
    guard = _FdGuard()
    locked: list[int] = []
    try:
        state_fd = guard.absolute_directory(state_home)
        usage_fd = guard.directory(state_fd, "codex-usage")
        integration_fd = guard.directory(usage_fd, "integration")
        lock_fd = guard.private_lock_directory(_lock_root())
        integration_path = state_home / "codex-usage" / "integration"
        for target in ("producer-install", "current.json"):
            descriptor = guard.lock(lock_fd, _evidence_lock_name(integration_path / target))
            _acquire_shared(descriptor)
            locked.append(descriptor)
        active_bytes = guard.read_file(
            integration_fd,
            "active.json",
            _MAX_MANIFEST_BYTES,
            missing_is_unavailable=True,
        )
        active = _attest_active_release(guard, integration_fd, state_home, active_bytes)
        generations_fd = guard.directory(integration_fd, "generations")
        pointer_bytes = guard.read_file(
            integration_fd,
            "current.json",
            _MAX_POINTER_BYTES,
            missing_is_unavailable=True,
        )
        generation_id, binding_sha256, previous_id, previous_sha256 = _pointer_v1(
            _canonical_json(pointer_bytes, _MAX_POINTER_BYTES)
        )
        current = _validate_generation_v2(
            guard,
            generations_fd,
            generation_id,
            binding_sha256,
            active,
            now,
        )
        previous: _ValidatedGenerationV2 | None = None
        if previous_id is not None and previous_sha256 is not None:
            previous = _validate_generation_v2(
                guard,
                generations_fd,
                previous_id,
                previous_sha256,
                None,
                now,
            )
        guard.revalidate()
        repeated_active_bytes = guard.read_file(
            integration_fd,
            "active.json",
            _MAX_MANIFEST_BYTES,
            missing_is_unavailable=True,
        )
        repeated_active = _attest_active_release(
            guard, integration_fd, state_home, repeated_active_bytes
        )
        repeated_pointer_bytes = guard.read_file(
            integration_fd,
            "current.json",
            _MAX_POINTER_BYTES,
            missing_is_unavailable=True,
        )
        if repeated_active != active or repeated_pointer_bytes != pointer_bytes:
            raise _Invalid()
        (
            repeated_generation,
            repeated_sha256,
            repeated_previous_id,
            repeated_previous_sha256,
        ) = (
            _pointer_v1(_canonical_json(repeated_pointer_bytes, _MAX_POINTER_BYTES))
        )
        repeated_current = _validate_generation_v2(
            guard,
            generations_fd,
            repeated_generation,
            repeated_sha256,
            repeated_active,
            now,
        )
        repeated_previous: _ValidatedGenerationV2 | None = None
        if repeated_previous_id is not None and repeated_previous_sha256 is not None:
            repeated_previous = _validate_generation_v2(
                guard,
                generations_fd,
                repeated_previous_id,
                repeated_previous_sha256,
                None,
                now,
            )
        if (
            repeated_current != current
            or repeated_previous != previous
            or repeated_previous_id != previous_id
            or repeated_previous_sha256 != previous_sha256
        ):
            raise _Invalid()
        guard.revalidate()
        return (
            current.accounts,
            current.status,
            current.captured_at,
            current.generated_at,
            current.authorities,
            current.model_invocability,
            current.binding.generation_id,
        )
    finally:
        for descriptor in reversed(locked):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        guard.close()


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
                guard.read_file(
                    integration_fd,
                    "current.json",
                    _MAX_POINTER_BYTES,
                    missing_is_unavailable=True,
                ),
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
        (
            accounts,
            status,
            captured_at,
            generated_at,
            authorities,
            model_invocability,
            generation_id,
        ) = _read_chain_v2(
            state_home or _default_state_home(), now
        )
        return UsageEvidenceV2(
            accounts,
            status,
            captured_at,
            generated_at,
            authorities,
            model_invocability,
            generation_id,
        )
    except _Busy:
        return UsageEvidenceV2((), "busy", None, None)
    except _Unavailable:
        return UsageEvidenceV2((), "unavailable", None, None)
    except Exception:
        return UsageEvidenceV2((), "invalid", None, None)


def find_model_invocability(
    evidence: UsageEvidenceV2,
    *,
    account_id: str,
    model_id: str,
    runner_id: str,
) -> ModelInvocabilityV1 | None:
    """Return one complete bound capability; never synthesize a negative or positive."""
    if (
        type(evidence) is not UsageEvidenceV2
        or evidence.status != "complete"
        or evidence.model_invocability.status != "complete"
        or not all(
            type(value) is str and value
            for value in (account_id, model_id, runner_id)
        )
    ):
        return None
    matches = tuple(
        capability
        for capability in evidence.model_invocability.capabilities
        if (
            capability.account_id == account_id
            and capability.model_id == model_id
            and capability.runner_id == runner_id
        )
    )
    return matches[0] if len(matches) == 1 else None


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
    "ModelInvocabilityProjectionV1",
    "ModelInvocabilityStatus",
    "ModelInvocabilityV1",
    "PoolAuthorityV2",
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
    "find_model_invocability",
    "read_usage_evidence_v2",
]
