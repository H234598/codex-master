"""Fail-closed Schema-2 consumer for codex-usage evidence."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import pwd
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from codex_master.usage_snapshot import UsageEvidenceV2


_PRODUCER_VERSION = "0.6.536"
_SPARK_POOL = "gpt-5.3-codex-spark"
_WINDOW_SECONDS = frozenset({18_000, 604_800, 2_592_000})
_MAX_POINTER_BYTES = 4_096
_MAX_BINDING_BYTES = 32_768
_MAX_PAYLOAD_BYTES = 2_097_152
_MAX_ACTIVE_BYTES = 32_768
_MAX_RELEASE_FILE_BYTES = 16 * 1024 * 1024
_ACTIVE_FIELDS = frozenset(
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
    }
)
_POINTER_FIELDS = frozenset(
    {
        "pointer_schema_version",
        "current_generation_id",
        "current_binding_sha256",
        "previous_generation_id",
        "previous_binding_sha256",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "binding_schema_version",
        "active_manifest_sha256",
        "generation_id",
        "payload_filename",
        "payload_sha256",
        "payload_size_bytes",
        "published_at",
        "producer_version",
        "release_id",
        "source_manifest_sha256",
    }
)
_DOCUMENT_FIELDS = frozenset({"accounts", "generated_at", "schema_version"})
_ACCOUNT_FIELDS = frozenset(
    {"account_id", "freshness", "limits", "status", "tracker_evidence"}
)
_FRESHNESS_FIELDS = frozenset({"captured_at", "fresh_until", "stale"})
_LIMIT_REQUIRED_FIELDS = frozenset(
    {"pool", "window_seconds", "used_percent", "remaining_percent"}
)
_TRACKER_FIELDS = frozenset(
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
    }
)
_ACCOUNT_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class _EvidenceError(Exception):
    pass


class _UnavailableEvidence(_EvidenceError):
    pass


class _BusyEvidence(_EvidenceError):
    pass


class _InvalidEvidence(_EvidenceError):
    pass


@dataclass(frozen=True)
class _EvidencePaths:
    state_home: Path
    data_home: Path
    lock_home: Path


@dataclass(frozen=True)
class EvidenceReadResult:
    status: str
    document: dict[str, Any] | None = None
    generation_id: str | None = None
    automatic_decisions_allowed: bool = False
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class LimitDecision:
    account_id: str
    pool: str
    window_seconds: int
    reset_generation: str
    automatic: bool
    reason: str


@dataclass(frozen=True)
class _Proof:
    path: Path
    identity: tuple[int, int, int, int, int, int, int, int]
    parent_fd: int | None = None
    name: str | None = None
    descriptor: int | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _now(value: datetime) -> datetime | None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        return None
    return value.astimezone(UTC)


def derive_limit_decisions(
    evidence: UsageEvidenceV2, *, now: datetime
) -> tuple[LimitDecision, ...]:
    """Describe eligibility from one supplied evidence value without taking action."""
    current = _now(now)
    if type(evidence) is not UsageEvidenceV2 or current is None:
        return ()
    decisions: list[LimitDecision] = []
    for account in evidence.accounts:
        trends = {
            (trend.pool, trend.window_seconds, trend.reset_generation): trend
            for trend in account.trends
        }
        tracker_evidence = {
            (item.pool, item.window_seconds, item.reset_generation): item
            for item in account.tracker_evidence
        }
        for limit in account.limits:
            key = (limit.pool, limit.window_seconds, limit.reset_generation)
            reason = "eligible"
            automatic = True
            if evidence.status != "complete":
                automatic, reason = False, "status_not_complete"
            elif current >= limit.reset_at:
                automatic, reason = False, "reset_elapsed"
            elif key not in tracker_evidence:
                automatic, reason = False, "evidence_mismatch"
            elif tracker_evidence[key].coverage != "complete":
                automatic, reason = False, "incomplete_coverage"
            elif key not in trends:
                automatic, reason = False, "missing_trend"
            elif trends[key].coverage != "complete":
                automatic, reason = False, "incomplete_coverage"
            elif trends[key].projected_exhaustion_at <= current:
                automatic, reason = False, "projection_elapsed"
            decisions.append(
                LimitDecision(
                    account.account_id,
                    limit.pool,
                    limit.window_seconds,
                    limit.reset_generation,
                    automatic,
                    reason,
                )
            )
    return tuple(decisions)


def _production_paths() -> _EvidencePaths:
    state_home = Path(
        os.environ.get("CODEX_USAGE_STATE_HOME", "~/.local/state")
    ).expanduser()
    return _EvidencePaths(
        state_home=state_home,
        data_home=Path(
            os.environ.get("CODEX_USAGE_DATA_HOME", "~/.local/share")
        ).expanduser(),
        lock_home=Path(pwd.getpwuid(os.geteuid()).pw_dir),
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return _identity(left) == _identity(right)


def _is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_private_directory(item: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or stat.S_IMODE(item.st_mode) != 0o700
        or item.st_uid != os.geteuid()
        or item.st_nlink < 2
    ):
        raise _InvalidEvidence("unsafe evidence directory")


def _validate_private_file(
    item: os.stat_result, *, maximum: int, minimum: int = 1
) -> None:
    if (
        not stat.S_ISREG(item.st_mode)
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_uid != os.geteuid()
        or item.st_nlink != 1
        or not minimum <= item.st_size <= maximum
    ):
        raise _InvalidEvidence("unsafe evidence file")


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _named_stat(parent_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise _UnavailableEvidence("missing evidence entry") from exc
    except OSError as exc:
        raise _InvalidEvidence("unreadable evidence entry") from exc


def _open_private_root_directory(path: Path) -> tuple[int, _Proof]:
    try:
        before = os.lstat(path)
        _validate_private_directory(before)
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except FileNotFoundError as exc:
        raise _UnavailableEvidence("missing evidence directory") from exc
    except OSError as exc:
        raise _InvalidEvidence("unsafe evidence directory") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened) or not _same_identity(
            before, os.lstat(path)
        ):
            raise _InvalidEvidence("evidence directory replaced during open")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, _Proof(path, _identity(before), descriptor=descriptor)


def _open_private_directory_at(
    parent_fd: int, name: str, *, path: Path
) -> tuple[int, _Proof]:
    before = _named_stat(parent_fd, name)
    _validate_private_directory(before)
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _UnavailableEvidence("missing evidence directory") from exc
    except OSError as exc:
        raise _InvalidEvidence("unsafe evidence directory") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened) or not _same_identity(
            before, _named_stat(parent_fd, name)
        ):
            raise _InvalidEvidence("evidence directory replaced during open")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, _Proof(
        path,
        _identity(before),
        parent_fd=parent_fd,
        name=name,
        descriptor=descriptor,
    )


def _read_private_file_at(
    parent_fd: int, name: str, *, path: Path, maximum: int, minimum: int = 1
) -> tuple[bytes, _Proof]:
    before = _named_stat(parent_fd, name)
    _validate_private_file(before, maximum=maximum, minimum=minimum)
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _UnavailableEvidence("missing evidence file") from exc
    except OSError as exc:
        raise _InvalidEvidence("unsafe evidence file") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened):
            raise _InvalidEvidence("evidence file replaced before read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        _validate_private_file(after, maximum=maximum, minimum=minimum)
        if (
            not _same_identity(before, after)
            or len(payload) != after.st_size
            or not _same_identity(before, _named_stat(parent_fd, name))
        ):
            raise _InvalidEvidence("evidence file changed during read")
        return payload, _Proof(path, _identity(before), parent_fd=parent_fd, name=name)
    finally:
        os.close(descriptor)


def _recheck(proof: _Proof) -> None:
    try:
        if proof.descriptor is not None:
            descriptor_item = os.fstat(proof.descriptor)
            if _identity(descriptor_item) != proof.identity:
                raise _InvalidEvidence("evidence descriptor changed during read")
        item = (
            _named_stat(proof.parent_fd, proof.name)
            if proof.parent_fd is not None and proof.name is not None
            else os.lstat(proof.path)
        )
    except OSError as exc:
        raise _InvalidEvidence("evidence disappeared during read") from exc
    if _identity(item) != proof.identity:
        raise _InvalidEvidence("evidence changed during read")


def _load_canonical_json(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), parse_constant=_reject_non_finite)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise _InvalidEvidence("invalid JSON") from exc
    if not isinstance(value, dict):
        raise _InvalidEvidence("evidence JSON must be an object")
    try:
        canonical = _canonical_bytes(value)
    except (TypeError, ValueError) as exc:
        raise _InvalidEvidence("uncanonical JSON") from exc
    if canonical != payload:
        raise _InvalidEvidence("noncanonical JSON")
    return value


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise _InvalidEvidence("invalid timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _InvalidEvidence("invalid timestamp") from exc
    if result.tzinfo is None:
        raise _InvalidEvidence("timestamp lacks timezone")
    return result.astimezone(UTC)


def _number(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise _InvalidEvidence("invalid number")
    return float(value)


def _printable_ascii_token(value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise _InvalidEvidence("invalid printable token")
    return value


def _source_pool(value: object) -> str:
    pool = _printable_ascii_token(value, maximum=64)
    if pool in {".", ".."} or "/" in pool or "\\" in pool or pool.startswith("~"):
        raise _InvalidEvidence("invalid source pool")
    return pool


def _validate_release_directory(item: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or stat.S_IMODE(item.st_mode) != 0o700
        or item.st_uid != os.geteuid()
        or item.st_nlink < 2
    ):
        raise _InvalidEvidence("unsafe release directory")


def _validate_release_file(item: os.stat_result) -> None:
    if (
        not stat.S_ISREG(item.st_mode)
        or stat.S_IMODE(item.st_mode) not in {0o600, 0o700}
        or item.st_uid != os.geteuid()
        or item.st_nlink != 1
        or item.st_size > _MAX_RELEASE_FILE_BYTES
    ):
        raise _InvalidEvidence("unsafe release file")


def _release_tree_digest(
    release_fd: int, release_path: Path, release_proof: _Proof, held_fds: list[int]
) -> tuple[str, list[_Proof], dict[str, bytes]]:
    rows: list[bytes] = []
    proofs: list[_Proof] = []
    artifacts: dict[str, bytes] = {}
    stack: list[tuple[int, str, int | None, str | None, os.stat_result]] = [
        (release_fd, ".", None, None, os.fstat(release_fd))
    ]
    while stack:
        descriptor, relative, parent_fd, name, initial = stack.pop()
        try:
            opened = os.fstat(descriptor)
            if not _same_identity(initial, opened):
                raise _InvalidEvidence("release entry changed before read")
            if stat.S_ISREG(opened.st_mode):
                _validate_release_file(opened)
                chunks: list[bytes] = []
                remaining = _MAX_RELEASE_FILE_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                after = os.fstat(descriptor)
                if (
                    len(data) != after.st_size
                    or not _same_identity(opened, after)
                    or parent_fd is None
                    or name is None
                    or not _same_identity(opened, _named_stat(parent_fd, name))
                ):
                    raise _InvalidEvidence("release file changed during read")
                artifacts[relative] = data
                proofs.append(
                    _Proof(
                        release_path / relative.removeprefix("./"),
                        _identity(opened),
                        parent_fd=parent_fd,
                        name=name,
                    )
                )
                rows.append(
                    f"F {relative}\0{stat.S_IMODE(opened.st_mode):04o}\0"
                    f"{len(data)}\0".encode()
                    + hashlib.sha256(data).hexdigest().encode()
                    + b"\n"
                )
                continue
            _validate_release_directory(opened)
            rows.append(f"D {relative}\0{stat.S_IMODE(opened.st_mode):04o}\n".encode())
            try:
                with os.scandir(descriptor) as entries:
                    children = sorted(
                        entries, key=lambda entry: entry.name, reverse=True
                    )
            except OSError as exc:
                raise _InvalidEvidence("release directory unreadable") from exc
            for entry in children:
                child_name = entry.name
                if (
                    not child_name
                    or child_name in {".", ".."}
                    or "/" in child_name
                    or "\\" in child_name
                ):
                    raise _InvalidEvidence("invalid release entry name")
                try:
                    child_initial = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise _InvalidEvidence("release entry unreadable") from exc
                if stat.S_ISDIR(child_initial.st_mode):
                    flags = _DIRECTORY_FLAGS
                elif stat.S_ISREG(child_initial.st_mode):
                    flags = _FILE_FLAGS
                else:
                    raise _InvalidEvidence("unsafe release entry")
                try:
                    child_fd = os.open(child_name, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise _InvalidEvidence("unsafe release entry open") from exc
                child_opened = os.fstat(child_fd)
                if not _same_identity(
                    child_initial, child_opened
                ) or not _same_identity(
                    child_initial, _named_stat(descriptor, child_name)
                ):
                    os.close(child_fd)
                    raise _InvalidEvidence("release entry replaced during open")
                child_relative = f"{relative}/{child_name}"
                if stat.S_ISDIR(child_opened.st_mode):
                    _validate_release_directory(child_opened)
                    proof = _Proof(
                        release_path / child_relative.removeprefix("./"),
                        _identity(child_opened),
                        parent_fd=descriptor,
                        name=child_name,
                        descriptor=child_fd,
                    )
                    proofs.append(proof)
                    held_fds.append(child_fd)
                stack.append(
                    (child_fd, child_relative, descriptor, child_name, child_opened)
                )
            if not _same_identity(opened, os.fstat(descriptor)):
                raise _InvalidEvidence("release directory changed during scan")
        finally:
            if descriptor not in held_fds:
                os.close(descriptor)
    _recheck(release_proof)
    return hashlib.sha256(b"".join(rows)).hexdigest(), proofs, artifacts


def _before_release_recheck() -> None:
    """Test hook for a real post-attestation release-tree race."""


def _verify_active(
    paths: _EvidencePaths,
    integration_fd: int,
    integration: Path,
    held_fds: list[int],
) -> tuple[dict[str, Any], bytes, list[_Proof]]:
    payload, active_proof = _read_private_file_at(
        integration_fd,
        "active.json",
        path=integration / "active.json",
        maximum=_MAX_ACTIVE_BYTES,
    )
    active = _load_canonical_json(payload)
    if (
        set(active) != _ACTIVE_FIELDS
        or type(active.get("schema_version")) is not int
        or active["schema_version"] != 2
    ):
        raise _InvalidEvidence("invalid active manifest")
    release_id = active.get("release_id")
    source_manifest = active.get("source_manifest_sha256")
    if (
        active.get("version") != _PRODUCER_VERSION
        or not isinstance(release_id, str)
        or not release_id.startswith(f"{_PRODUCER_VERSION}-")
        or not _is_hex(release_id.removeprefix(f"{_PRODUCER_VERSION}-"), 16)
        or not _is_hex(source_manifest, 64)
    ):
        raise _InvalidEvidence("invalid active release")
    releases = integration / "releases"
    releases_fd, releases_proof = _open_private_directory_at(
        integration_fd, "releases", path=releases
    )
    held_fds.append(releases_fd)
    release = releases / release_id
    release_fd, release_proof = _open_private_directory_at(
        releases_fd, release_id, path=release
    )
    held_fds.append(release_fd)
    proofs = [active_proof, releases_proof, release_proof]
    expected_paths = {
        "state_home": str(paths.state_home),
        "data_home": str(paths.data_home),
        "release_dir": str(release),
        "wheel_path": str(release / "producer.whl"),
        "launcher_path": str(release / "venv/bin/codex-usage"),
        "entrypoint_path": str(
            release
            / "venv/lib/python3.13/site-packages/codex_usage/integration_entrypoint.py"
        ),
        "record_path": str(
            release
            / "venv/lib/python3.13/site-packages/codex_usage_integration_producer-0.6.536.dist-info/RECORD"
        ),
    }
    if any(active[name] != value for name, value in expected_paths.items()):
        raise _InvalidEvidence("noncanonical active paths")
    tree_digest, tree_proofs, artifacts = _release_tree_digest(
        release_fd, release, release_proof, held_fds
    )
    if tree_digest != active.get("release_tree_sha256"):
        raise _InvalidEvidence("release tree digest drift")
    for digest_name, relative in (
        ("wheel_sha256", "./producer.whl"),
        ("launcher_sha256", "./venv/bin/codex-usage"),
        (
            "entrypoint_sha256",
            "./venv/lib/python3.13/site-packages/codex_usage/integration_entrypoint.py",
        ),
        (
            "record_sha256",
            "./venv/lib/python3.13/site-packages/codex_usage_integration_producer-0.6.536.dist-info/RECORD",
        ),
    ):
        if (
            not _is_hex(active.get(digest_name), 64)
            or relative not in artifacts
            or hashlib.sha256(artifacts[relative]).hexdigest() != active[digest_name]
        ):
            raise _InvalidEvidence("active artifact digest drift")
    _before_release_recheck()
    for proof in [release_proof, *tree_proofs]:
        _recheck(proof)
    return active, payload, [*proofs, *tree_proofs]


def _validate_pointer(pointer: dict[str, Any]) -> None:
    if (
        set(pointer) != _POINTER_FIELDS
        or type(pointer.get("pointer_schema_version")) is not int
        or pointer["pointer_schema_version"] != 1
    ):
        raise _InvalidEvidence("invalid current pointer")
    if not _is_hex(pointer.get("current_generation_id"), 32) or not _is_hex(
        pointer.get("current_binding_sha256"), 64
    ):
        raise _InvalidEvidence("invalid current pointer")
    previous_generation = pointer.get("previous_generation_id")
    previous_binding = pointer.get("previous_binding_sha256")
    if (previous_generation is None) != (previous_binding is None):
        raise _InvalidEvidence("partial previous pointer")
    if previous_generation is not None and (
        not _is_hex(previous_generation, 32) or not _is_hex(previous_binding, 64)
    ):
        raise _InvalidEvidence("invalid previous pointer")


def _validate_binding_shape(binding: dict[str, Any], *, generation: str) -> None:
    if (
        set(binding) != _BINDING_FIELDS
        or type(binding.get("binding_schema_version")) is not int
        or binding["binding_schema_version"] != 1
    ):
        raise _InvalidEvidence("invalid binding")
    release_id = binding.get("release_id")
    if (
        binding.get("generation_id") != generation
        or binding.get("payload_filename") != "account-usage-v2.json"
        or binding.get("producer_version") != _PRODUCER_VERSION
        or not _is_hex(binding.get("active_manifest_sha256"), 64)
        or not _is_hex(binding.get("payload_sha256"), 64)
        or not _is_hex(binding.get("source_manifest_sha256"), 64)
        or not isinstance(release_id, str)
        or not release_id.startswith(f"{_PRODUCER_VERSION}-")
        or not _is_hex(release_id.removeprefix(f"{_PRODUCER_VERSION}-"), 16)
        or not isinstance(binding.get("payload_size_bytes"), int)
        or isinstance(binding.get("payload_size_bytes"), bool)
        or not 1 <= binding["payload_size_bytes"] <= _MAX_PAYLOAD_BYTES
    ):
        raise _InvalidEvidence("binding drift")
    _parse_timestamp(binding.get("published_at"))


def _validate_binding(
    binding: dict[str, Any],
    *,
    generation: str,
    active: dict[str, Any],
    active_sha256: str,
) -> None:
    _validate_binding_shape(binding, generation=generation)
    if (
        binding["active_manifest_sha256"] != active_sha256
        or binding["release_id"] != active["release_id"]
        or binding["source_manifest_sha256"] != active["source_manifest_sha256"]
    ):
        raise _InvalidEvidence("binding drift")


def _generation_file_names(generation_fd: int) -> None:
    try:
        with os.scandir(generation_fd) as entries:
            names = {entry.name for entry in entries}
    except OSError as exc:
        raise _InvalidEvidence("generation namespace unreadable") from exc
    if names != {"account-usage-v2.json", "account-usage-v2.binding.json"}:
        raise _InvalidEvidence("invalid generation namespace")


def _validate_previous_binding(
    generations_fd: int,
    generations: Path,
    pointer: dict[str, Any],
    held_fds: list[int],
) -> list[_Proof]:
    generation = pointer.get("previous_generation_id")
    digest = pointer.get("previous_binding_sha256")
    if generation is None:
        return []
    generation_dir = generations / generation
    generation_fd, generation_proof = _open_private_directory_at(
        generations_fd, generation, path=generation_dir
    )
    held_fds.append(generation_fd)
    _generation_file_names(generation_fd)
    payload, binding_proof = _read_private_file_at(
        generation_fd,
        "account-usage-v2.binding.json",
        path=generation_dir / "account-usage-v2.binding.json",
        maximum=_MAX_BINDING_BYTES,
    )
    binding = _load_canonical_json(payload)
    _validate_binding_shape(binding, generation=generation)
    if hashlib.sha256(payload).hexdigest() != digest:
        raise _InvalidEvidence("previous binding drift")
    document_payload, document_proof = _read_private_file_at(
        generation_fd,
        "account-usage-v2.json",
        path=generation_dir / "account-usage-v2.json",
        maximum=_MAX_PAYLOAD_BYTES,
    )
    if (
        len(document_payload) != binding["payload_size_bytes"]
        or hashlib.sha256(document_payload).hexdigest() != binding["payload_sha256"]
    ):
        raise _InvalidEvidence("previous payload digest drift")
    document = _load_canonical_json(document_payload)
    _validate_document(document, now=_parse_timestamp(document.get("generated_at")))
    return [generation_proof, binding_proof, document_proof]


def _validate_document(
    document: dict[str, Any], *, now: datetime
) -> tuple[str, dict[str, dict[str, Any]]]:
    if (
        set(document) != _DOCUMENT_FIELDS
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 2
    ):
        raise _InvalidEvidence("invalid payload schema")
    generated_at = _parse_timestamp(document.get("generated_at"))
    accounts = document.get("accounts")
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 100:
        raise _InvalidEvidence("invalid accounts")
    account_index: dict[str, dict[str, Any]] = {}
    quality: list[str] = []
    for account in accounts:
        if not isinstance(account, dict) or set(account) != _ACCOUNT_FIELDS:
            raise _InvalidEvidence("invalid account")
        account_id = account.get("account_id")
        if (
            not isinstance(account_id, str)
            or _ACCOUNT_ID_RE.fullmatch(account_id) is None
            or account_id in account_index
        ):
            raise _InvalidEvidence("invalid account id")
        freshness = account.get("freshness")
        if (
            not isinstance(freshness, dict)
            or set(freshness) != _FRESHNESS_FIELDS
            or not isinstance(freshness.get("stale"), bool)
        ):
            raise _InvalidEvidence("invalid freshness")
        captured_at = _parse_timestamp(freshness.get("captured_at"))
        fresh_until = _parse_timestamp(freshness.get("fresh_until"))
        if fresh_until != captured_at + timedelta(seconds=900):
            raise _InvalidEvidence("invalid freshness range")
        limits = account.get("limits")
        trackers = account.get("tracker_evidence")
        status = account.get("status")
        if status not in {"ok", "partial", "error", "login_required", "unknown"}:
            raise _InvalidEvidence("invalid account status")
        if not isinstance(limits, list) or not isinstance(trackers, list):
            raise _InvalidEvidence("missing limit evidence")
        source_stale = (
            freshness["stale"] or generated_at > fresh_until or now > fresh_until
        )
        if status in {"error", "login_required", "unknown"}:
            if limits or trackers:
                raise _InvalidEvidence("status account has evidence")
            quality.append("stale" if source_stale else "partial")
            account_index[account_id] = account
            continue
        if not limits or not trackers or len(limits) > 32 or len(trackers) > 32:
            raise _InvalidEvidence("missing limit evidence")
        limit_index: dict[tuple[str, int], dict[str, Any]] = {}
        for limit in limits:
            if not isinstance(limit, dict) or not _LIMIT_REQUIRED_FIELDS <= set(
                limit
            ) <= _LIMIT_REQUIRED_FIELDS | {"reset_at"}:
                raise _InvalidEvidence("invalid limit")
            pool = _source_pool(limit.get("pool"))
            window = limit.get("window_seconds")
            if (
                not isinstance(window, int)
                or isinstance(window, bool)
                or window not in _WINDOW_SECONDS
            ):
                raise _InvalidEvidence("invalid limit window")
            used = _number(limit.get("used_percent"))
            remaining = _number(limit.get("remaining_percent"))
            if (
                not 0 <= used <= 100
                or not 0 <= remaining <= 100
                or not math.isclose(used + remaining, 100, rel_tol=0, abs_tol=1e-9)
            ):
                raise _InvalidEvidence("invalid limit percentage")
            if "reset_at" in limit:
                _parse_timestamp(limit["reset_at"])
            key = (pool, window)
            if key in limit_index:
                raise _InvalidEvidence("duplicate limit")
            limit_index[key] = limit
        tracker_index: dict[tuple[str, int], dict[str, Any]] = {}
        tracker_quality = "complete"
        for tracker in trackers:
            if not isinstance(tracker, dict) or set(tracker) != _TRACKER_FIELDS:
                raise _InvalidEvidence("invalid tracker")
            pool = tracker.get("pool")
            window = tracker.get("limit_window_seconds")
            coverage = tracker.get("coverage")
            if (
                pool not in {"main", _SPARK_POOL}
                or not isinstance(window, int)
                or isinstance(window, bool)
                or window not in _WINDOW_SECONDS
                or coverage not in {"complete", "partial", "insufficient", "stale"}
            ):
                raise _InvalidEvidence("invalid tracker window")
            if tracker.get("ema_time_constant_seconds") != 3_600:
                raise _InvalidEvidence("invalid tracker EMA")
            first_sample = _parse_timestamp(tracker.get("first_sample_at"))
            last_sample = _parse_timestamp(tracker.get("last_sample_at"))
            if last_sample < first_sample:
                raise _InvalidEvidence("invalid tracker range")
            sample_count = tracker.get("sample_count")
            if (
                not isinstance(sample_count, int)
                or isinstance(sample_count, bool)
                or not 1 <= sample_count <= 500_000
            ):
                raise _InvalidEvidence("invalid tracker sample count")
            rate = _number(tracker.get("rate_percentage_points_per_second"))
            projected = _number(tracker.get("projected_used_percent_at_reset"))
            if not 0 <= rate <= 100 or not 0 <= projected <= 100:
                raise _InvalidEvidence("invalid tracker rate")
            _printable_ascii_token(tracker.get("reset_generation"), maximum=128)
            key = (pool, window)
            limit = limit_index.get(key)
            if key in tracker_index or limit is None:
                raise _InvalidEvidence("main/spark mismatch")
            tracker_index[key] = tracker
            sample_age = (now - last_sample).total_seconds()
            if sample_age < 0:
                raise _InvalidEvidence("future tracker sample")
            if coverage in {"complete", "partial"}:
                if sample_count < 2 or sample_age > 900:
                    raise _InvalidEvidence("invalid tracker freshness")
            elif coverage == "stale":
                if sample_age <= 900:
                    raise _InvalidEvidence("invalid stale tracker")
            reset_at = limit.get("reset_at")
            active_reset = (
                isinstance(reset_at, str) and _parse_timestamp(reset_at) > now
            )
            if coverage == "stale":
                tracker_quality = "stale"
            elif coverage != "complete" or sample_count < 2 or not active_reset:
                tracker_quality = "partial"
        if source_stale or tracker_quality == "stale":
            quality.append("stale")
        elif status != "ok" or tracker_quality != "complete":
            quality.append("partial")
        else:
            quality.append("complete")
        account_index[account_id] = account
    if "stale" in quality:
        return "stale", account_index
    if "partial" in quality:
        return "partial", account_index
    return "complete", account_index


def _lock_name(target: Path) -> str:
    return hashlib.sha256(os.fsencode(os.path.abspath(target))).hexdigest() + ".lock"


@contextmanager
def _shared_locks(
    paths: _EvidencePaths, release_target: Path, current_target: Path
) -> Iterator[list[_Proof]]:
    lock_root = paths.lock_home / ".local/state/codex-usage/locks"
    handles: list[Any] = []
    held_fds: list[int] = []
    proofs: list[_Proof] = []
    try:
        lock_home_fd, lock_home_proof = _open_private_root_directory(paths.lock_home)
        held_fds.append(lock_home_fd)
        proofs.append(lock_home_proof)
        local_fd, local_proof = _open_private_directory_at(
            lock_home_fd, ".local", path=paths.lock_home / ".local"
        )
        held_fds.append(local_fd)
        proofs.append(local_proof)
        state_fd, state_proof = _open_private_directory_at(
            local_fd, "state", path=paths.lock_home / ".local/state"
        )
        held_fds.append(state_fd)
        proofs.append(state_proof)
        app_fd, app_proof = _open_private_directory_at(
            state_fd, "codex-usage", path=paths.lock_home / ".local/state/codex-usage"
        )
        held_fds.append(app_fd)
        proofs.append(app_proof)
        root_fd, root_proof = _open_private_directory_at(
            app_fd, "locks", path=lock_root
        )
        held_fds.append(root_fd)
        proofs.append(root_proof)
        for target in (release_target, current_target):
            name = _lock_name(target)
            lock_path = lock_root / name
            before = _named_stat(root_fd, name)
            _validate_private_file(before, maximum=_MAX_POINTER_BYTES, minimum=0)
            try:
                handle = os.fdopen(
                    os.open(
                        name,
                        os.O_RDWR
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=root_fd,
                    ),
                    "r+b",
                    buffering=0,
                )
            except OSError as exc:
                raise _InvalidEvidence("unsafe lock open") from exc
            if not _same_identity(
                before, os.fstat(handle.fileno())
            ) or not _same_identity(before, _named_stat(root_fd, name)):
                handle.close()
                raise _InvalidEvidence("lock changed during open")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise _BusyEvidence("lock busy") from exc
            handles.append(handle)
            proofs.append(
                _Proof(
                    lock_path,
                    _identity(before),
                    parent_fd=root_fd,
                    name=name,
                    descriptor=handle.fileno(),
                )
            )
        yield proofs
    finally:
        for handle in reversed(handles):
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
        for descriptor in reversed(held_fds):
            os.close(descriptor)


def _before_payload_recheck(_fd: int, _name: str, _held: int) -> None:
    """Test hook for proving that the post-read identity check is live."""


def _read_current_evidence(
    paths: _EvidencePaths, *, now: datetime | None = None
) -> EvidenceReadResult:
    now = now or _utc_now()
    held_fds: list[int] = []
    try:
        state_home = paths.state_home
        app = state_home / "codex-usage"
        integration = app / "integration"
        generations = integration / "generations"
        state_fd, state_proof = _open_private_root_directory(state_home)
        held_fds.append(state_fd)
        app_fd, app_proof = _open_private_directory_at(
            state_fd, "codex-usage", path=app
        )
        held_fds.append(app_fd)
        integration_fd, integration_proof = _open_private_directory_at(
            app_fd, "integration", path=integration
        )
        held_fds.append(integration_fd)
        generations_fd, generations_proof = _open_private_directory_at(
            integration_fd, "generations", path=generations
        )
        held_fds.append(generations_fd)
        directory_proofs = [
            state_proof,
            app_proof,
            integration_proof,
            generations_proof,
        ]
        current = integration / "current.json"
        with _shared_locks(
            paths, integration / "producer-install", current
        ) as lock_proofs:
            active, active_payload, active_proofs = _verify_active(
                paths, integration_fd, integration, held_fds
            )
            current_payload, current_proof = _read_private_file_at(
                integration_fd,
                "current.json",
                path=current,
                maximum=_MAX_POINTER_BYTES,
            )
            pointer = _load_canonical_json(current_payload)
            _validate_pointer(pointer)
            generation = pointer["current_generation_id"]
            generation_dir = generations / generation
            try:
                generation_fd, generation_proof = _open_private_directory_at(
                    generations_fd, generation, path=generation_dir
                )
            except _UnavailableEvidence as exc:
                raise _InvalidEvidence("pointer references missing generation") from exc
            held_fds.append(generation_fd)
            _generation_file_names(generation_fd)
            binding_payload, binding_proof = _read_private_file_at(
                generation_fd,
                "account-usage-v2.binding.json",
                path=generation_dir / "account-usage-v2.binding.json",
                maximum=_MAX_BINDING_BYTES,
            )
            binding = _load_canonical_json(binding_payload)
            active_digest = hashlib.sha256(active_payload).hexdigest()
            _validate_binding(
                binding,
                generation=generation,
                active=active,
                active_sha256=active_digest,
            )
            if (
                hashlib.sha256(binding_payload).hexdigest()
                != pointer["current_binding_sha256"]
            ):
                raise _InvalidEvidence("binding digest drift")
            payload_path = generation_dir / "account-usage-v2.json"
            document_payload, document_proof = _read_private_file_at(
                generation_fd,
                "account-usage-v2.json",
                path=payload_path,
                maximum=_MAX_PAYLOAD_BYTES,
            )
            if (
                len(document_payload) != binding["payload_size_bytes"]
                or hashlib.sha256(document_payload).hexdigest()
                != binding["payload_sha256"]
            ):
                raise _InvalidEvidence("payload digest drift")
            document = _load_canonical_json(document_payload)
            previous_proofs = _validate_previous_binding(
                generations_fd, generations, pointer, held_fds
            )
            _before_payload_recheck(-1, payload_path.name, len(document_payload))
            active_post_payload, active_post_proof = _read_private_file_at(
                integration_fd,
                "active.json",
                path=integration / "active.json",
                maximum=_MAX_ACTIVE_BYTES,
            )
            current_post_payload, current_post_proof = _read_private_file_at(
                integration_fd,
                "current.json",
                path=current,
                maximum=_MAX_POINTER_BYTES,
            )
            if (
                active_post_payload != active_payload
                or current_post_payload != current_payload
            ):
                raise _InvalidEvidence("evidence control file changed after read")
            for proof in [
                *directory_proofs,
                *lock_proofs,
                *active_proofs,
                current_proof,
                generation_proof,
                binding_proof,
                document_proof,
                *previous_proofs,
                active_post_proof,
                current_post_proof,
            ]:
                _recheck(proof)
            status, _ = _validate_document(document, now=now)
    except _BusyEvidence:
        return EvidenceReadResult(
            status="busy", error_code="usage_evidence_producer_unavailable"
        )
    except _UnavailableEvidence:
        return EvidenceReadResult(
            status="unavailable", error_code="usage_evidence_producer_unavailable"
        )
    except _InvalidEvidence:
        return EvidenceReadResult(
            status="invalid", error_code="usage_evidence_producer_unavailable"
        )
    finally:
        for descriptor in reversed(held_fds):
            os.close(descriptor)
    return EvidenceReadResult(
        status=status,
        document=document,
        generation_id=generation,
        automatic_decisions_allowed=status == "complete",
        error_code=None
        if status == "complete"
        else "usage_evidence_producer_unavailable",
    )


def _pool_view(
    account: dict[str, Any], pool: str, *, active_fast: bool
) -> dict[str, Any]:
    limit = next(
        item
        for item in account["limits"]
        if item["pool"] == pool and item["window_seconds"] == 18_000
    )
    tracker = next(
        item
        for item in account["tracker_evidence"]
        if item["pool"] == pool and item["limit_window_seconds"] == 18_000
    )
    projected = float(tracker["projected_used_percent_at_reset"])
    action = "keep_fast" if active_fast else ("activate" if projected >= 75 else "flex")
    return {
        "pool": pool,
        "window_seconds": 18_000,
        "used_percent": limit["used_percent"],
        "remaining_percent": limit["remaining_percent"],
        "projected_used_percent_at_reset": projected,
        "recommended_action": action,
    }


def evaluate_account(account: str, *, active_fast: bool = False) -> dict[str, Any]:
    if not isinstance(account, str) or not account or len(account) > 64:
        return {
            "account": account if isinstance(account, str) else None,
            "status": "invalid",
            "recommended_action": "flex",
            "error_code": "usage_evidence_producer_unavailable",
        }
    evidence = _read_current_evidence(_production_paths(), now=_utc_now())
    if not evidence.automatic_decisions_allowed or evidence.document is None:
        return {
            "account": account,
            "status": evidence.status,
            "recommended_action": "flex",
            "error_code": "usage_evidence_producer_unavailable",
        }
    selected = next(
        (
            item
            for item in evidence.document["accounts"]
            if item["account_id"] == account
        ),
        None,
    )
    if selected is None:
        return {
            "account": account,
            "status": "partial",
            "recommended_action": "flex",
            "error_code": "usage_evidence_producer_unavailable",
        }
    main = _pool_view(selected, "main", active_fast=active_fast)
    result = {
        "account": account,
        "status": "complete",
        "generation_id": evidence.generation_id,
        "main": main,
        "recommended_action": main["recommended_action"],
        "raw_output": "not_returned",
    }
    if any(
        item["pool"] == _SPARK_POOL and item["limit_window_seconds"] == 18_000
        for item in selected["tracker_evidence"]
    ):
        result["spark"] = _pool_view(selected, _SPARK_POOL, active_fast=False)
    return result


def preferred_delta_window(
    payload: dict[str, Any], *, pool: str = "main"
) -> str | None:
    if not isinstance(payload, dict):
        return None
    try:
        _, accounts = _validate_document(
            payload, now=_parse_timestamp(payload.get("generated_at"))
        )
    except _InvalidEvidence:
        return None
    selected_pool = (
        _SPARK_POOL if pool == "spark" else "main" if pool == "main" else None
    )
    if selected_pool is None:
        return None
    if any(
        any(
            item["pool"] == selected_pool and item["window_seconds"] == 18_000
            for item in account["limits"]
        )
        for account in accounts.values()
    ):
        return "5h"
    return None


def refresh_usage_snapshots() -> dict[str, Any]:
    evidence = _read_current_evidence(_production_paths(), now=_utc_now())
    if evidence.status == "complete":
        return {"attempted": False, "ok": True, "status": "complete"}
    return {
        "attempted": False,
        "ok": False,
        "status": "unavailable",
        "error_code": "usage_evidence_producer_unavailable",
    }


def _validate_control_input(account: str, reason: str = "") -> None:
    if (
        not isinstance(account, str)
        or not account
        or len(account) > 64
        or not isinstance(reason, str)
        or len(reason) > 200
    ):
        raise ValueError("limit_tracker_input_invalid")


_spark_priority: dict[str, dict[str, str | bool]] = {}
_display_overrides: dict[str, dict[str, str | bool | None]] = {}
_queen_state: dict[str, Any] = {
    "state": "idle",
    "generation": 0,
    "children": [],
    "plans": [],
}


def set_spark_priority(
    account: str, *, enabled: bool, reason: str = ""
) -> dict[str, Any]:
    _validate_control_input(account, reason)
    if not isinstance(enabled, bool):
        raise ValueError("limit_tracker_input_invalid")
    if enabled:
        _spark_priority[account] = {"active": True, "reason": reason}
    else:
        _spark_priority.pop(account, None)
    return {"account": account, "active": enabled, "reason": reason if enabled else ""}


def spark_priority_active(account: str) -> bool:
    return _spark_priority.get(account, {}).get("active") is True


def set_emergency_display_override(
    account: str, *, enabled: bool, limit_window: str | None = None, reason: str = ""
) -> dict[str, Any]:
    _validate_control_input(account, reason)
    if not isinstance(enabled, bool) or limit_window not in {
        None,
        "5h",
        "weekly",
        "monthly",
        "spark",
    }:
        raise ValueError("limit_tracker_input_invalid")
    if enabled:
        _display_overrides[account] = {
            "enabled": True,
            "limit_window": limit_window,
            "reason": reason,
        }
    else:
        _display_overrides.pop(account, None)
    return {
        "account": account,
        "enabled": enabled,
        "limit_window": limit_window if enabled else None,
    }


def _queen_snapshot() -> dict[str, Any]:
    return {
        "state": _queen_state["state"],
        "generation": _queen_state["generation"],
        "queen_agent": _queen_state.get("queen_agent"),
        "children": list(_queen_state.get("children", [])),
        "current_plan": _queen_state.get("current_plan"),
        "plans": list(_queen_state.get("plans", [])),
        "emergency_active": _queen_state.get("emergency_active") is True,
        "reason": _queen_state.get("reason"),
        "blocked_reason": _queen_state.get("blocked_reason"),
        "raw_output": "not_returned",
    }


def _reset_runtime_state_for_tests() -> None:
    _spark_priority.clear()
    _display_overrides.clear()
    _queen_state.clear()
    _queen_state.update({"state": "idle", "generation": 0, "children": [], "plans": []})


def emergency_queen_status() -> dict[str, Any]:
    return _queen_snapshot()


def request_emergency_queen_work(*, reason: str) -> dict[str, Any]:
    if not isinstance(reason, str) or not reason or len(reason) > 200:
        raise ValueError("limit_tracker_input_invalid")
    if _queen_state["state"] != "idle":
        return {
            "queued": False,
            "duplicate": True,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    _queen_state.update(
        {
            "state": "requested",
            "generation": _queen_state["generation"] + 1,
            "reason": reason,
            "plans": [reason],
            "current_plan": reason,
            "emergency_active": True,
            "queen_agent": None,
            "children": [],
            "blocked_reason": None,
        }
    )
    return {
        "queued": True,
        "duplicate": False,
        "state": _queen_snapshot(),
        "raw_output": "not_returned",
    }


def set_emergency_queen_running(generation: int, agent: str) -> dict[str, Any]:
    if _queen_state["generation"] != generation or _queen_state["state"] not in {
        "requested",
        "blocked",
    }:
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    _validate_control_input(agent)
    _queen_state.update(
        {"state": "running", "queen_agent": agent, "emergency_active": True}
    )
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def set_emergency_queen_blocked(generation: int, reason: str) -> dict[str, Any]:
    if _queen_state["generation"] != generation:
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    if not isinstance(reason, str) or len(reason) > 200:
        raise ValueError("limit_tracker_input_invalid")
    _queen_state.update(
        {"state": "blocked", "blocked_reason": reason, "emergency_active": True}
    )
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def register_emergency_queen_child(generation: int, agent: str) -> dict[str, Any]:
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
    ):
        return {
            "updated": False,
            "reason": "invalid_generation",
            "raw_output": "not_returned",
        }
    try:
        _validate_control_input(agent)
    except ValueError:
        return {
            "updated": False,
            "reason": "invalid_agent",
            "raw_output": "not_returned",
        }
    if _queen_state["generation"] != generation or _queen_state["state"] == "idle":
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    if agent not in _queen_state["children"]:
        _queen_state["children"].append(agent)
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def unregister_emergency_queen_child(generation: int, agent: str) -> dict[str, Any]:
    if _queen_state["generation"] != generation:
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    _queen_state["children"] = [
        child for child in _queen_state["children"] if child != agent
    ]
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def advance_emergency_queen(
    generation: int, *, emergency_active: bool, completed_plan: str
) -> dict[str, Any]:
    if _queen_state["generation"] != generation or _queen_state["state"] not in {
        "running",
        "next",
        "finishing",
    }:
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    _queen_state["plans"] = [
        plan for plan in _queen_state["plans"] if plan != completed_plan
    ]
    if emergency_active:
        _queen_state.update(
            {
                "state": "next",
                "current_plan": _queen_state["plans"][0]
                if _queen_state["plans"]
                else None,
                "emergency_active": True,
            }
        )
    else:
        _queen_state.update(
            {"state": "draining", "current_plan": None, "emergency_active": False}
        )
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def finish_emergency_queen(generation: int) -> dict[str, Any]:
    if _queen_state["generation"] != generation:
        return {
            "updated": False,
            "state": _queen_snapshot(),
            "raw_output": "not_returned",
        }
    _queen_state.update(
        {
            "state": "idle",
            "plans": [],
            "children": [],
            "current_plan": None,
            "emergency_active": False,
        }
    )
    return {"updated": True, "state": _queen_snapshot(), "raw_output": "not_returned"}


def emergency_recommendation(
    evaluation: dict[str, Any], *, active_fast: bool = False
) -> str:
    if not isinstance(evaluation, dict) or evaluation.get("status") != "complete":
        return "flex"
    if active_fast:
        return "keep_fast"
    return (
        "activate"
        if evaluation.get("recommended_action") == "activate"
        and evaluation.get("hot_window") is True
        else "flex"
    )


def emergency_refresh_needed(
    evaluation: dict[str, Any], *, active_fast: bool = False
) -> bool:
    return emergency_recommendation(evaluation, active_fast=active_fast) in {
        "activate",
        "keep_fast",
    }
