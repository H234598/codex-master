"""Private, reversible provisioning for the single local Hive pilot.

This module owns only the offline administrative transition from the checked-in
empty Shadow config to the explicitly authorised pilot.  It intentionally
does not issue an account attestation, start a process, install anything, or
provide a second status/controller path.  Runtime/Doctor continue to assemble
the authoritative state through :mod:`codex_master.hive.runtime`.
"""

from __future__ import annotations

import argparse
import contextlib
from collections.abc import Iterator, Mapping
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import sys

from codex_master.hive.config import (
    AgentClassCatalogSnapshot,
    HiveConfig,
    HiveConfigError,
    load_agent_class_catalog_snapshot_bytes,
    load_hive_config_bytes,
)
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.runtime import (
    HiveRuntimeError,
    build_hive_runtime,
    enforced_pilot_gate,
    read_hive_runtime_evidence,
)
from codex_master.hive.state import HiveStateError, HiveStateStore


_CONFIG_NAME = "codex-hive.json"
_CATALOG_NAME = "codex-agent-classes.json"
_JOURNAL = PurePosixPath("pilot-provisioner.json")
_PRINCIPALS = PurePosixPath("principals.json")
_MAX_PUBLIC_INPUT_BYTES = 256 * 1024
_REPOSITORY = "codex-master"
_PRINCIPAL = "queen-codex-master"
_REMOTE = "https://github.com/H234598/codex-master.git"
_FEATURE_FLAGS = {
    "sp0_passive": False,
    "sp1_deadline": False,
    "sp2_secondary_model": False,
    "sp3_fairness": False,
}
_PUBLIC_FILE_MODE = 0o644
_REPOSITORY_MODES = frozenset({0o700, 0o750, 0o755})


class PilotProvisionerError(ValueError):
    """Raised with a redacted code when pilot administration is unsafe."""


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        value = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise PilotProvisionerError("pilot_config_invalid") from exc
    return (value + "\n").encode("utf-8")


def _config_digest(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _repository_config_digest() -> str:
    """Bind exactly the stable public repository identity used by this pilot."""

    return _config_digest(
        {
            "default_branch": "main",
            "remote_identity": _REMOTE,
            "repo_id": _REPOSITORY,
            "schema_version": 1,
        }
    )


def _shadow_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "shadow",
        "repositories": [],
        "principals": [],
        "feature_flags": dict(_FEATURE_FLAGS),
    }


def _pilot_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "enforced",
        "repositories": [
            {
                "repo_id": _REPOSITORY,
                "remote_identity": _REMOTE,
                "default_branch": "main",
                "config_digest": _repository_config_digest(),
            }
        ],
        "principals": [
            {
                "principal_id": "godbee-main",
                "class_id": "gottbiene",
                "parent_principal_id": None,
                "repo_id": None,
            },
            {
                "principal_id": _PRINCIPAL,
                "class_id": "koenigin",
                "parent_principal_id": "godbee-main",
                "repo_id": _REPOSITORY,
            },
        ],
        "feature_flags": dict(_FEATURE_FLAGS),
    }


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _input_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_absolute_path(path: object, *, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise PilotProvisionerError(code)
    return path


def _validate_directory_chain(path: Path) -> None:
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for item in reversed(chain):
        try:
            info = item.lstat()
        except OSError as exc:
            raise PilotProvisionerError("pilot_repository_untrusted") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PilotProvisionerError("pilot_repository_untrusted")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise PilotProvisionerError("pilot_repository_untrusted")


def _open_repository_root(repository_root: Path) -> tuple[int, tuple[int, int]]:
    repository_root = _validate_absolute_path(repository_root, code="pilot_repository_untrusted")
    _validate_directory_chain(repository_root)
    try:
        initial = repository_root.lstat()
        descriptor = os.open(
            repository_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise PilotProvisionerError("pilot_repository_untrusted") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) not in _REPOSITORY_MODES
            or _identity(initial) != _identity(opened)
        ):
            raise PilotProvisionerError("pilot_repository_untrusted")
        return descriptor, _identity(opened)
    except Exception:
        os.close(descriptor)
        raise


def _validate_public_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != _PUBLIC_FILE_MODE
        or info.st_size < 1
        or info.st_size > _MAX_PUBLIC_INPUT_BYTES
    ):
        raise PilotProvisionerError("pilot_config_untrusted")


def _read_regular(root_descriptor: int, name: str) -> tuple[bytes, tuple[int, int]]:
    try:
        initial = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        _validate_public_file(initial)
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_descriptor)
    except PilotProvisionerError:
        raise
    except OSError as exc:
        raise PilotProvisionerError("pilot_config_untrusted") from exc
    try:
        opened = os.fstat(descriptor)
        _validate_public_file(opened)
        if _identity(initial) != _identity(opened):
            raise PilotProvisionerError("pilot_config_untrusted")
        parts: list[bytes] = []
        remaining = _MAX_PUBLIC_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(parts)
        if len(raw) > _MAX_PUBLIC_INPUT_BYTES:
            raise PilotProvisionerError("pilot_config_untrusted")
        current = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        _validate_public_file(current)
        if _identity(opened) != _identity(current):
            raise PilotProvisionerError("pilot_config_untrusted")
        return raw, _identity(opened)
    except PilotProvisionerError:
        raise
    except OSError as exc:
        raise PilotProvisionerError("pilot_config_untrusted") from exc
    finally:
        os.close(descriptor)


def _verify_repository_root_binding(
    repository_root: Path,
    root_descriptor: int,
    expected_identity: tuple[int, int],
) -> None:
    try:
        current = repository_root.lstat()
        opened = os.fstat(root_descriptor)
    except OSError as exc:
        raise PilotProvisionerError("pilot_repository_untrusted") from exc
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) not in _REPOSITORY_MODES
        or _identity(current) != expected_identity
        or _identity(opened) != expected_identity
    ):
        raise PilotProvisionerError("pilot_repository_untrusted")


def _replace_config_atomically(
    repository_root: Path,
    root_descriptor: int,
    expected_root_identity: tuple[int, int],
    expected_identity: tuple[int, int],
    expected_config_digest: str,
    expected_catalog_digest: str,
    payload: bytes,
) -> None:
    """Commit one fully fsynced public config replacement after identity recheck."""

    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_PUBLIC_INPUT_BYTES:
        raise PilotProvisionerError("pilot_config_invalid")
    temporary = f".{_CONFIG_NAME}.{secrets.token_hex(16)}"
    descriptor: int | None = None
    try:
        _verify_repository_root_binding(repository_root, root_descriptor, expected_root_identity)
        current_raw, current_identity = _read_regular(root_descriptor, _CONFIG_NAME)
        catalog_raw, _catalog_identity = _read_regular(root_descriptor, _CATALOG_NAME)
        if (
            current_identity != expected_identity
            or _input_digest(current_raw) != expected_config_digest
        ):
            raise PilotProvisionerError("pilot_config_drift")
        if _input_digest(catalog_raw) != expected_catalog_digest:
            raise PilotProvisionerError("pilot_catalog_drift")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            _PUBLIC_FILE_MODE,
            dir_fd=root_descriptor,
        )
        os.fchmod(descriptor, _PUBLIC_FILE_MODE)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise PilotProvisionerError("pilot_config_write_failed")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        current_raw, current_identity = _read_regular(root_descriptor, _CONFIG_NAME)
        catalog_raw, _catalog_identity = _read_regular(root_descriptor, _CATALOG_NAME)
        if (
            current_identity != expected_identity
            or _input_digest(current_raw) != expected_config_digest
        ):
            raise PilotProvisionerError("pilot_config_drift")
        if _input_digest(catalog_raw) != expected_catalog_digest:
            raise PilotProvisionerError("pilot_catalog_drift")
        _verify_repository_root_binding(repository_root, root_descriptor, expected_root_identity)
        os.replace(temporary, _CONFIG_NAME, src_dir_fd=root_descriptor, dst_dir_fd=root_descriptor)
        temporary = ""
        replaced = os.stat(_CONFIG_NAME, dir_fd=root_descriptor, follow_symlinks=False)
        _validate_public_file(replaced)
        os.fsync(root_descriptor)
        _verify_repository_root_binding(repository_root, root_descriptor, expected_root_identity)
    except PilotProvisionerError:
        raise
    except OSError as exc:
        raise PilotProvisionerError("pilot_config_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=root_descriptor)


@contextlib.contextmanager
def _opened_inputs(repository_root: Path) -> Iterator[tuple[int, tuple[int, int], AgentClassCatalogSnapshot, HiveConfig, tuple[int, int], str, str, HiveConfig, bytes]]:
    root_descriptor, root_identity = _open_repository_root(repository_root)
    try:
        catalog_raw, _ = _read_regular(root_descriptor, _CATALOG_NAME)
        config_raw, config_identity = _read_regular(root_descriptor, _CONFIG_NAME)
        try:
            snapshot = load_agent_class_catalog_snapshot_bytes(catalog_raw)
            current = load_hive_config_bytes(config_raw, snapshot.classes)
            target_bytes = _canonical_bytes(_pilot_payload())
            target = load_hive_config_bytes(target_bytes, snapshot.classes)
        except HiveConfigError as exc:
            raise PilotProvisionerError("pilot_config_invalid") from exc
        gate = enforced_pilot_gate(target, snapshot.classes, object())
        if gate.get("reason_code") == "pilot_config_invalid":
            raise PilotProvisionerError("pilot_profile_invalid")
        yield (
            root_descriptor,
            root_identity,
            snapshot,
            current,
            config_identity,
            _input_digest(config_raw),
            _input_digest(catalog_raw),
            target,
            target_bytes,
        )
    finally:
        os.close(root_descriptor)


def _is_shadow_baseline(config: HiveConfig) -> bool:
    return (
        config.mode == "shadow"
        and not config.repositories
        and not config.principals
        and dict(config.feature_flags) == _FEATURE_FLAGS
    )


def _is_target(config: HiveConfig, target: HiveConfig) -> bool:
    return config.digest == target.digest and config.mode == "enforced"


def _has_canonical_repository_binding(config: HiveConfig) -> bool:
    expected = _pilot_payload()["repositories"]
    return (
        len(config.repositories) == len(expected)
        and all(
            isinstance(repository, Mapping) and dict(repository) == required
            for repository, required in zip(config.repositories, expected, strict=True)
        )
    )


def _assert_canonical_repository(
    repository_root: Path, target: HiveConfig, current: HiveConfig | None = None
) -> None:
    binding = RepositoryBinding(
        _REPOSITORY,
        _REMOTE,
        repository_root,
        "main",
        _repository_config_digest(),
    )
    if not RepositoryRegistry((binding,)).validate(_REPOSITORY).allowed:
        raise PilotProvisionerError("pilot_repository_invalid")
    if not _has_canonical_repository_binding(target):
        raise PilotProvisionerError("pilot_repository_invalid")
    if current is not None and current.mode == "enforced" and not _has_canonical_repository_binding(current):
        raise PilotProvisionerError("pilot_repository_invalid")


def _journal_payload(phase: str, target: HiveConfig) -> dict[str, object]:
    return {
        "schema_version": 1,
        "phase": phase,
        "target_config_digest": target.digest,
    }


def _read_journal_locked(store: HiveStateStore, target: HiveConfig) -> str | None:
    try:
        payload = store.read_json_locked(_JOURNAL, max_bytes=4096)
    except HiveStateError as exc:
        if str(exc) == "state_not_found":
            return None
        raise PilotProvisionerError("pilot_state_unavailable") from exc
    if (
        set(payload) != {"schema_version", "phase", "target_config_digest"}
        or payload.get("schema_version") != 1
        or payload.get("phase") not in {"prepared", "committed", "killed", "rolled_back"}
        or payload.get("target_config_digest") != target.digest
    ):
        raise PilotProvisionerError("pilot_journal_invalid")
    return str(payload["phase"])


def _write_journal_locked(store: HiveStateStore, phase: str, target: HiveConfig) -> None:
    try:
        store.replace_json_locked(_JOURNAL, _journal_payload(phase, target))
    except HiveStateError as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc


def _materialize_target(
    target: HiveConfig,
    snapshot: AgentClassCatalogSnapshot,
    repository_root: Path,
    state_root: Path,
    *,
    materialize: bool,
    read_only: bool = False,
) -> None:
    try:
        build_hive_runtime(
            target,
            snapshot.classes,
            repository_roots={_REPOSITORY: repository_root},
            state_root=state_root,
            materialize_principals=materialize,
            read_only=read_only,
        )
    except (HiveRuntimeError, HiveStateError, OSError, TypeError, ValueError) as exc:
        raise PilotProvisionerError("pilot_principal_state_invalid") from exc


def _validate_state_parent(state_root: Path) -> None:
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    parent = state_root.parent
    try:
        _validate_directory_chain(parent)
        parent_info = parent.lstat()
    except (OSError, PilotProvisionerError) as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc
    if (
        parent_info.st_uid != os.geteuid()
        or not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_IMODE(parent_info.st_mode) not in _REPOSITORY_MODES
    ):
        raise PilotProvisionerError("pilot_state_unavailable")


def _open_writable_state(state_root: Path) -> HiveStateStore:
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    _validate_state_parent(state_root)
    try:
        existing = state_root.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISDIR(existing.st_mode)
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o700
    ):
        raise PilotProvisionerError("pilot_state_unavailable")
    try:
        return HiveStateStore(state_root)
    except HiveStateError as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc


def _open_read_only_state(state_root: Path) -> HiveStateStore:
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    _validate_state_parent(state_root)
    try:
        existing = state_root.lstat()
    except OSError as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc
    if (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISDIR(existing.st_mode)
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o700
    ):
        raise PilotProvisionerError("pilot_state_unavailable")
    try:
        return HiveStateStore(state_root, read_only=True)
    except HiveStateError as exc:
        raise PilotProvisionerError("pilot_state_unavailable") from exc


def plan_pilot_provisioning(*, repository_root: Path, state_root: Path) -> Mapping[str, object]:
    """Validate the authorised target without creating any state."""

    _validate_absolute_path(state_root, code="pilot_state_unavailable")
    _validate_state_parent(state_root)
    with _opened_inputs(repository_root) as (_fd, _root_identity, _snapshot, current, _identity_value, _config_digest_value, _catalog_digest_value, target, _bytes):
        _assert_canonical_repository(repository_root, target, current)
        if not _is_shadow_baseline(current):
            raise PilotProvisionerError("pilot_config_drift")
    return {
        "operation": "plan",
        "allowed": True,
        "mode": "shadow_to_enforced",
        "repository": _REPOSITORY,
        "principal": _PRINCIPAL,
        "feature_flags": "all_off",
        "raw_output": "not_returned",
    }


def apply_pilot_provisioning(*, repository_root: Path, state_root: Path) -> Mapping[str, object]:
    """Prepare exact principal state and atomically expose the closed pilot config."""

    repository_root = _validate_absolute_path(repository_root, code="pilot_repository_untrusted")
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    with _opened_inputs(repository_root) as (
        _root_fd,
        _root_identity,
        _snapshot,
        current,
        _config_identity,
        _config_input_digest,
        _catalog_input_digest,
        target,
        _target_bytes,
    ):
        _assert_canonical_repository(repository_root, target, current)
    store = _open_writable_state(state_root)
    with store.locked():
        with _opened_inputs(repository_root) as (
            root_fd,
            root_identity,
            snapshot,
            current,
            config_identity,
            config_input_digest,
            catalog_input_digest,
            target,
            target_bytes,
        ):
            _assert_canonical_repository(repository_root, target, current)
            phase = _read_journal_locked(store, target)
            if phase is None:
                if not _is_shadow_baseline(current):
                    raise PilotProvisionerError("pilot_config_drift")
                _materialize_target(target, snapshot, repository_root, state_root, materialize=True)
                _write_journal_locked(store, "prepared", target)
                _assert_canonical_repository(repository_root, target, current)
                _replace_config_atomically(
                    repository_root,
                    root_fd,
                    root_identity,
                    config_identity,
                    config_input_digest,
                    catalog_input_digest,
                    target_bytes,
                )
                _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                _write_journal_locked(store, "committed", target)
                applied = True
            elif phase == "prepared":
                if _is_shadow_baseline(current):
                    _materialize_target(target, snapshot, repository_root, state_root, materialize=True)
                    _assert_canonical_repository(repository_root, target, current)
                    _replace_config_atomically(
                        repository_root,
                        root_fd,
                        root_identity,
                        config_identity,
                        config_input_digest,
                        catalog_input_digest,
                        target_bytes,
                    )
                elif not _is_target(current, target):
                    raise PilotProvisionerError("pilot_config_drift")
                _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                _write_journal_locked(store, "committed", target)
                applied = True
            elif phase == "committed":
                if not _is_target(current, target):
                    raise PilotProvisionerError("pilot_config_drift")
                _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                applied = False
            elif phase == "rolled_back" and _is_shadow_baseline(current):
                _materialize_target(target, snapshot, repository_root, state_root, materialize=True)
                _write_journal_locked(store, "prepared", target)
                _assert_canonical_repository(repository_root, target, current)
                _replace_config_atomically(
                    repository_root,
                    root_fd,
                    root_identity,
                    config_identity,
                    config_input_digest,
                    catalog_input_digest,
                    target_bytes,
                )
                _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                _write_journal_locked(store, "committed", target)
                applied = True
            else:
                raise PilotProvisionerError("pilot_reactivation_requires_rollback")
    return {
        "operation": "apply",
        "applied": applied,
        "repository": _REPOSITORY,
        "principal": _PRINCIPAL,
        "feature_flags": "all_off",
        "raw_output": "not_returned",
    }


def verify_pilot_provisioning(*, repository_root: Path, state_root: Path) -> Mapping[str, object]:
    """Verify config/state parity through the existing runtime assembler only."""

    repository_root = _validate_absolute_path(repository_root, code="pilot_repository_untrusted")
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    with _opened_inputs(repository_root) as (_fd, _root_identity, snapshot, current, _identity_value, _config_digest_value, _catalog_digest_value, target, _bytes):
        _assert_canonical_repository(repository_root, target, current)
        if not _is_target(current, target):
            raise PilotProvisionerError("pilot_config_drift")
        store = _open_read_only_state(state_root)
        with store.locked():
            if _read_journal_locked(store, target) != "committed":
                raise PilotProvisionerError("pilot_journal_invalid")
            _materialize_target(
                target, snapshot, repository_root, state_root, materialize=False, read_only=True
            )
    evidence = read_hive_runtime_evidence(
        catalog_path=repository_root / _CATALOG_NAME,
        config_path=repository_root / _CONFIG_NAME,
        state_root=state_root,
        repository_roots={_REPOSITORY: repository_root},
    )
    return {
        "operation": "verify",
        "configured": True,
        "mode": evidence.mode,
        "repository": evidence.repository,
        "principal": evidence.principal,
        "authority": evidence.authority,
        "pilot": evidence.pilot,
        "raw_output": "not_returned",
    }


def kill_switch_pilot_provisioning(*, repository_root: Path, state_root: Path) -> Mapping[str, object]:
    """Atomically return to the known Shadow config before any cleanup."""

    repository_root = _validate_absolute_path(repository_root, code="pilot_repository_untrusted")
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    shadow_bytes = _canonical_bytes(_shadow_payload())
    with _opened_inputs(repository_root) as (
        _root_fd,
        _root_identity,
        _snapshot,
        current,
        _config_identity,
        _config_input_digest,
        _catalog_input_digest,
        target,
        _target_bytes,
    ):
        _assert_canonical_repository(repository_root, target, current)
    store = _open_writable_state(state_root)
    with store.locked():
        with _opened_inputs(repository_root) as (
            root_fd,
            root_identity,
            _snapshot,
            current,
            config_identity,
            config_input_digest,
            catalog_input_digest,
            target,
            _target_bytes,
        ):
            _assert_canonical_repository(repository_root, target, current)
            phase = _read_journal_locked(store, target)
            if phase not in {"prepared", "committed", "killed"}:
                raise PilotProvisionerError("pilot_journal_invalid")
            if _is_target(current, target):
                _assert_canonical_repository(repository_root, target, current)
                _replace_config_atomically(
                    repository_root,
                    root_fd,
                    root_identity,
                    config_identity,
                    config_input_digest,
                    catalog_input_digest,
                    shadow_bytes,
                )
                _write_journal_locked(store, "killed", target)
                applied = True
            elif _is_shadow_baseline(current) and phase == "killed":
                applied = False
            else:
                raise PilotProvisionerError("pilot_config_drift")
    return {
        "operation": "kill-switch",
        "applied": applied,
        "mode": "shadow",
        "raw_output": "not_returned",
    }


def rollback_pilot_provisioning(*, repository_root: Path, state_root: Path) -> Mapping[str, object]:
    """Keep Shadow first, then remove only the validated initial principal file."""

    repository_root = _validate_absolute_path(repository_root, code="pilot_repository_untrusted")
    state_root = _validate_absolute_path(state_root, code="pilot_state_unavailable")
    shadow_bytes = _canonical_bytes(_shadow_payload())
    with _opened_inputs(repository_root) as (
        _root_fd,
        _root_identity,
        _snapshot,
        current,
        _config_identity,
        _config_input_digest,
        _catalog_input_digest,
        target,
        _target_bytes,
    ):
        _assert_canonical_repository(repository_root, target, current)
    store = _open_writable_state(state_root)
    with store.locked():
        with _opened_inputs(repository_root) as (
            root_fd,
            root_identity,
            snapshot,
            current,
            config_identity,
            config_input_digest,
            catalog_input_digest,
            target,
            _target_bytes,
        ):
            _assert_canonical_repository(repository_root, target, current)
            phase = _read_journal_locked(store, target)
            if phase not in {"prepared", "committed", "killed", "rolled_back"}:
                raise PilotProvisionerError("pilot_journal_invalid")
            if not (_is_target(current, target) or _is_shadow_baseline(current)):
                raise PilotProvisionerError("pilot_config_drift")
            if _is_target(current, target):
                _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                _assert_canonical_repository(repository_root, target, current)
                _replace_config_atomically(
                    repository_root,
                    root_fd,
                    root_identity,
                    config_identity,
                    config_input_digest,
                    catalog_input_digest,
                    shadow_bytes,
                )
            elif phase != "rolled_back":
                try:
                    _materialize_target(target, snapshot, repository_root, state_root, materialize=False)
                except PilotProvisionerError:
                    try:
                        store.read_private_bytes(_PRINCIPALS, max_bytes=4 * 1024 * 1024)
                    except HiveStateError as exc:
                        if str(exc) != "state_not_found":
                            raise PilotProvisionerError("pilot_principal_state_invalid") from exc
                    else:
                        raise
            try:
                store.remove_private_bytes(_PRINCIPALS)
            except HiveStateError as exc:
                raise PilotProvisionerError("pilot_state_unavailable") from exc
            _write_journal_locked(store, "rolled_back", target)
    return {
        "operation": "rollback",
        "applied": phase != "rolled_back",
        "mode": "shadow",
        "raw_output": "not_returned",
    }


def main(arguments: list[str] | None = None) -> int:
    """Run the sole tracked administrative interface for this offline slice."""

    parser = argparse.ArgumentParser(
        prog="codex-master-hive-pilot-provisioner",
        description="Plan or reversibly administer the single local Hive enforced pilot.",
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("plan", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--repository-root", required=True, type=Path)
        command.add_argument("--state-root", required=True, type=Path)
    for name in ("apply", "rollback", "kill-switch"):
        command = subparsers.add_parser(name)
        command.add_argument("--repository-root", required=True, type=Path)
        command.add_argument("--state-root", required=True, type=Path)
        command.add_argument(
            "--confirm",
            action="store_true",
            required=True,
            help="explicitly authorise this local administrative mutation",
        )
    args = parser.parse_args(arguments)
    operations = {
        "plan": plan_pilot_provisioning,
        "apply": apply_pilot_provisioning,
        "verify": verify_pilot_provisioning,
        "rollback": rollback_pilot_provisioning,
        "kill-switch": kill_switch_pilot_provisioning,
    }
    try:
        result = operations[args.operation](
            repository_root=args.repository_root,
            state_root=args.state_root,
        )
    except PilotProvisionerError as exc:
        print(json.dumps({"ok": False, "reason_code": str(exc), "raw_output": "not_returned"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


__all__ = [
    "PilotProvisionerError",
    "apply_pilot_provisioning",
    "kill_switch_pilot_provisioning",
    "plan_pilot_provisioning",
    "rollback_pilot_provisioning",
    "verify_pilot_provisioning",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
