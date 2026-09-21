"""D298's fail-closed lifecycle transaction for the hourly-probe runtime.

The module deliberately has one mutator (``cutover``).  ``status`` and
``verify`` only inspect bounded local data and systemd's user-manager state.
"""

from __future__ import annotations

import argparse
import ast
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import runpy
import shutil
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace

from the_hive.runtime_process import BoundedProcessError, run_bounded


_NEW_SERVICE = "the-hive-hive-hourly-probe.service"
_NEW_TIMER = "the-hive-hive-hourly-probe.timer"
_LEGACY_SERVICE = "codex-master-hive-hourly-probe.service"
_LEGACY_TIMER = "codex-master-hive-hourly-probe.timer"
_EIGHT_UTC_TERMS = "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC"
_MAX_UNIT_BYTES = 128 * 1024
_MAX_HEALTH_BYTES = 256 * 1024
_LOCK_NAME = ".runtime-lifecycle.lock"
_OBSERVATION_NAME = "runtime-lifecycle-probe-observation.json"
_MAX_OBSERVATION_BYTES = 4096
_PROBE_OBSERVATION_SECONDS = 120.0
_PROBE_OUTPUT_BYTES = 16 * 1024
_PRODUCER_CONSUMER_CONTRACT = {
    "_PRODUCER_VERSION": "0.6.541",
    "_PRODUCER_SOURCE_MANIFEST_SHA256": "4cb02fabfb5a4b306e789cf685a6a83838e7fdd7f42e7f1af3491afd1723c7ce",
    "_PRODUCER_RELEASE_ID": "0.6.541-4cb02fabfb5a4b30",
}

Systemctl = Callable[[tuple[str, ...]], Mapping[str, str]]


class RuntimeLifecycleError(ValueError):
    """A stable, data-sparse lifecycle failure code."""


def _error(code: str) -> RuntimeLifecycleError:
    return RuntimeLifecycleError(code)


@dataclass(frozen=True, slots=True)
class _BoundCutover:
    home: Path
    release_root: Path
    units: Path
    state_root: Path
    files: tuple[tuple[Path, bytes | None, int], ...]
    source_digests: tuple[tuple[Path, str], ...]
    source_commit: str
    generations_before: frozenset[str]
    legacy_present: bool
    states: tuple[tuple[str, Mapping[str, str]], ...]
    source_tree_digest: str = ""


@dataclass(frozen=True, slots=True)
class _ProbeObservationBinding:
    """The installed, argumentless launcher and its current attested image."""

    generation: str
    manifest_digest: str
    launcher_sha256: str
    launcher: Path
    runtime_layout: object


@dataclass(frozen=True, slots=True)
class _PostInstallBinding:
    """The new attested image and pair of installed units before manager use."""

    identity: tuple[str, str]
    service: bytes
    timer: bytes


@dataclass(frozen=True, slots=True)
class _InstallerEntry:
    descriptor: int
    identity: tuple[int, int, int, int, int]
    digest: str


def _home_paths(home: Path) -> tuple[Path, Path, Path, Path]:
    if not isinstance(home, Path) or not home.is_absolute():
        raise _error("runtime_lifecycle_home_invalid")
    return (
        home / ".local" / "lib" / "the-hive-runtime",
        home / ".config" / "systemd" / "user",
        home / ".local" / "state" / "codex-master-mcp",
        home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
    )


def _private_directory(path: Path) -> None:
    try:
        item = path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise _error("runtime_lifecycle_lock_invalid")


def _bound_path_from_home(home: Path, path: Path) -> None:
    """Reject a symlink or writable parent in an existing home-relative path."""

    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    current = home
    try:
        root = current.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if (
        stat.S_ISLNK(root.st_mode)
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    for part in relative.parts:
        current /= part
        try:
            item = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _error("runtime_lifecycle_binding_invalid") from exc
        if stat.S_ISLNK(item.st_mode):
            raise _error("runtime_lifecycle_binding_invalid")
        if current != path and (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise _error("runtime_lifecycle_binding_invalid")


def _regular_bytes(
    path: Path, *, maximum: int, mode: int | None = None
) -> bytes | None:
    """Read one own, no-follow regular file or return absent; reject all else."""

    descriptor = -1
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_size <= 0
        or before.st_size > maximum
        or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != before.st_uid
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
            or (mode is not None and stat.S_IMODE(opened.st_mode) != mode)
        ):
            raise _error("runtime_lifecycle_binding_invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(value) != before.st_size
        or after.st_ino != before.st_ino
        or len(value) > maximum
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    return value


def _source_digest(path: Path) -> str:
    value = _regular_bytes(path, maximum=2 * 1024 * 1024)
    if value is None:
        raise _error("runtime_lifecycle_source_invalid")
    try:
        item = path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise _error("runtime_lifecycle_source_invalid")
    return hashlib.sha256(value).hexdigest()


def _source_tree_binding(repository: Path) -> tuple[str, str]:
    """Bind the entire clean tracked tree, not a selected source-file subset."""

    command_env = {"LANG": "C", "PATH": "/usr/bin:/bin"}
    commands = (
        ("status", "--porcelain=v1", "-z"),
        ("rev-parse", "--verify", "HEAD^{commit}"),
        ("rev-parse", "--verify", "HEAD^{tree}"),
        ("ls-tree", "-r", "-z", "HEAD"),
    )
    values: list[bytes] = []
    try:
        for arguments in commands:
            completed = subprocess.run(
                ["git", "-C", os.fspath(repository), *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=command_env,
            )
            if completed.returncode != 0:
                raise _error("runtime_lifecycle_source_invalid")
            values.append(completed.stdout)
    except OSError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    status, commit_raw, tree_raw, closure = values
    try:
        commit = commit_raw.decode("ascii", errors="strict").strip()
        tree = tree_raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    if (
        status
        or len(commit) != 40
        or len(tree) != 40
        or any(character not in "0123456789abcdef" for character in commit + tree)
        or not closure
    ):
        raise _error("runtime_lifecycle_source_dirty")
    return commit, hashlib.sha256(tree.encode("ascii") + b"\0" + closure).hexdigest()


@contextmanager
def _bound_installer_entry(repository: Path):
    """Hold the installer source FD across path loading and verify its identity."""

    path = repository / "scripts" / "the-hive-hive-hourly-probe-install"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > 2 * 1024 * 1024
        ):
            raise _error("runtime_lifecycle_source_entry_invalid")
        raw = bytearray()
        while len(raw) <= 2 * 1024 * 1024:
            part = os.read(descriptor, min(65536, 2 * 1024 * 1024 + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
        )
        if (
            len(raw) != before.st_size
            or len(raw) > 2 * 1024 * 1024
            or identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
            )
        ):
            raise _error("runtime_lifecycle_source_entry_invalid")
        yield _InstallerEntry(
            descriptor=descriptor,
            identity=identity,
            digest=hashlib.sha256(raw).hexdigest(),
        )
        current = path.lstat()
        if (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
        ) != identity or _source_digest(path) != hashlib.sha256(raw).hexdigest():
            raise _error("runtime_lifecycle_source_entry_changed")
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_source_entry_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bind_cutover_inputs(home: Path) -> _BoundCutover:
    """Bind exactly the source, pre-runtime and unit state before mutation."""

    release_root, units, state_root, legacy_launcher = _home_paths(home)
    try:
        home_info = home.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_home_invalid") from exc
    if (
        stat.S_ISLNK(home_info.st_mode)
        or not stat.S_ISDIR(home_info.st_mode)
        or home_info.st_uid != os.geteuid()
        or stat.S_IMODE(home_info.st_mode) & 0o022
    ):
        raise _error("runtime_lifecycle_home_invalid")
    for path in (release_root, units, state_root, legacy_launcher):
        _bound_path_from_home(home, path)
    repository = Path(__file__).resolve().parents[2]
    sources = (
        repository / "scripts" / "the-hive-hive-hourly-probe-install",
        repository / "src" / "the_hive" / "usage_snapshot.py",
        repository / "src" / "the_hive" / "limit_tracker.py",
        repository / "src" / "the_hive" / "runtime_lifecycle.py",
    )
    source_digests = tuple((path, _source_digest(path)) for path in sources)
    source_commit, source_tree_digest = _source_tree_binding(repository)
    generations = release_root / "generations"
    try:
        generations_before = frozenset(item.name for item in generations.iterdir())
    except FileNotFoundError:
        generations_before = frozenset()
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if any(
        not name or "/" in name or name in {".", ".."} for name in generations_before
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    files = (
        (
            release_root / ".the-hive-release-pointers.json",
            _regular_bytes(
                release_root / ".the-hive-release-pointers.json",
                maximum=_MAX_HEALTH_BYTES,
                mode=0o644,
            ),
            0o644,
        ),
        (
            release_root / "the-hive-mcp",
            _regular_bytes(
                release_root / "the-hive-mcp", maximum=_MAX_UNIT_BYTES, mode=0o755
            ),
            0o755,
        ),
        (
            legacy_launcher,
            _regular_bytes(legacy_launcher, maximum=_MAX_UNIT_BYTES, mode=0o755),
            0o755,
        ),
        (
            state_root / _OBSERVATION_NAME,
            _regular_bytes(
                state_root / _OBSERVATION_NAME,
                maximum=_MAX_OBSERVATION_BYTES,
                mode=0o600,
            ),
            0o600,
        ),
        *(
            (units / name, _unit_bytes(units, name), 0o644)
            for name in (_NEW_SERVICE, _NEW_TIMER, _LEGACY_SERVICE, _LEGACY_TIMER)
        ),
    )
    return _BoundCutover(
        home=home,
        release_root=release_root,
        units=units,
        state_root=state_root,
        files=files,
        source_digests=source_digests,
        source_commit=source_commit,
        generations_before=generations_before,
        legacy_present=any(
            value is not None
            for path, value, _mode in files
            if path.name in {_LEGACY_SERVICE, _LEGACY_TIMER}
        ),
        states=(),
        source_tree_digest=source_tree_digest,
    )


def _revalidate_cutover_inputs(bound: _BoundCutover) -> None:
    for path in (bound.release_root, bound.units, bound.state_root):
        _bound_path_from_home(bound.home, path)
    for path, digest in bound.source_digests:
        if _source_digest(path) != digest:
            raise _error("runtime_lifecycle_source_changed")
    if bound.source_tree_digest:
        repository = Path(__file__).resolve().parents[2]
        commit, tree_digest = _source_tree_binding(repository)
        if commit != bound.source_commit or tree_digest != bound.source_tree_digest:
            raise _error("runtime_lifecycle_source_changed")
    for path, content, mode in bound.files:
        maximum = (
            _MAX_HEALTH_BYTES
            if path.name == ".the-hive-release-pointers.json"
            else (
                _MAX_OBSERVATION_BYTES
                if path.name == _OBSERVATION_NAME
                else _MAX_UNIT_BYTES
            )
        )
        if _regular_bytes(path, maximum=maximum, mode=mode) != content:
            raise _error("runtime_lifecycle_input_changed")


def _bind_systemd_states(bound: _BoundCutover, systemctl: Systemctl) -> _BoundCutover:
    """Bind manager state before the installer changes either unit namespace."""

    states = tuple(
        (unit, _show(systemctl, unit))
        for unit in (_NEW_SERVICE, _NEW_TIMER, _LEGACY_SERVICE, _LEGACY_TIMER)
    )
    bound_states = dict(states)
    if any(not _valid_bound_unit_state(state) for state in bound_states.values()):
        raise _error("runtime_lifecycle_systemd_state_invalid")
    if (
        (
            _state_is_enabled(bound_states[_NEW_TIMER])
            and _state_is_enabled(bound_states[_LEGACY_TIMER])
        )
        or (
            _state_is_active(bound_states[_NEW_TIMER])
            and _state_is_active(bound_states[_LEGACY_TIMER])
        )
        or (
            _state_is_active(bound_states[_NEW_SERVICE])
            and _state_is_active(bound_states[_LEGACY_SERVICE])
        )
    ):
        raise _error("runtime_lifecycle_duplicate_preexisting")
    return replace(bound, states=states)


def _install_attested_runtime(home: Path) -> None:
    """Cross the existing attested-installer boundary; never compose a wrapper."""

    repository = Path(__file__).resolve().parents[2]
    try:
        _source_tree_binding(repository)
        with _bound_installer_entry(repository) as entry:
            installer = runpy.run_path(f"/proc/self/fd/{entry.descriptor}")
            install = installer.get("_install_attested_runtime")
            if not callable(install):
                raise _error("runtime_lifecycle_installer_invalid")
            result = install(home=home)
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_install_failed") from exc
    if not isinstance(result, Mapping) or result.get("status") != "installed":
        raise _error("runtime_lifecycle_install_failed")


def _bind_post_install(home: Path) -> _PostInstallBinding:
    """Attest the newly published image and exact new unit pair before use."""

    release_root, units, _state_root, _launcher = _home_paths(home)
    for path in (release_root, units):
        _bound_path_from_home(home, path)
    identity = _runtime_identity(release_root)
    if identity is None or identity.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_postinstall_invalid")
    generation = identity.get("generation")
    manifest_digest = identity.get("manifest_digest")
    if not isinstance(generation, str) or not isinstance(manifest_digest, str):
        raise _error("runtime_lifecycle_postinstall_invalid")
    service, timer = _attested_hourly_unit_bytes(
        release_root=release_root,
        generation=generation,
        manifest_digest=manifest_digest,
    )
    installed_service = _unit_bytes(units, _NEW_SERVICE)
    installed_timer = _unit_bytes(units, _NEW_TIMER)
    if installed_service != service or installed_timer != timer:
        raise _error("runtime_lifecycle_postinstall_invalid")
    return _PostInstallBinding(
        identity=(generation, manifest_digest),
        service=service,
        timer=timer,
    )


def _revalidate_post_install(bound: _PostInstallBinding, home: Path) -> None:
    if _bind_post_install(home) != bound:
        raise _error("runtime_lifecycle_postinstall_changed")


def _attested_hourly_unit_bytes(
    *, release_root: Path, generation: str, manifest_digest: str
) -> tuple[bytes, bytes]:
    """Render the installed pair only from the current manifest-attested image."""

    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_current_release(
            release_root, generation, manifest_digest
        )
        service_template = layout.read_attested_file(
            "systemd/user/the-hive-hive-hourly-probe.service"
        )
        timer = layout.read_attested_file(
            "systemd/user/the-hive-hive-hourly-probe.timer"
        )
        template = service_template.decode("utf-8")
    except (RuntimeLifecycleError, UnicodeDecodeError, ValueError) as exc:
        raise _error("runtime_lifecycle_postinstall_invalid") from exc
    if (
        template.count("@MASTERJET_GENERATION@") != 2
        or template.count("@MASTERJET_MANIFEST_DIGEST@") != 1
        or "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:%h/.local/lib/the-hive-runtime:norbind"
        not in template
    ):
        raise _error("runtime_lifecycle_postinstall_invalid")
    service = (
        template.replace("@MASTERJET_GENERATION@", generation)
        .replace("@MASTERJET_MANIFEST_DIGEST@", manifest_digest)
        .encode("utf-8")
    )
    expected = (
        "ExecStart=%h/.local/lib/the-hive-runtime/generations/"
        f"{generation}/bin/the-hive-hive-hourly-probe "
        "%h/.local/lib/the-hive-runtime "
        f"{generation} {manifest_digest} --json"
    )
    terms = [
        line.strip()
        for line in timer.decode("utf-8", errors="replace").splitlines()
        if line.strip().startswith("OnCalendar=")
    ]
    if (
        "@MASTERJET_" in service.decode("utf-8")
        or expected not in service.decode("utf-8")
        or terms != [_EIGHT_UTC_TERMS]
    ):
        raise _error("runtime_lifecycle_postinstall_invalid")
    return service, timer


def _systemctl_mutate(systemctl: Systemctl, arguments: tuple[str, ...]) -> None:
    try:
        result = systemctl(arguments)
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_systemd_failed") from exc
    if not isinstance(result, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in result.items()
    ):
        raise _error("runtime_lifecycle_systemd_invalid")


def _atomic_restore(path: Path, content: bytes, mode: int) -> None:
    descriptor = -1
    temporary = Path()
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.rollback.", dir=path.parent
        )
        temporary = Path(name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        temporary = Path()
    except OSError as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary != Path():
            try:
                temporary.unlink()
            except OSError:
                pass


def _remove_legacy_hourly_units(bound: _BoundCutover) -> None:
    for path, previous, mode in bound.files:
        if path.name not in {_LEGACY_SERVICE, _LEGACY_TIMER}:
            continue
        current = _regular_bytes(path, maximum=_MAX_UNIT_BYTES, mode=mode)
        if current != previous:
            raise _error("runtime_lifecycle_input_changed")
        if current is not None:
            try:
                path.unlink()
            except OSError as exc:
                raise _error("runtime_lifecycle_unit_remove_failed") from exc


def _legacy_requires_migration(bound: _BoundCutover) -> bool:
    states = dict(bound.states)
    return (
        bound.legacy_present
        or _state_is_enabled(states.get(_LEGACY_TIMER, {}))
        or _state_is_active(states.get(_LEGACY_TIMER, {}))
        or _state_is_active(states.get(_LEGACY_SERVICE, {}))
    )


def _revalidate_legacy_units(bound: _BoundCutover) -> None:
    """Keep each old-unit manager action bound to the exact pre-cutover pair."""

    _bound_path_from_home(bound.home, bound.units)
    for path, content, mode in bound.files:
        if path.name not in {_LEGACY_SERVICE, _LEGACY_TIMER}:
            continue
        if _regular_bytes(path, maximum=_MAX_UNIT_BYTES, mode=mode) != content:
            raise _error("runtime_lifecycle_legacy_changed")


def _discard_new_generation(bound: _BoundCutover) -> None:
    """Discard only this transaction's newly attested, unreferenced generation."""

    if bound.source_commit in bound.generations_before:
        return
    candidate = bound.release_root / "generations" / bound.source_commit
    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_runtime_root(candidate)
        raw = _regular_bytes(
            candidate / ".the-hive-runtime-manifest.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        manifest = json.loads(raw.decode("utf-8")) if raw is not None else None
        if (
            layout.root != candidate
            or not isinstance(manifest, dict)
            or manifest.get("generation") != bound.source_commit
            or manifest.get("commit") != bound.source_commit
        ):
            raise _error("runtime_lifecycle_rollback_failed")
        shutil.rmtree(candidate)
    except RuntimeLifecycleError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc


def _restore_bound_state(bound: _BoundCutover, systemctl: Systemctl) -> bool:
    """Restore every bound file before returning a failed transaction result."""

    try:
        for path, content, mode in bound.files:
            maximum = (
                _MAX_HEALTH_BYTES
                if path.name == ".the-hive-release-pointers.json"
                else (
                    _MAX_OBSERVATION_BYTES
                    if path.name == _OBSERVATION_NAME
                    else _MAX_UNIT_BYTES
                )
            )
            current = _regular_bytes(path, maximum=maximum, mode=mode)
            if content is None:
                if current is not None:
                    path.unlink()
            elif current != content:
                _atomic_restore(path, content, mode)
            if _regular_bytes(path, maximum=maximum, mode=mode) != content:
                raise _error("runtime_lifecycle_rollback_failed")
        _discard_new_generation(bound)
        _systemctl_mutate(systemctl, ("daemon-reload",))
        previous = dict(bound.states)
        # Quiesce the newly activated namespace before restoring an old active
        # one, so rollback also never creates a second running probe timer.
        for unit in (_NEW_TIMER, _NEW_SERVICE):
            state = previous.get(unit)
            operation = _restore_operation(unit, state)
            if operation is None:
                continue
            _systemctl_mutate(systemctl, operation)
        for unit in (_LEGACY_TIMER, _LEGACY_SERVICE):
            state = previous.get(unit)
            operation = _restore_operation(unit, state)
            if operation is None:
                continue
            _systemctl_mutate(systemctl, operation)
        for unit, expected in previous.items():
            actual = _show(systemctl, unit)
            if not _state_exactly_matches(actual, expected):
                return False
    except RuntimeLifecycleError:
        return False
    except OSError:
        return False
    return True


def _publish_rollback_failure(bound: _BoundCutover) -> bool:
    """Best-effort only after rollback loss: publish the canonical red Hive alarm.

    The transaction never continues on an alarm publication error; its returned
    stable failure code remains fail closed.  A malformed runtime cannot be
    allowed to select an arbitrary queen, so the probe API receives ``None``
    when the currently bound release no longer attests.
    """

    layout = None
    try:
        from the_hive.runtime_layout import RuntimeLayout

        raw = _regular_bytes(
            bound.release_root / ".the-hive-release-pointers.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        if raw is not None:
            pointer = json.loads(raw.decode("utf-8"))
            current = pointer.get("current") if isinstance(pointer, dict) else None
            if isinstance(current, dict):
                generation = current.get("generation")
                digest = current.get("manifest_digest")
                if isinstance(generation, str) and isinstance(digest, str):
                    layout = RuntimeLayout.from_current_release(
                        bound.release_root, generation, digest
                    )
    except (
        RuntimeLifecycleError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        layout = None
    try:
        from the_hive.hive.hourly_probe import publish_lifecycle_failure

        publish_lifecycle_failure(
            layout=layout,
            state_directory=bound.state_root,
            reason_code="runtime_lifecycle_rollback_failed",
        )
    except Exception:
        return False
    return True


def _unit_bytes(units: Path, name: str) -> bytes | None:
    return _regular_bytes(units / name, maximum=_MAX_UNIT_BYTES, mode=0o644)


def _systemctl_default(arguments: tuple[str, ...]) -> Mapping[str, str]:
    """Use the same UID's user manager with a bounded, data-sparse protocol."""

    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "--user", "--no-pager", *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            env={"LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error("runtime_lifecycle_systemd_unavailable") from exc
    if completed.returncode != 0:
        raise _error("runtime_lifecycle_systemd_failed")
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or len(key) > 64 or len(value) > 256:
            raise _error("runtime_lifecycle_systemd_invalid")
        result[key] = value
    return result


def _show(systemctl: Systemctl, unit: str) -> Mapping[str, str]:
    try:
        result = systemctl(
            (
                "show",
                unit,
                "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
            )
        )
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_systemd_unavailable") from exc
    if not isinstance(result, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in result.items()
    ):
        raise _error("runtime_lifecycle_systemd_invalid")
    return result


def _unit_state(systemctl: Systemctl, unit: str) -> Mapping[str, str]:
    try:
        return _show(systemctl, unit)
    except RuntimeLifecycleError as exc:
        return {"error": str(exc)}


def _state_is_enabled(state: Mapping[str, str]) -> bool:
    return state.get("UnitFileState") in {"enabled", "enabled-runtime"}


def _state_is_active(state: Mapping[str, str]) -> bool:
    return state.get("ActiveState") == "active"


def _valid_bound_unit_state(state: Mapping[str, str]) -> bool:
    """Accept only states for which rollback has a defined, safe operation."""

    load = state.get("LoadState")
    unit_file = state.get("UnitFileState")
    active = state.get("ActiveState")
    if load == "not-found":
        return unit_file == "disabled" and active == "inactive"
    return (
        load == "loaded"
        and unit_file
        in {"enabled", "enabled-runtime", "disabled", "masked", "static", "indirect"}
        and active in {"active", "inactive", "failed"}
    )


def _restore_operation(
    unit: str, state: Mapping[str, str] | None
) -> tuple[str, ...] | None:
    if state is None:
        return None
    if not _valid_bound_unit_state(state):
        raise _error("runtime_lifecycle_systemd_state_invalid")
    if state.get("LoadState") == "not-found":
        return None
    if unit.endswith(".timer"):
        return (
            ("enable", "--now", unit)
            if _state_is_enabled(state)
            else ("disable", "--now", unit)
        )
    return ("start", unit) if _state_is_active(state) else ("stop", unit)


def _state_exactly_matches(
    actual: Mapping[str, str], expected: Mapping[str, str]
) -> bool:
    return all(
        actual.get(key) == expected.get(key)
        for key in ("LoadState", "UnitFileState", "ActiveState")
    )


def _parse_health(state_root: Path) -> tuple[bool, bool]:
    """Return (health-v3-green, queen-alarm-cleared) without repairing anything."""

    try:
        raw = _regular_bytes(
            state_root / "hive-hourly-health.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o600,
        )
        if raw is None:
            return False, False
        value = json.loads(raw.decode("utf-8"))
    except (RuntimeLifecycleError, UnicodeDecodeError, json.JSONDecodeError):
        return False, False
    if not isinstance(value, dict) or value.get("schema_version") != 3:
        return False, False
    checks = value.get("checks")
    alarm = value.get("alarm")
    health = isinstance(checks, dict) and checks == {
        "runtime_layout": True,
        "hive_runtime": True,
        "hive_doctor": True,
    }
    cleared = (
        isinstance(alarm, dict)
        and alarm.get("scope") == "hive"
        and alarm.get("status") == "cleared"
        and alarm.get("reason_codes") == []
    )
    return health, cleared


def _runtime_identity(release_root: Path) -> dict[str, object] | None:
    try:
        from the_hive.runtime_layout import RuntimeLayout

        raw = _regular_bytes(
            release_root / ".the-hive-release-pointers.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        if raw is None:
            return None
        pointer = json.loads(raw.decode("utf-8"))
        if not isinstance(pointer, dict) or not isinstance(
            pointer.get("current"), dict
        ):
            return None
        current = pointer["current"]
        generation, digest = current.get("generation"), current.get("manifest_digest")
        if not isinstance(generation, str) or not isinstance(digest, str):
            return None
        layout = RuntimeLayout.from_current_release(release_root, generation, digest)
        consumer = layout.read_attested_file("src/the_hive/usage_snapshot.py")
        pin = _consumer_producer_contract(consumer)
        return {
            "generation": generation,
            "manifest_digest": digest,
            "consumer_pin": pin,
        }
    except (
        RuntimeLifecycleError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None


def _consumer_producer_contract(raw: bytes) -> bool:
    """Parse named consumer constants from the attested Runtime Image source."""

    try:
        module = ast.parse(raw.decode("utf-8"), mode="exec")
    except (SyntaxError, UnicodeDecodeError):
        return False
    values: dict[str, str] = {}
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        value = statement.value
        if (
            isinstance(target, ast.Name)
            and target.id in _PRODUCER_CONSUMER_CONTRACT
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            values[target.id] = value.value
    python_directory_contract = any(
        isinstance(node, ast.Compare)
        and len(node.ops) == len(node.comparators) == 1
        and isinstance(node.ops[0], ast.NotEq)
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == "python3.14"
        and isinstance(node.left, ast.Subscript)
        and isinstance(node.left.value, ast.Name)
        and node.left.value.id == "python_directory"
        and isinstance(node.left.slice, ast.Constant)
        and node.left.slice.value == 2
        for node in ast.walk(module)
    )
    return values == _PRODUCER_CONSUMER_CONTRACT and python_directory_contract


def _probe_observation_binding(
    *, home: Path, release_root: Path, identity: Mapping[str, object]
) -> _ProbeObservationBinding:
    """Bind the installed zero-argument launcher to its current image pair."""

    generation = identity.get("generation")
    manifest_digest = identity.get("manifest_digest")
    if (
        not isinstance(generation, str)
        or len(generation) != 40
        or any(character not in "0123456789abcdef" for character in generation)
        or not isinstance(manifest_digest, str)
        or not manifest_digest.startswith("sha256:")
        or len(manifest_digest) != 71
    ):
        raise _error("runtime_lifecycle_probe_binding_invalid")
    _release_root, _units, _state_root, launcher = _home_paths(home)
    _bound_path_from_home(home, launcher)
    launcher_bytes = _regular_bytes(launcher, maximum=_MAX_UNIT_BYTES, mode=0o755)
    if launcher_bytes is None:
        raise _error("runtime_lifecycle_probe_binding_invalid")
    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_current_release(
            release_root, generation, manifest_digest
        )
    except (ValueError, RuntimeLifecycleError) as exc:
        raise _error("runtime_lifecycle_probe_binding_invalid") from exc
    return _ProbeObservationBinding(
        generation=generation,
        manifest_digest=manifest_digest,
        launcher_sha256=hashlib.sha256(launcher_bytes).hexdigest(),
        launcher=launcher,
        runtime_layout=layout,
    )


def _observation_payload(
    binding: _ProbeObservationBinding, *, observed_at: datetime
) -> bytes:
    return (
        json.dumps(
            {
                "generation": binding.generation,
                "launcher_sha256": binding.launcher_sha256,
                "manifest_digest": binding.manifest_digest,
                "observed_at": observed_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "returncode": 0,
                "schema_version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_observation(state_root: Path, binding: _ProbeObservationBinding) -> None:
    """Atomically record only a successful bounded launcher invocation."""

    _regular_bytes(
        state_root / _OBSERVATION_NAME,
        maximum=_MAX_OBSERVATION_BYTES,
        mode=0o600,
    )
    _atomic_restore(
        state_root / _OBSERVATION_NAME,
        _observation_payload(binding, observed_at=datetime.now(UTC)),
        0o600,
    )


def _observation_matches(
    *, home: Path, state_root: Path, identity: Mapping[str, object] | None
) -> bool:
    """Read one exact receipt; never infer observation from other health data."""

    if identity is None:
        return False
    try:
        binding = _probe_observation_binding(
            home=home,
            release_root=_home_paths(home)[0],
            identity=identity,
        )
        raw = _regular_bytes(
            state_root / _OBSERVATION_NAME,
            maximum=_MAX_OBSERVATION_BYTES,
            mode=0o600,
        )
        if raw is None:
            return False
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "generation",
            "manifest_digest",
            "launcher_sha256",
            "observed_at",
            "returncode",
        }:
            return False
        observed_at = value.get("observed_at")
        if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
            return False
        parsed = datetime.fromisoformat(observed_at.removesuffix("Z") + "+00:00")
        age = (datetime.now(UTC) - parsed).total_seconds()
        return (
            value.get("schema_version") == 1
            and value.get("generation") == binding.generation
            and value.get("manifest_digest") == binding.manifest_digest
            and value.get("launcher_sha256") == binding.launcher_sha256
            and value.get("returncode") == 0
            and 0 <= age <= 4 * 60 * 60
        )
    except (
        RuntimeLifecycleError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return False


def _observe_argumentless_installed_probe(home: Path) -> None:
    """Run exactly the installed launcher with no arguments, then bind its receipt."""

    release_root, _units, state_root, _launcher = _home_paths(home)
    identity = _runtime_identity(release_root)
    if identity is None or identity.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_probe_binding_invalid")
    binding = _probe_observation_binding(
        home=home, release_root=release_root, identity=identity
    )
    try:
        result = run_bounded(
            (os.fspath(binding.launcher),),
            cwd=home,
            home=home,
            timeout_seconds=_PROBE_OBSERVATION_SECONDS,
            stdout_limit=_PROBE_OUTPUT_BYTES,
            stderr_limit=_PROBE_OUTPUT_BYTES,
            runtime_layout=binding.runtime_layout,
        )
    except BoundedProcessError as exc:
        raise _error("runtime_lifecycle_probe_observation_failed") from exc
    if result.returncode != 0:
        raise _error("runtime_lifecycle_probe_failed")
    current = _runtime_identity(release_root)
    if current is None or current.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_probe_binding_changed")
    rebound = _probe_observation_binding(
        home=home, release_root=release_root, identity=current
    )
    if rebound != binding:
        raise _error("runtime_lifecycle_probe_binding_changed")
    _write_observation(state_root, rebound)


def _d296_and_v2_accepted() -> bool:
    """Ask the independently bound V2 reader for the six fixed owner records."""

    try:
        from the_hive.usage_snapshot import read_usage_evidence_v2

        evidence = read_usage_evidence_v2()
    except Exception:
        return False
    expected = (
        "BW_Nufker",
        "BW_Privat",
        "BW_Work",
        "Birthe_Privat",
        "GPT1",
        "RH_Privat",
    )
    authorities = getattr(evidence, "pool_authorities", ())
    if getattr(evidence, "status", None) != "complete" or len(authorities) != len(
        expected
    ):
        return False
    observed = [
        (
            getattr(item, "account_id", None),
            getattr(item, "pool_id", None),
            getattr(item, "provider", None),
            getattr(item, "hive_available", None),
            tuple(getattr(item, "allowed_model_families", ())),
            getattr(item, "reasoning_minimum", None),
            getattr(item, "reasoning_maximum", None),
            tuple(getattr(item, "allowed_lifecycles", ())),
            getattr(item, "persistent_leadership_eligible", None),
            getattr(item, "long_running_leadership_eligible", None),
        )
        for item in authorities
    ]
    expected_records = [
        (
            account,
            "openai",
            "openai",
            True,
            ("luna", "sol", "terra"),
            "low",
            "max",
            ("ephemeral", "persistent", "session"),
            True,
            True,
        )
        for account in expected
    ]
    return sorted(observed) == sorted(expected_records)


def _probe_gate_allowed(state_root: Path) -> bool:
    try:
        from the_hive.hive.hourly_probe import read_probe_gate

        return (
            read_probe_gate(state_file=state_root / "hive-hourly-health.json").get(
                "allowed"
            )
            is True
        )
    except Exception:
        return False


def _verify_failure(code: str) -> dict[str, object]:
    """Return one bounded, stable red result without inspecting other paths."""

    return {
        "status": "runtime_lifecycle_red",
        "error_code": code,
        "installed": False,
        "enabled": False,
        "active": False,
        "observed": False,
        "runtime_identity": {
            "generation": None,
            "manifest_digest": None,
            "consumer_pin": False,
        },
        "checks": {
            "runtime_attested": False,
            "unit_files": False,
            "eight_utc_terms": False,
            "no_legacy_or_duplicate_timer": False,
            "v2_generation_and_d296_parity": False,
            "health_v3_green": False,
            "queen_alarm_cleared": False,
            "probe_gate_allowed": False,
            "argumentless_probe_observed": False,
        },
        "raw_output": "not_returned",
    }


def _verify_error_code(
    *, checks: Mapping[str, bool], enabled: bool, active: bool, observed: bool
) -> str | None:
    for check, code in (
        ("runtime_attested", "runtime_lifecycle_consumer_pin_invalid"),
        ("unit_files", "runtime_lifecycle_unit_files_invalid"),
        ("eight_utc_terms", "runtime_lifecycle_timer_terms_invalid"),
        ("no_legacy_or_duplicate_timer", "runtime_lifecycle_legacy_timer_present"),
        ("v2_generation_and_d296_parity", "runtime_lifecycle_v2_parity_invalid"),
        ("health_v3_green", "runtime_lifecycle_health_red"),
        ("queen_alarm_cleared", "runtime_lifecycle_queen_alarm_active"),
        ("probe_gate_allowed", "runtime_lifecycle_probe_gate_red"),
        ("argumentless_probe_observed", "runtime_lifecycle_probe_unobserved"),
    ):
        if checks[check] is not True:
            return code
    if not enabled:
        return "runtime_lifecycle_timer_disabled"
    if not active:
        return "runtime_lifecycle_timer_inactive"
    if not observed:
        return "runtime_lifecycle_probe_unobserved"
    return None


def verify(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Read only D298 postconditions; never starts, enables, or repairs a unit."""

    try:
        release_root, units, state_root, _legacy_launcher = _home_paths(home)
        for path in (release_root, units, state_root):
            _bound_path_from_home(home, path)
        service = _unit_bytes(units, _NEW_SERVICE)
        timer = _unit_bytes(units, _NEW_TIMER)
        legacy_service = _unit_bytes(units, _LEGACY_SERVICE)
        legacy_timer = _unit_bytes(units, _LEGACY_TIMER)
        identity = _runtime_identity(release_root)
        if identity is None:
            return _verify_failure("runtime_lifecycle_runtime_identity_invalid")
        generation = identity.get("generation")
        manifest_digest = identity.get("manifest_digest")
        if not isinstance(generation, str) or not isinstance(manifest_digest, str):
            return _verify_failure("runtime_lifecycle_runtime_identity_invalid")
        expected_service, expected_timer = _attested_hourly_unit_bytes(
            release_root=release_root,
            generation=generation,
            manifest_digest=manifest_digest,
        )
        if service != expected_service or timer != expected_timer:
            return _verify_failure("runtime_lifecycle_unit_attestation_invalid")
    except RuntimeLifecycleError as exc:
        code = str(exc)
        if code == "runtime_lifecycle_postinstall_invalid":
            code = "runtime_lifecycle_unit_attestation_invalid"
        return _verify_failure(code)
    timer_state = _unit_state(systemctl, _NEW_TIMER)
    old_timer_state = _unit_state(systemctl, _LEGACY_TIMER)
    old_service_state = _unit_state(systemctl, _LEGACY_SERVICE)
    for state in (timer_state, old_timer_state, old_service_state):
        error = state.get("error")
        if isinstance(error, str):
            return _verify_failure(error)
    runtime = identity.get("consumer_pin") is True
    unit_files = service is not None and timer is not None
    timer_terms = (
        [
            line.strip()
            for line in timer.decode("utf-8", errors="replace").splitlines()
            if line.strip().startswith("OnCalendar=")
        ]
        if timer is not None
        else []
    )
    eight = timer_terms == [_EIGHT_UTC_TERMS]
    no_old = (
        legacy_service is None
        and legacy_timer is None
        and old_timer_state.get("LoadState") in {None, "not-found"}
        and old_service_state.get("LoadState") in {None, "not-found"}
        and not _state_is_enabled(old_timer_state)
        and not _state_is_active(old_timer_state)
        and not _state_is_active(old_service_state)
    )
    health, alarm_cleared = _parse_health(state_root)
    v2 = _d296_and_v2_accepted()
    gate_allowed = _probe_gate_allowed(state_root)
    enabled, active = _state_is_enabled(timer_state), _state_is_active(timer_state)
    observed = _observation_matches(home=home, state_root=state_root, identity=identity)
    checks = {
        "runtime_attested": runtime,
        "unit_files": unit_files,
        "eight_utc_terms": eight,
        "no_legacy_or_duplicate_timer": no_old,
        "v2_generation_and_d296_parity": v2,
        "health_v3_green": health,
        "queen_alarm_cleared": alarm_cleared,
        "probe_gate_allowed": gate_allowed,
        "argumentless_probe_observed": observed,
    }
    all_green = all(checks.values()) and enabled and active and observed
    return {
        "status": "runtime_lifecycle_green" if all_green else "runtime_lifecycle_red",
        "error_code": _verify_error_code(
            checks=checks, enabled=enabled, active=active, observed=observed
        ),
        "installed": runtime and unit_files,
        "enabled": enabled,
        "active": active,
        "observed": observed,
        "runtime_identity": identity
        or {"generation": None, "manifest_digest": None, "consumer_pin": False},
        "checks": checks,
        "raw_output": "not_returned",
    }


def status(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Alias with the same read-only data-sparse contract as ``verify``."""

    return verify(home=home, systemctl=systemctl)


@contextmanager
def _lifecycle_lock(home: Path):
    lock = home / ".local" / "state" / "codex-master-mcp" / "hive" / _LOCK_NAME
    descriptor = -1
    try:
        for directory in (
            home / ".local",
            home / ".local" / "state",
            home / ".local" / "state" / "codex-master-mcp",
        ):
            _private_directory(directory)
        try:
            _private_directory(lock.parent)
        except RuntimeLifecycleError as exc:
            if str(exc) != "runtime_lifecycle_lock_invalid":
                raise
            try:
                lock.parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as create_exc:
                raise _error("runtime_lifecycle_lock_invalid") from create_exc
            _private_directory(lock.parent)
        descriptor = os.open(
            lock,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise _error("runtime_lifecycle_lock_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("runtime_lifecycle_busy") from exc
        yield
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def cutover(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Run the sole D298 mutating runtime/user-manager transaction."""

    try:
        with _lifecycle_lock(home):
            bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
            # A completely verified target is a no-op; it must not re-install
            # an image or perturb the user manager merely to prove idempotence.
            already_green = verify(home=home, systemctl=systemctl)
            if already_green.get("status") == "runtime_lifecycle_green":
                return already_green
            # This final rebind check deliberately remains outside the mutation
            # handler: a hostile replacement before installer entry must not
            # even cause a compensating manager reload.
            _revalidate_cutover_inputs(bound)
            try:
                # The preceding statement is immediately before crossing the
                # existing installer mutation boundary.
                _install_attested_runtime(home)
                post_install = _bind_post_install(home)
                if _legacy_requires_migration(bound):
                    _revalidate_legacy_units(bound)
                _revalidate_post_install(post_install, home)
                _systemctl_mutate(systemctl, ("daemon-reload",))
                if _legacy_requires_migration(bound):
                    _revalidate_legacy_units(bound)
                    _revalidate_post_install(post_install, home)
                    _systemctl_mutate(systemctl, ("stop", _LEGACY_SERVICE))
                    _revalidate_legacy_units(bound)
                    _revalidate_post_install(post_install, home)
                    _systemctl_mutate(systemctl, ("disable", "--now", _LEGACY_TIMER))
                _revalidate_post_install(post_install, home)
                _systemctl_mutate(systemctl, ("enable", "--now", _NEW_TIMER))
                _revalidate_post_install(post_install, home)
                _systemctl_mutate(systemctl, ("start", _NEW_SERVICE))
                _revalidate_post_install(post_install, home)
                _observe_argumentless_installed_probe(home)
                _remove_legacy_hourly_units(bound)
                _revalidate_post_install(post_install, home)
                _systemctl_mutate(systemctl, ("daemon-reload",))
                result = verify(home=home, systemctl=systemctl)
                if result.get("status") != "runtime_lifecycle_green":
                    raise _error("runtime_lifecycle_postconditions_failed")
                return result
            except RuntimeLifecycleError:
                if not _restore_bound_state(bound, systemctl):
                    if not _publish_rollback_failure(bound):
                        return {
                            "status": "runtime_lifecycle_rollback_alarm_failed",
                            "raw_output": "not_returned",
                        }
                    return {
                        "status": "runtime_lifecycle_rollback_failed",
                        "raw_output": "not_returned",
                    }
                raise
    except RuntimeLifecycleError as exc:
        return {"status": str(exc), "raw_output": "not_returned"}


def main() -> int:
    parser = argparse.ArgumentParser(prog="the-hive-runtime-service")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("cutover", "status", "verify"):
        child = commands.add_parser(command)
        child.add_argument("--home", type=Path, required=True)
    arguments = parser.parse_args()
    operation = {"cutover": cutover, "status": status, "verify": verify}[
        arguments.command
    ]
    result = operation(home=arguments.home)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "runtime_lifecycle_green" else 1


__all__ = ["cutover", "main", "status", "verify"]
