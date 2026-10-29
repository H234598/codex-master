"""Bounded subprocess support inside one non-delegated systemd cgroup-v2 unit."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator, Sequence
import contextlib
import ctypes
from dataclasses import asdict, dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from typing import Callable

from the_hive.runtime_layout import (
    LayoutError,
    RuntimeLayout,
    validate_runtime_metadata,
)


DEFAULT_STDOUT_LIMIT = 256 * 1024
DEFAULT_STDERR_LIMIT = 64 * 1024
_SYSTEMD_RUN = "/usr/bin/systemd-run"
_SYSTEMCTL = "/usr/bin/systemctl"
_ENV = "/usr/bin/env"
_CGROUP_ROOT = Path("/sys/fs/cgroup")
_RUNTIME_DIRECTORY_ROOT = Path("/run/user")
# ProtectHome=tmpfs recreates the UID runtime root. The Hourly unit exposes only
# the two manager sockets there; bounded child units mask both again.
_PROTECTED_HOME_RUNTIME_DIRECTORY = _RUNTIME_DIRECTORY_ROOT / str(os.geteuid())
BOUNDED_PROCESS_CLEANUP_SECONDS = 0.5
_PREEXEC_STAGE_CODES = frozenset(
    {
        "command_runtime_directory_unavailable",
        "command_spawn_helper_unavailable",
        "command_cgroup_preflight_unavailable",
        "command_manager_preflight_unavailable",
        "command_native_spawn_unavailable",
        "command_cgroup_bind_unavailable",
    }
)


class BoundedProcessError(RuntimeError):
    """A redacted subprocess failure that never carries child output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@contextlib.contextmanager
def _preexec_stage(code: str) -> Iterator[None]:
    """Replace only the legacy group collapse with one fixed stage code."""

    if code not in _PREEXEC_STAGE_CODES:
        raise BoundedProcessError("command_group_unavailable")
    try:
        yield
    except BoundedProcessError as exc:
        if exc.code != "command_group_unavailable":
            raise
        raise BoundedProcessError(code) from exc


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class G5ScopeIdentity:
    unit_name: str
    control_group: str
    invocation_id: str
    device: int
    inode: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"the-hive-resource-[0-9a-f]{32}\.scope", self.unit_name):
            raise BoundedProcessError("command_group_unavailable")
        if (
            not isinstance(self.control_group, str)
            or not 2 <= len(self.control_group) <= 512
        ):
            raise BoundedProcessError("command_group_unavailable")
        if not self.control_group.startswith("/") or self.control_group.endswith("/"):
            raise BoundedProcessError("command_group_unavailable")
        parts = self.control_group[1:].split("/")
        if (
            len(parts) < 2
            or any(
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}", part)
                for part in parts
            )
            or parts[-1] != self.unit_name
            or parts[-2] != "the-hive.slice"
            or parts.count("the-hive.slice") != 1
            or not (
                parts == ["the-hive.slice", self.unit_name] or parts[0] == "user.slice"
            )
        ):
            raise BoundedProcessError("command_group_unavailable")
        if not re.fullmatch(r"[0-9a-f]{32}", self.invocation_id):
            raise BoundedProcessError("command_group_unavailable")
        if type(self.device) is not int or self.device < 0:
            raise BoundedProcessError("command_group_unavailable")
        if type(self.inode) is not int or self.inode <= 0:
            raise BoundedProcessError("command_group_unavailable")


@dataclass(frozen=True, slots=True)
class _NativeSpawnHelper:
    library: object
    spawn: object


@dataclass(frozen=True, slots=True)
class _UnitSnapshot:
    control_group: Path | None
    invocation_id: str | None


@dataclass(slots=True)
class _SpawnedProcess:
    unit: str
    pidfd: int
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    cgroup: Path | None = None
    cgroup_fd: int = -1
    cgroup_identity: tuple[int, int] | None = None
    invocation_id: str | None = None
    returncode: int | None = None
    cgroup_released: bool = False


def _runtime_directory(*, bound_runtime_directory: Path | None = None) -> Path:
    """Return the canonical runtime directory or the one fixed Hourly bind."""

    if bound_runtime_directory is None:
        path = _RUNTIME_DIRECTORY_ROOT / str(os.geteuid())
    elif (
        not isinstance(bound_runtime_directory, Path)
        or bound_runtime_directory != _PROTECTED_HOME_RUNTIME_DIRECTORY
    ):
        raise BoundedProcessError("command_group_unavailable")
    else:
        path = bound_runtime_directory
    try:
        info = path.lstat()
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise BoundedProcessError("command_group_unavailable")
    return path


def minimal_environment(
    *, home: Path, bound_runtime_directory: Path | None = None
) -> dict[str, str]:
    """Return the complete direct-child environment; no caller values leak in."""

    if (
        not isinstance(home, Path)
        or not home.is_absolute()
        or "\x00" in os.fspath(home)
    ):
        raise BoundedProcessError("command_environment_invalid")
    return {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "XDG_RUNTIME_DIR": os.fspath(
            _runtime_directory(bound_runtime_directory=bound_runtime_directory)
        ),
    }


def _close_descriptor(descriptor: int) -> int:
    if descriptor >= 0:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    return -1


def _digest_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    return digest.hexdigest()


def _load_runtime_spawn_helper(layout: RuntimeLayout) -> _NativeSpawnHelper:
    """Load exactly the verified helper FD from the validated Runtime Image.

    The Runtime Image manifest is an atomic-image integrity contract, not an
    independent signing authority: an actor who can replace that whole private
    image already has runtime-code authority. This binding prevents a helper
    pathname swap or an individual helper/manifest deviation between validation
    and ``dlopen``; stronger authority requires an external trust root.
    """

    if not isinstance(layout, RuntimeLayout):
        raise BoundedProcessError("command_group_unavailable")
    try:
        validate_runtime_metadata(layout)
    except (LayoutError, TypeError, ValueError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    descriptor = -1
    try:
        descriptor = os.open(
            layout.spawn_helper,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_nlink != 1
            or _digest_descriptor(descriptor) != layout.spawn_helper_digest
        ):
            raise BoundedProcessError("command_group_unavailable")
        bound_identity = (info.st_dev, info.st_ino)
        library = ctypes.CDLL(f"/proc/self/fd/{descriptor}", use_errno=True)
        loaded = os.fstat(descriptor)
        if (loaded.st_dev, loaded.st_ino) != bound_identity:
            raise BoundedProcessError("command_group_unavailable")
        spawn = library.codex_master_pidfd_spawnp
        spawn.argtypes = (
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
        )
        spawn.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        descriptor = _close_descriptor(descriptor)
    return _NativeSpawnHelper(library, spawn)


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise BoundedProcessError("command_timeout")
    return value


def _manager_runtime_limit(deadline: float) -> str:
    """Encode the absolute runner deadline plus its fixed cleanup bound."""

    microseconds = int(
        (deadline + BOUNDED_PROCESS_CLEANUP_SECONDS - time.monotonic()) * 1_000_000
    )
    if microseconds <= 0:
        raise BoundedProcessError("command_timeout")
    return f"{microseconds}us"


def _systemctl(
    arguments: Sequence[str], *, environment: dict[str, str], deadline: float
) -> bytes:
    try:
        completed = subprocess.run(
            [_SYSTEMCTL, "--user", *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=_remaining(deadline),
        )
    except subprocess.TimeoutExpired as exc:
        raise BoundedProcessError("command_timeout") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    if completed.returncode != 0:
        raise BoundedProcessError("command_group_unavailable")
    return completed.stdout


def _verify_runner_capability(*, environment: dict[str, str], deadline: float) -> None:
    """Require the user manager and cgroup-v2 before launching the command."""

    try:
        controllers = (_CGROUP_ROOT / "cgroup.controllers").read_bytes()
    except OSError as exc:
        raise BoundedProcessError("command_cgroup_preflight_unavailable") from exc
    if not controllers or not hasattr(os, "P_PIDFD") or not hasattr(os, "pipe2"):
        raise BoundedProcessError("command_cgroup_preflight_unavailable")
    with _preexec_stage("command_manager_preflight_unavailable"):
        _systemctl(("show-environment",), environment=environment, deadline=deadline)


def _unit_name() -> str:
    return f"codex-master-runtime-{os.geteuid()}-{secrets.token_hex(16)}.service"


def _systemd_run_arguments(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    manager_runtime: str,
    unit: str,
) -> tuple[str, ...]:
    runtime_directory = environment["XDG_RUNTIME_DIR"]
    clean_environment = tuple(
        f"{name}={value}"
        for name, value in environment.items()
        if name != "XDG_RUNTIME_DIR"
    )
    return (
        _SYSTEMD_RUN,
        "--user",
        f"--unit={unit}",
        "--property=Delegate=no",
        "--property=KillMode=control-group",
        f"--property=RuntimeMaxSec={manager_runtime}",
        "--property=TimeoutStopSec=0",
        "--property=SendSIGKILL=yes",
        "--property=CollectMode=inactive-or-failed",
        "--property=ExitType=main",
        "--property=InaccessiblePaths="
        f"{runtime_directory}/bus {runtime_directory}/systemd/private",
        "--pipe",
        "--wait",
        "--collect",
        "--quiet",
        f"--working-directory={os.fspath(cwd)}",
        "--",
        _ENV,
        "-i",
        *clean_environment,
        *arguments,
    )


def _terminate_unbound_spawn(pidfd: int) -> None:
    with contextlib.suppress(OSError):
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError, OSError):
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)


def _spawn_with_pidfd(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    helper: _NativeSpawnHelper,
    unit: str,
) -> _SpawnedProcess:
    """Spawn one systemd-run client with typed glibc state and raw pipe FDs."""

    try:
        encoded_cwd = os.fsencode(cwd)
        encoded_arguments = [os.fsencode(argument) for argument in arguments]
        encoded_environment = [
            os.fsencode(f"{name}={value}") for name, value in environment.items()
        ]
    except (TypeError, ValueError) as exc:
        raise BoundedProcessError("command_arguments_invalid") from exc
    if any(
        b"\x00" in value
        for value in (encoded_cwd, *encoded_arguments, *encoded_environment)
    ):
        raise BoundedProcessError("command_arguments_invalid")
    argv = (ctypes.c_char_p * (len(encoded_arguments) + 1))(*encoded_arguments, None)
    envp = (ctypes.c_char_p * (len(encoded_environment) + 1))(
        *encoded_environment, None
    )
    stdin_child = stdin_parent = stdout_parent = stdout_child = stderr_parent = (
        stderr_child
    ) = -1
    pidfd = -1
    transferred = False
    try:
        stdin_child, stdin_parent = os.pipe2(os.O_CLOEXEC)
        stdout_parent, stdout_child = os.pipe2(os.O_CLOEXEC)
        stderr_parent, stderr_child = os.pipe2(os.O_CLOEXEC)
        for descriptor in (stdin_parent, stdout_parent, stderr_parent):
            os.set_blocking(descriptor, False)
        spawned_pidfd = ctypes.c_int(-1)
        result = helper.spawn(
            ctypes.byref(spawned_pidfd),
            stdin_child,
            stdout_child,
            stderr_child,
            encoded_cwd,
            argv,
            envp,
        )
        if result != 0 or spawned_pidfd.value < 0:
            raise BoundedProcessError("command_group_unavailable")
        pidfd = spawned_pidfd.value
        process = _SpawnedProcess(
            unit, pidfd, stdin_parent, stdout_parent, stderr_parent
        )
        stdin_parent = stdout_parent = stderr_parent = -1
        transferred = True
        return process
    except BoundedProcessError:
        raise
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        for descriptor in (stdin_child, stdout_child, stderr_child):
            _close_descriptor(descriptor)
        if not transferred:
            for descriptor in (stdin_parent, stdout_parent, stderr_parent):
                _close_descriptor(descriptor)
            if pidfd >= 0:
                _terminate_unbound_spawn(pidfd)
                _close_descriptor(pidfd)


def _cgroup_path(value: bytes) -> Path:
    try:
        relative = value.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    path = Path(relative)
    if (
        not path.is_absolute()
        or "\x00" in relative
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise BoundedProcessError("command_group_unavailable")
    return _CGROUP_ROOT / path.relative_to(path.anchor)


def _unit_snapshot(
    unit: str, *, environment: dict[str, str], deadline: float
) -> _UnitSnapshot:
    output = _systemctl(
        (
            "show",
            "--property=ControlGroup",
            "--property=InvocationID",
            "--property=LoadState",
            unit,
        ),
        environment=environment,
        deadline=deadline,
    )
    properties: dict[str, str] = {}
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name in properties:
            raise BoundedProcessError("command_group_unavailable")
        properties[name] = value
    if set(properties) != {"ControlGroup", "InvocationID", "LoadState"}:
        raise BoundedProcessError("command_group_unavailable")
    if properties["LoadState"] == "not-found":
        if properties["ControlGroup"] or properties["InvocationID"]:
            raise BoundedProcessError("command_group_unavailable")
        return _UnitSnapshot(None, None)
    if not properties["ControlGroup"] or not properties["InvocationID"]:
        return _UnitSnapshot(None, None)
    if len(properties["InvocationID"]) != 32 or any(
        character not in "0123456789abcdef" for character in properties["InvocationID"]
    ):
        raise BoundedProcessError("command_group_unavailable")
    return _UnitSnapshot(
        _cgroup_path(properties["ControlGroup"].encode("utf-8")),
        properties["InvocationID"],
    )


def _open_cgroup_directory(cgroup: Path) -> tuple[int, tuple[int, int]]:
    descriptor = -1
    retained = False
    try:
        descriptor = os.open(
            cgroup,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise BoundedProcessError("command_group_unavailable")
        retained = True
        return descriptor, (info.st_dev, info.st_ino)
    except BoundedProcessError:
        raise
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        if not retained:
            descriptor = _close_descriptor(descriptor)


def _g5_unit_snapshot(unit_name: str) -> tuple[str, str, str]:
    if not re.fullmatch(r"the-hive-resource-[0-9a-f]{32}\.scope", unit_name):
        raise BoundedProcessError("command_group_unavailable")
    environment = minimal_environment(home=Path.home())
    output = _systemctl(
        (
            "show",
            "--property=ControlGroup",
            "--property=InvocationID",
            "--property=LoadState",
            unit_name,
        ),
        environment=environment,
        deadline=time.monotonic() + 5.0,
    )
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise BoundedProcessError("command_group_unavailable")
        values[key] = value
    if set(values) != {"ControlGroup", "InvocationID", "LoadState"}:
        raise BoundedProcessError("command_group_unavailable")
    if values["LoadState"] == "not-found":
        if values["ControlGroup"] or values["InvocationID"]:
            raise BoundedProcessError("command_group_unavailable")
        return "", "", "not-found"
    if values["LoadState"] != "loaded":
        raise BoundedProcessError("command_group_unavailable")
    if not re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]):
        raise BoundedProcessError("command_group_unavailable")
    cgroup = _cgroup_path(values["ControlGroup"].encode("ascii"))
    control_group = "/" + str(cgroup.relative_to(_CGROUP_ROOT))
    if control_group.rsplit("/", 1)[-1] != unit_name:
        raise BoundedProcessError("command_group_unavailable")
    return control_group, values["InvocationID"], values["LoadState"]


def _read_g5_cgroup_file(descriptor: int, name: str) -> bytes:
    file_descriptor = -1
    try:
        file_descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        chunks = bytearray()
        while len(chunks) <= 4096:
            chunk = os.read(file_descriptor, 4097 - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > 4096:
            raise BoundedProcessError("command_group_unavailable")
        return bytes(chunks)
    except BoundedProcessError:
        raise
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        file_descriptor = _close_descriptor(file_descriptor)


def bind_g5_scope(unit_name: str, expected_control_group: str) -> G5ScopeIdentity:
    """Bind a confirmed G5 unit to its current InvocationID and cgroup inode."""

    control_group, invocation_id, _load_state = _g5_unit_snapshot(unit_name)
    if control_group.lstrip("/") != expected_control_group.lstrip("/"):
        raise BoundedProcessError("command_group_unavailable")
    cgroup = _CGROUP_ROOT / control_group.lstrip("/")
    descriptor, identity = _open_cgroup_directory(cgroup)
    try:
        events = _read_g5_cgroup_file(descriptor, "cgroup.events").decode("ascii")
        populated = [
            line for line in events.splitlines() if line.startswith("populated ")
        ]
        processes = _read_g5_cgroup_file(descriptor, "cgroup.procs").split()
        if populated != ["populated 1"] or not processes:
            raise BoundedProcessError("command_group_unavailable")
        confirmed_group, confirmed_invocation, _ = _g5_unit_snapshot(unit_name)
        if confirmed_group != control_group or confirmed_invocation != invocation_id:
            raise BoundedProcessError("command_group_unavailable")
        return G5ScopeIdentity(
            unit_name=unit_name,
            control_group=control_group,
            invocation_id=invocation_id,
            device=identity[0],
            inode=identity[1],
        )
    finally:
        descriptor = _close_descriptor(descriptor)


def g5_scope_is_empty(identity: G5ScopeIdentity) -> bool:
    """Recheck the bound systemd InvocationID and complete cgroup emptiness."""

    if type(identity) is not G5ScopeIdentity:
        return False
    try:
        control_group, invocation_id, load_state = _g5_unit_snapshot(identity.unit_name)
        if load_state == "not-found":
            try:
                (_CGROUP_ROOT / identity.control_group.lstrip("/")).lstat()
            except FileNotFoundError:
                return True
            except OSError:
                return False
            return False
        if (
            control_group != identity.control_group
            or invocation_id != identity.invocation_id
        ):
            return False
        descriptor, current_identity = _open_cgroup_directory(
            _CGROUP_ROOT / identity.control_group.lstrip("/")
        )
        try:
            if current_identity != (identity.device, identity.inode):
                return False
            events = _read_g5_cgroup_file(descriptor, "cgroup.events").decode("ascii")
            populated = [
                line for line in events.splitlines() if line.startswith("populated ")
            ]
            processes = _read_g5_cgroup_file(descriptor, "cgroup.procs").split()
            return populated == ["populated 0"] and not processes
        finally:
            descriptor = _close_descriptor(descriptor)
    except (BoundedProcessError, OSError, UnicodeError, ValueError):
        return False


def _bind_cgroup(
    process: _SpawnedProcess, *, environment: dict[str, str], deadline: float
) -> None:
    while True:
        snapshot = _unit_snapshot(
            process.unit, environment=environment, deadline=deadline
        )
        if snapshot.control_group is not None and snapshot.invocation_id is not None:
            descriptor, identity = _open_cgroup_directory(snapshot.control_group)
            try:
                confirmed = _unit_snapshot(
                    process.unit, environment=environment, deadline=deadline
                )
                if confirmed == snapshot:
                    process.cgroup = snapshot.control_group
                    process.cgroup_fd = descriptor
                    process.cgroup_identity = identity
                    process.invocation_id = snapshot.invocation_id
                    return
            finally:
                if process.cgroup_fd != descriptor:
                    descriptor = _close_descriptor(descriptor)
        time.sleep(min(0.005, _remaining(deadline)))


def _bound_cgroup_descriptor(process: _SpawnedProcess) -> int:
    if process.cgroup_fd < 0 or process.cgroup_identity is None:
        raise BoundedProcessError("command_group_unavailable")
    try:
        info = os.fstat(process.cgroup_fd)
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_dev, info.st_ino) != process.cgroup_identity
    ):
        raise BoundedProcessError("command_group_unavailable")
    return process.cgroup_fd


def _read_bound_cgroup_file(process: _SpawnedProcess, name: str) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=_bound_cgroup_descriptor(process),
        )
        chunks = bytearray()
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            chunks.extend(chunk)
        return chunks.decode("ascii")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        descriptor = _close_descriptor(descriptor)


def _cgroup_is_empty(process: _SpawnedProcess) -> bool:
    try:
        events = _read_bound_cgroup_file(process, "cgroup.events")
    except FileNotFoundError:
        return True
    populated = [line for line in events.splitlines() if line.startswith("populated ")]
    if populated != ["populated 0"]:
        return False
    try:
        return not _read_bound_cgroup_file(process, "cgroup.procs").split()
    except FileNotFoundError:
        return True


def _wait_for_cgroup_empty(process: _SpawnedProcess, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if _cgroup_is_empty(process):
            return True
        time.sleep(0.005)
    return _cgroup_is_empty(process)


def _kill_bound_cgroup(process: _SpawnedProcess) -> None:
    """Kill only the directory-FD-bound cgroup generation of this process."""

    descriptor = -1
    try:
        descriptor = os.open(
            "cgroup.kill",
            os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=_bound_cgroup_descriptor(process),
        )
        if os.write(descriptor, b"1") != 1:
            raise BoundedProcessError("command_group_unavailable")
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        descriptor = _close_descriptor(descriptor)


def _wait_for_unit_resolved(
    process: _SpawnedProcess, *, environment: dict[str, str], deadline: float
) -> None:
    while True:
        snapshot = _unit_snapshot(
            process.unit, environment=environment, deadline=deadline
        )
        if snapshot.invocation_id != process.invocation_id:
            return
        time.sleep(min(0.005, _remaining(deadline)))


def _stop_cgroup(
    process: _SpawnedProcess, *, environment: dict[str, str], deadline: float
) -> None:
    try:
        _kill_bound_cgroup(process)
    except BoundedProcessError as exc:
        raise BoundedProcessError("command_cleanup_bounded") from exc
    if not _wait_for_cgroup_empty(process, deadline):
        raise BoundedProcessError("command_cleanup_bounded")
    _wait_for_unit_resolved(process, environment=environment, deadline=deadline)


def _close_bound_cgroup(process: _SpawnedProcess) -> None:
    process.cgroup_fd = _close_descriptor(process.cgroup_fd)
    process.cgroup_identity = None


def _returncode(waited: object) -> int:
    if waited.si_code == os.CLD_EXITED:
        return waited.si_status
    return -waited.si_status


def _wait_for_process(process: _SpawnedProcess, timeout: float) -> int:
    if process.returncode is not None:
        return process.returncode
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited = os.waitid(os.P_PIDFD, process.pidfd, os.WEXITED | os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise BoundedProcessError("command_unavailable") from exc
        if waited is not None:
            process.returncode = _returncode(waited)
            return process.returncode
        if time.monotonic() >= deadline:
            raise TimeoutError
        time.sleep(0.005)


def _reap_process(process: _SpawnedProcess, deadline: float) -> None:
    try:
        _wait_for_process(process, max(0.0, deadline - time.monotonic()))
    except (BoundedProcessError, TimeoutError):
        with contextlib.suppress(OSError):
            signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
        with contextlib.suppress(
            BoundedProcessError, ChildProcessError, OSError, TimeoutError
        ):
            _wait_for_process(process, max(0.0, deadline - time.monotonic()))


def _close_process_descriptors(process: _SpawnedProcess) -> None:
    process.stdin_fd = _close_descriptor(process.stdin_fd)
    process.stdout_fd = _close_descriptor(process.stdout_fd)
    process.stderr_fd = _close_descriptor(process.stderr_fd)


def _close_selector_descriptor(
    selector: selectors.BaseSelector, descriptor: int
) -> None:
    with contextlib.suppress(KeyError):
        selector.unregister(descriptor)
    _close_descriptor(descriptor)


def run_bounded(
    arguments: Sequence[str],
    *,
    cwd: Path,
    home: Path,
    timeout_seconds: float,
    stdout_limit: int = DEFAULT_STDOUT_LIMIT,
    stderr_limit: int = DEFAULT_STDERR_LIMIT,
    input_data: bytes = b"",
    runtime_layout: RuntimeLayout | None = None,
    bound_runtime_directory: Path | None = None,
) -> BoundedProcessResult:
    """Run one command inside a bounded non-delegated cgroup-v2 service."""

    if (
        not isinstance(cwd, Path)
        or not cwd.is_absolute()
        or "\x00" in os.fspath(cwd)
        or not arguments
        or any(
            not isinstance(argument, str) or not argument or "\x00" in argument
            for argument in arguments
        )
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or not isinstance(stdout_limit, int)
        or not isinstance(stderr_limit, int)
        or stdout_limit <= 0
        or stderr_limit <= 0
        or not isinstance(input_data, bytes)
        or len(input_data) > 64 * 1024
    ):
        raise BoundedProcessError("command_arguments_invalid")
    deadline = time.monotonic() + float(timeout_seconds)
    try:
        layout = (
            RuntimeLayout.from_module_path(Path(__file__))
            if runtime_layout is None
            else runtime_layout
        )
    except LayoutError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    with _preexec_stage("command_runtime_directory_unavailable"):
        environment = minimal_environment(
            home=home, bound_runtime_directory=bound_runtime_directory
        )
    with _preexec_stage("command_spawn_helper_unavailable"):
        helper = _load_runtime_spawn_helper(layout)
    _verify_runner_capability(environment=environment, deadline=deadline)
    unit = _unit_name()
    command = _systemd_run_arguments(
        arguments,
        cwd=cwd,
        environment=environment,
        manager_runtime=_manager_runtime_limit(deadline),
        unit=unit,
    )
    process: _SpawnedProcess | None = None
    selector: selectors.BaseSelector | None = None
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with _preexec_stage("command_native_spawn_unavailable"):
            process = _spawn_with_pidfd(
                command, cwd=cwd, environment=environment, helper=helper, unit=unit
            )
        with _preexec_stage("command_cgroup_bind_unavailable"):
            _bind_cgroup(process, environment=environment, deadline=deadline)
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout_fd: ("stdout", stdout_limit),
            process.stderr_fd: ("stderr", stderr_limit),
        }
        for descriptor, (name, _limit) in streams.items():
            selector.register(descriptor, selectors.EVENT_READ, name)
        pending = memoryview(input_data)
        offset = 0
        if pending:
            selector.register(process.stdin_fd, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin_fd = _close_descriptor(process.stdin_fd)
        while streams or process.stdin_fd >= 0:
            ready = selector.select(_remaining(deadline))
            if not ready:
                raise BoundedProcessError("command_timeout")
            for key, _events in ready:
                descriptor = key.fd
                if key.data == "stdin":
                    try:
                        written = os.write(descriptor, pending[offset:])
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        if exc.errno != errno.EPIPE:
                            raise
                        written = 0
                    if written <= 0:
                        _close_selector_descriptor(selector, descriptor)
                        process.stdin_fd = -1
                        continue
                    offset += written
                    if offset == len(pending):
                        _close_selector_descriptor(selector, descriptor)
                        process.stdin_fd = -1
                    continue
                name, limit = streams[descriptor]
                try:
                    chunk = os.read(
                        descriptor, min(8192, limit + 1 - len(outputs[name]))
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    _close_selector_descriptor(selector, descriptor)
                    streams.pop(descriptor)
                    if descriptor == process.stdout_fd:
                        process.stdout_fd = -1
                    else:
                        process.stderr_fd = -1
                    continue
                outputs[name].extend(chunk)
                if len(outputs[name]) > limit:
                    raise BoundedProcessError(f"command_{name}_limit")
        try:
            returncode = _wait_for_process(process, _remaining(deadline))
        except TimeoutError as exc:
            raise BoundedProcessError("command_timeout") from exc
        if process.cgroup is None or not _wait_for_cgroup_empty(process, deadline):
            raise BoundedProcessError("command_timeout")
        _wait_for_unit_resolved(process, environment=environment, deadline=deadline)
        process.cgroup_released = True
        try:
            stdout = outputs["stdout"].decode("utf-8")
            stderr = outputs["stderr"].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BoundedProcessError("command_output_invalid") from exc
        return BoundedProcessResult(returncode=returncode, stdout=stdout, stderr=stderr)
    except BoundedProcessError:
        raise
    except OSError as exc:
        raise BoundedProcessError("command_unavailable") from exc
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            cleanup_deadline = time.monotonic() + BOUNDED_PROCESS_CLEANUP_SECONDS
            _close_process_descriptors(process)
            cleanup_error: BoundedProcessError | None = None
            try:
                if process.cgroup_fd >= 0 and not process.cgroup_released:
                    _stop_cgroup(
                        process, environment=environment, deadline=cleanup_deadline
                    )
            except BoundedProcessError as exc:
                cleanup_error = exc
            finally:
                _reap_process(process, cleanup_deadline)
                process.pidfd = _close_descriptor(process.pidfd)
                _close_bound_cgroup(process)
            if cleanup_error is not None:
                raise cleanup_error


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "G5ScopeIdentity",
    "BOUNDED_PROCESS_CLEANUP_SECONDS",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "minimal_environment",
    "bind_g5_scope",
    "g5_scope_is_empty",
    "run_bounded",
]

# Prospective direct-child owner. Existing run_bounded/systemd-run bodies stay unchanged.


@dataclass(frozen=True, slots=True)
class OwnedChildSpec:
    kind: str
    executable_fd: int
    executable_sha256: str
    cwd_fd: int
    arguments: tuple[str, ...]
    environment: dict[str, str]
    start_deadline_ns: int
    run_deadline_ns: int
    cleanup_deadline_ns: int
    stdout_limit: int = DEFAULT_STDOUT_LIMIT
    stderr_limit: int = DEFAULT_STDERR_LIMIT
    d17_target_fd: int | None = None


@dataclass(frozen=True, slots=True)
class OwnedChildIdentity:
    nonce: str
    parent_pid: int
    pid: int
    pidfd_device: int | None
    pidfd_inode: int | None
    scope: G5ScopeIdentity
    launch_sha256: str


@dataclass(frozen=True, slots=True)
class OwnedStartReservation:
    task9_executing_sha256: str
    prepared_request_ref: str
    owner_reference: object


@dataclass(frozen=True, slots=True)
class OwnedExecutionBinding:
    reservation: OwnedStartReservation
    child: OwnedChildIdentity
    execution_binding_id: str
    executing_record_sha256: str
    prepared_request_ref: str


@dataclass(frozen=True, slots=True)
class OwnedD17Publication:
    binding: OwnedExecutionBinding
    started_sha256: str
    canonical_payload: bytes


@dataclass(frozen=True, slots=True)
class OwnedCompletion:
    binding: OwnedExecutionBinding
    evidence_sha256: str
    completion_record_sha256: str


@dataclass(frozen=True, slots=True)
class OwnedObservation:
    kind: str
    sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class OwnedCompletionEvidence:
    child: OwnedChildIdentity
    exit_code: int
    child_wait: OwnedObservation
    stdout_eof: OwnedObservation
    stderr_eof: OwnedObservation
    kernel_quiescence: OwnedObservation
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class OwnedChildEvent:
    seq: int
    kind: str
    data: bytes = b""
    observation: OwnedObservation | None = None


@dataclass(frozen=True, slots=True)
class OwnedJournalPorts:
    # Proposed in-process composition contract, not existing B implementations.
    # The actual admission owner must bind these callables; no argv/caller booleans do so.
    reserve_execution: Callable[[OwnedChildSpec, int], OwnedStartReservation]
    fail_unstarted: Callable[[OwnedStartReservation, str, int], str]
    persist_executing: Callable[[OwnedStartReservation, OwnedChildIdentity, int], OwnedExecutionBinding]
    publish_d17_for_started_child: Callable[
        [OwnedExecutionBinding, OwnedObservation, int], OwnedD17Publication
    ]
    complete_execution: Callable[
        [OwnedExecutionBinding, OwnedCompletionEvidence, int], OwnedCompletion
    ]


class OwnedChildHold(BoundedProcessError):
    def __init__(self, code: str, child: "OwnedDirectChild") -> None:
        super().__init__(code)
        self.child = child


class _OwnedNativeArgs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int) for name in (
        "cgroup_fd", "executable_fd", "cwd_fd", "stdin_fd", "stdout_fd", "stderr_fd",
        "control_fd", "events_fd", "d17_fd", "d17_target", "release_fd", "error_fd", "kind"
    )] + [("start_deadline_ns", ctypes.c_int64),
         ("argv", ctypes.POINTER(ctypes.c_char_p)),
         ("envp", ctypes.POINTER(ctypes.c_char_p))]


class _OwnedNativeResult(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_int), ("pidfd", ctypes.c_int)]


def _owned_native_entry(layout: RuntimeLayout) -> tuple[object, object]:
    verified = _load_runtime_spawn_helper(layout)
    try:
        entry = verified.library.codex_master_owned_child_start_v1
        entry.argtypes = (ctypes.POINTER(_OwnedNativeResult), ctypes.POINTER(_OwnedNativeArgs))
        entry.restype = ctypes.c_int
    except AttributeError as exc:
        raise BoundedProcessError("owned_child_native_unavailable") from exc
    return verified.library, entry


def _owned_wire_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {key: _owned_wire_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_owned_wire_value(item) for item in value]
    return value


def _owned_observation(kind: str, body: object) -> OwnedObservation:
    payload = json.dumps({"kind": kind, "body": _owned_wire_value(body)}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return OwnedObservation(kind, hashlib.sha256(payload).hexdigest(), payload)


def _owned_deadline(deadline_ns: int) -> float:
    remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise BoundedProcessError("owned_child_deadline")
    return remaining


def _owned_hash_valid(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def owned_completion_evidence_sha256(evidence: OwnedCompletionEvidence) -> str:
    return _owned_observation("completion_evidence", asdict(evidence)).sha256


class OwnedDirectChild:
    """T-held direct child, its actual pidfd/pipes and its one G5 generation."""

    def __init__(self, spec: OwnedChildSpec, scope_owner: object, ports: OwnedJournalPorts) -> None:
        from the_hive.resource_cgroup import SystemdDirectChildScopeOwner
        if type(scope_owner) is not SystemdDirectChildScopeOwner or type(ports) is not OwnedJournalPorts:
            raise BoundedProcessError("owned_child_owner_unavailable")
        now = time.monotonic_ns()
        if (spec.kind not in {"leadership", "mcp"} or not spec.arguments
            or not spec.arguments[0]
            or not all(isinstance(x, str) and "\0" not in x for x in spec.arguments)
            or not _owned_hash_valid(spec.executable_sha256)
            or not now < spec.start_deadline_ns <= spec.run_deadline_ns < spec.cleanup_deadline_ns
            or spec.cleanup_deadline_ns > (1 << 63) - 1
            or spec.stdout_limit <= 0 or spec.stderr_limit <= 0
            or (spec.kind == "leadership" and (spec.arguments[1:3] != ("--hive-owned-entry", "exec")
                or spec.d17_target_fd is not None))
            or (spec.kind == "mcp" and (type(spec.d17_target_fd) is not int
                or not 3 <= spec.d17_target_fd <= 190))):
            raise BoundedProcessError("owned_child_spec_invalid")
        self.spec, self.scope_owner, self.ports = spec, scope_owner, ports
        self.ticket = None
        self.scope_identity = None
        self.process = _SpawnedProcess("", -1, -1, -1, -1)
        self._pid = -1
        self.unstarted_completion_sha256 = None
        self.identity = None
        self.reservation = None
        self.binding = None
        self.started = None
        self.evidence = None
        self._eof_observations = {}
        self._child_wait_observation = None
        self.completion = None
        self.failure_code = None
        self._fds: dict[str, int] = {}
        self._sockets: dict[str, socket.socket] = {}
        self._condition = threading.Condition(threading.RLock())
        self._stdin_lock = threading.Lock()
        self.scope_preparation_hold = None
        self._events: deque[OwnedChildEvent] = deque()
        self._event_bytes = 0
        self._seq = 0
        self._cancel = threading.Event()
        self._settled = threading.Event()
        self._finished = threading.Event()
        self._thread = None
        self._group_consumed = False
        self._executable_snapshot = None

    def _own_fd(self, name: str, descriptor: int) -> int:
        self._fds[name] = descriptor
        return descriptor

    def _close_fd(self, name: str) -> None:
        descriptor = self._fds.pop(name, -1)
        _close_descriptor(descriptor)

    def _pipe(self, first: str, second: str) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        self._own_fd(first, read_fd)
        self._own_fd(second, write_fd)

    def _close_child_copies(self) -> None:
        for name in ("stdin_child", "stdout_child", "stderr_child", "release_child", "exec_error_child"):
            self._close_fd(name)
        for name in ("control_child", "events_child", "d17_child"):
            endpoint = self._sockets.pop(name, None)
            if endpoint is not None:
                endpoint.close()

    def _pair(self, parent: str, child: str) -> None:
        one, two = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        one.set_inheritable(False)
        two.set_inheritable(False)
        self._sockets[parent], self._sockets[child] = one, two

    def _emit(self, kind: str, data: bytes = b"", observation: OwnedObservation | None = None) -> None:
        with self._condition:
            self._seq += 1
            self._events.append(OwnedChildEvent(self._seq, kind, data, observation))
            self._event_bytes += len(data)
            while len(self._events) > 1024 or self._event_bytes > 1024 * 1024:
                self._event_bytes -= len(self._events.popleft().data)
            self._condition.notify_all()

    def events_after(self, after_seq: int, deadline_ns: int) -> tuple[OwnedChildEvent, ...]:
        with self._condition:
            if type(after_seq) is not int or after_seq < 0:
                raise OwnedChildHold("owned_child_read_invalid", self)
            while True:
                if self._events and after_seq < self._events[0].seq - 1:
                    raise OwnedChildHold("owned_child_replay_lost", self)
                events = tuple(event for event in self._events if event.seq > after_seq)
                if events or self._finished.is_set():
                    return events
                self._condition.wait(_owned_deadline(deadline_ns))

    def _pin_inputs(self) -> tuple[int, int, str]:
        executable = self._own_fd("executable", os.dup(self.spec.executable_fd))
        cwd = self._own_fd("cwd", os.dup(self.spec.cwd_fd))
        before = os.fstat(executable)
        def snapshot(x):
            return (x.st_dev, x.st_ino, x.st_mode, x.st_uid,
                x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o022 or before.st_mode & 0o111 == 0
            or fcntl.fcntl(executable, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or os.pread(executable, 4, 0) != b"\x7fELF"
            or not stat.S_ISDIR(os.fstat(cwd).st_mode)):
            raise OwnedChildHold("owned_child_input_unavailable", self)
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(executable, min(65536, before.st_size - offset), offset)
            if not chunk:
                raise OwnedChildHold("owned_child_input_changed", self)
            digest.update(chunk)
            offset += len(chunk)
        if digest.hexdigest() != self.spec.executable_sha256 or snapshot(os.fstat(executable)) != snapshot(before):
            raise OwnedChildHold("owned_child_input_changed", self)
        self._executable_snapshot = snapshot(before)
        environment = dict(self.spec.environment)
        if any(not isinstance(k, str) or not k or "=" in k or "\0" in k
            or not isinstance(v, str) or "\0" in v for k, v in environment.items()):
            raise OwnedChildHold("owned_child_environment_invalid", self)
        cwd_info = os.fstat(cwd)
        launch = _owned_observation("launch", {"executable": digest.hexdigest(),
            "cwd": [cwd_info.st_dev, cwd_info.st_ino], "argv": self.spec.arguments,
            "environment_sha256": hashlib.sha256(json.dumps(environment, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()})
        self._encoded_environment = tuple(os.fsencode(f"{k}={v}") for k, v in environment.items())
        return executable, cwd, launch.sha256

    def _start(self, layout: RuntimeLayout) -> "OwnedDirectChild":
        try:
            executable, cwd, launch_sha = self._pin_inputs()
            self._library, native = _owned_native_entry(layout)
            reservation = self.ports.reserve_execution(self.spec, self.spec.start_deadline_ns)
            if (type(reservation) is not OwnedStartReservation
                or not _owned_hash_valid(reservation.task9_executing_sha256)
                or not reservation.prepared_request_ref or reservation.owner_reference is None):
                raise OwnedChildHold("owned_child_reservation_unavailable", self)
            self.reservation = reservation
            _owned_deadline(self.spec.start_deadline_ns)
            from the_hive.resource_cgroup import DirectScopePreparationHold
            try:
                self.ticket = self.scope_owner.prepare()
            except DirectScopePreparationHold as hold:
                self.scope_preparation_hold = hold
                self.ticket = hold.ticket
                raise
            self.process.unit = self.ticket.unit_name
            group_fd = self._own_fd("cgroup", self.scope_owner.take_cgroup_fd_once(self.ticket))
            group, _invocation, _load = _g5_unit_snapshot(self.ticket.unit_name)
            self.scope_identity = bind_g5_scope(self.ticket.unit_name, group)
            info = os.fstat(group_fd)
            self.process.cgroup_fd = group_fd
            self.process.cgroup_identity = (self.scope_identity.device, self.scope_identity.inode)
            self.process.invocation_id = self.scope_identity.invocation_id
            if (info.st_dev, info.st_ino) != (self.scope_identity.device, self.scope_identity.inode):
                raise OwnedChildHold("owned_child_scope_changed", self)
            self._pipe("stdin_child", "stdin")
            self._pipe("stdout", "stdout_child")
            self._pipe("stderr", "stderr_child")
            self._pipe("release_child", "release")
            self._pipe("exec_error", "exec_error_child")
            self._pipe("wake", "wake_write")
            if self.spec.kind == "leadership":
                self._pair("control", "control_child")
                self._pair("events", "events_child")
            else:
                self._pair("d17", "d17_child")
            argv_bytes = tuple(os.fsencode(x) for x in self.spec.arguments)
            argv = (ctypes.c_char_p * (len(argv_bytes) + 1))(*argv_bytes, None)
            envp = (ctypes.c_char_p * (len(self._encoded_environment) + 1))(*self._encoded_environment, None)
            def raw(name):
                return self._sockets[name].fileno() if name in self._sockets else -1
            args = _OwnedNativeArgs(group_fd, executable, cwd, self._fds["stdin_child"],
                self._fds["stdout_child"], self._fds["stderr_child"], raw("control_child"),
                raw("events_child"), raw("d17_child"), self.spec.d17_target_fd or -1,
                self._fds["release_child"], self._fds["exec_error_child"],
                1 if self.spec.kind == "leadership" else 2, self.spec.start_deadline_ns, argv, envp)
            result = _OwnedNativeResult(-1, -1)
            error = native(ctypes.byref(result), ctypes.byref(args))
            # Retain the exact native pidfd before any subsequent observation can fail.
            self.process.pidfd = result.pidfd
            self._pid = result.pid
            if result.pid > 0 and result.pidfd >= 0:
                self.identity = OwnedChildIdentity(secrets.token_hex(16), os.getpid(), result.pid,
                    None, None, self.scope_identity, launch_sha)
            if error != 0 or result.pid <= 0 or result.pidfd < 0:
                raise OwnedChildHold("owned_child_native_start_failed", self)
            pidfd_info = os.fstat(result.pidfd)
            self.identity = OwnedChildIdentity(self.identity.nonce, os.getpid(), result.pid,
                pidfd_info.st_dev, pidfd_info.st_ino, self.scope_identity, launch_sha)
            self._close_child_copies()
            for name in ("stdin", "stdout", "stderr", "exec_error", "wake", "wake_write"):
                os.set_blocking(self._fds[name], False)
            self.process.stdin_fd = self._fds["stdin"]
            self.process.stdout_fd = self._fds["stdout"]
            self.process.stderr_fd = self._fds["stderr"]
            self._thread = threading.Thread(target=self._pump, name="hive-owned-child", daemon=False)
            self._thread.start()
            self._require_start_forward()
            self.scope_owner.release_after_attach(self.ticket, result.pid)
            self._require_start_forward()
            binding = self.ports.persist_executing(self.reservation, self.identity, self.spec.start_deadline_ns)
            if (type(binding) is not OwnedExecutionBinding or binding.reservation is not self.reservation
                or binding.child != self.identity or not binding.execution_binding_id
                or binding.prepared_request_ref != self.reservation.prepared_request_ref
                or not _owned_hash_valid(binding.executing_record_sha256)):
                raise OwnedChildHold("owned_child_binding_unavailable", self)
            self.binding = binding
            self._require_start_forward()
            if os.write(self._fds["release"], b"\x01") != 1:
                raise OwnedChildHold("owned_child_release_failed", self)
            self._close_fd("release")
            self.started = self._observe_exec()
            if self.spec.kind == "mcp":
                self._require_start_forward()
                publication = self.ports.publish_d17_for_started_child(
                    binding, self.started, self.spec.start_deadline_ns)
                if (type(publication) is not OwnedD17Publication or publication.binding is not binding
                    or publication.started_sha256 != self.started.sha256):
                    raise OwnedChildHold("owned_child_d17_unbound", self)
                payload = publication.canonical_payload
                fields = {"principal_id", "class_id", "repo_id", "principal_version",
                    "config_digest", "execution_binding_id", "issued_at_utc", "expires_at_utc"}
                if not isinstance(payload, bytes) or not 0 < len(payload) <= 4096:
                    raise OwnedChildHold("owned_child_d17_invalid", self)
                decoded = json.loads(payload)
                canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, allow_nan=False).encode()
                if (type(decoded) is not dict or payload != canonical or set(decoded) != fields
                    or decoded["execution_binding_id"] != binding.execution_binding_id):
                    raise OwnedChildHold("owned_child_d17_invalid", self)
                self._require_start_forward()
                endpoint = self._sockets.pop("d17")
                try:
                    endpoint.settimeout(_owned_deadline(self.spec.start_deadline_ns))
                    endpoint.sendall(struct.pack("!I", len(payload)) + payload)
                    endpoint.shutdown(socket.SHUT_WR)
                finally:
                    endpoint.close()
            else:
                payload = json.dumps({"schema": "HiveStartedOwnerBootstrapV1",
                    "owner_pid": os.getpid(), "child_pid": result.pid,
                    "prepared_request_ref": binding.prepared_request_ref},
                    separators=(",", ":"), ensure_ascii=True).encode()
                if len(payload) > 4096:
                    raise OwnedChildHold("owned_child_bootstrap_invalid", self)
                self._require_start_forward()
                endpoint = self._sockets["control"]
                endpoint.settimeout(_owned_deadline(self.spec.start_deadline_ns))
                endpoint.sendall(struct.pack("!I", len(payload)) + payload)
            self._settled.set()
            return self
        except Exception as exc:
            self._close_child_copies()
            self._close_fd("release")
            self.failure_code = "owned_child_start_failed"
            self._settled.set()
            if self.process.pidfd >= 0:
                self.cancel()
                if self._thread is None:
                    self._thread = threading.Thread(target=self._pump, name="hive-owned-cleanup", daemon=False)
                    self._thread.start()
                try:
                    self.wait_completion(self.spec.cleanup_deadline_ns)
                except Exception:
                    raise OwnedChildHold("owned_child_cleanup_unverified", self) from exc
            else:
                if self._pid > 0 or (self.scope_preparation_hold is not None and self.ticket is None):
                    raise OwnedChildHold("owned_child_scope_cleanup_unverified", self) from exc
                if self.ticket is not None:
                    try:
                        self.scope_owner.abort(self.ticket)
                        self._group_consumed = True
                    except Exception:
                        raise OwnedChildHold("owned_child_cleanup_unverified", self) from exc
                try:
                    if self.reservation is not None:
                        closed = self.ports.fail_unstarted(self.reservation,
                            "owned_child_not_created", self.spec.cleanup_deadline_ns)
                        if not _owned_hash_valid(closed):
                            raise OwnedChildHold("owned_child_unstarted_completion_unverified", self)
                        self.unstarted_completion_sha256 = closed
                except Exception as completion_error:
                    raise OwnedChildHold("owned_child_unstarted_completion_unverified", self) from completion_error
                finally:
                    self._close_owned()
            raise OwnedChildHold("owned_child_start_failed", self) from exc

    def _require_start_forward(self) -> None:
        _owned_deadline(self.spec.start_deadline_ns)
        if self._cancel.is_set() or self._finished.is_set() or self.failure_code is not None:
            raise OwnedChildHold("owned_child_forward_denied", self)
        if os.waitid(os.P_PIDFD, self.process.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            raise OwnedChildHold("owned_child_not_live", self)

    def _observe_exec(self) -> OwnedObservation:
        with selectors.DefaultSelector() as selector:
            selector.register(self._fds["exec_error"], selectors.EVENT_READ)
            while True:
                if not selector.select(_owned_deadline(self.spec.start_deadline_ns)):
                    raise OwnedChildHold("owned_child_exec_unobserved", self)
                try:
                    error = os.read(self._fds["exec_error"], 8)
                except BlockingIOError:
                    continue
                if error:
                    raise OwnedChildHold("owned_child_exec_failed", self)
                break
        self._close_fd("exec_error")
        if os.waitid(os.P_PIDFD, self.process.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            raise OwnedChildHold("owned_child_exec_unobserved", self)
        # PID comes only from this same native clone/pidfd pair, never from client lookup.
        actual = os.stat(f"/proc/{self.identity.pid}/exe")
        expected = os.fstat(self._fds["executable"])
        snapshot = (expected.st_dev, expected.st_ino, expected.st_mode, expected.st_uid,
            expected.st_nlink, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)
        if (snapshot != self._executable_snapshot or (actual.st_dev, actual.st_ino) != snapshot[:2]
            or os.waitid(os.P_PIDFD, self.process.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None):
            raise OwnedChildHold("owned_child_exec_unobserved", self)
        return _owned_observation("exec_observed", {"child": asdict(self.identity),
            "executable_sha256": self.spec.executable_sha256, "observed_monotonic_ns": time.monotonic_ns()})

    def leadership_channels(self) -> tuple[socket.socket, socket.socket]:
        if (self.spec.kind != "leadership" or self.started is None or not self._settled.is_set()
            or self._finished.is_set() or self.failure_code is not None
            or "control" not in self._sockets or "events" not in self._sockets):
            raise OwnedChildHold("owned_child_channel_unavailable", self)
        # Borrowed by the real T assembly; no origin can be reconstructed from argv.
        return self._sockets["control"], self._sockets["events"]

    def _check_write_live_locked(self) -> None:
        if (not self._settled.is_set() or self.failure_code is not None
            or self._cancel.is_set() or self._finished.is_set()
            or self.process.returncode is not None or "stdin" not in self._fds):
            raise OwnedChildHold("owned_child_write_denied", self)

    def write(self, chunk: bytes, deadline_ns: int) -> None:
        if not isinstance(chunk, bytes):
            raise OwnedChildHold("owned_child_write_denied", self)
        view = memoryview(chunk)
        with self._stdin_lock:
            with self._condition:
                self._check_write_live_locked()
                descriptor = os.dup(self._fds["stdin"])
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(descriptor, selectors.EVENT_WRITE)
                    while view:
                        with self._condition:
                            self._check_write_live_locked()
                        if not selector.select(_owned_deadline(deadline_ns)):
                            raise OwnedChildHold("owned_child_write_deadline", self)
                        with self._condition:
                            self._check_write_live_locked()
                            try:
                                count = os.write(descriptor, view)
                            except BlockingIOError:
                                continue
                            if count <= 0:
                                raise OwnedChildHold("owned_child_stdin_closed", self)
                            view = view[count:]
            finally:
                os.close(descriptor)

    def close_stdin(self) -> None:
        with self._condition:
            self._close_fd("stdin")
            self.process.stdin_fd = -1

    def interrupt(self) -> None:
        with self._condition:
            if self.process.pidfd < 0 or self._finished.is_set():
                raise OwnedChildHold("owned_child_signal_denied", self)
            signal.pidfd_send_signal(self.process.pidfd, signal.SIGINT)

    def cancel(self) -> None:
        with self._condition:
            if self.completion is not None or self.process.pidfd < 0:
                return
            self.failure_code = self.failure_code or "owned_child_cancelled"
            self._cancel.set()
            if self.process.pidfd >= 0:
                try:
                    signal.pidfd_send_signal(self.process.pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if "wake_write" in self._fds:
                try:
                    os.write(self._fds["wake_write"], b"1")
                except BlockingIOError:
                    pass

    def wait_completion(self, deadline_ns: int) -> OwnedCompletion:
        if not self._finished.wait(_owned_deadline(deadline_ns)) or self.completion is None:
            raise OwnedChildHold("owned_child_completion_unverified", self)
        return self.completion

    def _pump(self) -> None:
        hashes = {name: hashlib.sha256() for name in ("stdout", "stderr")}
        counts = {name: 0 for name in hashes}
        eof = self._eof_observations
        waited = None
        try:
            with selectors.DefaultSelector() as selector:
                for name in ("stdout", "stderr", "wake"):
                    if name in self._fds:
                        selector.register(self._fds[name], selectors.EVENT_READ, name)
                selector.register(self.process.pidfd, selectors.EVENT_READ, "pidfd")
                while len(eof) != 2 or waited is None:
                    if time.monotonic_ns() >= self.spec.run_deadline_ns:
                        with self._condition:
                            self.failure_code = self.failure_code or "owned_child_run_deadline"
                            self._cancel.set()
                    if self._cancel.is_set() and not self._group_consumed:
                        _kill_bound_cgroup(self.process)
                        self.scope_owner.abort(self.ticket)
                        self._group_consumed = True
                        self.close_stdin()
                    deadline = self.spec.cleanup_deadline_ns if self._cancel.is_set() else self.spec.run_deadline_ns
                    ready = selector.select(min(0.05, _owned_deadline(deadline)))
                    for key, _events in ready:
                        name = key.data
                        if name == "wake":
                            try:
                                os.read(key.fd, 4096)
                            except BlockingIOError:
                                pass
                            continue
                        if name == "pidfd":
                            try:
                                with self._condition:
                                    code = _wait_for_process(self.process, 0.0)
                            except TimeoutError:
                                continue
                            waited = _owned_observation("child_wait", {"child": asdict(self.identity),
                                "exit_code": code, "observed_monotonic_ns": time.monotonic_ns()})
                            self._child_wait_observation = waited
                            self._emit("exited", observation=waited)
                            selector.unregister(key.fd)
                            continue
                        try:
                            chunk = os.read(key.fd, 8192)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            eof[name] = _owned_observation(name + "_eof", {"child": asdict(self.identity),
                                "bytes": counts[name], "content_sha256": hashes[name].hexdigest(),
                                "observed_monotonic_ns": time.monotonic_ns()})
                            selector.unregister(key.fd)
                            self._close_fd(name)
                            continue
                        hashes[name].update(chunk)
                        counts[name] += len(chunk)
                        limit = self.spec.stdout_limit if name == "stdout" else self.spec.stderr_limit
                        if counts[name] > limit:
                            with self._condition:
                                self.failure_code = self.failure_code or "owned_child_output_limit"
                                self._cancel.set()
                        else:
                            self._emit(name, chunk)
            if not self._settled.wait(_owned_deadline(self.spec.cleanup_deadline_ns)):
                raise OwnedChildHold("owned_child_start_unsettled", self)
            while not g5_scope_is_empty(self.scope_identity):
                _owned_deadline(self.spec.cleanup_deadline_ns)
                if not self._group_consumed:
                    with self._condition:
                        self.failure_code = self.failure_code or "owned_child_descendants_remained"
                    _kill_bound_cgroup(self.process)
                    self.scope_owner.abort(self.ticket)
                    self._group_consumed = True
                time.sleep(0.005)
            quiet = _owned_observation("kernel_quiescence", {"child": asdict(self.identity),
                "scope": asdict(self.scope_identity), "observed_monotonic_ns": time.monotonic_ns()})
            self.evidence = OwnedCompletionEvidence(self.identity, self.process.returncode,
                waited, eof["stdout"], eof["stderr"], quiet, self.failure_code)
            if self.binding is None:
                # Physical cleanup may be known, but absent admission completion is still HOLD.
                raise OwnedChildHold("owned_child_binding_unavailable", self)
            evidence_hash = owned_completion_evidence_sha256(self.evidence)
            completion = self.ports.complete_execution(self.binding, self.evidence,
                self.spec.cleanup_deadline_ns)
            if (type(completion) is not OwnedCompletion or completion.binding is not self.binding
                or completion.evidence_sha256 != evidence_hash
                or not _owned_hash_valid(completion.completion_record_sha256)):
                raise OwnedChildHold("owned_child_admission_completion_unverified", self)
            if not self._group_consumed:
                self.scope_owner.close_empty(self.ticket)
                self._group_consumed = True
            self.completion = completion
            self._emit("closed", observation=_owned_observation("completion", {
                "child": asdict(self.identity), "execution_binding_id": self.binding.execution_binding_id,
                "evidence_sha256": completion.evidence_sha256,
                "completion_record_sha256": completion.completion_record_sha256}))
        except Exception:
            with self._condition:
                self.failure_code = self.failure_code or "owned_child_cleanup_unverified"
                self._emit("failed")
        finally:
            # Unknown wait/EOF/group state keeps its actual pidfd/pipes and G5 owner in HOLD.
            if self.evidence is not None:
                self._close_owned()
            with self._condition:
                self._finished.set()
                self._condition.notify_all()

    def _close_owned(self) -> None:
        with self._condition:
            for name in tuple(self._fds):
                self._close_fd(name)
            for endpoint in self._sockets.values():
                endpoint.close()
            self._sockets.clear()
            self.process.pidfd = _close_descriptor(self.process.pidfd)


def start_owned_child(spec: OwnedChildSpec, *, runtime_layout: RuntimeLayout,
    scope_owner: object, ports: OwnedJournalPorts) -> OwnedDirectChild:
    """New private mechanism entry; actual admission composition is a separate caller."""
    return OwnedDirectChild(spec, scope_owner, ports)._start(runtime_layout)


__all__ += ["OwnedChildSpec", "OwnedJournalPorts", "OwnedDirectChild", "OwnedChildHold",
    "OwnedChildIdentity", "OwnedStartReservation", "OwnedExecutionBinding", "OwnedD17Publication",
    "OwnedCompletionEvidence", "OwnedCompletion", "owned_completion_evidence_sha256", "start_owned_child"]
