"""Bounded subprocess support inside one non-delegated systemd cgroup-v2 unit."""

from __future__ import annotations

from collections.abc import Sequence
import contextlib
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import secrets
import selectors
import signal
import stat
import subprocess
import time

from codex_master.runtime_layout import (
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
_CLEANUP_SECONDS = 0.5


class BoundedProcessError(RuntimeError):
    """A redacted subprocess failure that never carries child output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class _NativeSpawnHelper:
    library: object
    spawn: object


@dataclass(slots=True)
class _SpawnedProcess:
    unit: str
    pidfd: int
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    cgroup: Path | None = None
    returncode: int | None = None


def _runtime_directory() -> Path:
    path = _RUNTIME_DIRECTORY_ROOT / str(os.geteuid())
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


def minimal_environment(*, home: Path) -> dict[str, str]:
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
        "XDG_RUNTIME_DIR": os.fspath(_runtime_directory()),
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
        raise BoundedProcessError("command_group_unavailable") from exc
    if not controllers or not hasattr(os, "P_PIDFD") or not hasattr(os, "pipe2"):
        raise BoundedProcessError("command_group_unavailable")
    _systemctl(("show-environment",), environment=environment, deadline=deadline)


def _unit_name() -> str:
    return f"codex-master-runtime-{os.geteuid()}-{secrets.token_hex(16)}.service"


def _systemd_run_arguments(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    unit: str,
) -> tuple[str, ...]:
    clean_environment = tuple(f"{name}={value}" for name, value in environment.items())
    return (
        _SYSTEMD_RUN,
        "--user",
        f"--unit={unit}",
        "--property=Delegate=no",
        "--property=KillMode=control-group",
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


def _bind_cgroup(
    process: _SpawnedProcess, *, environment: dict[str, str], deadline: float
) -> None:
    while True:
        output = _systemctl(
            ("show", "--value", "--property=ControlGroup", process.unit),
            environment=environment,
            deadline=deadline,
        )
        if output.strip():
            cgroup = _cgroup_path(output)
            if (cgroup / "cgroup.events").is_file():
                process.cgroup = cgroup
                return
        time.sleep(min(0.005, _remaining(deadline)))


def _cgroup_is_empty(cgroup: Path) -> bool:
    try:
        events = (cgroup / "cgroup.events").read_text(encoding="ascii")
    except FileNotFoundError:
        return True
    except (OSError, UnicodeError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    populated = [line for line in events.splitlines() if line.startswith("populated ")]
    if populated != ["populated 0"]:
        return False
    try:
        return not (cgroup / "cgroup.procs").read_text(encoding="ascii").split()
    except FileNotFoundError:
        return True
    except (OSError, UnicodeError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc


def _wait_for_cgroup_empty(cgroup: Path, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if _cgroup_is_empty(cgroup):
            return True
        time.sleep(0.005)
    return _cgroup_is_empty(cgroup)


def _stop_cgroup(
    process: _SpawnedProcess, *, environment: dict[str, str], deadline: float
) -> None:
    with contextlib.suppress(BoundedProcessError):
        _systemctl(("stop", process.unit), environment=environment, deadline=deadline)
    if process.cgroup is not None:
        with contextlib.suppress(BoundedProcessError):
            _wait_for_cgroup_empty(process.cgroup, deadline)


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
    environment = minimal_environment(home=home)
    helper = _load_runtime_spawn_helper(layout)
    _verify_runner_capability(environment=environment, deadline=deadline)
    unit = _unit_name()
    command = _systemd_run_arguments(
        arguments, cwd=cwd, environment=environment, unit=unit
    )
    process: _SpawnedProcess | None = None
    selector: selectors.BaseSelector | None = None
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = _spawn_with_pidfd(
            command, cwd=cwd, environment=environment, helper=helper, unit=unit
        )
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
        if process.cgroup is None or not _wait_for_cgroup_empty(
            process.cgroup, deadline
        ):
            raise BoundedProcessError("command_timeout")
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
            cleanup_deadline = time.monotonic() + _CLEANUP_SECONDS
            _close_process_descriptors(process)
            _stop_cgroup(process, environment=environment, deadline=cleanup_deadline)
            _reap_process(process, cleanup_deadline)
            process.pidfd = _close_descriptor(process.pidfd)


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "minimal_environment",
    "run_bounded",
]
