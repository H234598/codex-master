"""Bounded, isolated subprocess support for autonomous runtime checks."""

from __future__ import annotations

from collections.abc import Sequence
import contextlib
import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import selectors
import signal
import stat
import time


DEFAULT_STDOUT_LIMIT = 256 * 1024
DEFAULT_STDERR_LIMIT = 64 * 1024
_RUNTIME_SPAWN_HELPER = "_runtime_spawn_helper.so"
_GROUP_BINDING_ERRORS = frozenset(
    {
        errno.EAGAIN,
        errno.EINVAL,
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOMEM,
        errno.ENOSYS,
        errno.EOPNOTSUPP,
    }
)


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
    enable_subreaper: object


@dataclass(slots=True)
class _SpawnedProcess:
    process_group: int
    pidfd: int
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    returncode: int | None = None


def minimal_environment(*, home: Path) -> dict[str, str]:
    """Return the complete child environment; no caller environment is inherited."""

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
    }


def _close_descriptor(descriptor: int) -> int:
    if descriptor >= 0:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    return -1


def _runtime_spawn_helper_path(helper_path: Path | None = None) -> Path:
    if helper_path is not None and (
        not isinstance(helper_path, Path)
        or not helper_path.is_absolute()
        or "\x00" in os.fspath(helper_path)
    ):
        raise BoundedProcessError("command_group_unavailable")
    path = (
        Path(__file__).with_name(_RUNTIME_SPAWN_HELPER)
        if helper_path is None
        else helper_path
    )
    try:
        item = path.lstat()
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise BoundedProcessError("command_group_unavailable")
    return path


def _load_runtime_spawn_helper(
    helper_path: Path | None = None,
) -> _NativeSpawnHelper:
    """Load the image-built helper with its checked C header/ABI contract."""

    try:
        library = ctypes.CDLL(
            os.fspath(_runtime_spawn_helper_path(helper_path)), use_errno=True
        )
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
        enable_subreaper = library.codex_master_enable_subreaper
        enable_subreaper.argtypes = ()
        enable_subreaper.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    return _NativeSpawnHelper(library, spawn, enable_subreaper)


def _pid_from_fdinfo(pidfd: int) -> int:
    """Read the unreusable leader PID that the kernel associates with pidfd."""

    try:
        lines = (
            (Path("/proc/self/fdinfo") / str(pidfd))
            .read_text(encoding="ascii")
            .splitlines()
        )
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    values = [line.split("\t", 1)[1] for line in lines if line.startswith("Pid:\t")]
    if len(values) != 1:
        raise BoundedProcessError("command_group_unavailable")
    try:
        process_group = int(values[0])
    except ValueError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    if process_group <= 0:
        raise BoundedProcessError("command_group_unavailable")
    return process_group


def _verify_pidfd_capability(helper: _NativeSpawnHelper) -> None:
    """Fail before opening pipes unless every process-control primitive exists."""

    if (
        not hasattr(os, "P_PIDFD")
        or not hasattr(os, "P_PGID")
        or not hasattr(os, "O_CLOEXEC")
        or not hasattr(os, "pipe2")
        or not hasattr(signal, "pidfd_send_signal")
    ):
        raise BoundedProcessError("command_group_unavailable")
    if helper.enable_subreaper() != 0:
        raise BoundedProcessError("command_group_unavailable")
    try:
        pidfd = os.pidfd_open(os.getpid())
    except (AttributeError, OSError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    try:
        if _pid_from_fdinfo(pidfd) != os.getpid():
            raise BoundedProcessError("command_group_unavailable")
    finally:
        _close_descriptor(pidfd)


def _signal_bound_group(process_group: int, pidfd: int, signal_number: int) -> bool:
    """Signal only a process group whose leader PID remains held by pidfd."""

    while True:
        try:
            os.killpg(process_group, signal_number)
            return True
        except InterruptedError:
            continue
        except ProcessLookupError:
            return False
        except OSError:
            with contextlib.suppress(OSError):
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            return False


def _reap_process_group(process_group: int) -> None:
    """Reap subreaper-adopted descendants after their pinned group is killed."""

    while True:
        try:
            os.waitid(os.P_PGID, process_group, os.WEXITED)
        except InterruptedError:
            continue
        except (ChildProcessError, OSError):
            return


def _terminate_unbound_spawn(pidfd: int) -> None:
    """Kill/reap a partial spawn while its leader PID cannot be reused."""

    with contextlib.suppress(OSError):
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    waited = None
    while True:
        try:
            waited = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
            break
        except InterruptedError:
            continue
        except (ChildProcessError, OSError):
            break
    process_group = waited.si_pid if waited is not None else None
    if type(process_group) is int and process_group > 0:
        _signal_bound_group(process_group, pidfd, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError, OSError):
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
    if type(process_group) is int and process_group > 0:
        _reap_process_group(process_group)


def _spawn_with_pidfd(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    helper: _NativeSpawnHelper,
) -> _SpawnedProcess:
    """Spawn with typed native glibc state and only raw parent pipe FDs."""

    _verify_pidfd_capability(helper)
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
        if result != 0:
            code = (
                "command_group_unavailable"
                if result in _GROUP_BINDING_ERRORS
                else "command_unavailable"
            )
            raise BoundedProcessError(code)
        pidfd = spawned_pidfd.value
        if pidfd < 0:
            raise BoundedProcessError("command_group_unavailable")
        process = _SpawnedProcess(
            _pid_from_fdinfo(pidfd),
            pidfd,
            stdin_parent,
            stdout_parent,
            stderr_parent,
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


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(process: _SpawnedProcess) -> None:
    """Terminate only the session whose group number is held by its pidfd."""

    if not _signal_bound_group(process.process_group, process.pidfd, signal.SIGTERM):
        return
    deadline = time.monotonic() + 0.05
    while time.monotonic() < deadline:
        if not _process_group_exists(process.process_group):
            return
        time.sleep(0.005)
    _signal_bound_group(process.process_group, process.pidfd, signal.SIGKILL)


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


def _reap_process(process: _SpawnedProcess) -> None:
    try:
        _wait_for_process(process, 1)
    except (BoundedProcessError, TimeoutError):
        with contextlib.suppress(OSError):
            signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
        with contextlib.suppress(
            BoundedProcessError, ChildProcessError, OSError, TimeoutError
        ):
            _wait_for_process(process, 1)


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
    _runtime_spawn_helper_path: Path | None = None,
) -> BoundedProcessResult:
    """Run one command with bounded nonblocking I/O and pidfd-bound cleanup."""

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
    environment = minimal_environment(home=home)
    helper = _load_runtime_spawn_helper(_runtime_spawn_helper_path)
    if time.monotonic() >= deadline:
        raise BoundedProcessError("command_timeout")
    process: _SpawnedProcess | None = None
    selector: selectors.BaseSelector | None = None
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = _spawn_with_pidfd(
            arguments, cwd=cwd, environment=environment, helper=helper
        )
        if time.monotonic() >= deadline:
            raise BoundedProcessError("command_timeout")
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("command_timeout")
            ready = selector.select(remaining)
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
            returncode = _wait_for_process(
                process, max(0.0, deadline - time.monotonic())
            )
        except TimeoutError as exc:
            raise BoundedProcessError("command_timeout") from exc
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
            _terminate_process_group(process)
            _reap_process(process)
            _reap_process_group(process.process_group)
            _close_process_descriptors(process)
            process.pidfd = _close_descriptor(process.pidfd)


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "minimal_environment",
    "run_bounded",
]
