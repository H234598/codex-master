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
import time
from typing import BinaryIO


DEFAULT_STDOUT_LIMIT = 256 * 1024
DEFAULT_STDERR_LIMIT = 64 * 1024
_POSIX_SPAWN_SETSID = 0x80
_SPAWN_BUFFER_BYTES = 512
_GROUP_BINDING_ERRORS = frozenset(
    {
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


@dataclass(slots=True)
class _SpawnedProcess:
    process_group: int
    pidfd: int
    stdin: BinaryIO
    stdout: BinaryIO
    stderr: BinaryIO
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


def _native_function(library: object, name: str, argtypes: list[object]) -> object:
    try:
        function = getattr(library, name)
    except AttributeError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    function.argtypes = argtypes
    function.restype = ctypes.c_int
    return function


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


def _verify_pidfd_fdinfo_capability() -> None:
    """Fail before execution unless a pidfd can supply its stable process ID."""

    if not hasattr(signal, "pidfd_send_signal") or not hasattr(os, "P_PIDFD"):
        raise BoundedProcessError("command_group_unavailable")
    try:
        pidfd = os.pidfd_open(os.getpid())
    except (AttributeError, OSError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    try:
        if _pid_from_fdinfo(pidfd) != os.getpid():
            raise BoundedProcessError("command_group_unavailable")
    finally:
        with contextlib.suppress(OSError):
            os.close(pidfd)


def _terminate_unbound_spawn(pidfd: int) -> None:
    """Kill and reap an incomplete spawn without releasing its group leader PID.

    `WNOWAIT` keeps the pidfd-target leader as a zombie while `killpg` uses the
    PID reported by that same pidfd. The number therefore cannot be reused for
    a foreign process before the group is terminated.
    """

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
    if waited is not None and type(waited.si_pid) is int and waited.si_pid > 0:
        with contextlib.suppress(OSError):
            os.killpg(waited.si_pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError, OSError):
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)


def _spawn_with_pidfd(
    arguments: Sequence[str], *, cwd: Path, environment: dict[str, str]
) -> _SpawnedProcess:
    """Spawn a new session with glibc 2.39+'s atomic pidfd_spawnp primitive."""

    _verify_pidfd_fdinfo_capability()
    try:
        library = ctypes.CDLL(None, use_errno=True)
        spawn = _native_function(
            library,
            "pidfd_spawnp",
            [
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.POINTER(ctypes.c_char_p),
            ],
        )
        attr_init = _native_function(library, "posix_spawnattr_init", [ctypes.c_void_p])
        attr_destroy = _native_function(
            library, "posix_spawnattr_destroy", [ctypes.c_void_p]
        )
        attr_setflags = _native_function(
            library, "posix_spawnattr_setflags", [ctypes.c_void_p, ctypes.c_short]
        )
        actions_init = _native_function(
            library, "posix_spawn_file_actions_init", [ctypes.c_void_p]
        )
        actions_destroy = _native_function(
            library, "posix_spawn_file_actions_destroy", [ctypes.c_void_p]
        )
        actions_dup2 = _native_function(
            library,
            "posix_spawn_file_actions_adddup2",
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_int],
        )
        actions_chdir = _native_function(
            library,
            "posix_spawn_file_actions_addchdir_np",
            [ctypes.c_void_p, ctypes.c_char_p],
        )
        actions_closefrom = _native_function(
            library,
            "posix_spawn_file_actions_addclosefrom_np",
            [ctypes.c_void_p, ctypes.c_int],
        )
    except (AttributeError, OSError) as exc:
        raise BoundedProcessError("command_group_unavailable") from exc

    attr = ctypes.create_string_buffer(_SPAWN_BUFFER_BYTES)
    actions = ctypes.create_string_buffer(_SPAWN_BUFFER_BYTES)
    attr_initialized = False
    actions_initialized = False
    stdin_read = stdin_write = stdout_read = stdout_write = stderr_read = (
        stderr_write
    ) = -1
    stdin: BinaryIO | None = None
    stdout: BinaryIO | None = None
    stderr: BinaryIO | None = None
    pidfd = -1
    transferred = False
    try:
        if attr_init(attr) != 0:
            raise BoundedProcessError("command_group_unavailable")
        attr_initialized = True
        if attr_setflags(attr, _POSIX_SPAWN_SETSID) != 0:
            raise BoundedProcessError("command_group_unavailable")
        if actions_init(actions) != 0:
            raise BoundedProcessError("command_group_unavailable")
        actions_initialized = True
        stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
        stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
        stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
        stdin = os.fdopen(stdin_write, "wb", buffering=0)
        stdin_write = -1
        stdout = os.fdopen(stdout_read, "rb", buffering=0)
        stdout_read = -1
        stderr = os.fdopen(stderr_read, "rb", buffering=0)
        stderr_read = -1
        for source, target in ((stdin_read, 0), (stdout_write, 1), (stderr_write, 2)):
            if actions_dup2(actions, source, target) != 0:
                raise BoundedProcessError("command_group_unavailable")
        if (
            actions_chdir(actions, os.fsencode(cwd)) != 0
            or actions_closefrom(actions, 3) != 0
        ):
            raise BoundedProcessError("command_group_unavailable")
        encoded_arguments = [os.fsencode(argument) for argument in arguments]
        argv = (ctypes.c_char_p * (len(encoded_arguments) + 1))(
            *encoded_arguments, None
        )
        encoded_environment = [
            os.fsencode(f"{name}={value}") for name, value in environment.items()
        ]
        envp = (ctypes.c_char_p * (len(encoded_environment) + 1))(
            *encoded_environment, None
        )
        spawned_pidfd = ctypes.c_int(-1)
        result = spawn(
            ctypes.byref(spawned_pidfd),
            encoded_arguments[0],
            actions,
            attr,
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
        process_group = _pid_from_fdinfo(pidfd)
        process = _SpawnedProcess(process_group, pidfd, stdin, stdout, stderr)
        transferred = True
        return process
    except BoundedProcessError:
        raise
    except OSError as exc:
        raise BoundedProcessError("command_group_unavailable") from exc
    finally:
        if actions_initialized:
            actions_destroy(actions)
        if attr_initialized:
            attr_destroy(attr)
        for descriptor in (stdin_read, stdout_write, stderr_write):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        if not transferred:
            for stream in (stdin, stdout, stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
            if pidfd >= 0:
                _terminate_unbound_spawn(pidfd)
                with contextlib.suppress(OSError):
                    os.close(pidfd)


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(process: _SpawnedProcess) -> None:
    """Terminate only the session whose group ID is pinned by atomic pidfd spawn."""

    try:
        os.killpg(process.process_group, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        with contextlib.suppress(AttributeError, OSError):
            signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
        return
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if not _process_group_exists(process.process_group):
            return
        time.sleep(0.02)
    with contextlib.suppress(OSError):
        os.killpg(process.process_group, signal.SIGKILL)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if not _process_group_exists(process.process_group):
            return
        time.sleep(0.02)


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
        except ChildProcessError as exc:
            raise BoundedProcessError("command_unavailable") from exc
        if waited is not None:
            process.returncode = _returncode(waited)
            return process.returncode
        if time.monotonic() >= deadline:
            raise TimeoutError
        time.sleep(0.01)


def _reap_process(process: _SpawnedProcess) -> None:
    try:
        _wait_for_process(process, 1)
    except (BoundedProcessError, TimeoutError):
        with contextlib.suppress(AttributeError, OSError):
            signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
        with contextlib.suppress(
            BoundedProcessError, ChildProcessError, OSError, TimeoutError
        ):
            _wait_for_process(process, 1)


def _close_process_streams(process: _SpawnedProcess) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        with contextlib.suppress(OSError):
            stream.close()


def run_bounded(
    arguments: Sequence[str],
    *,
    cwd: Path,
    home: Path,
    timeout_seconds: float,
    stdout_limit: int = DEFAULT_STDOUT_LIMIT,
    stderr_limit: int = DEFAULT_STDERR_LIMIT,
    input_data: bytes = b"",
) -> BoundedProcessResult:
    """Run one command with isolated environment, bounded pipes and group cleanup."""

    if (
        not isinstance(cwd, Path)
        or not cwd.is_absolute()
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
    process: _SpawnedProcess | None = None
    selector: selectors.BaseSelector | None = None
    streams: dict[int, tuple[str, BinaryIO, int]] = {}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = _spawn_with_pidfd(
            arguments, cwd=cwd, environment=minimal_environment(home=home)
        )
        try:
            process.stdin.write(input_data)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()
        selector = selectors.DefaultSelector()
        for name, stream, limit in (
            ("stdout", process.stdout, stdout_limit),
            ("stderr", process.stderr, stderr_limit),
        ):
            descriptor = stream.fileno()
            streams[descriptor] = (name, stream, limit)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + float(timeout_seconds)
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("command_timeout")
            ready = selector.select(remaining)
            if not ready:
                raise BoundedProcessError("command_timeout")
            for key, _events in ready:
                descriptor = key.fileobj.fileno()
                name, stream, limit = streams[descriptor]
                chunk = os.read(descriptor, min(8192, limit + 1 - len(output[name])))
                if not chunk:
                    selector.unregister(stream)
                    streams.pop(descriptor)
                    continue
                output[name].extend(chunk)
                if len(output[name]) > limit:
                    raise BoundedProcessError(f"command_{name}_limit")
        try:
            returncode = _wait_for_process(
                process, max(0.0, deadline - time.monotonic())
            )
        except TimeoutError as exc:
            raise BoundedProcessError("command_timeout") from exc
        try:
            stdout = output["stdout"].decode("utf-8")
            stderr = output["stderr"].decode("utf-8")
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
            _close_process_streams(process)
            with contextlib.suppress(OSError):
                os.close(process.pidfd)


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "minimal_environment",
    "run_bounded",
]
