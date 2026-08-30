"""Bounded, isolated subprocess support for autonomous runtime checks."""

from __future__ import annotations

from collections.abc import Sequence
import contextlib
from dataclasses import dataclass
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


DEFAULT_STDOUT_LIMIT = 256 * 1024
DEFAULT_STDERR_LIMIT = 64 * 1024


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


def minimal_environment(*, home: Path) -> dict[str, str]:
    """Return the complete child environment; no caller environment is inherited."""

    if not isinstance(home, Path) or not home.is_absolute() or "\x00" in os.fspath(home):
        raise BoundedProcessError("command_environment_invalid")
    return {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        with contextlib.suppress(OSError):
            process.terminate()
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        with contextlib.suppress(OSError):
            process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)


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
        or any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in arguments)
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
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    streams: dict[int, tuple[str, object, int]] = {}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(
            list(arguments),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=minimal_environment(home=home),
            close_fds=True,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise BoundedProcessError("command_pipe_unavailable")
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
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
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
        for _name, stream, _limit in streams.values():
            with contextlib.suppress(OSError):
                stream.close()
        if process is not None:
            _terminate_process_group(process)


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResult",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "minimal_environment",
    "run_bounded",
]
