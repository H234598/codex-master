from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass


MAX_HEADLESS_STDOUT_BYTES = 1024 * 1024
MAX_HEADLESS_STDERR_BYTES = 256 * 1024
MAX_HEADLESS_TOTAL_BYTES = MAX_HEADLESS_STDOUT_BYTES + MAX_HEADLESS_STDERR_BYTES
MAX_HEADLESS_TIMEOUT_SECONDS = 120 * 60
HEADLESS_CANCEL_GRACE_SECONDS = 1.0
HEADLESS_TERM_GRACE_SECONDS = 1.0
HEADLESS_POLL_SECONDS = 0.02


class HeadlessJobError(RuntimeError):
    pass


@dataclass(slots=True)
class HeadlessJob:
    agent: str
    assignment_id: str
    process: object | None
    started_monotonic: float
    generation: int
    cancel_requested: bool = False
    force_cancel: bool = False
    cancel_sent_monotonic: float | None = None
    term_sent_monotonic: float | None = None
    kill_sent_monotonic: float | None = None


@dataclass(frozen=True, slots=True)
class HeadlessProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    cancelled: bool
    readers_alive: bool = False


def _pid(process: object) -> int | None:
    value = getattr(process, "pid", None)
    return value if isinstance(value, int) and value > 0 else None


def _poll(process: object) -> int | None:
    poll = getattr(process, "poll", None)
    if not callable(poll):
        raise HeadlessJobError("headless_process_invalid")
    value = poll()
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise HeadlessJobError("headless_process_invalid")
    return value


def signal_process_group(process: object, signum: int) -> None:
    pid = _pid(process)
    if pid is None:
        raise HeadlessJobError("headless_process_identity_unknown")
    try:
        pgid = os.getpgid(pid)
    except OSError as exc:
        raise HeadlessJobError("headless_process_identity_unknown") from exc
    if pgid != pid or pgid == os.getpgrp():
        raise HeadlessJobError("headless_process_identity_unknown")
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise HeadlessJobError("headless_process_signal_failed") from exc


class HeadlessJobRegistry:
    def __init__(self, *, signal_group: Callable[[object, int], None] = signal_process_group) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, HeadlessJob] = {}
        self._last: dict[str, dict[str, object]] = {}
        self._signal_group = signal_group

    def register(self, job: HeadlessJob) -> None:
        with self._lock:
            if job.agent in self._jobs:
                raise HeadlessJobError("headless_job_already_running")
            self._jobs[job.agent] = job

    def get(self, agent: str) -> HeadlessJob | None:
        with self._lock:
            return self._jobs.get(agent)

    def request_cancel(self, agent: str, *, force: bool = False) -> dict[str, object]:
        with self._lock:
            job = self._jobs.get(agent)
            if job is None:
                return dict(self._last.get(agent, {
                    "agent": agent,
                    "status": "not_running",
                    "raw_output": "not_returned",
                }))
            self._begin_cancel_locked(job, time.monotonic(), force=force)
            return self._public_running(job)

    def request_timeout(self, agent: str, now: float) -> None:
        with self._lock:
            job = self._jobs.get(agent)
            if job is not None:
                self._begin_cancel_locked(job, now, force=False)

    def advance_cancel(self, agent: str, now: float) -> None:
        with self._lock:
            job = self._jobs.get(agent)
            if job is None or not job.cancel_requested:
                return
            if job.force_cancel:
                self._send_kill_locked(job, now)
            elif job.cancel_sent_monotonic is None:
                self._begin_cancel_locked(job, now, force=False)
            elif now - job.cancel_sent_monotonic >= HEADLESS_CANCEL_GRACE_SECONDS:
                if job.term_sent_monotonic is None:
                    job.term_sent_monotonic = now
                    self._signal_locked(job, signal.SIGTERM)
                elif now - job.term_sent_monotonic >= HEADLESS_TERM_GRACE_SECONDS:
                    self._send_kill_locked(job, now)

    def cancel_requested(self, agent: str) -> bool:
        with self._lock:
            job = self._jobs.get(agent)
            return bool(job and job.cancel_requested)

    def _signal_locked(self, job: HeadlessJob, signum: int) -> bool:
        try:
            self._signal_group(job.process, signum)
        except HeadlessJobError:
            if signum != signal.SIGKILL:
                job.force_cancel = True
            return False
        return True

    def _send_kill_locked(self, job: HeadlessJob, now: float) -> None:
        if job.kill_sent_monotonic is None:
            if self._signal_locked(job, signal.SIGKILL):
                job.kill_sent_monotonic = now

    def _begin_cancel_locked(self, job: HeadlessJob, now: float, *, force: bool) -> None:
        job.cancel_requested = True
        job.force_cancel = job.force_cancel or force
        if force:
            self._send_kill_locked(job, now)
        elif job.cancel_sent_monotonic is None:
            job.cancel_sent_monotonic = now
            self._signal_locked(job, signal.SIGINT)

    def finish(self, job: HeadlessJob, result: HeadlessProcessResult) -> None:
        with self._lock:
            self._jobs.pop(job.agent, None)
            self._last[job.agent] = {
                "agent": job.agent,
                "assignment_id": job.assignment_id,
                "generation": job.generation,
                "status": (
                    "timeout" if result.timed_out
                    else "cancelled" if result.cancelled
                    else "completed" if result.returncode == 0 and not result.stdout_truncated and not result.stderr_truncated
                    else "failed"
                ),
                "returncode": result.returncode,
                "stdout_truncated": result.stdout_truncated,
                "stderr_truncated": result.stderr_truncated,
                "cancelled": result.cancelled,
                "timed_out": result.timed_out,
                "raw_output": "not_returned",
            }

    def status(self, agent: str) -> dict[str, object]:
        with self._lock:
            job = self._jobs.get(agent)
            if job is not None:
                return self._public_running(job)
            return dict(self._last.get(agent, {
                "agent": agent,
                "status": "not_running",
                "raw_output": "not_returned",
            }))

    @staticmethod
    def _public_running(job: HeadlessJob) -> dict[str, object]:
        return {
            "agent": job.agent,
            "assignment_id": job.assignment_id,
            "generation": job.generation,
            "status": "cancelling" if job.cancel_requested else "running",
            "pid_state": "set" if _pid(job.process) is not None else "unknown",
            "cancel_requested": job.cancel_requested,
            "raw_output": "not_returned",
        }


def _read_pipe(
    pipe: object,
    limit: int,
    shared: dict[str, int],
    shared_lock: threading.Lock,
    output: bytearray,
) -> bool:
    read = getattr(pipe, "read", None)
    if not callable(read):
        return True
    truncated = False
    try:
        while True:
            chunk = read(64 * 1024)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                chunk = str(chunk).encode("utf-8", errors="replace")
            with shared_lock:
                available = max(0, limit - len(output))
                total_available = max(0, MAX_HEADLESS_TOTAL_BYTES - shared["total"])
                accepted = min(len(chunk), available, total_available)
                if accepted:
                    output.extend(chunk[:accepted])
                    shared["total"] += accepted
                if accepted < len(chunk):
                    truncated = True
    finally:
        close = getattr(pipe, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()
    return truncated


def run_bounded_process(
    job: HeadlessJob,
    argv: tuple[str, ...],
    prompt: str,
    env: Mapping[str, str],
    registry: HeadlessJobRegistry,
    *,
    timeout_seconds: float,
    popen_factory: Callable[..., object] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> HeadlessProcessResult:
    if not 0 < timeout_seconds <= MAX_HEADLESS_TIMEOUT_SECONDS:
        raise HeadlessJobError("headless_timeout_invalid")
    popen = popen_factory or subprocess.Popen
    process = job.process
    owns_process = process is None
    threads: list[threading.Thread] = []
    if process is None:
        process = popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            shell=False,
            start_new_session=True,
        )
        job.process = process
    try:
        stdin = getattr(process, "stdin", None)
        if stdin is None:
            raise HeadlessJobError("headless_stdin_unavailable")

        shared = {"total": 0}
        shared_lock = threading.Lock()
        stdout = bytearray()
        stderr = bytearray()
        truncated_flags = {"stdout": False, "stderr": False}
        for pipe, limit, target, label in (
            (getattr(process, "stdout", None), MAX_HEADLESS_STDOUT_BYTES, stdout, "stdout"),
            (getattr(process, "stderr", None), MAX_HEADLESS_STDERR_BYTES, stderr, "stderr"),
        ):
            if pipe is None:
                raise HeadlessJobError(f"headless_{label}_unavailable")
            thread = threading.Thread(
                target=lambda p=pipe, byte_limit=limit, o=target, name=label: truncated_flags.__setitem__(
                    name, _read_pipe(p, byte_limit, shared, shared_lock, o)
                ),
                name=f"codex-headless-{job.agent}-{label}",
                daemon=True,
            )
            threads.append(thread)
            thread.start()
        try:
            stdin.write(prompt.encode("utf-8"))
            stdin.close()
        except (OSError, UnicodeError) as exc:
            raise HeadlessJobError("headless_stdin_failed") from exc

        deadline = clock() + timeout_seconds
        timed_out = False
        cancel_deadline: float | None = None
        while True:
            returncode = _poll(process)
            if returncode is not None:
                break
            now = clock()
            if not timed_out and now >= deadline:
                timed_out = True
                registry.request_timeout(job.agent, now)
            if registry.cancel_requested(job.agent):
                if cancel_deadline is None:
                    cancel_deadline = now + HEADLESS_CANCEL_GRACE_SECONDS + HEADLESS_TERM_GRACE_SECONDS + 1.0
                registry.advance_cancel(job.agent, now)
            if cancel_deadline is not None and now >= cancel_deadline:
                registry.request_cancel(job.agent, force=True)
                if _poll(process) is None:
                    raise HeadlessJobError("headless_process_unreaped")
            sleeper(HEADLESS_POLL_SECONDS)

        wait = getattr(process, "wait", None)
        if callable(wait):
            returncode = wait()
        for thread in threads:
            thread.join(timeout=1.0)
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise HeadlessJobError("headless_process_invalid")
        cancelled = registry.cancel_requested(job.agent) and not timed_out
        readers_alive = any(thread.is_alive() for thread in threads)
        with shared_lock:
            stdout_bytes = bytes(stdout)
            stderr_bytes = bytes(stderr)
            stdout_truncated = truncated_flags["stdout"] or readers_alive
            stderr_truncated = truncated_flags["stderr"] or readers_alive
        return HeadlessProcessResult(
            returncode,
            stdout_bytes,
            stderr_bytes,
            stdout_truncated,
            stderr_truncated,
            timed_out,
            cancelled,
            readers_alive,
        )
    except Exception:
        for thread in threads:
            thread.join(timeout=1.0)
        if owns_process and process is not None:
            with contextlib.suppress(Exception):
                registry._signal_group(process, signal.SIGKILL)
            for stream_name in ("stdin", "stdout", "stderr"):
                stream = getattr(process, stream_name, None)
                close = getattr(stream, "close", None)
                if callable(close):
                    with contextlib.suppress(Exception):
                        close()
            wait = getattr(process, "wait", None)
            if callable(wait):
                with contextlib.suppress(Exception):
                    wait(timeout=5)
            job.process = None
        raise
