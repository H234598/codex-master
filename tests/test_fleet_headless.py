from __future__ import annotations

import io
import signal
import threading
import time

import pytest

from codex_master.fleet_headless import (
    HeadlessJobError,
    MAX_HEADLESS_TIMEOUT_SECONDS,
    MAX_HEADLESS_STDERR_BYTES,
    MAX_HEADLESS_STDOUT_BYTES,
    HeadlessJob,
    HeadlessJobRegistry,
    HeadlessProcessResult,
    run_bounded_process,
)


class FakeProcess:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", *, returncode: int | None = 0) -> None:
        self.pid = 81234
        self.stdin = TrackingInput()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self._returncode = returncode
        self.signals: list[int] = []
        self._lock = threading.Lock()
        self.prompt = b""

    def poll(self) -> int | None:
        with self._lock:
            return self._returncode

    def wait(self) -> int:
        with self._lock:
            if self._returncode is None:
                self._returncode = 0
            return self._returncode

    def signal(self, signum: int) -> None:
        with self._lock:
            self.signals.append(signum)
            if signum in {signal.SIGINT, signal.SIGTERM, signal.SIGKILL}:
                self._returncode = 130 if signum == signal.SIGINT else 143


class TrackingInput(io.BytesIO):
    def close(self) -> None:
        self.prompt = self.getvalue()
        super().close()


def make_job(process: FakeProcess) -> tuple[HeadlessJob, HeadlessJobRegistry, list[tuple[int, int]]]:
    signals: list[tuple[int, int]] = []

    def send(process_object: object, signum: int) -> None:
        process_object.signal(signum)  # type: ignore[attr-defined]
        signals.append((process_object.pid, signum))  # type: ignore[attr-defined]

    registry = HeadlessJobRegistry(signal_group=send)
    job = HeadlessJob("d1", "assignment-1", process, time.monotonic(), 7)
    registry.register(job)
    return job, registry, signals


def test_bounded_process_reads_both_streams_and_only_prompt_enters_stdin() -> None:
    process = FakeProcess(b"answer\n", b"diagnostic\n")
    job, registry, _signals = make_job(process)
    result = run_bounded_process(
        job,
        ("/private/gemini", "--output-format", "stream-json"),
        '{"task":"private"}',
        {"HOME": "/private/home", "GEMINI_API_KEY": "secret"},
        registry,
        timeout_seconds=5,
    )

    assert result == HeadlessProcessResult(0, b"answer\n", b"diagnostic\n", False, False, False, False)
    assert process.stdin.prompt == b'{"task":"private"}'
    assert registry.status("d1")["raw_output"] == "not_returned"
    assert "private" not in repr(registry.status("d1"))


def test_bounded_process_accepts_only_the_120_minute_timeout_cap() -> None:
    process = FakeProcess(b"answer\n")
    job, registry, _signals = make_job(process)
    result = run_bounded_process(
        job, ("/private/gemini",), "prompt", {}, registry,
        timeout_seconds=MAX_HEADLESS_TIMEOUT_SECONDS,
    )

    assert result.returncode == 0

    too_long_process = FakeProcess()
    too_long_job, too_long_registry, _signals = make_job(too_long_process)
    with pytest.raises(HeadlessJobError, match="headless_timeout_invalid"):
        run_bounded_process(
            too_long_job, ("/private/gemini",), "prompt", {}, too_long_registry,
            timeout_seconds=MAX_HEADLESS_TIMEOUT_SECONDS + 1,
        )


def test_bounded_process_caps_each_stream_and_combined_output() -> None:
    process = FakeProcess(
        b"o" * (MAX_HEADLESS_STDOUT_BYTES + 100),
        b"e" * (MAX_HEADLESS_STDERR_BYTES + 100),
    )
    job, registry, _signals = make_job(process)
    result = run_bounded_process(
        job, ("/private/gemini",), "prompt", {}, registry, timeout_seconds=5,
    )

    assert len(result.stdout) <= MAX_HEADLESS_STDOUT_BYTES
    assert len(result.stderr) <= MAX_HEADLESS_STDERR_BYTES
    assert len(result.stdout) + len(result.stderr) <= MAX_HEADLESS_STDOUT_BYTES + MAX_HEADLESS_STDERR_BYTES
    assert result.stdout_truncated or result.stderr_truncated


def test_cancel_escalates_only_through_the_process_group() -> None:
    process = FakeProcess(returncode=None)
    job, registry, signals = make_job(process)
    registry.request_cancel("d1")
    result = run_bounded_process(
        job, ("/private/gemini",), "prompt", {}, registry, timeout_seconds=5,
    )

    assert result.cancelled is True
    assert signals[0] == (process.pid, signal.SIGINT)
    assert all(pid == process.pid for pid, _signum in signals)


def test_finish_keeps_public_job_record_data_sparse() -> None:
    process = FakeProcess()
    job, registry, _signals = make_job(process)
    registry.finish(
        job,
        HeadlessProcessResult(0, b"private answer", b"private stderr", False, False, False, False),
    )

    public = registry.status("d1")
    assert public["status"] == "completed"
    assert public["raw_output"] == "not_returned"
    assert "private" not in repr(public)


def test_new_process_setup_failure_reaps_owned_process() -> None:
    process = FakeProcess()
    process.stderr = None
    signals: list[int] = []
    registry = HeadlessJobRegistry(signal_group=lambda _process, signum: signals.append(signum))
    job = HeadlessJob("d1", "assignment-1", None, time.monotonic(), 7)

    with pytest.raises(Exception, match="headless_stderr_unavailable"):
        run_bounded_process(
            job, ("/private/gemini",), "prompt", {}, registry,
            timeout_seconds=5, popen_factory=lambda *_args, **_kwargs: process,
        )

    assert job.process is None
    assert signal.SIGKILL in signals
