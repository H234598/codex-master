from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from http import client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import io
import ipaddress
import math
import selectors
import socket
import threading
import time


MAX_METRICS_BYTES = 1_048_576
MIN_REQUEST_TIMEOUT_SECONDS = 0.05
MAX_REQUEST_TIMEOUT_SECONDS = 5.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 1.0
MAX_HANDLER_THREADS = 16
DEFAULT_MAX_HANDLER_THREADS = 4
HEALTH_HANDLER_RESERVE = 2
METRICS_OVERLOAD_HANDLER_RESERVE = 1
MAX_REQUEST_HEADER_BYTES = 65_536
MAX_PENDING_PREFACE_CONNECTIONS = 16
PREFACE_SELECTOR_TIMEOUT_SECONDS = 0.02
PREFACE_SHUTDOWN_TIMEOUT_SECONDS = 1.0
SOURCE_WAIT_POLL_SECONDS = 0.05


def _metrics_body(value: object) -> bytes:
    if type(value) is not str or not value:
        raise ValueError("invalid metrics payload")
    try:
        body = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid metrics payload") from None
    if len(body) > MAX_METRICS_BYTES:
        raise ValueError("invalid metrics payload")
    return body


class TimedMetricsReader:
    def __init__(
        self,
        source: Callable[[], str],
        *,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(source):
            raise TypeError("source must be callable")
        if type(ttl_seconds) not in {int, float} or not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 60:
            raise ValueError("invalid ttl_seconds")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._source = source
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._cached_value: str | None = None
        self._expires_at: float | None = None
        self._cache_generation: int | None = None
        self._lock = threading.Lock()
        self._generation_lock = threading.Lock()
        self._generation = 0

    def __call__(self) -> str:
        with self._generation_lock:
            generation = self._generation
        return self._read_generation(generation)

    def _begin_lifecycle(self) -> int:
        with self._generation_lock:
            self._generation += 1
            return self._generation

    def _cancel_lifecycle(self, generation: int) -> None:
        with self._generation_lock:
            if self._generation == generation:
                self._generation += 1

    def _read_generation(self, generation: int) -> str:
        with self._lock:
            now = self._clock()
            with self._generation_lock:
                if self._generation != generation:
                    raise RuntimeError("metrics reader unavailable")
                if (
                    self._cached_value is not None
                    and self._expires_at is not None
                    and self._cache_generation == generation
                    and now < self._expires_at
                ):
                    return self._cached_value
            value = self._source()
            _metrics_body(value)
            with self._generation_lock:
                if self._generation != generation:
                    raise RuntimeError("metrics reader unavailable")
                self._cached_value = value
                self._expires_at = now + self._ttl_seconds
                self._cache_generation = generation
            return value


class _MetricsSourceRun:
    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.completed = threading.Event()
        self.value: object = None
        self.failed = False
        self.timed_reader_generation: int | None = None


class _ProcessSourceWorkerGuard:
    """Keep H1 at one source worker across server lifecycle transitions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._starting = False

    def reserve(self, worker: threading.Thread, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + min(timeout_seconds, SOURCE_WAIT_POLL_SECONDS)
        while True:
            with self._lock:
                current = self._worker
                if current is None or (not self._starting and not current.is_alive()):
                    self._worker = worker
                    self._starting = True
                    return True
                if self._starting:
                    return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            threading.Event().wait(timeout=min(remaining, SOURCE_WAIT_POLL_SECONDS))

    def mark_started(self, worker: threading.Thread) -> None:
        with self._lock:
            if self._worker is worker:
                self._starting = False

    def cancel(self, worker: threading.Thread) -> None:
        with self._lock:
            if self._worker is worker:
                self._worker = None
                self._starting = False


_PROCESS_SOURCE_WORKER_GUARD = _ProcessSourceWorkerGuard()


class _BoundedMetricsSource:
    """Run at most one uninterruptible metrics source outside request handlers."""

    def __init__(self, source: Callable[[], str], stopping: threading.Event) -> None:
        self._source = source
        self._stopping = stopping
        self._lock = threading.Lock()
        self._active: _MetricsSourceRun | None = None
        self._next_generation = 0
        self._timed_reader_generation: int | None = None

    def read(self, timeout_seconds: float) -> object:
        with self._lock:
            if self._stopping.is_set():
                raise RuntimeError("metrics source unavailable")
            run = self._active
            if run is None:
                self._next_generation += 1
                run = _MetricsSourceRun(self._next_generation)
                worker = threading.Thread(
                    target=self._run,
                    args=(run,),
                    daemon=True,
                    name="metrics-source",
                )
                if not _PROCESS_SOURCE_WORKER_GUARD.reserve(worker, timeout_seconds):
                    raise RuntimeError("metrics source unavailable")
                if isinstance(self._source, TimedMetricsReader):
                    if self._timed_reader_generation is None:
                        self._timed_reader_generation = self._source._begin_lifecycle()
                    run.timed_reader_generation = self._timed_reader_generation
                self._active = run
                try:
                    worker.start()
                    _PROCESS_SOURCE_WORKER_GUARD.mark_started(worker)
                except RuntimeError:
                    self._active = None
                    run.failed = True
                    run.completed.set()
                    _PROCESS_SOURCE_WORKER_GUARD.cancel(worker)
        deadline = time.monotonic() + timeout_seconds
        while not self._stopping.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if run.completed.wait(timeout=min(remaining, SOURCE_WAIT_POLL_SECONDS)):
                if not self._stopping.is_set() and not run.failed:
                    return run.value
                break
        raise RuntimeError("metrics source unavailable")

    def cancel(self) -> None:
        if not isinstance(self._source, TimedMetricsReader):
            return
        with self._lock:
            generation = self._timed_reader_generation
        if generation is not None:
            self._source._cancel_lifecycle(generation)

    def _run(self, run: _MetricsSourceRun) -> None:
        try:
            if isinstance(self._source, TimedMetricsReader):
                assert run.timed_reader_generation is not None
                value = self._source._read_generation(run.timed_reader_generation)
            else:
                value = self._source()
        except BaseException:
            value = None
            failed = True
        else:
            failed = False
        with self._lock:
            accepted = self._active is run and not self._stopping.is_set()
            if self._active is run:
                self._active = None
            run.value = value
            run.failed = failed or not accepted
            run.completed.set()


class _PrefaceRequest:
    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        deadline: float,
    ) -> None:
        self.request = request
        self.client_address = client_address
        self.deadline = deadline
        self.preface = bytearray()


class _PrefixedSocketReader(io.RawIOBase):
    def __init__(self, preface: bytes, socket_reader: io.BufferedReader) -> None:
        self._preface = memoryview(preface)
        self._socket_reader = socket_reader

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int | None:
        if self._preface:
            size = min(len(buffer), len(self._preface))
            buffer[:size] = self._preface[:size]
            self._preface = self._preface[size:]
            return size
        return self._socket_reader.readinto(buffer)

    def close(self) -> None:
        if not self.closed:
            self._socket_reader.close()
        super().close()


def _preface_route(preface: bytes) -> str:
    header_end = preface.find(b"\r\n\r\n")
    if header_end < 0:
        return "other"
    header_block = preface[: header_end + 4]
    try:
        request_line, header_fields = header_block.split(b"\r\n", maxsplit=1)
        method, target, version = request_line.split(b" ")
        if version not in {b"HTTP/1.0", b"HTTP/1.1"}:
            return "other"
        http_client.parse_headers(BytesIO(header_fields))
    except (http_client.HTTPException, UnicodeError, ValueError):
        return "other"
    if method != b"GET":
        return "other"
    if target in {b"/health", b"/healthz"}:
        return "health"
    if target == b"/metrics":
        return "metrics"
    return "other"


class _MetricsRequestHandler(BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        socket_reader = self.rfile
        preface = self.server.take_handler_preface(self.request)  # type: ignore[attr-defined]
        self.rfile = io.BufferedReader(_PrefixedSocketReader(preface, socket_reader))

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/health", "/healthz"}:
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.path != "/metrics":
            self._send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        if not self.server.try_acquire_metrics_slot():  # type: ignore[attr-defined]
            self._send(503, b"metrics unavailable\n", "text/plain; charset=utf-8")
            return
        try:
            try:
                body = _metrics_body(self.server.read_metrics())  # type: ignore[attr-defined]
            except Exception:
                self._send(503, b"metrics unavailable\n", "text/plain; charset=utf-8")
                return
            self._send(
                200,
                body,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
                no_store=True,
            )
        finally:
            self.server.release_metrics_slot()  # type: ignore[attr-defined]

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        if code == 501:
            self._send(
                405,
                b"method not allowed\n",
                "text/plain; charset=utf-8",
                allow="GET",
            )
            return
        super().send_error(code, message, explain)

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        no_store: bool = False,
        allow: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if no_store:
            self.send_header("Cache-Control", "no-store")
        if allow is not None:
            self.send_header("Allow", allow)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class MetricsHttpServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        metrics_reader: Callable[[], str],
        *,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_handler_threads: int = DEFAULT_MAX_HANDLER_THREADS,
    ) -> None:
        host, port = server_address
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid port")
        if not callable(metrics_reader):
            raise TypeError("metrics_reader must be callable")
        if (
            type(request_timeout_seconds) not in {int, float}
            or not math.isfinite(request_timeout_seconds)
            or not MIN_REQUEST_TIMEOUT_SECONDS <= request_timeout_seconds <= MAX_REQUEST_TIMEOUT_SECONDS
        ):
            raise ValueError("invalid request timeout")
        if (
            type(max_handler_threads) is not int
            or not 1 <= max_handler_threads <= MAX_HANDLER_THREADS
        ):
            raise ValueError("invalid handler limit")
        if type(host) is not str:
            raise ValueError("loopback address required")
        if "%" in host:
            raise ValueError("loopback address required")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("loopback address required") from None
        if not address.is_loopback:
            raise ValueError("loopback address required")
        self.address_family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        self.metrics_reader = metrics_reader
        self.request_timeout_seconds = float(request_timeout_seconds)
        self._request_slots = threading.BoundedSemaphore(max_handler_threads)
        self._connection_slots = threading.BoundedSemaphore(max_handler_threads)
        self._health_slots = threading.BoundedSemaphore(HEALTH_HANDLER_RESERVE)
        self._metrics_overload_slots = threading.BoundedSemaphore(
            METRICS_OVERLOAD_HANDLER_RESERVE
        )
        self._admission_lock = threading.Lock()
        self._admitted_slots: dict[int, threading.BoundedSemaphore] = {}
        self._handler_prefaces: dict[int, bytes] = {}
        self._stopping = threading.Event()
        self._metrics_source = _BoundedMetricsSource(metrics_reader, self._stopping)
        self._preface_lock = threading.Lock()
        self._preface_pending: OrderedDict[socket.socket, _PrefaceRequest] = OrderedDict()
        self._preface_registered: set[socket.socket] = set()
        self._preface_selector = selectors.DefaultSelector()
        self._preface_wakeup_reader, self._preface_wakeup_writer = socket.socketpair()
        self._preface_wakeup_reader.setblocking(False)
        self._preface_wakeup_writer.setblocking(False)
        self._preface_selector.register(
            self._preface_wakeup_reader, selectors.EVENT_READ, data="wakeup"
        )
        self._preface_thread: threading.Thread | None = None
        self._preface_resources_closed = False
        super().__init__((host, port), _MetricsRequestHandler)

    def read_metrics(self) -> object:
        return self._metrics_source.read(self.request_timeout_seconds)

    def try_acquire_metrics_slot(self) -> bool:
        return self._request_slots.acquire(blocking=False)

    def release_metrics_slot(self) -> None:
        self._request_slots.release()

    def take_handler_preface(self, request: socket.socket) -> bytes:
        with self._admission_lock:
            return self._handler_prefaces.pop(id(request), b"")

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self._start_preface_dispatcher()
        super().serve_forever(poll_interval)

    def shutdown(self) -> None:
        self._metrics_source.cancel()
        self._stopping.set()
        self._stop_preface_dispatcher()
        super().shutdown()

    def server_close(self) -> None:
        self._metrics_source.cancel()
        self._stopping.set()
        self._stop_preface_dispatcher()
        super().server_close()
        self._close_preface_resources()

    def _start_preface_dispatcher(self) -> None:
        with self._preface_lock:
            if self._preface_thread is not None or self._stopping.is_set():
                return
            thread = threading.Thread(
                target=self._run_preface_dispatcher,
                daemon=True,
                name="metrics-preface",
            )
            self._preface_thread = thread
        try:
            thread.start()
        except RuntimeError:
            with self._preface_lock:
                if self._preface_thread is thread:
                    self._preface_thread = None
            raise

    def _wake_preface_dispatcher(self) -> None:
        try:
            self._preface_wakeup_writer.send(b"\0")
        except (BlockingIOError, OSError):
            return

    def _drain_preface_wakeup(self) -> None:
        while True:
            try:
                if not self._preface_wakeup_reader.recv(1024):
                    return
            except BlockingIOError:
                return
            except OSError:
                return

    def _metrics_slot_is_busy(self) -> bool:
        if self.try_acquire_metrics_slot():
            self.release_metrics_slot()
            return False
        return True

    def _sync_preface_selector(self) -> None:
        with self._preface_lock:
            pending = set(self._preface_pending)
        for request in self._preface_registered - pending:
            try:
                self._preface_selector.unregister(request)
            except (KeyError, OSError, ValueError):
                pass
            self._preface_registered.discard(request)
        for request in pending - self._preface_registered:
            try:
                self._preface_selector.register(request, selectors.EVENT_READ)
            except (KeyError, OSError, ValueError):
                with self._preface_lock:
                    removed = self._preface_pending.pop(request, None)
                if removed is not None:
                    self.shutdown_request(request)
                continue
            self._preface_registered.add(request)

    def _expire_preface_requests(self) -> None:
        now = time.monotonic()
        with self._preface_lock:
            expired = [
                request
                for request, state in self._preface_pending.items()
                if state.deadline <= now
            ]
            for request in expired:
                del self._preface_pending[request]
        for request in expired:
            self.shutdown_request(request)

    def _remove_preface_request(self, request: socket.socket) -> _PrefaceRequest | None:
        with self._preface_lock:
            state = self._preface_pending.pop(request, None)
        if state is None:
            return None
        try:
            self._preface_selector.unregister(request)
        except (KeyError, OSError, ValueError):
            pass
        self._preface_registered.discard(request)
        return state

    def _handle_preface_request(self, request: socket.socket) -> None:
        with self._preface_lock:
            state = self._preface_pending.get(request)
        if state is None:
            return
        if state.deadline <= time.monotonic():
            removed = self._remove_preface_request(request)
            if removed is not None:
                self.shutdown_request(request)
            return
        try:
            received = request.recv(MAX_REQUEST_HEADER_BYTES - len(state.preface))
        except BlockingIOError:
            return
        except OSError:
            removed = self._remove_preface_request(request)
            if removed is not None:
                self.shutdown_request(request)
            return
        if not received:
            removed = self._remove_preface_request(request)
            if removed is not None:
                self.shutdown_request(request)
            return
        state.preface.extend(received)
        if b"\r\n\r\n" not in state.preface and len(state.preface) >= MAX_REQUEST_HEADER_BYTES:
            removed = self._remove_preface_request(request)
            if removed is not None:
                self.shutdown_request(request)
            return
        if b"\r\n\r\n" not in state.preface:
            return
        state = self._remove_preface_request(request)
        if state is not None:
            self._dispatch_preface_request(state, _preface_route(bytes(state.preface)))

    def _dispatch_preface_request(self, state: _PrefaceRequest, route: str) -> None:
        request = state.request
        if self._stopping.is_set():
            self.shutdown_request(request)
            return
        try:
            request.settimeout(self.request_timeout_seconds)
        except OSError:
            self.shutdown_request(request)
            return
        if route == "health":
            slot = self._health_slots
        elif route == "metrics" and self._metrics_slot_is_busy():
            slot = self._metrics_overload_slots
        else:
            slot = self._connection_slots
        if not slot.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._admission_lock:
            self._admitted_slots[id(request)] = slot
            self._handler_prefaces[id(request)] = bytes(state.preface)
        try:
            super().process_request(request, state.client_address)
        except Exception:
            with self._admission_lock:
                admitted_slot = self._admitted_slots.pop(id(request), None)
                self._handler_prefaces.pop(id(request), None)
            if admitted_slot is not None:
                admitted_slot.release()
            self.shutdown_request(request)

    def _run_preface_dispatcher(self) -> None:
        try:
            while True:
                self._expire_preface_requests()
                self._sync_preface_selector()
                with self._preface_lock:
                    stopped = self._stopping.is_set() and not self._preface_pending
                if stopped:
                    return
                for key, _events in self._preface_selector.select(
                    PREFACE_SELECTOR_TIMEOUT_SECONDS
                ):
                    if key.data == "wakeup":
                        self._drain_preface_wakeup()
                    else:
                        self._handle_preface_request(key.fileobj)
        finally:
            with self._preface_lock:
                pending = list(self._preface_pending)
                self._preface_pending.clear()
            for request in pending:
                self.shutdown_request(request)
            self._sync_preface_selector()

    def _stop_preface_dispatcher(self) -> None:
        with self._preface_lock:
            pending = list(self._preface_pending)
            self._preface_pending.clear()
            thread = self._preface_thread
        for request in pending:
            self.shutdown_request(request)
        self._wake_preface_dispatcher()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=PREFACE_SHUTDOWN_TIMEOUT_SECONDS)

    def _close_preface_resources(self) -> None:
        with self._preface_lock:
            if self._preface_resources_closed:
                return
            self._preface_resources_closed = True
        self._preface_selector.close()
        self._preface_wakeup_reader.close()
        self._preface_wakeup_writer.close()

    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            request.setblocking(False)
        except OSError:
            self.shutdown_request(request)
            return
        with self._preface_lock:
            if self._stopping.is_set():
                evicted = None
                rejected = True
            else:
                evicted = None
                if len(self._preface_pending) >= MAX_PENDING_PREFACE_CONNECTIONS:
                    evicted, _state = self._preface_pending.popitem(last=False)
                self._preface_pending[request] = _PrefaceRequest(
                    request,
                    client_address,
                    time.monotonic() + self.request_timeout_seconds,
                )
                rejected = False
        if evicted is not None:
            self.shutdown_request(evicted)
        if rejected:
            self.shutdown_request(request)
            return
        self._wake_preface_dispatcher()

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._admission_lock:
                slot = self._admitted_slots.pop(id(request), None)
                self._handler_prefaces.pop(id(request), None)
            if slot is not None:
                slot.release()

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        return
