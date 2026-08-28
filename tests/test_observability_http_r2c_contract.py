from __future__ import annotations

import http.client
import ipaddress
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest

import codex_master.observability_http_r2c_contract as observability_http
from codex_master.observability_http_r2c_contract import MetricsHttpServer


@contextmanager
def running(server: MetricsHttpServer) -> Iterator[MetricsHttpServer]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def request(
    server: MetricsHttpServer, method: str, path: str
) -> tuple[int, dict[str, str], bytes]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def get(server: MetricsHttpServer, path: str) -> tuple[int, dict[str, str], bytes]:
    return request(server, "GET", path)


def wait_until(predicate: Callable[[], bool], timeout_seconds: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if predicate():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        threading.Event().wait(timeout=min(remaining, 0.01))


def no_active_metrics_source_workers() -> bool:
    return not any(
        worker.name == "metrics-source" and worker.is_alive()
        for worker in threading.enumerate()
    )


def test_metrics_passthroughs_stale_openmetrics_body_byte_for_byte() -> None:
    payload = (
        "codex_master_snapshot_state{state=\"stale\"} 1\n"
        "codex_master_snapshot_age_seconds 61\n"
        "# EOF\n"
    )
    server = MetricsHttpServer(("127.0.0.1", 0), lambda: payload)

    with running(server):
        status, headers, body = get(server, "/metrics")

    assert status == 200
    assert headers["Content-Type"] == "application/openmetrics-text; version=1.0.0; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Length"] == str(len(payload.encode("utf-8")))
    assert body == payload.encode("utf-8")


@pytest.mark.parametrize("host", ("localhost", "0.0.0.0", "::", "192.0.2.1", "bad host"))
def test_rejects_nonliteral_or_nonloopback_bind_address(host: str) -> None:
    server: MetricsHttpServer | None = None
    try:
        with pytest.raises(ValueError, match="loopback address required"):
            server = MetricsHttpServer((host, 0), lambda: "# EOF\n")
    finally:
        if server is not None:
            server.server_close()


def test_serves_on_ipv6_loopback_when_locally_available() -> None:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is unavailable on this host")

    server = MetricsHttpServer(("::1", 0), lambda: "# EOF\n")
    with running(server):
        status, _headers, body = get(server, "/metrics")

    assert status == 200
    assert body == b"# EOF\n"


def test_health_endpoints_are_available_without_calling_metrics_source() -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        return "# EOF\n"

    server = MetricsHttpServer(("127.0.0.1", 0), source)
    with running(server):
        health = get(server, "/health")
        healthz = get(server, "/healthz")

    assert health[0] == 200
    assert health[2] == b"ok\n"
    assert healthz[0] == 200
    assert healthz[2] == b"ok\n"
    assert calls == 0


def test_http_serves_fresh_valid_metrics_without_untrusted_state_header() -> None:
    reader = observability_http.TimedMetricsReader(
        lambda: "fresh\n", ttl_seconds=5.0, clock=lambda: 0.0
    )
    server = MetricsHttpServer(("127.0.0.1", 0), reader)

    with running(server):
        status, headers, body = get(server, "/metrics")

    assert status == 200
    assert body == b"fresh\n"
    assert headers.get("X-Codex-Metrics-State") is None


def test_http_returns_503_after_expired_last_good_on_source_error() -> None:
    now = 0.0
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "last-good\n"
        raise RuntimeError("source secret token /run/internal.sock")

    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )
    server = MetricsHttpServer(("127.0.0.1", 0), reader)

    with running(server):
        fresh = get(server, "/metrics")
        now = 1.0
        failed = get(server, "/metrics")

    assert fresh[0] == 200
    assert failed[0] == 503
    assert failed[1].get("X-Codex-Metrics-State") is None
    assert failed[2] == b"metrics unavailable\n"


def test_http_returns_503_for_source_error_without_last_good() -> None:
    def source() -> str:
        raise RuntimeError("internal secret token /run/internal.sock")

    server = MetricsHttpServer(("127.0.0.1", 0), source)

    with running(server):
        status, headers, body = get(server, "/metrics")

    assert status == 503
    assert body == b"metrics unavailable\n"
    assert headers.get("X-Codex-Metrics-State") is None


def test_http_returns_503_for_validation_error_without_last_good() -> None:
    def source() -> str:
        raise ValueError("schema token /run/internal.sock")

    server = MetricsHttpServer(("127.0.0.1", 0), source)

    with running(server):
        status, _headers, body = get(server, "/metrics")

    assert status == 503
    assert body == b"metrics unavailable\n"


def test_http_returns_503_for_validation_error_with_last_good() -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "last-good\n"
        raise ValueError("schema token /run/internal.sock")

    now = 0.0
    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )
    server = MetricsHttpServer(("127.0.0.1", 0), reader)

    with running(server):
        assert get(server, "/metrics")[0] == 200
        now = 1.0
        status, headers, body = get(server, "/metrics")

    assert status == 503
    assert headers.get("X-Codex-Metrics-State") is None
    assert body == b"metrics unavailable\n"


@pytest.mark.parametrize(
    "invalid",
    ("", "\ud800", "x" * (observability_http.MAX_METRICS_BYTES + 1)),
    ids=("empty", "invalid-utf8", "oversize"),
)
def test_http_returns_503_for_invalid_refresh_with_last_good(invalid: object) -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "last-good\n"
        return invalid  # type: ignore[return-value]

    now = 0.0
    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )
    server = MetricsHttpServer(("127.0.0.1", 0), reader)

    with running(server):
        assert get(server, "/metrics")[0] == 200
        now = 1.0
        status, headers, body = get(server, "/metrics")

    assert status == 503
    assert headers.get("X-Codex-Metrics-State") is None
    assert body == b"metrics unavailable\n"


def test_health_remains_available_when_metrics_source_is_broken() -> None:
    def source() -> str:
        raise RuntimeError("host=/secret/socket token=private")

    server = MetricsHttpServer(("127.0.0.1", 0), source)

    with running(server):
        status, _headers, body = get(server, "/health")

    assert status == 200
    assert body == b"ok\n"


def test_http_error_response_redacts_internal_details() -> None:
    details = b"secret token socket host /private/internal/path"

    def source() -> str:
        raise RuntimeError(details.decode())

    server = MetricsHttpServer(("127.0.0.1", 0), source)

    with running(server):
        status, headers, body = get(server, "/metrics")

    serialized = repr(headers).encode() + body
    assert status == 503
    assert serialized == repr(headers).encode() + b"metrics unavailable\n"
    assert details not in serialized


def test_http_passthroughs_valid_stale_openmetrics_without_fresh_header() -> None:
    payload = (
        "codex_master_snapshot_state{state=\"stale\"} 1\n"
        "codex_master_snapshot_age_seconds 61\n"
        "# EOF\n"
    )
    server = MetricsHttpServer(("127.0.0.1", 0), lambda: payload)

    with running(server):
        status, headers, body = get(server, "/metrics")

    assert status == 200
    assert headers.get("X-Codex-Metrics-State") is None
    assert body == payload.encode("utf-8")


def test_unknown_path_returns_not_found() -> None:
    server = MetricsHttpServer(("127.0.0.1", 0), lambda: "# EOF\n")
    with running(server):
        status, _headers, _body = get(server, "/not-a-route")

    assert status == 404


def _raising_source() -> str:
    raise RuntimeError("secret-agent-id")


@pytest.mark.parametrize(
    "source",
    (
        _raising_source,
        lambda: None,
        lambda: "",
        lambda: 42,
        lambda: "\ud800",
    ),
)
def test_metrics_source_failures_return_static_service_unavailable(
    source: object,
) -> None:
    server = MetricsHttpServer(("127.0.0.1", 0), source)  # type: ignore[arg-type]
    with running(server):
        status, _headers, body = get(server, "/metrics")

    assert status == 503
    assert body == b"metrics unavailable\n"
    assert b"secret-agent-id" not in body


@pytest.mark.parametrize(
    ("payload", "expected_status"),
    (
        ("x" * 1_048_576, 200),
        ("x" * 1_048_577, 503),
        ("é" * 524_289, 503),
    ),
    ids=("exactly-one-mebibyte", "one-byte-over", "multibyte-over"),
)
def test_metrics_enforces_one_mebibyte_utf8_byte_limit(
    payload: str, expected_status: int
) -> None:
    server = MetricsHttpServer(("127.0.0.1", 0), lambda: payload)
    with running(server):
        status, _headers, body = get(server, "/metrics")

    assert status == expected_status
    if expected_status == 503:
        assert body == b"metrics unavailable\n"
    else:
        assert len(body) == 1_048_576


def test_timed_metrics_reader_reuses_valid_value_until_exact_ttl_expiry() -> None:
    now = 100.0
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        return f"value-{calls}"

    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=5.0, clock=lambda: now
    )

    assert reader() == "value-1"
    now = 104.999
    assert reader() == "value-1"
    now = 105.0
    assert reader() == "value-2"
    assert calls == 2


@pytest.mark.parametrize(
    "invalid",
    ("", None, "\ud800", "x" * 1_048_577),
    ids=("empty", "non-string", "invalid-utf8", "oversize"),
)
def test_timed_metrics_reader_never_caches_invalid_refresh_value(invalid: object) -> None:
    values = iter(("valid", invalid, "fresh"))

    def source() -> str:
        return next(values)  # type: ignore[return-value]

    now = 0.0
    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )

    assert reader() == "valid"
    now = 1.0
    with pytest.raises(ValueError, match="invalid metrics payload"):
        reader()
    now = 1.1
    assert reader() == "fresh"


@pytest.mark.parametrize("ttl_seconds", (0, -1, 60.1, float("inf"), float("nan"), True, "5"))
def test_timed_metrics_reader_rejects_invalid_ttl(ttl_seconds: object) -> None:
    with pytest.raises(ValueError, match="invalid ttl_seconds"):
        observability_http.TimedMetricsReader(
            lambda: "# EOF\n", ttl_seconds=ttl_seconds  # type: ignore[arg-type]
        )


def test_timed_metrics_reader_rejects_noncallable_source_or_clock() -> None:
    with pytest.raises(TypeError, match="source must be callable"):
        observability_http.TimedMetricsReader(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="clock must be callable"):
        observability_http.TimedMetricsReader(lambda: "# EOF\n", clock=None)  # type: ignore[arg-type]


@pytest.mark.parametrize("port", (-1, 65_536, True, "0"))
def test_server_rejects_invalid_port_before_binding(port: object) -> None:
    server: MetricsHttpServer | None = None
    try:
        with pytest.raises(ValueError, match="invalid port"):
            server = MetricsHttpServer(
                ("127.0.0.1", port), lambda: "# EOF\n"  # type: ignore[arg-type]
            )
    finally:
        if server is not None:
            server.server_close()


def test_server_rejects_noncallable_metrics_reader_before_binding() -> None:
    with pytest.raises(TypeError, match="metrics_reader must be callable"):
        MetricsHttpServer(("127.0.0.1", 0), None)  # type: ignore[arg-type]


def test_server_rejects_nonstring_loopback_object_before_binding() -> None:
    with pytest.raises(ValueError, match="loopback address required"):
        MetricsHttpServer(
            (ipaddress.ip_address("127.0.0.1"), 0), lambda: "# EOF\n"  # type: ignore[arg-type]
        )


def test_timed_metrics_reader_coordinates_concurrent_expired_refresh() -> None:
    now = 0.0
    calls = 0
    calls_lock = threading.Lock()
    refresh_started = threading.Event()
    second_refresh_started = threading.Event()
    release_refresh = threading.Event()
    results: list[str] = []
    errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        with calls_lock:
            calls += 1
            call = calls
        if call == 1:
            return "initial"
        if call == 2:
            refresh_started.set()
        else:
            second_refresh_started.set()
        assert release_refresh.wait(timeout=2)
        return "fresh"

    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )
    assert reader() == "initial"
    now = 1.0

    def read() -> None:
        try:
            results.append(reader())
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=read)
    second = threading.Thread(target=read)
    first.start()
    try:
        assert refresh_started.wait(timeout=1)
        second.start()
        assert not second_refresh_started.wait(timeout=0.2)
    finally:
        release_refresh.set()
        first.join(timeout=2)
        second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert results == ["fresh", "fresh"]
    assert calls == 2


def test_timed_metrics_reader_does_not_mask_expired_value_after_source_failure() -> None:
    now = 0.0
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "initial"
        raise RuntimeError("refresh failed")

    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=lambda: now
    )
    assert reader() == "initial"
    now = 1.0

    with pytest.raises(RuntimeError, match="refresh failed"):
        reader()
    assert calls == 2


def test_timed_metrics_reader_rechecks_clock_after_waiting_for_refresh_lock() -> None:
    now = 0.0
    calls = 0
    clock_calls = 0
    refresh_started = threading.Event()
    release_refresh = threading.Event()
    results: list[str] = []
    errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "initial"
        if calls == 2:
            refresh_started.set()
            assert release_refresh.wait(timeout=2)
            return "first-refresh"
        return "second-refresh"

    def clock() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return now

    reader = observability_http.TimedMetricsReader(
        source, ttl_seconds=1.0, clock=clock
    )
    assert reader() == "initial"
    now = 1.0

    def read() -> None:
        try:
            results.append(reader())
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=read)
    second = threading.Thread(target=read)
    first.start()
    try:
        assert refresh_started.wait(timeout=1)
        second.start()
        assert clock_calls == 2
        now = 2.1
    finally:
        release_refresh.set()
        first.join(timeout=2)
        second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert calls == 3
    assert clock_calls == 3
    assert results == ["first-refresh", "second-refresh"]
    assert reader() == "second-refresh"


def test_partial_request_times_out_and_releases_handler_slot() -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=0.05,
        max_handler_threads=1,
    )
    with running(server):
        client = socket.create_connection(server.server_address[:2], timeout=1)
        try:
            client.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n")
            client.settimeout(1)
            assert client.recv(1) == b""
        finally:
            client.close()
        status, _headers, body = get(server, "/metrics")

    assert status == 200
    assert body == b"# EOF\n"
    assert calls == 1


def test_full_parallel_limit_returns_static_service_unavailable_without_sourcecall() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    first_result: list[tuple[int, dict[str, str], bytes]] = []
    first_errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            source_started.set()
            assert release_source.wait(timeout=2)
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=1.0,
        max_handler_threads=1,
    )

    def first_request() -> None:
        try:
            first_result.append(get(server, "/metrics"))
        except BaseException as error:
            first_errors.append(error)

    with running(server):
        first = threading.Thread(target=first_request)
        first.start()
        try:
            assert source_started.wait(timeout=1)
            extra = get(server, "/metrics")
            assert extra[0] == 503
            assert extra[2] == b"metrics unavailable\n"
            assert calls == 1
        finally:
            release_source.set()
            first.join(timeout=2)
        assert not first.is_alive()
        status, _headers, body = get(server, "/metrics")

    assert first_errors == []
    assert first_result[0][0] == 200
    assert status == 200
    assert body == b"# EOF\n"
    assert calls == 2


def test_health_endpoints_keep_reserved_capacity_during_blocked_metrics_request() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    metrics_results: list[tuple[int, dict[str, str], bytes]] = []
    metrics_errors: list[BaseException] = []
    health_results: list[tuple[str, tuple[int, dict[str, str], bytes]]] = []
    health_errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        source_started.set()
        assert release_source.wait(timeout=2)
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=5.0,
        max_handler_threads=1,
    )

    def request_metrics() -> None:
        try:
            metrics_results.append(get(server, "/metrics"))
        except BaseException as error:
            metrics_errors.append(error)

    def request_health(path: str) -> None:
        try:
            health_results.append((path, get(server, path)))
        except BaseException as error:
            health_errors.append(error)

    with running(server):
        metrics = threading.Thread(target=request_metrics)
        metrics.start()
        health_threads: list[threading.Thread] = []
        try:
            assert source_started.wait(timeout=1)
            for path in ("/health", "/healthz"):
                health = threading.Thread(target=request_health, args=(path,))
                health.start()
                health_threads.append(health)
            for health in health_threads:
                health.join(timeout=1)
                assert not health.is_alive()
            assert health_errors == []
            assert {
                path: (response[0], response[2]) for path, response in health_results
            } == {
                "/health": (200, b"ok\n"),
                "/healthz": (200, b"ok\n"),
            }
            assert calls == 1
        finally:
            release_source.set()
            metrics.join(timeout=2)
            for health in health_threads:
                health.join(timeout=1)

    assert not metrics.is_alive()
    assert metrics_errors == []
    assert metrics_results[0][0] == 200
    assert calls == 1
    assert wait_until(no_active_metrics_source_workers)


def test_incomplete_metrics_requests_do_not_consume_health_reserve() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    metrics_results: list[tuple[int, dict[str, str], bytes]] = []
    metrics_errors: list[BaseException] = []
    health_results: list[tuple[str, tuple[int, dict[str, str], bytes]]] = []
    health_errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        source_started.set()
        assert release_source.wait(timeout=2)
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=1.0,
        max_handler_threads=1,
    )

    def request_metrics() -> None:
        try:
            metrics_results.append(get(server, "/metrics"))
        except BaseException as error:
            metrics_errors.append(error)

    def request_health(path: str) -> None:
        try:
            health_results.append((path, get(server, path)))
        except BaseException as error:
            health_errors.append(error)

    with running(server):
        metrics = threading.Thread(target=request_metrics)
        metrics.start()
        partial_clients: list[socket.socket] = []
        health_threads: list[threading.Thread] = []
        try:
            assert source_started.wait(timeout=1)
            for _ in range(2):
                client = socket.create_connection(server.server_address[:2], timeout=1)
                client.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n")
                partial_clients.append(client)

            def connection_slots_are_busy() -> bool:
                if not server._connection_slots.acquire(blocking=False):
                    return True
                server._connection_slots.release()
                return False

            assert wait_until(connection_slots_are_busy)
            for path in ("/health", "/healthz"):
                health = threading.Thread(target=request_health, args=(path,))
                health.start()
                health_threads.append(health)
            for health in health_threads:
                health.join(timeout=0.75)
                assert not health.is_alive()
            assert health_errors == []
            assert {
                path: (response[0], response[2]) for path, response in health_results
            } == {
                "/health": (200, b"ok\n"),
                "/healthz": (200, b"ok\n"),
            }
            assert calls == 1
        finally:
            for client in partial_clients:
                client.close()
            release_source.set()
            metrics.join(timeout=2)
            for health in health_threads:
                health.join(timeout=1)

    assert not metrics.is_alive()
    assert metrics_errors == []
    assert metrics_results[0][0] == 200
    assert calls == 1
    assert wait_until(no_active_metrics_source_workers)


@pytest.mark.parametrize(
    "invalid_health_preface",
    (
        b"GET /health HTTP/1.1\r\nHost: localhost\r\n",
        b"GET /healthz HTTP/1.1 fake",
        b"GET /healthx HTTP/1.1 fake",
        b"POST /health HTTP/1.1 fake",
    ),
)
def test_incomplete_or_invalid_health_prefaces_do_not_consume_health_capacity(
    invalid_health_preface: bytes,
) -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    metrics_results: list[tuple[int, dict[str, str], bytes]] = []
    metrics_errors: list[BaseException] = []
    health_results: list[tuple[str, tuple[int, dict[str, str], bytes]]] = []
    health_errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        source_started.set()
        assert release_source.wait(timeout=2)
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=1.0,
        max_handler_threads=1,
    )

    def request_metrics() -> None:
        try:
            metrics_results.append(get(server, "/metrics"))
        except BaseException as error:
            metrics_errors.append(error)

    def request_health(path: str) -> None:
        try:
            health_results.append((path, get(server, path)))
        except BaseException as error:
            health_errors.append(error)

    with running(server):
        metrics = threading.Thread(target=request_metrics)
        metrics.start()
        invalid_clients: list[socket.socket] = []
        health_threads: list[threading.Thread] = []
        try:
            assert source_started.wait(timeout=1)
            for _ in range(2):
                client = socket.create_connection(server.server_address[:2], timeout=1)
                client.sendall(invalid_health_preface)
                invalid_clients.append(client)
            for path in ("/health", "/healthz"):
                health = threading.Thread(target=request_health, args=(path,))
                health.start()
                health_threads.append(health)
            for health in health_threads:
                health.join(timeout=0.75)
                assert not health.is_alive()
            assert health_errors == []
            assert {
                path: (response[0], response[2]) for path, response in health_results
            } == {
                "/health": (200, b"ok\n"),
                "/healthz": (200, b"ok\n"),
            }
            assert calls == 1
        finally:
            for client in invalid_clients:
                client.close()
            release_source.set()
            metrics.join(timeout=2)
            for health in health_threads:
                health.join(timeout=1)

    assert not metrics.is_alive()
    assert metrics_errors == []
    assert metrics_results[0][0] == 200
    assert calls == 1
    assert wait_until(no_active_metrics_source_workers)


def test_silent_prefaces_do_not_stall_health_or_shutdown() -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=0.05,
        max_handler_threads=1,
    )
    accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
    accept_thread.start()
    silent_clients: list[socket.socket] = []
    health_results: list[tuple[int, dict[str, str], bytes]] = []
    health_errors: list[BaseException] = []

    def request_health() -> None:
        try:
            health_results.append(get(server, "/health"))
        except BaseException as error:
            health_errors.append(error)

    health = threading.Thread(target=request_health)
    try:
        for _ in range(4):
            silent_clients.append(socket.create_connection(server.server_address[:2], timeout=1))
        health.start()
        health.join(timeout=0.1)
        assert not health.is_alive()
        assert health_errors == []
        assert health_results[0][0] == 200
        assert health_results[0][2] == b"ok\n"
        assert calls == 0
        server.shutdown()
        accept_thread.join(timeout=0.5)
        assert not accept_thread.is_alive()
    finally:
        for client in silent_clients:
            client.close()
        if accept_thread.is_alive():
            server.shutdown()
            accept_thread.join(timeout=1)
        health.join(timeout=1)
        server.server_close()


def test_overloaded_metrics_with_long_complete_header_returns_static_service_unavailable() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    first_results: list[tuple[int, dict[str, str], bytes]] = []
    first_errors: list[BaseException] = []
    overload_results: list[tuple[int, dict[str, str], bytes]] = []
    overload_errors: list[BaseException] = []

    def source() -> str:
        nonlocal calls
        calls += 1
        source_started.set()
        assert release_source.wait(timeout=2)
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=1.0,
        max_handler_threads=1,
    )

    def first_request() -> None:
        try:
            first_results.append(get(server, "/metrics"))
        except BaseException as error:
            first_errors.append(error)

    def overloaded_request() -> None:
        host, port = server.server_address[:2]
        connection = http.client.HTTPConnection(host, port, timeout=1)
        try:
            connection.request("GET", "/metrics", headers={"X-Fill": "x" * 512})
            response = connection.getresponse()
            overload_results.append(
                (response.status, dict(response.getheaders()), response.read())
            )
        except BaseException as error:
            overload_errors.append(error)
        finally:
            connection.close()

    with running(server):
        first = threading.Thread(target=first_request)
        first.start()
        try:
            assert source_started.wait(timeout=1)
            overloaded_request()
            assert overload_errors == []
            assert overload_results[0][0] == 503
            assert overload_results[0][2] == b"metrics unavailable\n"
            assert calls == 1
        finally:
            release_source.set()
            first.join(timeout=2)

    assert not first.is_alive()
    assert first_errors == []
    assert first_results[0][0] == 200
    assert calls == 1
    assert wait_until(no_active_metrics_source_workers)


def test_handler_slot_releases_after_metrics_source_exception() -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("secret-agent-id")

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=1.0,
        max_handler_threads=1,
    )
    with running(server):
        first = get(server, "/metrics")
        second = get(server, "/metrics")

    assert first[0] == 503
    assert second[0] == 503
    assert first[2] == b"metrics unavailable\n"
    assert second[2] == b"metrics unavailable\n"
    assert calls == 2


def test_metrics_timeout_returns_503_and_does_not_cache_late_source_result() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    source_finished = threading.Event()

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            source_started.set()
            assert release_source.wait(timeout=2)
            source_finished.set()
            return "late\n"
        return "fresh\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=0.05,
        max_handler_threads=2,
    )
    with running(server):
        try:
            first = get(server, "/metrics")
            assert source_started.is_set()
            second = get(server, "/metrics")
            assert first[0] == 503
            assert first[2] == b"metrics unavailable\n"
            assert second[0] == 503
            assert second[2] == b"metrics unavailable\n"
            assert calls == 1
        finally:
            release_source.set()
        assert source_finished.wait(timeout=1)

    assert calls == 1


def test_shutdown_releases_handler_slot_then_source_worker_exits() -> None:
    source_started = threading.Event()
    release_source = threading.Event()
    source_finished = threading.Event()

    def source() -> str:
        source_started.set()
        assert release_source.wait(timeout=2)
        source_finished.set()
        return "released\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0),
        source,
        request_timeout_seconds=5.0,
        max_handler_threads=1,
    )
    accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
    accept_thread.start()
    client = socket.create_connection(server.server_address[:2], timeout=1)
    try:
        client.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert source_started.wait(timeout=1)
        server.shutdown()
        accept_thread.join(timeout=1)
        assert not accept_thread.is_alive()
        client.settimeout(1)
        assert b" 503 " in client.recv(4096)

        def handler_slot_is_released() -> bool:
            if not server._request_slots.acquire(blocking=False):
                return False
            server._request_slots.release()
            return True

        assert wait_until(handler_slot_is_released)
    finally:
        client.close()
        release_source.set()
        assert source_finished.wait(timeout=1)
        server.server_close()
    assert wait_until(no_active_metrics_source_workers)


def test_process_guard_rejects_second_server_until_old_source_worker_exits() -> None:
    calls = 0
    source_started = threading.Event()
    release_source = threading.Event()
    source_finished = threading.Event()

    def source() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            source_started.set()
            assert release_source.wait(timeout=2)
            source_finished.set()
            return "old\n"
        return "fresh\n"

    first_server = MetricsHttpServer(
        ("127.0.0.1", 0), source, request_timeout_seconds=0.05
    )
    second_server = MetricsHttpServer(
        ("127.0.0.1", 0), source, request_timeout_seconds=0.05
    )
    fresh_responses: list[tuple[int, dict[str, str], bytes]] = []
    try:
        with running(first_server):
            first = get(first_server, "/metrics")
            assert first[0] == 503
            assert source_started.is_set()
            first_server.shutdown()
            with running(second_server):
                rejected = get(second_server, "/metrics")
                assert rejected[0] == 503
                assert calls == 1
                release_source.set()
                assert source_finished.wait(timeout=1)

                def second_server_recovers() -> bool:
                    response = get(second_server, "/metrics")
                    if response[0] != 200:
                        return False
                    fresh_responses.append(response)
                    return True

                assert wait_until(second_server_recovers)
    finally:
        release_source.set()

    assert fresh_responses[0][2] == b"fresh\n"
    assert calls == 2
    assert wait_until(no_active_metrics_source_workers)


def test_shutdown_prevents_timed_reader_late_result_from_becoming_cache() -> None:
    raw_calls = 0
    raw_started = threading.Event()
    release_raw = threading.Event()
    raw_finished = threading.Event()

    def raw_source() -> str:
        nonlocal raw_calls
        raw_calls += 1
        if raw_calls == 1:
            raw_started.set()
            assert release_raw.wait(timeout=2)
            raw_finished.set()
            return "late-after-shutdown\n"
        return "fresh-after-shutdown\n"

    reader = observability_http.TimedMetricsReader(raw_source, ttl_seconds=60.0)
    server = MetricsHttpServer(
        ("127.0.0.1", 0), reader, request_timeout_seconds=0.05
    )
    try:
        with running(server):
            first = get(server, "/metrics")
            assert first[0] == 503
            assert first[2] == b"metrics unavailable\n"
            assert raw_started.is_set()
            server.shutdown()
            release_raw.set()
            assert raw_finished.wait(timeout=1)
    finally:
        release_raw.set()

    assert reader() == "fresh-after-shutdown\n"
    assert raw_calls == 2
    assert wait_until(no_active_metrics_source_workers)


@pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
def test_unsupported_methods_are_static_and_skip_metrics_source(method: str) -> None:
    calls = 0

    def source() -> str:
        nonlocal calls
        calls += 1
        return "# EOF\n"

    server = MetricsHttpServer(("127.0.0.1", 0), source)
    with running(server):
        status, _headers, body = request(server, method, "/metrics")

    assert status == 405
    assert _headers["Allow"] == "GET"
    assert body == b"method not allowed\n"
    assert calls == 0


@pytest.mark.parametrize("host", ("::1%0", "::1%lo"))
def test_rejects_scoped_ipv6_loopbacks_before_binding(host: str) -> None:
    with pytest.raises(ValueError, match="loopback address required"):
        MetricsHttpServer((host, 0), lambda: "# EOF\n")


@pytest.mark.parametrize(
    "request_timeout_seconds", (0, 0.01, 5.1, float("inf"), float("nan"), True, "1")
)
def test_server_rejects_invalid_request_timeout(request_timeout_seconds: object) -> None:
    with pytest.raises(ValueError, match="invalid request timeout"):
        MetricsHttpServer(
            ("127.0.0.1", 0),
            lambda: "# EOF\n",
            request_timeout_seconds=request_timeout_seconds,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("max_handler_threads", (0, 17, True, "1"))
def test_server_rejects_invalid_handler_limit(max_handler_threads: object) -> None:
    with pytest.raises(ValueError, match="invalid handler limit"):
        MetricsHttpServer(
            ("127.0.0.1", 0),
            lambda: "# EOF\n",
            max_handler_threads=max_handler_threads,  # type: ignore[arg-type]
        )


def test_partial_preface_waits_for_new_bytes_then_routes_once() -> None:
    calls = 0
    preface_calls = 0
    preface_lock = threading.Lock()
    first_preface_read = threading.Event()

    def source() -> str:
        nonlocal calls
        calls += 1
        return "# EOF\n"

    server = MetricsHttpServer(
        ("127.0.0.1", 0), source, request_timeout_seconds=1.0
    )
    original_handle_preface = server._handle_preface_request

    def observe_preface(request: socket.socket) -> None:
        nonlocal preface_calls
        original_handle_preface(request)
        with preface_lock:
            preface_calls += 1
            if preface_calls == 1:
                first_preface_read.set()

    server._handle_preface_request = observe_preface  # type: ignore[method-assign]
    client = socket.create_connection(server.server_address[:2], timeout=1)
    try:
        with running(server):
            client.sendall(b"GET /health")
            assert first_preface_read.wait(timeout=1)
            with preface_lock:
                preface_calls_after_partial_read = preface_calls

            # The selector gets multiple chances to repeat stale readability; no
            # additional preface work is valid until the client makes progress.
            threading.Event().wait(observability_http.PREFACE_SELECTOR_TIMEOUT_SECONDS * 3)
            with preface_lock:
                assert preface_calls == preface_calls_after_partial_read

            client.sendall(b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            client.settimeout(1)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                response.extend(client.recv(4096))
            while not response.endswith(b"ok\n"):
                response.extend(client.recv(4096))
            assert b" 200 " in response
            assert response.endswith(b"ok\n")
            def preface_call_completed() -> bool:
                with preface_lock:
                    return preface_calls == preface_calls_after_partial_read + 1

            assert wait_until(preface_call_completed)
    finally:
        client.close()

    assert calls == 0
