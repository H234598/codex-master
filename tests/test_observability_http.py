from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from typing import Iterator
import urllib.error
import urllib.request

import pytest

from codex_master.observability_http import MAX_METRICS_BYTES, MetricsHttpServer, TimedMetricsReader


@contextmanager
def _running_server(host: str, metrics_reader: object) -> Iterator[MetricsHttpServer]:
    server = MetricsHttpServer((host, 0), metrics_reader)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _fetch(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as raised:
        return raised.code, raised.read()


def test_metrics_http_server_only_exposes_bounded_metrics_and_health() -> None:
    server = MetricsHttpServer(("127.0.0.1", 0), lambda: "metric 1\n# EOF\n")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base}/metrics", timeout=2) as response:
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("application/openmetrics-text")
            assert response.read() == b"metric 1\n# EOF\n"
        with urllib.request.urlopen(f"{base}/healthz", timeout=2) as response:
            assert response.read() == b"ok\n"
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(f"{base}/unknown", timeout=2)
        assert raised.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_timed_reader_reuses_one_snapshot_until_ttl_expires() -> None:
    now = [100.0]
    calls: list[int] = []

    def source() -> str:
        calls.append(len(calls) + 1)
        return f"snapshot {calls[-1]}"

    reader = TimedMetricsReader(source, ttl_seconds=5, clock=lambda: now[0])
    assert reader() == "snapshot 1"
    now[0] = 104.9
    assert reader() == "snapshot 1"
    now[0] = 105.0
    assert reader() == "snapshot 2"
    assert calls == [1, 2]


@pytest.mark.parametrize(
    ("host", "url_host"),
    (("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")),
)
def test_metrics_server_binds_explicit_ipv4_and_ipv6_loopback(
    host: str, url_host: str
) -> None:
    if host == "::1" and not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    with _running_server(host, lambda: "metric 1\n# EOF\n") as server:
        status, body = _fetch(f"http://{url_host}:{server.server_port}/metrics")
    assert status == 200
    assert body == b"metric 1\n# EOF\n"


@pytest.mark.parametrize("host", ("0.0.0.0", "::", "192.0.2.1"))
def test_metrics_server_rejects_non_loopback_binding(host: str) -> None:
    with pytest.raises(ValueError, match="invalid_observability_host"):
        MetricsHttpServer((host, 0), lambda: "metric 1\n")


def _raising_reader() -> object:
    raise RuntimeError("scrape failed")


@pytest.mark.parametrize(
    "metrics_reader",
    (
        _raising_reader,
        lambda: None,
        lambda: "",
        lambda: "x" * (MAX_METRICS_BYTES + 1),
    ),
    ids=("source-exception", "none", "empty", "oversized"),
)
def test_metrics_returns_exactly_503_for_unavailable_payloads(metrics_reader: object) -> None:
    with _running_server("127.0.0.1", metrics_reader) as server:
        status, body = _fetch(f"http://127.0.0.1:{server.server_port}/metrics")
    assert status == 503
    assert body == b"metrics unavailable\n"


def test_metrics_accepts_one_mib_payload() -> None:
    payload = "x" * MAX_METRICS_BYTES
    with _running_server("127.0.0.1", lambda: payload) as server:
        status, body = _fetch(f"http://127.0.0.1:{server.server_port}/metrics")
    assert status == 200
    assert body == payload.encode("utf-8")


def test_metrics_preserves_stale_openmetrics_text_verbatim() -> None:
    stale = (
        "# HELP codex_master_bees_native Native bees\n"
        "# TYPE codex_master_bees_native gauge\n"
        "codex_master_bees_native 3 1\n"
        "# EOF\n"
    )
    with _running_server("127.0.0.1", lambda: stale) as server:
        status, body = _fetch(f"http://127.0.0.1:{server.server_port}/metrics")
    assert status == 200
    assert body == stale.encode("utf-8")


def test_health_remains_available_when_metrics_scrape_fails() -> None:
    with _running_server("127.0.0.1", _raising_reader) as server:
        base = f"http://127.0.0.1:{server.server_port}"
        assert _fetch(f"{base}/metrics")[0] == 503
        status, body = _fetch(f"{base}/health")
    assert status == 200
    assert body == b"ok\n"


def test_timed_reader_does_not_cache_failed_refresh() -> None:
    calls = [0]

    def source() -> str:
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("temporary failure")
        return "snapshot"

    reader = TimedMetricsReader(source)
    with pytest.raises(RuntimeError, match="temporary failure"):
        reader()
    assert reader() == "snapshot"
    assert reader() == "snapshot"
    assert calls == [2]
