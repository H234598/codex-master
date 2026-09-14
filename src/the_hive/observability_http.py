from __future__ import annotations

import ipaddress
import math
import socket
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_METRICS_BYTES = 1024 * 1024


def _encode_metrics_payload(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid_metrics_payload")
    payload = value.encode("utf-8")
    if len(payload) > MAX_METRICS_BYTES:
        raise ValueError("invalid_metrics_payload")
    return payload


class TimedMetricsReader:
    def __init__(
        self,
        source: Callable[[], str],
        *,
        ttl_seconds: float = 5,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(source) or not callable(clock) or not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("invalid_metrics_reader")
        self._source = source
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._value: str | None = None
        self._expires_at = 0.0

    def __call__(self) -> str:
        with self._lock:
            now = self._clock()
            if self._value is not None and now < self._expires_at:
                return self._value
            value = self._source()
            _encode_metrics_payload(value)
            self._value = value
            self._expires_at = now + self._ttl_seconds
            return value


class _MetricsHandler(BaseHTTPRequestHandler):
    server: "MetricsHttpServer"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path in {"/health", "/healthz"}:
            self._reply(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.path != "/metrics":
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")
            return
        try:
            payload = _encode_metrics_payload(self.server.metrics_reader())
        except Exception:
            self._reply(503, b"metrics unavailable\n", "text/plain; charset=utf-8")
            return
        self._reply(200, payload, "application/openmetrics-text; version=1.0.0; charset=utf-8")

    def _reply(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class MetricsHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], metrics_reader: Callable[[], str]) -> None:
        if not callable(metrics_reader):
            raise ValueError("invalid_metrics_reader")
        try:
            host = ipaddress.ip_address(address[0])
        except (TypeError, ValueError):
            raise ValueError("invalid_observability_host") from None
        if not host.is_loopback:
            raise ValueError("invalid_observability_host")
        self.address_family = socket.AF_INET6 if host.version == 6 else socket.AF_INET
        self.metrics_reader = metrics_reader
        super().__init__(address, _MetricsHandler)
