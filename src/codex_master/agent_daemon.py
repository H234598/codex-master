"""Isolated TLS 1.3, client-certificate-only host-agent listener."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
from types import FrameType
from typing import Iterator, Mapping, Sequence

from .admin_hosts import HostRegistry, HostRegistryError
from .agent_http import (
    AgentHttpApplication,
    AgentHttpResponse,
    MAX_AGENT_BODY_BYTES,
    MAX_AGENT_HEADER_BYTES,
)
from .agent_identity import AgentIdentityResolver
from .agent_operations import AgentOperationStore


_STATE_ROOT = Path("/var/lib/codex-master")
_CREDENTIAL_NAMES = ("agent-server.crt", "agent-server.key", "agent-ca.crt")
TLS_HANDSHAKE_TIMEOUT_SECONDS = 2.0
HTTP_HEADER_TIMEOUT_SECONDS = 2.0
HTTP_BODY_TIMEOUT_SECONDS = 2.0
AGENT_DRAIN_TIMEOUT_SECONDS = 5.0
_active_server: object | None = None


@dataclass(frozen=True, slots=True)
class AgentCredentialFds:
    certificate: int
    private_key: int
    agent_ca: int

    def __iter__(self) -> Iterator[int]:
        return iter((self.certificate, self.private_key, self.agent_ca))


class _CredentialOwner(AbstractContextManager[AgentCredentialFds]):
    def __init__(self, credentials: AgentCredentialFds) -> None:
        self.credentials = credentials

    def __enter__(self) -> AgentCredentialFds:
        return self.credentials

    def __exit__(self, *_error: object) -> None:
        for fd in self.credentials:
            try:
                os.close(fd)
            except OSError:
                pass


def open_systemd_credentials(environment: Mapping[str, str]) -> _CredentialOwner:
    directory_raw = environment.get("CREDENTIALS_DIRECTORY")
    if not directory_raw or not Path(directory_raw).is_absolute():
        raise RuntimeError("agent.credentials_unavailable")
    directory = Path(directory_raw)
    opened: list[int] = []
    try:
        for name in _CREDENTIAL_NAMES:
            fd = os.open(
                directory / name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            if not os.fstat(fd).st_size:
                raise OSError
            opened.append(fd)
        return _CredentialOwner(AgentCredentialFds(*opened))
    except OSError:
        for fd in opened:
            os.close(fd)
        raise RuntimeError("agent.credentials_unavailable") from None


def create_agent_ssl_context(credentials: AgentCredentialFds) -> ssl.SSLContext:
    if type(credentials) is not AgentCredentialFds:
        raise RuntimeError("agent.credentials_unavailable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        f"/proc/self/fd/{credentials.certificate}",
        f"/proc/self/fd/{credentials.private_key}",
    )
    context.load_verify_locations(cafile=f"/proc/self/fd/{credentials.agent_ca}")
    return context


class _AgentRequestHandler(socketserver.StreamRequestHandler):
    server: AgentApiServer

    def handle(self) -> None:
        try:
            self.request.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
            self.request.do_handshake()
            self.request.settimeout(HTTP_HEADER_TIMEOUT_SECONDS)
            header = self._read_headers()
            if header is None:
                return
            method, target, headers = header
            certificate = self.request.getpeercert(binary_form=True)
            if type(certificate) is not bytes or not certificate:
                self._reply(403, {"error": "agent.identity_invalid"})
                return
            try:
                principal = self.server.resolver.resolve(certificate)
            except HostRegistryError:
                self._reply(403, {"error": "agent.identity_invalid"})
                return

            if headers.get("content-type") != "application/json":
                self._reply(415, {"error": "agent.content_type_invalid"})
                return
            length_status, length = _parse_content_length(headers.get("content-length"))
            if length_status != 200:
                self._reply(length_status, {"error": "agent.request_too_large" if length_status == 413 else "agent.request_invalid"})
                return
            self.request.settimeout(HTTP_BODY_TIMEOUT_SECONDS)
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400, {"error": "agent.request_invalid"})
                return
            self._send(self.server.application.handle(principal, method, target, body))
        except (ConnectionError, OSError, ssl.SSLError):
            return

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.server.release_request_socket(self.request)

    def _read_headers(self) -> tuple[str, str, dict[str, str]] | None:
        data = bytearray()
        while not data.endswith(b"\r\n\r\n"):
            if len(data) >= MAX_AGENT_HEADER_BYTES:
                self._reply(431, {"error": "agent.headers_too_large"})
                return None
            chunk = self.rfile.read(1)
            if not chunk:
                return None
            data.extend(chunk)
        try:
            lines = bytes(data[:-4]).decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ")
            if version != "HTTP/1.1" or not method or not target:
                raise ValueError
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, value = line.split(":", 1)
                name = name.strip().lower()
                value = value.strip()
                if not name or name in headers:
                    raise ValueError
                headers[name] = value
            return method, target, headers
        except (UnicodeError, ValueError):
            self._reply(400, {"error": "agent.request_invalid"})
            return None

    def _reply(self, status: int, value: object) -> None:
        self._send(
            AgentHttpResponse(
                status,
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"),
            )
        )

    def _send(self, response: AgentHttpResponse) -> None:
        reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 413: "Content Too Large", 415: "Unsupported Media Type", 431: "Request Header Fields Too Large", 503: "Service Unavailable"}
        headers = [
            f"HTTP/1.1 {response.status} {reasons.get(response.status, 'Error')}\r\n",
            *[f"{name}: {value}\r\n" for name, value in response.headers],
            f"Content-Length: {len(response.body)}\r\n",
            "Connection: close\r\n\r\n",
        ]
        self.wfile.write("".join(headers).encode("ascii") + response.body)


class AgentApiServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, server_address, application, resolver, ssl_context) -> None:
        self.application = application
        self.resolver = resolver
        self.ssl_context = ssl_context
        self._request_condition = threading.Condition()
        self._request_sockets: set[socket.socket] = set()
        self._shutdown_worker: threading.Thread | None = None
        super().__init__(server_address, _AgentRequestHandler)

    def get_request(self):
        plain, address = super().get_request()
        try:
            return self.get_request_from_socket(plain, address)
        except BaseException:
            plain.close()
            raise

    def get_request_from_socket(self, plain: socket.socket, address):
        wrapped = self.ssl_context.wrap_socket(
            plain, server_side=True, do_handshake_on_connect=False
        )
        with self._request_condition:
            self._request_sockets.add(wrapped)
        return wrapped, address

    def release_request_socket(self, request: socket.socket) -> None:
        with self._request_condition:
            self._request_sockets.discard(request)
            self._request_condition.notify_all()

    def stop_accepting(self) -> None:
        with self._request_condition:
            if self._shutdown_worker is not None:
                return
            self._shutdown_worker = threading.Thread(
                target=self.shutdown, name="agent-api-stop-accepting", daemon=True
            )
            self._shutdown_worker.start()

    def drain(self, timeout: float) -> bool:
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout < 0:
            raise ValueError("agent.drain_timeout_invalid")
        deadline = time.monotonic() + float(timeout)
        worker = self._shutdown_worker
        if worker is not None:
            worker.join(max(0.0, deadline - time.monotonic()))
        with self._request_condition:
            while self._request_sockets:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    outstanding = tuple(self._request_sockets)
                    break
                self._request_condition.wait(remaining)
            else:
                outstanding = ()
        for request in outstanding:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
        stopped = worker is None or not worker.is_alive()
        if outstanding or not stopped:
            self.socket.close()
        return not outstanding and stopped


def _parse_content_length(value: str | None) -> tuple[int, int]:
    if (
        value is None
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        return 400, 0
    limit = str(MAX_AGENT_BODY_BYTES)
    if len(value) > len(limit) or (len(value) == len(limit) and value > limit):
        return 413, 0
    return 200, int(value)


def assemble_server(address: str, port: int, credentials: AgentCredentialFds) -> AgentApiServer:
    registry = HostRegistry(_STATE_ROOT)
    store = AgentOperationStore(_STATE_ROOT)
    return AgentApiServer(
        (address, port),
        AgentHttpApplication(store),
        AgentIdentityResolver(registry),
        create_agent_ssl_context(credentials),
    )


def _handle_signal(_signum: int, _frame: FrameType | None) -> None:
    server = _active_server
    if server is None:
        return
    server.stop_accepting()


def run_server(server: object) -> None:
    global _active_server
    previous = signal.getsignal(signal.SIGTERM)
    _active_server = server
    signal.signal(signal.SIGTERM, _handle_signal)
    try:
        server.serve_forever()
    finally:
        server.stop_accepting()
        server.drain(AGENT_DRAIN_TIMEOUT_SECONDS)
        server.server_close()
        _active_server = None
        signal.signal(signal.SIGTERM, previous)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    parser.add_argument("--listen-address", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    try:
        arguments = parser.parse_args(argv)
        if not 1 <= arguments.port <= 65535:
            raise ValueError
    except (argparse.ArgumentError, SystemExit, ValueError):
        print("codex-master-agent-api: agent.arguments_invalid", file=sys.stderr)
        return os.EX_USAGE
    try:
        with open_systemd_credentials(os.environ) as credentials:
            run_server(assemble_server(arguments.listen_address, arguments.port, credentials))
    except (OSError, RuntimeError, HostRegistryError):
        print("codex-master-agent-api: agent.startup_failed", file=sys.stderr)
        return os.EX_UNAVAILABLE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["AgentApiServer", "AgentCredentialFds", "create_agent_ssl_context", "main", "open_systemd_credentials", "run_server"]
