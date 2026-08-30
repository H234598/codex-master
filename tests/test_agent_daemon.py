from __future__ import annotations

import os
import signal
import ssl
from io import BytesIO
from pathlib import Path

import pytest

from codex_master import agent_daemon
from codex_master.agent_daemon import AgentApiServer, AgentCredentialFds, open_systemd_credentials
from codex_master.admin_hosts import HostRegistryError


class FakeContext:
    def __init__(self) -> None:
        self.minimum_version = None
        self.verify_mode = None
        self.check_hostname = True
        self.cert_chain: tuple[str, str] | None = None
        self.ca_file: str | None = None

    def load_cert_chain(self, certfile: str, keyfile: str) -> None:
        self.cert_chain = (certfile, keyfile)

    def load_verify_locations(self, *, cafile: str) -> None:
        self.ca_file = cafile

    def wrap_socket(self, sock, *, server_side: bool):
        assert server_side is True
        return sock


def _credential_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700)
    for name in ("agent-server.crt", "agent-server.key", "agent-ca.crt"):
        (directory / name).write_bytes(name.encode())
    return directory


def test_systemd_credentials_are_opened_as_fds_and_names_are_fixed(tmp_path) -> None:
    directory = _credential_directory(tmp_path)
    with open_systemd_credentials({"CREDENTIALS_DIRECTORY": str(directory)}) as credentials:
        assert isinstance(credentials, AgentCredentialFds)
        assert [os.read(fd, 64) for fd in credentials] == [
            b"agent-server.crt",
            b"agent-server.key",
            b"agent-ca.crt",
        ]
    assert all(_fd_is_closed(fd) for fd in credentials)


def _fd_is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False


def test_tls_context_is_tls13_client_certificate_only_and_loads_fd_paths(monkeypatch) -> None:
    context = FakeContext()
    monkeypatch.setattr(agent_daemon.ssl, "SSLContext", lambda protocol: context)
    result = agent_daemon.create_agent_ssl_context(AgentCredentialFds(11, 12, 13))
    assert result is context
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is False
    assert context.cert_chain == ("/proc/self/fd/11", "/proc/self/fd/12")
    assert context.ca_file == "/proc/self/fd/13"


class Application:
    def handle(self, principal, method, target, body):
        raise AssertionError("not reached")


class Resolver:
    def resolve(self, certificate):
        raise AssertionError("not reached")


def test_server_wraps_every_accepted_connection_before_http(monkeypatch) -> None:
    context = FakeContext()
    server = AgentApiServer(("127.0.0.1", 0), Application(), Resolver(), context)
    try:
        marker = object()
        assert server.get_request_from_socket(marker, ("127.0.0.1", 1)) == (marker, ("127.0.0.1", 1))
    finally:
        server.server_close()


class _OpenBuffer(BytesIO):
    def close(self) -> None:
        pass


class _WireSocket:
    def __init__(self, request: bytes) -> None:
        self.input = _OpenBuffer(request)
        self.output = _OpenBuffer()
        self.certificate_reads = 0

    def makefile(self, mode: str, _buffering: int | None = None):
        return self.input if "r" in mode else self.output

    def getpeercert(self, *, binary_form: bool):
        assert binary_form is True
        self.certificate_reads += 1
        return b"certificate"

    def sendall(self, value: bytes) -> None:
        self.output.write(value)

    def close(self) -> None:
        pass


class _HandlerServer:
    def __init__(self, resolver, application) -> None:
        self.resolver = resolver
        self.application = application


def test_peer_certificate_selects_principal_before_body_parse() -> None:
    wire = _WireSocket(
        b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
        b"Content-Length: 8\r\n\r\nnot-json"
    )

    class RejectingResolver:
        def resolve(self, certificate):
            assert certificate == b"certificate"
            raise HostRegistryError("host.identity_not_found")

    class UntouchedApplication:
        def handle(self, principal, method, target, body):
            raise AssertionError("body reached application")

    agent_daemon._AgentRequestHandler(
        wire, ("127.0.0.1", 1), _HandlerServer(RejectingResolver(), UntouchedApplication())
    )
    assert wire.certificate_reads == 1
    assert wire.input.read() == b"not-json"
    assert b" 403 " in wire.output.getvalue()


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (b"POST /agent/v1/polls HTTP/1.1\r\nX: " + b"a" * (16 * 1024) + b"\r\n\r\n", b" 431 "),
        (b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 0\r\n\r\n", b" 415 "),
        (b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n", b" 413 "),
    ],
)
def test_transport_enforces_header_body_and_exact_content_type(request_bytes, status) -> None:
    wire = _WireSocket(request_bytes)

    class ResolverValue:
        def resolve(self, certificate):
            return object()

    agent_daemon._AgentRequestHandler(
        wire, ("127.0.0.1", 1), _HandlerServer(ResolverValue(), Application())
    )
    assert status in wire.output.getvalue()


def test_sigterm_stops_acceptance_and_drains_owned_server(monkeypatch) -> None:
    events: list[str] = []

    class Server:
        def serve_forever(self) -> None:
            events.append("serve")
            agent_daemon._handle_signal(signal.SIGTERM, None)

        def shutdown(self) -> None:
            events.append("shutdown")

        def server_close(self) -> None:
            events.append("close")

    agent_daemon.run_server(Server())
    assert events == ["serve", "shutdown", "close"]


def test_assemble_server_wires_task_two_store_and_task_three_resolver(monkeypatch) -> None:
    values: dict[str, object] = {}
    monkeypatch.setattr(agent_daemon, "HostRegistry", lambda root: ("registry", root))
    monkeypatch.setattr(agent_daemon, "AgentOperationStore", lambda root: ("store", root))
    monkeypatch.setattr(agent_daemon, "AgentIdentityResolver", lambda registry: ("resolver", registry))
    monkeypatch.setattr(agent_daemon, "AgentHttpApplication", lambda store: ("application", store))
    monkeypatch.setattr(agent_daemon, "create_agent_ssl_context", lambda fds: ("tls", fds))
    monkeypatch.setattr(
        agent_daemon,
        "AgentApiServer",
        lambda address, application, resolver, context: values.update(
            address=address, application=application, resolver=resolver, context=context
        ) or values,
    )
    fds = AgentCredentialFds(1, 2, 3)
    result = agent_daemon.assemble_server("127.0.0.1", 9443, fds)
    assert result is values
    assert values["address"] == ("127.0.0.1", 9443)
    assert values["application"][0] == "application"
    assert values["resolver"][0] == "resolver"
    assert values["context"] == ("tls", fds)


def test_main_accepts_only_listen_address_and_port(monkeypatch, capsys) -> None:
    assert agent_daemon.main(["--server-key", "secret"]) == os.EX_USAGE
    assert "agent.arguments_invalid" in capsys.readouterr().err


def test_main_assembles_from_credential_directory_without_secret_arguments(monkeypatch, tmp_path) -> None:
    directory = _credential_directory(tmp_path)
    observed: dict[str, object] = {}

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    monkeypatch.setattr(agent_daemon, "assemble_server", lambda address, port, credentials: observed.update(address=address, port=port, fds=tuple(credentials)) or _StoppedServer())
    assert agent_daemon.main(["--listen-address", "127.0.0.1", "--port", "9443"]) == 0
    assert observed["address"] == "127.0.0.1"
    assert observed["port"] == 9443
    assert len(observed["fds"]) == 3


class _StoppedServer:
    def serve_forever(self) -> None:
        agent_daemon._handle_signal(signal.SIGTERM, None)

    def shutdown(self) -> None:
        pass

    def server_close(self) -> None:
        pass
