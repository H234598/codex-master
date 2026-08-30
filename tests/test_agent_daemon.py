from __future__ import annotations

import os
import signal
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from codex_master import agent_daemon
from codex_master.agent_daemon import AgentApiServer, AgentCredentialFds, open_systemd_credentials
from codex_master.admin_hosts import HostRegistryError
from codex_master.admin_hosts import AgentPrincipalV1
from codex_master.agent_http import AgentHttpResponse


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

    def wrap_socket(self, sock, *, server_side: bool, do_handshake_on_connect: bool):
        assert server_side is True
        assert do_handshake_on_connect is False
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


@pytest.mark.parametrize(
    ("length", "status"),
    [
        ("", b" 400 "),
        ("+1", b" 400 "),
        ("-1", b" 400 "),
        ("1x", b" 400 "),
        ("00", b" 400 "),
        ("065536", b" 400 "),
        ("65536", b" 400 "),
        ("65537", b" 413 "),
        ("9" * 5000, b" 413 "),
    ],
)
def test_content_length_text_is_bounded_before_integer_conversion(length, status) -> None:
    wire = _WireSocket(
        b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {length}\r\n\r\n".encode()
    )

    class ResolverValue:
        def resolve(self, certificate):
            return AgentPrincipalV1("worker-one", 7, 3)

    agent_daemon._AgentRequestHandler(
        wire, ("127.0.0.1", 1), _HandlerServer(ResolverValue(), Application())
    )
    assert status in wire.output.getvalue()
    assert len(wire.output.getvalue()) < 512


class _OpenBuffer(BytesIO):
    def close(self) -> None:
        pass


class _WireSocket:
    def __init__(self, request: bytes) -> None:
        self.input = _OpenBuffer(request)
        self.output = _OpenBuffer()
        self.certificate_reads = 0
        self.timeouts: list[float] = []

    def makefile(self, mode: str, _buffering: int | None = None):
        return self.input if "r" in mode else self.output

    def getpeercert(self, *, binary_form: bool):
        assert binary_form is True
        self.certificate_reads += 1
        return b"certificate"

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def do_handshake(self) -> None:
        pass

    def sendall(self, value: bytes) -> None:
        self.output.write(value)

    def close(self) -> None:
        pass


class _HandlerServer:
    def __init__(self, resolver, application) -> None:
        self.resolver = resolver
        self.application = application

    def release_request_socket(self, request) -> None:
        pass


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

        def stop_accepting(self) -> None:
            events.append("stop")

        def drain(self, timeout: float) -> bool:
            events.append(f"drain:{timeout}")
            return True

        def server_close(self) -> None:
            events.append("close")

    agent_daemon.run_server(Server())
    assert events == ["serve", "stop", "stop", "drain:5.0", "close"]


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

    def stop_accepting(self) -> None:
        pass

    def drain(self, timeout: float) -> bool:
        return True

    def shutdown(self) -> None:
        pass

    def server_close(self) -> None:
        pass


def _issue_certificate(
    subject: str,
    issuer_certificate: x509.Certificate,
    issuer_key,
    public_key,
    *,
    client: bool,
) -> x509.Certificate:
    now = datetime.now(UTC)
    usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if not client:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _test_ca(name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _pem_private_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def live_pki(tmp_path_factory):
    directory = tmp_path_factory.mktemp("agent-live-pki")
    ca_key, ca = _test_ca("agent-ca")
    wrong_ca_key, wrong_ca = _test_ca("wrong-ca")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    files = {
        "agent-server.crt": _issue_certificate(
            "localhost", ca, ca_key, server_key.public_key(), client=False
        ).public_bytes(serialization.Encoding.PEM),
        "agent-server.key": _pem_private_key(server_key),
        "agent-ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "agent-client.crt": _issue_certificate(
            "agent", ca, ca_key, client_key.public_key(), client=True
        ).public_bytes(serialization.Encoding.PEM),
        "agent-client.key": _pem_private_key(client_key),
        "wrong-ca.crt": wrong_ca.public_bytes(serialization.Encoding.PEM),
        "wrong-client.crt": _issue_certificate(
            "wrong", wrong_ca, wrong_ca_key, wrong_key.public_key(), client=True
        ).public_bytes(serialization.Encoding.PEM),
        "wrong-client.key": _pem_private_key(wrong_key),
    }
    for name, payload in files.items():
        (directory / name).write_bytes(payload)
    return directory


class _LiveResolver:
    def resolve(self, certificate):
        assert x509.load_der_x509_certificate(certificate)
        return AgentPrincipalV1("worker-one", 7, 3)


class _LiveApplication:
    def __init__(self, entered: threading.Event | None = None, release: threading.Event | None = None):
        self.entered = entered
        self.release = release

    def handle(self, principal, method, target, body):
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(2)
        return AgentHttpResponse(200, b'{}')


def _live_server(live_pki: Path, application=None):
    with open_systemd_credentials({"CREDENTIALS_DIRECTORY": str(live_pki)}) as credentials:
        context = agent_daemon.create_agent_ssl_context(credentials)
    server = AgentApiServer(
        ("127.0.0.1", 0), application or _LiveApplication(), _LiveResolver(), context
    )
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    return server, thread


def _client_context(live_pki: Path, *, certificate: str | None = "agent-client"):
    context = ssl.create_default_context(cafile=str(live_pki / "agent-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if certificate is not None:
        context.load_cert_chain(
            live_pki / f"{certificate}.crt", live_pki / f"{certificate}.key"
        )
    return context


def _stop_live(server, thread) -> None:
    server.stop_accepting()
    assert server.drain(1.0)
    server.server_close()
    thread.join(1)
    assert not thread.is_alive()


def test_live_mtls_rejects_tls12_missing_certificate_and_wrong_ca(live_pki) -> None:
    server, thread = _live_server(live_pki)
    address = server.server_address
    try:
        tls12 = _client_context(live_pki)
        tls12.minimum_version = ssl.TLSVersion.TLSv1_2
        tls12.maximum_version = ssl.TLSVersion.TLSv1_2
        for context in (tls12, _client_context(live_pki, certificate=None), _client_context(live_pki, certificate="wrong-client")):
            with socket.create_connection(address, timeout=1) as plain:
                with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                    with context.wrap_socket(plain, server_hostname="localhost") as client:
                        client.sendall(b"GET / HTTP/1.1\r\n\r\n")
                        client.recv(1)
    finally:
        _stop_live(server, thread)


def test_live_mtls_presents_server_leaf_and_accepts_configured_agent(live_pki) -> None:
    server, thread = _live_server(live_pki)
    try:
        with socket.create_connection(server.server_address, timeout=1) as plain:
            with _client_context(live_pki).wrap_socket(plain, server_hostname="localhost") as client:
                peer = x509.load_der_x509_certificate(client.getpeercert(binary_form=True))
                assert peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "localhost"
                client.sendall(
                    b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                assert b" 200 " in client.recv(512)
    finally:
        _stop_live(server, thread)


@pytest.mark.parametrize("stall", ["handshake", "header", "body"])
def test_live_slow_clients_do_not_make_shutdown_unbounded(live_pki, stall) -> None:
    server, thread = _live_server(live_pki)
    plain = socket.create_connection(server.server_address, timeout=1)
    client = plain
    try:
        if stall != "handshake":
            client = _client_context(live_pki).wrap_socket(plain, server_hostname="localhost")
            if stall == "header":
                client.sendall(b"POST /agent/v1/polls HTTP/1.1\r\nX: partial")
            else:
                client.sendall(
                    b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 10\r\n\r\n{}"
                )
        started = time.monotonic()
        server.stop_accepting()
        server.drain(0.4)
        server.server_close()
        thread.join(1)
        assert time.monotonic() - started < 1.0
        assert not thread.is_alive()
    finally:
        client.close()
        if thread.is_alive():
            _stop_live(server, thread)


@pytest.mark.parametrize("phase", ["handshake", "header", "body"])
def test_live_handshake_header_and_body_deadlines_close_stalled_peer(
    live_pki, monkeypatch, phase
) -> None:
    monkeypatch.setattr(agent_daemon, "TLS_HANDSHAKE_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(agent_daemon, "HTTP_HEADER_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(agent_daemon, "HTTP_BODY_TIMEOUT_SECONDS", 0.15)
    server, thread = _live_server(live_pki)
    plain = socket.create_connection(server.server_address, timeout=1)
    client = plain
    try:
        if phase != "handshake":
            client = _client_context(live_pki).wrap_socket(plain, server_hostname="localhost")
            if phase == "header":
                client.sendall(b"POST /agent/v1/polls HTTP/1.1\r\nX: partial")
            else:
                client.sendall(
                    b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 10\r\n\r\n{}"
                )
        client.settimeout(1)
        assert client.recv(1) == b""
    finally:
        client.close()
        _stop_live(server, thread)


def test_live_drain_preserves_successful_inflight_completion(live_pki) -> None:
    entered = threading.Event()
    release = threading.Event()
    server, thread = _live_server(live_pki, _LiveApplication(entered, release))
    try:
        with socket.create_connection(server.server_address, timeout=1) as plain:
            with _client_context(live_pki).wrap_socket(plain, server_hostname="localhost") as client:
                client.sendall(
                    b"POST /agent/v1/polls HTTP/1.1\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                assert entered.wait(1)
                server.stop_accepting()
                release.set()
                assert server.drain(1.0)
                assert b" 200 " in client.recv(512)
    finally:
        server.stop_accepting()
        server.drain(0.2)
        server.server_close()
        thread.join(1)
        assert not thread.is_alive()
