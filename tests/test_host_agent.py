from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.error import URLError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from codex_master.agent_ollama import AgentOllamaNoEffectError
from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentResultV1,
)
from codex_master.host_agent import (
    BACKOFF_SECONDS,
    MAX_RESPONSE_BYTES,
    HostAgent,
    HostAgentClient,
    HostAgentError,
    HostAgentExecutor,
    HostProbeExecutor,
    build_tls_context,
    load_host_agent_config,
    main,
    open_host_agent_credentials,
    run_poll_loop,
)
from codex_master.host_agent_state import HostAgentState, HostAgentStateError


def _private_key_bytes(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate(
    name: str,
    *,
    key: rsa.RSAPrivateKey,
    issuer_key: rsa.RSAPrivateKey,
    issuer: x509.Certificate | None,
    client: bool,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(datetime(2099, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=issuer is not None,
                content_commitment=False,
                key_encipherment=issuer is not None,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=issuer is None,
                crl_sign=issuer is None,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if issuer is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                    if client
                    else ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            critical=True,
        )
        if not client:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def host_agent_pki(tmp_path: Path) -> Path:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _certificate("host-agent-ca", key=ca_key, issuer_key=ca_key, issuer=None, client=False)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    files = {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "server.crt": _certificate(
            "localhost", key=server_key, issuer_key=ca_key, issuer=ca, client=False
        ).public_bytes(serialization.Encoding.PEM),
        "server.key": _private_key_bytes(server_key),
        "client.crt": _certificate(
            "agent", key=client_key, issuer_key=ca_key, issuer=ca, client=True
        ).public_bytes(serialization.Encoding.PEM),
        "client.key": _private_key_bytes(client_key),
    }
    for name, payload in files.items():
        (tmp_path / name).write_bytes(payload)
    return tmp_path


class _RawTlsServer:
    def __init__(self, pki: Path, response: bytes) -> None:
        self._response = response
        self.requests = 0
        self.peer_certificates = 0
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(5)
        self._listener.settimeout(0.2)
        self.port = int(self._listener.getsockname()[1])
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.load_verify_locations(cafile=str(pki / "ca.crt"))
        self._context.load_cert_chain(pki / "server.crt", pki / "server.key")
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with self._context.wrap_socket(connection, server_side=True) as tls:
                    self.requests += 1
                    if tls.getpeercert(binary_form=True):
                        self.peer_certificates += 1
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 65536:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                    tls.sendall(self._response)
                    try:
                        tls.unwrap()
                    except (ConnectionError, OSError, ssl.SSLError):
                        pass
            except (ConnectionError, OSError, ssl.SSLError):
                pass

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(2)
        assert not self._thread.is_alive()


def _live_client(pki: Path, port: int) -> HostAgentClient:
    context = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(pki / "client.crt", pki / "client.key")
    return HostAgentClient(f"https://localhost:{port}", context=context, sleep=lambda _: None)


def _idle_body() -> bytes:
    return b'{"schema_version":1,"registry_generation":7,"lease_epoch":3,"max_wait_seconds":5}'


def digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def lease(**changes: object) -> AgentLeaseV1:
    args = changes.pop("arguments", {"plan_ref": "plan-one"})
    values: dict[str, object] = {
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "host_ref": "worker-one",
        "kind": "ollama.instance",
        "action": "apply",
        "registry_generation": 7,
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": "sha256:" + "a" * 64,
        "arguments_digest": digest(args),
        "deadline": datetime(2099, 1, 1, tzinfo=UTC),
        "arguments": args,
    }
    values.update(changes)
    return AgentLeaseV1(**values)  # type: ignore[arg-type]


class Ollama:
    def __init__(self) -> None:
        self.apply_calls = 0

    def apply(self, arguments: object) -> dict[str, object]:
        self.apply_calls += 1
        return {"instance_ref": "one"}


def test_same_operation_returns_receipt_without_second_effect(tmp_path: Path) -> None:
    runtime = Ollama()
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    executor = HostAgentExecutor(state=state, ollama=runtime)
    first = executor.execute(lease())
    second = executor.execute(lease())
    assert second == first and runtime.apply_calls == 1


def test_dispatch_is_closed_and_begin_effect_precedes_mutation(tmp_path: Path) -> None:
    events: list[str] = []

    class State(HostAgentState):
        def begin_effect(self, item: AgentLeaseV1) -> str | None:
            claim = super().begin_effect(item)
            events.append("durable")
            return claim

    class Ordered(Ollama):
        def apply(self, arguments: object) -> dict[str, object]:
            events.append("effect")
            return super().apply(arguments)

    executor = HostAgentExecutor(
        state=State.for_test(tmp_path, host_ref="worker-one"), ollama=Ordered()
    )
    executor.execute(lease())
    assert events == ["durable", "effect"]
    with pytest.raises(HostAgentError, match="host.action_unsupported"):
        executor.dispatch("unknown", "run", {})


def test_expired_lease_is_rejected_before_state_or_effect(tmp_path: Path) -> None:
    runtime = Ollama()
    executor = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"), ollama=runtime
    )
    with pytest.raises(HostAgentError, match="host.lease_expired"):
        executor.execute(lease(deadline=datetime(2020, 1, 1, tzinfo=UTC)))
    assert runtime.apply_calls == 0


def test_finish_failure_propagates_without_second_finish(tmp_path: Path) -> None:
    class FailingState(HostAgentState):
        finish_calls = 0

        def finish(self, *args: object, **kwargs: object) -> object:
            self.finish_calls += 1
            raise HostAgentStateError("host.state_unavailable")

    state = FailingState.for_test(tmp_path, host_ref="worker-one")
    executor = HostAgentExecutor(state=state, ollama=Ollama())
    with pytest.raises(HostAgentStateError, match="host.state_unavailable"):
        executor.execute(lease())
    assert state.finish_calls == 1


def test_concurrent_mutating_execution_performs_exactly_one_effect(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class Blocking(Ollama):
        def apply(self, arguments: object) -> dict[str, object]:
            self.apply_calls += 1
            entered.set()
            assert release.wait(2)
            return {"instance_ref": "one"}

    runtime = Blocking()
    executor = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"),
        ollama=runtime,
    )
    receipts = []
    errors = []

    def execute() -> None:
        try:
            receipts.append(executor.execute(lease()))
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=execute)
    second = threading.Thread(target=execute)
    first.start()
    assert entered.wait(1)
    second.start()
    time.sleep(0.05)
    assert runtime.apply_calls == 1
    release.set()
    first.join(2)
    second.join(2)
    assert errors == []
    assert len(receipts) == 2 and receipts[0] == receipts[1]
    assert runtime.apply_calls == 1


def test_mutating_exception_is_unknown(
    tmp_path: Path,
) -> None:
    class Ambiguous(Ollama):
        def apply(self, arguments: object) -> dict[str, object]:
            self.apply_calls += 1
            raise RuntimeError("effect may already exist")

    ambiguous = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path / "ambiguous", host_ref="worker-one"),
        ollama=Ambiguous(),
    ).execute(lease())
    assert ambiguous.state == "unknown"
    assert ambiguous.reason_codes == ("host.operation_unknown",)


def test_typed_pre_effect_rejection_is_failed(tmp_path: Path) -> None:
    class Rejected(Ollama):
        def apply(self, arguments: object) -> dict[str, object]:
            raise AgentOllamaNoEffectError("provider.plan_missing")

    receipt = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"),
        ollama=Rejected(),
    ).execute(lease())
    assert receipt.state == "failed"
    assert receipt.reason_codes == ("host.operation_failed",)


def test_run_once_polls_executes_receipt_and_honors_idle() -> None:
    class Client:
        def __init__(self, response: object) -> None:
            self.response = response
            self.receipts = []

        def poll(self, poll: object) -> object:
            return self.response

        def put_receipt(self, receipt: object) -> None:
            self.receipts.append(receipt)

    class Executor:
        def execute(self, item: AgentLeaseV1) -> AgentResultV1:
            return AgentResultV1("ollama.instance", "apply", {"ok": True})

    idle = Client(AgentNoWorkV1(7, 3, 5))
    agent = HostAgent(
        client=idle,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    assert agent.run_once() == 5
    busy = Client(lease())
    agent = HostAgent(
        client=busy,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    assert agent.run_once() == 0 and len(busy.receipts) == 1

    wrong_generation = Client(AgentNoWorkV1(8, 3, 5))
    agent = HostAgent(
        client=wrong_generation,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    with pytest.raises(HostAgentError, match="host.response_fence_mismatch"):
        agent.run_once()


def test_tls_context_and_static_url_and_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []

    class Context:
        minimum_version = None
        check_hostname = False
        verify_mode = None

        def load_verify_locations(self, *, cafile: str) -> None:
            calls.append(("ca", cafile))

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            calls.extend((("cert", certfile), ("key", keyfile)))

    monkeypatch.setattr(ssl, "SSLContext", lambda protocol: Context())
    context = build_tls_context(trust_fd=10, certificate_fd=11, key_fd=12)
    assert (
        context.minimum_version == ssl.TLSVersion.TLSv1_3
        and context.check_hostname
        and context.verify_mode == ssl.CERT_REQUIRED
    )
    assert calls == [
        ("ca", "/proc/self/fd/10"),
        ("cert", "/proc/self/fd/11"),
        ("key", "/proc/self/fd/12"),
    ]
    client = HostAgentClient("https://master.internal:9443", context=context)
    assert client.master_url == "https://master.internal:9443" and BACKOFF_SECONDS == (
        1,
        2,
        5,
        10,
        20,
        30,
    )
    with pytest.raises(HostAgentError, match="host.master_url_invalid"):
        HostAgentClient("http://master.internal", context=context)
    with pytest.raises(HostAgentError, match="host.master_url_invalid"):
        HostAgentClient(None, context=context)  # type: ignore[arg-type]


def test_client_parses_bounded_poll_and_receipt_and_retries_transport(
    tmp_path: Path,
) -> None:
    class Headers:
        def __init__(self, length: int) -> None:
            self.length = length

        def get_all(self, name: str) -> list[str] | None:
            if name == "Content-Type":
                return ["application/json"]
            if name == "Content-Length":
                return [str(self.length)]
            return None

    class Response:
        status = 200

        def __init__(self, body: object, url: str) -> None:
            self.body = json.dumps(body).encode()
            self.headers = Headers(len(self.body))
            self.url = url

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, maximum: int) -> bytes:
            return self.body[:maximum]

        def geturl(self) -> str:
            return self.url

    class Opener:
        def __init__(self) -> None:
            self.calls = 0
            self.body: object = {
                "schema_version": 1,
                "registry_generation": 7,
                "lease_epoch": 3,
                "max_wait_seconds": 5,
            }

        def open(self, request: object, timeout: int) -> Response:
            self.calls += 1
            if self.calls <= 2:
                raise URLError("offline")
            return Response(self.body, request.full_url)  # type: ignore[attr-defined]

    delays: list[int] = []
    client = HostAgentClient(
        "https://master.internal",
        context=ssl.create_default_context(),
        sleep=delays.append,
    )
    opener = Opener()
    client._opener = opener  # type: ignore[attr-defined]
    idle = client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))
    assert isinstance(idle, AgentNoWorkV1)
    assert delays == [1, 2]
    receipt = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"),
        ollama=Ollama(),
    ).execute(lease())
    opener.body = {
        "schema_version": 1,
        "operation_id": receipt.operation_id,
        "accepted": True,
    }
    client.put_receipt(receipt)


def test_client_enforces_full_backoff_response_bound_and_exact_idle_type() -> None:
    class Offline:
        def open(self, request: object, timeout: int) -> object:
            raise URLError("offline")

    delays: list[int] = []
    client = HostAgentClient(
        "https://master.internal",
        context=ssl.create_default_context(),
        sleep=delays.append,
    )
    client._opener = Offline()  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_unreachable"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))
    assert delays == list(BACKOFF_SECONDS)

    class Headers:
        def __init__(self, length: int) -> None:
            self.length = length

        def get_all(self, name: str) -> list[str] | None:
            if name == "Content-Type":
                return ["application/json"]
            if name == "Content-Length":
                return [str(self.length)]
            return None

    class Response:
        status = 200
        def __init__(self, body: bytes, url: str) -> None:
            self.body = body
            self.headers = Headers(len(body))
            self.url = url

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, maximum: int) -> bytes:
            return self.body[:maximum]

        def geturl(self) -> str:
            return self.url

    class Fixed:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def open(self, request: object, timeout: int) -> Response:
            return Response(self.body, request.full_url)  # type: ignore[attr-defined]

    client._opener = Fixed(b" " * (MAX_RESPONSE_BYTES + 1))  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))

    malformed_idle = json.dumps(
        {
            "schema_version": 1,
            "registry_generation": True,
            "lease_epoch": 3,
            "max_wait_seconds": 5,
        }
    ).encode()
    client._opener = Fixed(malformed_idle)  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("cross_origin", [False, True])
def test_live_client_rejects_every_redirect_without_second_mtls_connection(
    host_agent_pki: Path, status: int, cross_origin: bool
) -> None:
    target = _RawTlsServer(
        host_agent_pki,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(_idle_body())}\r\nConnection: close\r\n\r\n".encode()
        + _idle_body(),
    )
    origin = None
    try:
        target_port = target.port if cross_origin else 1
        location = f"https://localhost:{target_port}/redirected"
        response = (
            f"HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode()
        origin = _RawTlsServer(host_agent_pki, response)
        if not cross_origin:
            location = f"https://localhost:{origin.port}/redirected"
            origin.close()
            response = (
                f"HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode()
            origin = _RawTlsServer(host_agent_pki, response)
        client = _live_client(host_agent_pki, origin.port)
        with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
            client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))
        time.sleep(0.05)
        assert origin.requests == 1
        assert target.requests == 0
    finally:
        if origin is not None:
            origin.close()
        target.close()


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
        + f"Content-Length: {len(_idle_body())}\r\nConnection: close\r\n\r\n".encode()
        + _idle_body(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(_idle_body())}\r\nConnection: close\r\n\r\n".encode()
        + _idle_body(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 89\r\nConnection: close\r\n\r\n"
        b'{"schema_version":1,"registry_generation":7,"registry_generation":8,'
        b'"lease_epoch":3,"max_wait_seconds":5}',
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(_idle_body()) + 5}\r\nConnection: close\r\n\r\n".encode()
        + _idle_body(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(_idle_body())}\r\n".encode()
        + f"Content-Length: {len(_idle_body()) + 1}\r\nConnection: close\r\n\r\n".encode()
        + _idle_body(),
    ],
)
def test_live_client_rejects_ambiguous_or_truncated_http_response(
    host_agent_pki: Path, response: bytes
) -> None:
    server = _RawTlsServer(host_agent_pki, response)
    try:
        with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
            _live_client(host_agent_pki, server.port).poll(
                AgentPollV1(7, 3, "sha256:" + "c" * 64, 5)
            )
    finally:
        server.close()


def test_host_probe_and_credentials_are_descriptor_first_and_exact(
    tmp_path: Path,
) -> None:
    assert (
        HostProbeExecutor().collect({"probe_profile": "basic"})["status"] == "collected"
    )
    with pytest.raises(HostAgentError, match="host.arguments_invalid"):
        HostProbeExecutor().collect({"probe_profile": "free"})
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    config = {
        "schema_version": 1,
        "master_url": "https://master.internal",
        "host_ref": "worker-one",
        "registry_generation": 7,
        "lease_epoch": 3,
        "capabilities_digest": "sha256:" + "c" * 64,
        "state_root": str(tmp_path / "state"),
        "ollama_registry_path": str(tmp_path / "ollama-registry.json"),
        "max_wait_seconds": 20,
    }
    (credentials / "agent-config").write_text(json.dumps(config))
    for name in ("agent-master-ca", "agent-client-cert", "agent-client-key"):
        (credentials / name).write_text(name)
    with open_host_agent_credentials(
        {"CREDENTIALS_DIRECTORY": str(credentials)}
    ) as opened:
        loaded = load_host_agent_config(opened.config)
        assert loaded.host_ref == "worker-one" and loaded.registry_generation == 7

    (credentials / "agent-client-key").unlink()
    (credentials / "agent-client-key").symlink_to(credentials / "agent-master-ca")
    with pytest.raises(HostAgentError, match="host.credentials_invalid"):
        open_host_agent_credentials({"CREDENTIALS_DIRECTORY": str(credentials)})


def test_poll_loop_is_stoppable_and_cli_accepts_no_secret_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop = threading.Event()

    class Agent:
        calls = 0

        def run_once(self, *, max_wait_seconds: int) -> int:
            assert max_wait_seconds == 20
            self.calls += 1
            stop.set()
            return 30

    agent = Agent()
    run_poll_loop(agent, max_wait_seconds=20, stop_event=stop)  # type: ignore[arg-type]
    assert agent.calls == 1

    with pytest.raises(SystemExit):
        main(["--master-url", "https://secret.invalid"])
