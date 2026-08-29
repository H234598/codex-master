from __future__ import annotations

from array import array
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
import hmac
import json
import os
from pathlib import Path
import socket
import stat
import struct
from threading import Event, Thread, enumerate as enumerate_threads
from time import monotonic, sleep
from typing import Iterator

import pytest

import codex_master.admin_socket as admin_socket
from codex_master.admin_contracts import (
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    public_admin_result,
)
from codex_master.admin_hosts import ControlHostV1
from codex_master.admin_service import (
    MasterjetControlService,
    SecretIngressSessionV1,
    SecretIngressUploadReceiptV1,
)
from codex_master.admin_socket import (
    MAX_ADMIN_REQUEST_BYTES,
    MAX_ADMIN_SECRET_BYTES,
    AdminSocketClient,
    AdminSocketError,
    AdminSocketServer,
    UnixPeerCredentials,
    local_attestation_verifier,
)


class _UnusedOwner:
    pass


class _Hosts:
    def __init__(self) -> None:
        self.calls = 0

    def list(self) -> tuple[ControlHostV1, ...]:
        self.calls += 1
        return (
            ControlHostV1(
                "worker-one",
                "Worker One",
                "execution",
                {"kind": "ssh", "binding_ref": "worker-one"},
                ("codex.execute",),
                {"state": "reachable"},
                {"cpu_threads": 8, "memory_bytes": 16_000_000_000},
                4,
                datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
                "host-agent",
            ),
        )


class _BlockingHosts(_Hosts):
    def __init__(self, entered: Event, release: Event) -> None:
        super().__init__()
        self.entered = entered
        self.release = release

    def list(self) -> tuple[ControlHostV1, ...]:
        self.calls += 1
        self.entered.set()
        self.release.wait()
        return _Hosts().list()


class _SecretIngress:
    def __init__(self) -> None:
        self.put_calls = 0
        self.received = b""
        self.buffer: bytearray | None = None
        self.fail = False
        self.reserve_signal: BaseException | None = None
        self.process_signal: BaseException | None = None
        self.rollback_signal: BaseException | None = None
        self.claims: list[object] = []
        self.rollback_calls = 0

    def reserve_upload(self, session_id: str, **values: object) -> object:
        if self.reserve_signal is not None:
            raise self.reserve_signal
        claim = (session_id, dict(values))
        self.claims.append(claim)
        return claim

    def put_secret(
        self,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        principal: str,
        upload_claim: object,
    ) -> SecretIngressUploadReceiptV1:
        assert upload_claim in self.claims
        self.put_calls += 1
        self.received = bytes(secret)
        self.buffer = secret.obj if type(secret) is memoryview else secret
        assert principal == "operator-one"
        if self.process_signal is not None:
            raise self.process_signal
        if self.fail:
            raise RuntimeError("private-marker /home/operator/auth.json")
        return SecretIngressUploadReceiptV1(session_id, "openai-one", "consumed", 1)

    def commit_upload(self, _claim: object, _receipt: object) -> None:
        return None

    def rollback_upload(self, _claim: object) -> None:
        self.rollback_calls += 1
        if self.rollback_signal is not None:
            raise self.rollback_signal

    def create_session(self, **_values: object) -> SecretIngressSessionV1:
        raise AssertionError("not used")

    def resolve(self, _session: object, **_values: object) -> tuple[object, object]:
        raise AssertionError("not used")


def _service(
    ingress: _SecretIngress, hosts: _Hosts | None = None
) -> MasterjetControlService:
    unused = _UnusedOwner()
    return MasterjetControlService(
        operation_store=unused,  # type: ignore[arg-type]
        openai_accounts=None,
        openai_credentials=None,
        google_manager=unused,  # type: ignore[arg-type]
        google_oauth=None,
        quota_collector=None,
        google_provisioner=None,
        google_billing=None,
        host_registry=hosts or _Hosts(),
        secret_ingress=ingress,
    )


PRINCIPAL = AdminPrincipalV1(
    "operator-one",
    ("fleet.host.read", "fleet.secrets.ingress"),
    "unix_peer",
    True,
)


@dataclass
class _RunningServer:
    socket: AdminSocketServer
    service: MasterjetControlService
    ingress: _SecretIngress
    hosts: _Hosts
    authorize_calls: list[UnixPeerCredentials]
    attestation_key_fd: int

    @property
    def path(self) -> Path:
        return self.socket.path


@pytest.fixture
def attestation_key_fd(tmp_path: Path) -> Iterator[int]:
    path = tmp_path / "admin-attestation.key"
    path.write_bytes(b"test-admin-attestation-key-value")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


@pytest.fixture
def server(tmp_path: Path, attestation_key_fd: int) -> Iterator[_RunningServer]:
    ingress = _SecretIngress()
    hosts = _Hosts()
    service = _service(ingress, hosts)
    authorize_calls: list[UnixPeerCredentials] = []

    def authorize(peer: UnixPeerCredentials) -> AdminPrincipalV1:
        authorize_calls.append(peer)
        assert peer.pid == os.getpid()
        assert peer.uid == os.getuid()
        assert peer.gid == os.getgid()
        return PRINCIPAL

    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        service,
        authorize,
        attestation_key_fd=attestation_key_fd,
    )
    adapter.start()
    try:
        yield _RunningServer(
            adapter,
            service,
            ingress,
            hosts,
            authorize_calls,
            attestation_key_fd,
        )
    finally:
        adapter.close()


@pytest.fixture
def auth_fd(tmp_path: Path) -> Iterator[int]:
    path = tmp_path / "auth.json"
    path.write_bytes(b'{"access_token":"private-marker"}')
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def _wire_request(request: AdminRequestV1) -> bytes:
    return (
        json.dumps(
            public_admin_result(request), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        + b"\n"
    )


def _secret_put_wire(session_id: str = "ingress-one") -> bytes:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "transport": "secret.put",
                "session_id": session_id,
                "expected_generation": 0,
                "idempotency_key": "socket-secret-put",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _track_request_parsing(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    calls: list[bool] = []
    receive_frame = getattr(admin_socket, "_receive_frame")

    def track(connection: socket.socket) -> tuple[bytes, list[int]]:
        calls.append(True)
        return receive_frame(connection)

    monkeypatch.setattr(admin_socket, "_receive_frame", track)
    return calls


def _send_raw(
    path: Path,
    payload: bytes,
    fds: tuple[int, ...] = (),
    *,
    attestation_key_fd: int | None = None,
) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(os.fspath(path))
        if attestation_key_fd is not None:
            peer = struct.unpack(
                "3i",
                connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                ),
            )
            verifier = getattr(admin_socket, "local_attestation_verifier")(
                attestation_key_fd
            )
            assert verifier(*peer, connection) is True
        if fds:
            rights = array("i", fds)
            sent = connection.sendmsg(
                [payload],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            )
            if sent < len(payload):
                connection.sendall(payload[sent:])
        else:
            connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    value = json.loads(response)
    assert type(value) is dict
    return value


def _client(server: _RunningServer) -> AdminSocketClient:
    return AdminSocketClient(
        server.path,
        attestation_key_fd=server.attestation_key_fd,
    )


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_client_process_signals_propagate_after_real_socket_connection_closes(
    server: _RunningServer,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    real_attestation = getattr(admin_socket, "_client_attestation")
    before = _fd_count()

    def interrupt_after_attestation(*args: object) -> None:
        real_attestation(*args)
        raise signal_type(23)

    monkeypatch.setattr(
        admin_socket, "_client_attestation", interrupt_after_attestation
    )

    with pytest.raises(signal_type):
        _client(server).call(AdminRequestV1("hosts.list", {}, None, None, None))

    deadline = monotonic() + 1
    while getattr(server.socket, "_active_connection") is not None:
        assert monotonic() < deadline
        sleep(0.01)
    assert _fd_count() == before


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "seam",
    ["peer", "principal", "decode", "dispatch", "reply"],
)
def test_server_adapter_process_signals_propagate_and_received_fds_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
    seam: str,
) -> None:
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress()),
        lambda _peer: PRINCIPAL,
    )
    server_connection, client_connection = socket.socketpair()
    received_fd = os.dup(server_connection.fileno())
    peer = UnixPeerCredentials(os.getpid(), os.geteuid(), os.getegid())

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise signal_type(23)

    monkeypatch.setattr(admin_socket, "_peer_credentials", lambda _socket: peer)
    monkeypatch.setattr(admin_socket, "_server_attestation", lambda *_args: None)
    monkeypatch.setattr(
        admin_socket,
        "_receive_frame",
        lambda _socket: (b"{}", [received_fd]),
    )
    monkeypatch.setattr(admin_socket, "_decode_json", lambda _payload: {})
    monkeypatch.setattr(adapter, "_dispatch", lambda *_args: {})
    monkeypatch.setattr(admin_socket, "_send_reply", lambda *_args, **_kwargs: None)
    if seam == "peer":
        monkeypatch.setattr(admin_socket, "_peer_credentials", interrupt)
    elif seam == "principal":
        monkeypatch.setattr(adapter, "_authorize_peer", interrupt)
    elif seam == "decode":
        monkeypatch.setattr(admin_socket, "_decode_json", interrupt)
    elif seam == "dispatch":
        monkeypatch.setattr(adapter, "_dispatch", interrupt)
    else:
        monkeypatch.setattr(admin_socket, "_send_reply", interrupt)
    client_connection.shutdown(socket.SHUT_WR)
    try:
        with pytest.raises(signal_type):
            adapter._handle(server_connection)
        if seam in {"decode", "dispatch", "reply"}:
            with pytest.raises(OSError):
                os.fstat(received_fd)
    finally:
        try:
            os.close(received_fd)
        except OSError:
            pass
        server_connection.close()
        client_connection.close()


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("codec", ["decode", "encode"])
def test_socket_json_codecs_do_not_normalize_process_signals(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
    codec: str,
) -> None:
    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise signal_type(23)

    if codec == "decode":
        monkeypatch.setattr(admin_socket.json, "loads", interrupt)
        call = partial(admin_socket._decode_json, b"{}")
    else:
        monkeypatch.setattr(admin_socket.json, "dumps", interrupt)
        call = partial(admin_socket._encode_json, {}, MAX_ADMIN_REQUEST_BYTES)

    with pytest.raises(signal_type):
        call()


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["getpeername", "getsockopt"])
def test_peer_credentials_do_not_normalize_process_signals(
    signal_type: type[BaseException], seam: str
) -> None:
    class _PeerSocket:
        def getpeername(self) -> None:
            if seam == "getpeername":
                raise signal_type(23)

        def getsockopt(self, *_args: object) -> bytes:
            if seam == "getsockopt":
                raise signal_type(23)
            return struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())

    with pytest.raises(signal_type):
        admin_socket._peer_credentials(_PeerSocket())


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_receive_frame_closes_received_fds_without_normalizing_process_signals(
    signal_type: type[BaseException],
) -> None:
    received_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    rights = array("i", [received_fd]).tobytes()

    class _FrameSocket:
        calls = 0

        def recvmsg(
            self, *_args: object
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
            self.calls += 1
            if self.calls == 1:
                return b"{", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)], 0, None
            raise signal_type(23)

    try:
        with pytest.raises(signal_type):
            admin_socket._receive_frame(_FrameSocket())
        with pytest.raises(OSError):
            os.fstat(received_fd)
    finally:
        try:
            os.close(received_fd)
        except OSError:
            pass
        os.close(write_fd)


@pytest.mark.parametrize("target", ["receive", "drain"])
def test_fd_cleanup_does_not_replace_primary_process_signal(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    received_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    rights = array("i", [received_fd]).tobytes()
    real_close = os.close

    class _InterruptingSocket:
        calls = 0

        def recvmsg(
            self, *_args: object
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
            self.calls += 1
            if self.calls == 1:
                return b"x", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)], 0, None
            raise KeyboardInterrupt("primary")

    def close_then_interrupt(fd: int) -> None:
        real_close(fd)
        if fd == received_fd:
            raise SystemExit("cleanup")

    monkeypatch.setattr(admin_socket.os, "close", close_then_interrupt)
    try:
        with pytest.raises(KeyboardInterrupt, match="primary"):
            if target == "receive":
                admin_socket._receive_frame(_InterruptingSocket())
            else:
                admin_socket._drain_input(_InterruptingSocket())
        with pytest.raises(OSError):
            os.fstat(received_fd)
    finally:
        monkeypatch.setattr(admin_socket.os, "close", real_close)
        for fd in (received_fd, write_fd):
            try:
                real_close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["reserve", "read", "put", "rollback"])
def test_secret_upload_rolls_back_without_normalizing_process_signals(
    tmp_path: Path,
    auth_fd: int,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
    seam: str,
) -> None:
    ingress = _SecretIngress()
    if seam == "reserve":
        ingress.reserve_signal = signal_type(23)
    elif seam == "read":
        monkeypatch.setattr(
            admin_socket.os,
            "preadv",
            lambda *_args: (_ for _ in ()).throw(signal_type(23)),
        )
    elif seam == "put":
        ingress.process_signal = signal_type(23)
    else:
        ingress.fail = True
        ingress.rollback_signal = signal_type(23)
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(ingress),
        lambda _peer: PRINCIPAL,
    )
    peer = UnixPeerCredentials(os.getpid(), os.geteuid(), os.getegid())

    with pytest.raises(signal_type):
        adapter._put_secret(
            PRINCIPAL,
            peer,
            "ingress-one",
            auth_fd,
            expected_generation=0,
            idempotency_key="socket-secret-put",
        )

    if seam == "reserve":
        assert ingress.rollback_calls == 0
        assert ingress.buffer is None
    elif seam == "read":
        assert ingress.rollback_calls == 1
        assert ingress.buffer is None
    else:
        assert ingress.rollback_calls == 1
        assert ingress.buffer is not None
        assert bytes(ingress.buffer) == b"\0" * len(ingress.buffer)


def test_handle_preserves_primary_process_signal_when_cleanup_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress = _SecretIngress()
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(ingress),
        lambda _peer: PRINCIPAL,
    )
    received_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    peer = UnixPeerCredentials(os.getpid(), os.geteuid(), os.getegid())
    monkeypatch.setattr(admin_socket, "_peer_credentials", lambda _socket: peer)
    monkeypatch.setattr(admin_socket, "_server_attestation", lambda *_args: None)
    monkeypatch.setattr(
        admin_socket,
        "_receive_frame",
        lambda _socket: (b"{}", [received_fd]),
    )
    monkeypatch.setattr(
        adapter,
        "_dispatch",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("primary")),
    )
    monkeypatch.setattr(
        admin_socket,
        "_drain_input",
        lambda _socket: (_ for _ in ()).throw(SystemExit("cleanup")),
    )

    try:
        with pytest.raises(KeyboardInterrupt, match="primary"):
            adapter._handle(object())  # type: ignore[arg-type]
        with pytest.raises(OSError):
            os.fstat(received_fd)
    finally:
        try:
            os.close(received_fd)
        except OSError:
            pass
        os.close(write_fd)


def test_close_fds_continues_after_process_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_fd, first_write_fd = os.pipe2(os.O_CLOEXEC)
    second_fd, second_write_fd = os.pipe2(os.O_CLOEXEC)
    real_close = os.close
    interrupted = False

    def interrupt_once(fd: int) -> None:
        nonlocal interrupted
        real_close(fd)
        if fd == first_fd and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("primary")

    monkeypatch.setattr(admin_socket.os, "close", interrupt_once)
    try:
        with pytest.raises(KeyboardInterrupt, match="primary"):
            admin_socket._close_fds([second_fd, first_fd])
        with pytest.raises(OSError):
            os.fstat(first_fd)
        with pytest.raises(OSError):
            os.fstat(second_fd)
    finally:
        monkeypatch.setattr(admin_socket.os, "close", real_close)
        for fd in (first_fd, second_fd, first_write_fd, second_write_fd):
            try:
                real_close(fd)
            except OSError:
                pass


def test_secret_upload_preserves_primary_signal_over_rollback_signal(
    tmp_path: Path,
    auth_fd: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress = _SecretIngress()
    ingress.rollback_signal = SystemExit("cleanup")
    monkeypatch.setattr(
        admin_socket.os,
        "preadv",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("primary")),
    )
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(ingress),
        lambda _peer: PRINCIPAL,
    )

    with pytest.raises(KeyboardInterrupt, match="primary"):
        adapter._put_secret(
            PRINCIPAL,
            UnixPeerCredentials(os.getpid(), os.geteuid(), os.getegid()),
            "ingress-one",
            auth_fd,
            expected_generation=0,
            idempotency_key="socket-secret-put",
        )

    assert ingress.rollback_calls == 1


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_drain_input_closes_received_fds_without_normalizing_process_signals(
    signal_type: type[BaseException],
) -> None:
    received_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    rights = array("i", [received_fd]).tobytes()

    class _DrainSocket:
        calls = 0

        def recvmsg(
            self, *_args: object
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
            self.calls += 1
            if self.calls == 1:
                return b"x", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)], 0, None
            raise signal_type(23)

    try:
        with pytest.raises(signal_type):
            admin_socket._drain_input(_DrainSocket())
        with pytest.raises(OSError):
            os.fstat(received_fd)
    finally:
        try:
            os.close(received_fd)
        except OSError:
            pass
        os.close(write_fd)


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_problem_parser_does_not_normalize_process_signals(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    class _InterruptingDateTime:
        @classmethod
        def fromisoformat(cls, _value: str) -> datetime:
            raise signal_type(23)

        @classmethod
        def now(cls, timezone: object) -> datetime:
            return datetime.now(timezone)  # type: ignore[arg-type]

    monkeypatch.setattr(admin_socket, "datetime", _InterruptingDateTime)
    problem = {
        "schema_version": 1,
        "code": "control.request_invalid",
        "severity": "error",
        "title": "Request failed",
        "detail": "Request could not be completed",
        "effect": "No action was started",
        "action": "Review access and retry",
        "retryable": False,
        "retry_after_seconds": None,
        "correlation_id": "corr-process-signal",
        "occurred_at": "2026-08-29T12:00:00+00:00",
    }

    with pytest.raises(signal_type):
        admin_socket._parse_problem(problem)


def _recv_line(connection: socket.socket, limit: int = 4096) -> bytes:
    payload = bytearray()
    while b"\n" not in payload:
        chunk = connection.recv(limit + 1 - len(payload))
        if not chunk:
            raise AssertionError("connection closed before JSONL frame")
        payload.extend(chunk)
        if len(payload) > limit:
            raise AssertionError("JSONL frame exceeded test limit")
    assert payload.count(b"\n") == 1
    assert payload[-1:] == b"\n"
    return bytes(payload[:-1])


def _test_attestation_transcript(
    challenge: dict[str, object],
    client_nonce: bytes,
) -> bytes:
    return (
        b"codex-master/admin-socket/attestation/transcript\0"
        + struct.pack(
            "!BIII",
            1,
            challenge["server_pid"],
            challenge["server_uid"],
            challenge["server_gid"],
        )
        + bytes.fromhex(challenge["server_nonce"])
        + client_nonce
    )


def _test_attestation_response(
    challenge: dict[str, object],
    key: bytes,
    client_nonce: bytes,
) -> bytes:
    transcript = _test_attestation_transcript(challenge, client_nonce)
    proof = hmac.digest(
        key,
        b"codex-master/admin-socket/attestation/client-proof\0" + transcript,
        "sha256",
    )
    return (
        json.dumps(
            {
                "schema_version": 1,
                "transport": "attestation.response",
                "client_nonce": client_nonce.hex(),
                "proof": proof.hex(),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _problem_code(reply: dict[str, object]) -> str:
    assert reply["ok"] is False
    problem = reply["problem"]
    assert type(problem) is dict
    code = problem["code"]
    assert type(code) is str
    return code


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


class _OneRecvmsgConnection:
    def __init__(self, ancillary: list[tuple[int, int, bytes]]) -> None:
        self.ancillary = ancillary
        self.calls = 0

    def recvmsg(
        self, _size: int, _ancillary_size: int, _flags: int
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        self.calls += 1
        if self.calls == 1:
            return b"{}\n", self.ancillary, 0, None
        return b"", [], 0, None


def test_server_creates_owner_only_parent_and_socket(server: _RunningServer) -> None:
    parent = server.path.parent.stat()
    endpoint = server.path.stat()

    assert stat.S_IMODE(parent.st_mode) == 0o700
    assert stat.S_IMODE(endpoint.st_mode) == 0o600
    assert parent.st_uid == os.geteuid()
    assert endpoint.st_uid == os.geteuid()
    assert stat.S_ISSOCK(endpoint.st_mode)


def test_usage_compatible_attestation_verifier_authenticates_connection(
    server: _RunningServer,
) -> None:
    verifier = local_attestation_verifier(server.attestation_key_fd)
    for _attempt in range(2):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(os.fspath(server.path))
            pid, uid, gid = struct.unpack(
                "3i",
                connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                ),
            )

            assert verifier(pid, uid, gid, connection) is True

            connection.sendall(
                _wire_request(AdminRequestV1("hosts.list", {}, None, None, None))
            )
            connection.shutdown(socket.SHUT_WR)
            reply = json.loads(_recv_line(connection))

        assert reply["ok"] is True
    assert len(server.authorize_calls) == 2
    assert os.fstat(server.attestation_key_fd)


def test_missing_attestation_key_fails_closed_before_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = _Hosts()
    ingress = _SecretIngress()
    authorize_calls: list[UnixPeerCredentials] = []
    parse_calls = _track_request_parsing(monkeypatch)

    def authorize(peer: UnixPeerCredentials) -> AdminPrincipalV1:
        authorize_calls.append(peer)
        return PRINCIPAL

    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(ingress, hosts),
        authorize,
    )
    adapter.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(os.fspath(adapter.path))
            reply = json.loads(_recv_line(connection))
    finally:
        adapter.close()

    assert _problem_code(reply) == "control.attestation_required"
    assert authorize_calls == []
    assert parse_calls == []
    assert hosts.calls == 0
    assert ingress.put_calls == 0


@pytest.mark.parametrize("invalid_fd", [-1, "private-marker"], ids=("negative", "type"))
def test_invalid_attestation_key_fd_is_typed_and_redacted(
    tmp_path: Path,
    invalid_fd: object,
) -> None:
    constructors = (
        lambda: AdminSocketServer(
            tmp_path / "private" / "admin.sock",
            _service(_SecretIngress()),
            lambda _peer: PRINCIPAL,
            attestation_key_fd=invalid_fd,  # type: ignore[arg-type]
        ),
        lambda: AdminSocketClient(
            tmp_path / "private" / "admin.sock",
            attestation_key_fd=invalid_fd,  # type: ignore[arg-type]
        ),
        lambda: local_attestation_verifier(invalid_fd),  # type: ignore[arg-type]
    )
    for constructor in constructors:
        with pytest.raises(AdminSocketError) as raised:
            constructor()
        assert raised.value.problem.code == "control.attestation_required"
        assert repr(raised.value) == "AdminSocketError('control.attestation_required')"
        assert "private-marker" not in str(raised.value)


def test_usage_verifier_factory_rejects_closed_positive_key_fd(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private-marker-closed-attestation.key"
    path.write_bytes(b"private-marker-closed-attestation-key")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    os.close(fd)
    before = _fd_count()

    with pytest.raises(AdminSocketError) as raised:
        local_attestation_verifier(fd)

    assert raised.value.problem.code == "control.attestation_required"
    assert repr(raised.value) == "AdminSocketError('control.attestation_required')"
    assert "private-marker" not in str(raised.value)
    assert _fd_count() == before


@pytest.mark.parametrize("invalidity", ["write-only", "private-mode-drift"])
def test_usage_verifier_factory_rejects_unreadable_or_drifting_key_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalidity: str,
) -> None:
    path = tmp_path / "private-marker-invalid-attestation.key"
    path.write_bytes(b"private-marker-invalid-attestation-key")
    path.chmod(0o600)
    flags = os.O_WRONLY if invalidity == "write-only" else os.O_RDONLY
    fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
    if invalidity == "private-mode-drift":
        real_fstat = os.fstat
        calls = 0

        def drifting_fstat(candidate: int) -> os.stat_result:
            nonlocal calls
            metadata = real_fstat(candidate)
            if candidate == fd:
                calls += 1
                if calls == 1:
                    path.chmod(0o644)
            return metadata

        monkeypatch.setattr(admin_socket.os, "fstat", drifting_fstat)
    before = _fd_count()
    try:
        with pytest.raises(AdminSocketError) as raised:
            local_attestation_verifier(fd)

        assert raised.value.problem.code == "control.attestation_required"
        assert repr(raised.value) == "AdminSocketError('control.attestation_required')"
        assert "private-marker" not in str(raised.value)
        assert _fd_count() == before
        assert os.fstat(fd)
    finally:
        os.close(fd)


def test_wrong_attestation_key_sends_no_secret_fd(
    server: _RunningServer,
    auth_fd: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_calls = _track_request_parsing(monkeypatch)
    wrong_path = tmp_path / "wrong-attestation.key"
    wrong_path.write_bytes(b"wrong-admin-attestation-key-value")
    wrong_path.chmod(0o600)
    wrong_fd = os.open(wrong_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminSocketError, match="control.attestation_required"):
            AdminSocketClient(
                server.path,
                attestation_key_fd=wrong_fd,
            ).put_secret_fd("ingress-one", auth_fd)
    finally:
        os.close(wrong_fd)

    assert server.authorize_calls == []
    assert parse_calls == []
    assert server.hosts.calls == 0
    assert server.ingress.put_calls == 0
    assert os.fstat(auth_fd)


def test_attestation_response_cannot_be_replayed_on_new_connection(
    server: _RunningServer,
) -> None:
    key = os.pread(server.attestation_key_fd, 4096, 0)
    client_nonce = bytes.fromhex("22" * 32)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first:
        first.settimeout(2)
        first.connect(os.fspath(server.path))
        first_challenge = json.loads(_recv_line(first))
        response = _test_attestation_response(first_challenge, key, client_nonce)
        first.sendall(response)
        accepted = json.loads(_recv_line(first))

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second:
        second.settimeout(2)
        second.connect(os.fspath(server.path))
        second_challenge = json.loads(_recv_line(second))
        second.sendall(response)
        rejected = json.loads(_recv_line(second))

    assert accepted["transport"] == "attestation.accepted"
    assert first_challenge["server_nonce"] != second_challenge["server_nonce"]
    assert _problem_code(rejected) == "control.attestation_required"


@pytest.mark.parametrize(
    "response",
    [
        b"not-json\n",
        (
            b'{"schema_version":1,"schema_version":1,'
            b'"transport":"attestation.response"}\n'
        ),
        json.dumps(
            {
                "schema_version": 2,
                "transport": "attestation.response",
                "client_nonce": "00" * 32,
                "proof": "00" * 32,
            },
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n",
        json.dumps(
            {
                "schema_version": 1,
                "transport": "attestation.response",
                "client_nonce": "00",
                "proof": "00" * 32,
            },
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n",
        b"{" + b"x" * 4096 + b"\n",
    ],
    ids=("malformed", "duplicate", "version", "nonce", "oversize"),
)
def test_attestation_rejects_invalid_bounded_frames(
    server: _RunningServer,
    response: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_calls = _track_request_parsing(monkeypatch)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(os.fspath(server.path))
        challenge = json.loads(_recv_line(connection))
        assert challenge["transport"] == "attestation.challenge"
        connection.sendall(response)
        reply = json.loads(_recv_line(connection))

    assert _problem_code(reply) == "control.attestation_required"
    assert server.authorize_calls == []
    assert parse_calls == []
    assert server.hosts.calls == 0
    assert server.ingress.put_calls == 0


def test_attestation_accepts_fragmented_frames(
    server: _RunningServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fragmented_send(connection: socket.socket, value: object) -> None:
        frame = getattr(admin_socket, "_encode_json")(
            value, admin_socket.MAX_ADMIN_ATTESTATION_BYTES
        )
        for byte in frame:
            connection.sendall(bytes((byte,)))

    monkeypatch.setattr(admin_socket, "_send_attestation_frame", fragmented_send)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(os.fspath(server.path))
        verifier = getattr(admin_socket, "local_attestation_verifier")(
            server.attestation_key_fd
        )
        assert verifier(os.getpid(), os.geteuid(), os.getegid(), connection) is True


def test_usage_verifier_rejects_connection_identity_swap(
    server: _RunningServer,
) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(os.fspath(server.path))
        verifier = getattr(admin_socket, "local_attestation_verifier")(
            server.attestation_key_fd
        )
        assert (
            verifier(
                os.getpid() + 1,
                os.geteuid(),
                os.getegid(),
                connection,
            )
            is False
        )

    assert server.ingress.put_calls == 0


def test_usage_verifier_rereads_key_fd_after_factory_construction(
    server: _RunningServer,
    tmp_path: Path,
) -> None:
    path = tmp_path / "drifting-attestation.key"
    path.write_bytes(os.pread(server.attestation_key_fd, 4096, 0))
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        verifier = local_attestation_verifier(fd)
        path.chmod(0o644)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(os.fspath(server.path))
            assert (
                verifier(os.getpid(), os.geteuid(), os.getegid(), connection) is False
            )

        assert os.fstat(fd)
    finally:
        os.close(fd)

    assert server.authorize_calls == []


def test_attestation_timeout_is_typed_and_redacted(
    tmp_path: Path,
    attestation_key_fd: int,
) -> None:
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress()),
        lambda _peer: PRINCIPAL,
        timeout_seconds=0.05,
        attestation_key_fd=attestation_key_fd,
    )
    adapter.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(os.fspath(adapter.path))
            assert json.loads(_recv_line(connection))["transport"] == (
                "attestation.challenge"
            )
            connection.sendall(b'{"private-marker":')
            reply = json.loads(_recv_line(connection))
    finally:
        adapter.close()

    assert _problem_code(reply) == "control.attestation_required"
    assert "private-marker" not in json.dumps(reply)


def test_close_interrupts_partial_attestation(
    tmp_path: Path,
    attestation_key_fd: int,
) -> None:
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress()),
        lambda _peer: PRINCIPAL,
        timeout_seconds=10,
        attestation_key_fd=attestation_key_fd,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    adapter.start()
    worker = getattr(adapter, "_thread")
    assert type(worker) is Thread
    try:
        connection.connect(os.fspath(adapter.path))
        assert json.loads(_recv_line(connection))["transport"] == (
            "attestation.challenge"
        )
        connection.sendall(b'{"schema_version":1')

        adapter.close()

        assert not worker.is_alive()
        assert getattr(adapter, "_thread") is None
    finally:
        connection.close()
        adapter.close()


def test_server_rejects_parent_swap_between_pin_and_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "private" / "admin.sock"
    displaced_parent = tmp_path / "displaced-private"
    real_prepare_parent = getattr(admin_socket, "_prepare_parent")

    def swap_parent(parent: Path) -> object:
        pinned = real_prepare_parent(parent)
        parent.rename(displaced_parent)
        parent.mkdir(mode=0o700)
        return pinned

    monkeypatch.setattr(admin_socket, "_prepare_parent", swap_parent)
    adapter = AdminSocketServer(
        path, _service(_SecretIngress()), lambda _peer: PRINCIPAL
    )
    try:
        with pytest.raises(AdminSocketError, match="control.socket_unavailable"):
            adapter.start()
    finally:
        adapter.close()

    assert not path.exists()


def test_server_rejects_parent_replacement_after_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "private" / "admin.sock"
    displaced_parent = tmp_path / "displaced-private"
    real_chmod = os.chmod
    fake_listener: socket.socket | None = None

    def replace_after_socket_chmod(
        target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal fake_listener
        real_chmod(
            target,
            mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        metadata = os.stat(
            target,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if fake_listener is None and stat.S_ISSOCK(metadata.st_mode):
            path.parent.rename(displaced_parent)
            path.parent.mkdir(mode=0o700)
            fake_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fake_listener.bind(os.fspath(path))
            real_chmod(path, 0o600, follow_symlinks=False)

    monkeypatch.setattr(admin_socket.os, "chmod", replace_after_socket_chmod)
    adapter = AdminSocketServer(
        path, _service(_SecretIngress()), lambda _peer: PRINCIPAL
    )
    try:
        with pytest.raises(AdminSocketError, match="control.socket_unavailable"):
            adapter.start()
    finally:
        adapter.close()
        if fake_listener is not None:
            fake_listener.close()
        for endpoint in (path, displaced_parent / path.name):
            try:
                endpoint.unlink()
            except FileNotFoundError:
                pass

    assert fake_listener is not None


def test_client_verifies_server_peer_before_sending_secret_fd(
    tmp_path: Path,
    auth_fd: int,
) -> None:
    path = tmp_path / "private" / "admin.sock"
    path.parent.mkdir(mode=0o700)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(path))
    listener.listen(1)
    listener.settimeout(1)
    received: list[tuple[bytes, list[tuple[int, int, bytes]]]] = []

    def receive_once() -> None:
        try:
            connection, _address = listener.accept()
        except (OSError, TimeoutError):
            return
        with connection:
            data, ancillary, _flags, _address = connection.recvmsg(
                MAX_ADMIN_REQUEST_BYTES,
                socket.CMSG_SPACE(array("i").itemsize),
            )
            received.append((data, ancillary))

    receiver = Thread(target=receive_once)
    receiver.start()
    try:
        with pytest.raises(AdminSocketError, match="authority.peer_denied"):
            AdminSocketClient(
                path,
                expected_server_uid=os.geteuid() + 1,
            ).put_secret_fd("ingress-one", auth_fd)
    finally:
        receiver.join(2)
        listener.close()
        receiver.join(1)

    assert received == [(b"", [])]
    assert os.fstat(auth_fd)


def test_socket_rejects_oversized_request(server: _RunningServer) -> None:
    reply = _send_raw(
        server.path,
        b"{" + b"x" * (MAX_ADMIN_REQUEST_BYTES + 1),
        attestation_key_fd=server.attestation_key_fd,
    )

    assert _problem_code(reply) == "control.request_too_large"
    assert "x" * 32 not in json.dumps(reply)


def test_socket_result_matches_direct_service(server: _RunningServer) -> None:
    request = AdminRequestV1("hosts.list", {}, None, None, None)

    assert _client(server).call(request) == server.service.handle(PRINCIPAL, request)


def test_peer_authority_is_resolved_after_attestation_before_malformed_json(
    tmp_path: Path, attestation_key_fd: int
) -> None:
    ingress = _SecretIngress()
    path = tmp_path / "private" / "admin.sock"

    def deny(_peer: UnixPeerCredentials) -> AdminPrincipalV1:
        raise RuntimeError("private-peer-marker")

    adapter = AdminSocketServer(
        path,
        _service(ingress),
        deny,
        attestation_key_fd=attestation_key_fd,
    )
    adapter.start()
    try:
        reply = _send_raw(
            path,
            b"not-json\n",
            attestation_key_fd=attestation_key_fd,
        )
    finally:
        adapter.close()

    assert _problem_code(reply) == "authority.peer_denied"
    assert "private-peer-marker" not in json.dumps(reply)


def test_close_finishes_active_request_before_restart(
    tmp_path: Path,
    attestation_key_fd: int,
) -> None:
    ingress = _SecretIngress()
    hosts = _Hosts()
    accepted = Event()

    def authorize(_peer: UnixPeerCredentials) -> AdminPrincipalV1:
        accepted.set()
        return PRINCIPAL

    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(ingress, hosts),
        authorize,
        timeout_seconds=10,
        attestation_key_fd=attestation_key_fd,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_thread: Thread | None = None
    new_thread: Thread | None = None
    try:
        adapter.start()
        old_thread = getattr(adapter, "_thread")
        assert type(old_thread) is Thread
        connection.connect(os.fspath(adapter.path))
        assert local_attestation_verifier(attestation_key_fd)(
            os.getpid(), os.geteuid(), os.getegid(), connection
        )
        assert accepted.wait(1)

        closer = Thread(target=adapter.close)
        closer.start()
        closer.join(3)
        assert not closer.is_alive()

        adapter.start()
        new_thread = getattr(adapter, "_thread")
        assert type(new_thread) is Thread
        try:
            connection.sendall(
                _wire_request(AdminRequestV1("hosts.list", {}, None, None, None))
            )
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        assert AdminSocketClient(
            adapter.path,
            attestation_key_fd=attestation_key_fd,
        ).call(AdminRequestV1("hosts.list", {}, None, None, None))
        old_thread.join(1)

        assert hosts.calls == 1
        assert not old_thread.is_alive()
        assert [
            thread
            for thread in enumerate_threads()
            if thread.name == "masterjet-admin-socket"
        ] == [new_thread]
    finally:
        connection.close()
        adapter.close()
        if old_thread is not None:
            old_thread.join(2)
        if new_thread is not None:
            new_thread.join(2)

    assert new_thread is not None
    assert not new_thread.is_alive()


def test_close_is_bounded_and_fail_closed_for_blocked_authorizer(
    tmp_path: Path,
    attestation_key_fd: int,
) -> None:
    entered = Event()
    release = Event()

    def authorize(_peer: UnixPeerCredentials) -> AdminPrincipalV1:
        entered.set()
        release.wait()
        return PRINCIPAL

    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress()),
        authorize,
        attestation_key_fd=attestation_key_fd,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    close_errors: list[BaseException] = []
    close_elapsed: list[float] = []

    def close_once() -> None:
        started = monotonic()
        try:
            adapter.close()
        except BaseException as error:
            close_errors.append(error)
        finally:
            close_elapsed.append(monotonic() - started)

    closer = Thread(target=close_once)
    worker: Thread | None = None
    try:
        adapter.start()
        worker = getattr(adapter, "_thread")
        assert type(worker) is Thread
        connection.connect(os.fspath(adapter.path))
        assert local_attestation_verifier(attestation_key_fd)(
            os.getpid(), os.geteuid(), os.getegid(), connection
        )
        assert entered.wait(1)

        closer.start()
        closer.join(1.5)

        assert not closer.is_alive()
        assert close_elapsed[0] < 1.5
        assert len(close_errors) == 1
        error = close_errors[0]
        assert type(error) is AdminSocketError
        assert error.problem.code == "control.socket_shutdown_incomplete"
        assert repr(error) == "AdminSocketError('control.socket_shutdown_incomplete')"
        assert worker.is_alive()
        assert getattr(adapter, "_thread") is worker
        assert getattr(adapter, "_parent") is not None
        assert adapter.path.exists()

        with pytest.raises(AdminSocketError, match="control.socket_invalid"):
            adapter.start()

        release.set()
        adapter.close()

        assert not worker.is_alive()
        assert getattr(adapter, "_thread") is None
        assert not adapter.path.exists()
    finally:
        release.set()
        connection.close()
        if closer.ident is not None:
            closer.join(3)
        adapter.close()


def test_close_is_bounded_and_fail_closed_for_blocked_service_owner(
    tmp_path: Path,
    attestation_key_fd: int,
) -> None:
    entered = Event()
    release = Event()
    hosts = _BlockingHosts(entered, release)
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress(), hosts),
        lambda _peer: PRINCIPAL,
        attestation_key_fd=attestation_key_fd,
    )
    client_errors: list[AdminSocketError] = []

    def call_hosts() -> None:
        try:
            AdminSocketClient(
                adapter.path,
                attestation_key_fd=attestation_key_fd,
            ).call(AdminRequestV1("hosts.list", {}, None, None, None))
        except AdminSocketError as error:
            client_errors.append(error)

    close_errors: list[BaseException] = []

    def close_once() -> None:
        try:
            adapter.close()
        except BaseException as error:
            close_errors.append(error)

    client = Thread(target=call_hosts)
    closer = Thread(target=close_once)
    worker: Thread | None = None
    try:
        adapter.start()
        worker = getattr(adapter, "_thread")
        assert type(worker) is Thread
        client.start()
        assert entered.wait(1)

        closer.start()
        closer.join(1.5)

        assert not closer.is_alive()
        assert len(close_errors) == 1
        error = close_errors[0]
        assert type(error) is AdminSocketError
        assert error.problem.code == "control.socket_shutdown_incomplete"
        assert worker.is_alive()
        assert getattr(adapter, "_thread") is worker
        assert getattr(adapter, "_socket_identity") is not None
        assert adapter.path.exists()

        with pytest.raises(AdminSocketError, match="control.socket_invalid"):
            adapter.start()

        release.set()
        adapter.close()
        client.join(2)

        assert hosts.calls == 1
        assert not worker.is_alive()
        assert not client.is_alive()
        assert client_errors
        assert getattr(adapter, "_thread") is None
        assert not adapter.path.exists()
    finally:
        release.set()
        if closer.ident is not None:
            closer.join(3)
        if client.ident is not None:
            client.join(3)
        adapter.close()


def test_socket_rejects_more_than_one_jsonl_request(server: _RunningServer) -> None:
    request = _wire_request(AdminRequestV1("hosts.list", {}, None, None, None))

    reply = _send_raw(
        server.path,
        request + request,
        attestation_key_fd=server.attestation_key_fd,
    )

    assert _problem_code(reply) == "control.request_invalid"


def test_local_secret_ingress_requires_received_fd(server: _RunningServer) -> None:
    reply = _send_raw(
        server.path,
        _secret_put_wire(),
        attestation_key_fd=server.attestation_key_fd,
    )

    assert _problem_code(reply) == "control.secret_fd_required"
    assert server.ingress.put_calls == 0


def test_local_secret_ingress_consumes_received_fd(
    server: _RunningServer, auth_fd: int
) -> None:
    receipt = _client(server).put_secret_fd("ingress-one", auth_fd)

    assert receipt.state == "consumed"
    assert server.ingress.received == b'{"access_token":"private-marker"}'
    assert server.ingress.buffer is not None
    assert bytes(server.ingress.buffer) == b"\0" * len(server.ingress.buffer)
    assert os.fstat(auth_fd).st_size == len(server.ingress.received)


def test_secret_put_reads_from_zero_without_changing_shared_offset(
    server: _RunningServer, auth_fd: int
) -> None:
    expected = os.pread(auth_fd, MAX_ADMIN_SECRET_BYTES, 0)
    offset = len(expected) // 2
    os.lseek(auth_fd, offset, os.SEEK_SET)

    receipt = _client(server).put_secret_fd("ingress-one", auth_fd)

    assert receipt.state == "consumed"
    assert server.ingress.received == expected
    assert os.lseek(auth_fd, 0, os.SEEK_CUR) == offset


def test_secret_put_ignores_shared_offset_moves(
    server: _RunningServer,
    auth_fd: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = os.pread(auth_fd, MAX_ADMIN_SECRET_BYTES, 0)
    real_readv = os.readv
    real_preadv = os.preadv
    real_lseek = os.lseek

    def moved_readv(fd: int, buffers: list[memoryview]) -> int:
        real_lseek(fd, len(expected) // 2, os.SEEK_SET)
        return real_readv(fd, buffers)

    def moved_preadv(
        fd: int, buffers: list[memoryview], offset: int, flags: int = 0
    ) -> int:
        real_lseek(fd, len(expected), os.SEEK_SET)
        return real_preadv(fd, buffers, offset, flags)

    monkeypatch.setattr(admin_socket.os, "readv", moved_readv)
    monkeypatch.setattr(admin_socket.os, "preadv", moved_preadv)

    receipt = _client(server).put_secret_fd("ingress-one", auth_fd)

    assert receipt.state == "consumed"
    assert server.ingress.received == expected


@pytest.mark.parametrize("link_state", ["unlinked", "hardlinked"])
def test_secret_put_requires_exactly_one_link(
    server: _RunningServer,
    tmp_path: Path,
    link_state: str,
) -> None:
    path = tmp_path / "linked-secret"
    path.write_bytes(b"private-marker")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if link_state == "unlinked":
            path.unlink()
        else:
            os.link(path, tmp_path / "second-link")

        with pytest.raises(AdminSocketError, match="control.secret_fd_invalid"):
            _client(server).put_secret_fd("ingress-one", fd)
    finally:
        os.close(fd)

    assert server.ingress.put_calls == 0


@pytest.mark.parametrize("mutation", ["shrink", "grow", "rewrite"])
def test_secret_put_rejects_file_drift_after_first_snapshot(
    server: _RunningServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = tmp_path / "drifting-secret"
    original = b"private-marker-credential"
    path.write_bytes(original)
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    real_fstat = os.fstat
    target_ino = real_fstat(fd).st_ino
    changed = False

    def drifting_fstat(candidate: int) -> os.stat_result:
        nonlocal changed
        snapshot = real_fstat(candidate)
        if candidate != fd and snapshot.st_ino == target_ino and not changed:
            changed = True
            if mutation == "shrink":
                os.truncate(path, len(original) // 2)
            elif mutation == "grow":
                with path.open("ab") as output:
                    output.write(b"-grown")
            else:
                with path.open("r+b") as output:
                    output.write(b"X" * len(original))
        return snapshot

    monkeypatch.setattr(admin_socket.os, "fstat", drifting_fstat)
    try:
        with pytest.raises(AdminSocketError, match="control.secret_fd_invalid"):
            _client(server).put_secret_fd("ingress-one", fd)
    finally:
        os.close(fd)

    assert changed is True
    assert server.ingress.put_calls == 0


def test_secret_put_rejects_json_secret_without_owner_call(
    server: _RunningServer,
) -> None:
    payload = (
        json.dumps(
            {
                "schema_version": 1,
                "transport": "secret.put",
                "session_id": "ingress-one",
                "secret": "cHJpdmF0ZS1tYXJrZXI=",
            }
        ).encode()
        + b"\n"
    )

    reply = _send_raw(
        server.path,
        payload,
        attestation_key_fd=server.attestation_key_fd,
    )

    assert _problem_code(reply) == "control.request_invalid"
    assert "cHJpdmF0ZS1tYXJrZXI" not in json.dumps(reply)
    assert server.ingress.put_calls == 0


def test_secret_put_requires_exactly_one_received_fd(
    server: _RunningServer, auth_fd: int
) -> None:
    before = _fd_count()

    reply = _send_raw(
        server.path,
        _secret_put_wire(),
        (auth_fd, auth_fd),
        attestation_key_fd=server.attestation_key_fd,
    )

    assert _problem_code(reply) == "control.secret_fd_required"
    assert _fd_count() == before
    assert server.ingress.put_calls == 0


def test_secret_put_rejects_non_regular_fd_and_closes_duplicate(
    server: _RunningServer,
) -> None:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        before = _fd_count()

        with pytest.raises(AdminSocketError, match="control.secret_fd_invalid"):
            _client(server).put_secret_fd("ingress-one", read_fd)

        assert _fd_count() == before
        assert os.fstat(read_fd)
        assert server.ingress.put_calls == 0
        assert server.ingress.rollback_calls == 1
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_received_fd_is_closed_when_cloexec_enforcement_fails(
    server: _RunningServer,
    auth_fd: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_set_inheritable = os.set_inheritable

    def fail_received_regular_fd(fd: int, inheritable: bool) -> None:
        if stat.S_ISREG(os.fstat(fd).st_mode) and fd != auth_fd:
            raise OSError("private-marker")
        real_set_inheritable(fd, inheritable)

    monkeypatch.setattr(admin_socket.os, "set_inheritable", fail_received_regular_fd)
    before = {int(item) for item in os.listdir("/proc/self/fd")}

    with pytest.raises(AdminSocketError, match="control.request_invalid"):
        _client(server).put_secret_fd("ingress-one", auth_fd)

    after = {int(item) for item in os.listdir("/proc/self/fd")}
    leaked = after - before
    for fd in leaked:
        os.close(fd)
    assert leaked == set()


def test_all_multi_rights_fds_are_closed_when_first_cloexec_fails(
    server: _RunningServer,
    auth_fd: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second_fd = os.dup(auth_fd)
    caller_fds = {auth_fd, second_fd}
    real_set_inheritable = os.set_inheritable
    failed = False

    def fail_first_received_fd(fd: int, inheritable: bool) -> None:
        nonlocal failed
        if not failed and fd not in caller_fds and stat.S_ISREG(os.fstat(fd).st_mode):
            failed = True
            raise OSError("private-marker")
        real_set_inheritable(fd, inheritable)

    monkeypatch.setattr(admin_socket.os, "set_inheritable", fail_first_received_fd)
    before = {int(item) for item in os.listdir("/proc/self/fd")}
    try:
        reply = _send_raw(
            server.path,
            _secret_put_wire(),
            (auth_fd, second_fd),
            attestation_key_fd=server.attestation_key_fd,
        )
        after = {int(item) for item in os.listdir("/proc/self/fd")}
        leaked = after - before
        for fd in leaked:
            os.close(fd)
    finally:
        os.close(second_fd)

    assert failed is True
    assert _problem_code(reply) == "control.request_invalid"
    assert leaked == set()


def test_receive_owns_rights_after_unknown_ancillary_before_raising() -> None:
    received_fd = os.dup(0)
    rights = array("i", [received_fd]).tobytes()
    connection = _OneRecvmsgConnection(
        [
            (socket.SOL_SOCKET, 0x7FFF, b"unknown"),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
        ]
    )

    with pytest.raises(Exception, match="control.request_invalid"):
        getattr(admin_socket, "_receive_frame")(connection)

    with pytest.raises(OSError):
        os.fstat(received_fd)


def test_drain_closes_all_multi_rights_fds_when_first_cloexec_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received_fds = [os.dup(0), os.dup(0)]
    rights = array("i", received_fds).tobytes()
    connection = _OneRecvmsgConnection([(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
    real_set_inheritable = os.set_inheritable
    failed = False

    def fail_first(fd: int, inheritable: bool) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("private-marker")
        real_set_inheritable(fd, inheritable)

    monkeypatch.setattr(admin_socket.os, "set_inheritable", fail_first)

    getattr(admin_socket, "_drain_input")(connection)

    assert failed is True
    for fd in received_fds:
        try:
            os.fstat(fd)
        except OSError:
            continue
        os.close(fd)
        pytest.fail(f"received fd {fd} leaked")


def test_drain_owns_rights_after_unknown_ancillary_before_error() -> None:
    received_fd = os.dup(0)
    rights = array("i", [received_fd]).tobytes()
    connection = _OneRecvmsgConnection(
        [
            (socket.SOL_SOCKET, 0x7FFF, b"unknown"),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
        ]
    )

    getattr(admin_socket, "_drain_input")(connection)

    with pytest.raises(OSError):
        os.fstat(received_fd)


def test_secret_put_rejects_non_private_fd(
    server: _RunningServer, tmp_path: Path
) -> None:
    path = tmp_path / "shared-secret"
    path.write_bytes(b"private-marker")
    path.chmod(0o640)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminSocketError, match="control.secret_fd_invalid"):
            _client(server).put_secret_fd("ingress-one", fd)
        assert os.fstat(fd)
    finally:
        os.close(fd)

    assert server.ingress.put_calls == 0


def test_secret_put_rejects_oversized_regular_fd(
    server: _RunningServer, tmp_path: Path
) -> None:
    path = tmp_path / "oversized-secret"
    with path.open("wb") as file:
        file.truncate(MAX_ADMIN_SECRET_BYTES + 1)
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminSocketError, match="control.secret_too_large"):
            _client(server).put_secret_fd("ingress-one", fd)
    finally:
        os.close(fd)

    assert server.ingress.put_calls == 0


def test_secret_owner_failure_is_typed_and_redacted(
    server: _RunningServer, auth_fd: int
) -> None:
    server.ingress.fail = True

    with pytest.raises(AdminSocketError) as caught:
        _client(server).put_secret_fd("ingress-one", auth_fd)

    assert type(caught.value.problem) is HiveProblemV1
    assert caught.value.problem.code == "control.owner_unavailable"
    assert "private-marker" not in repr(caught.value)
    assert server.ingress.buffer is not None
    assert bytes(server.ingress.buffer) == b"\0" * len(server.ingress.buffer)
