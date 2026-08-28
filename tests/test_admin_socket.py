from __future__ import annotations

from array import array
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import socket
import stat
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
)
from codex_master.admin_socket import (
    MAX_ADMIN_REQUEST_BYTES,
    MAX_ADMIN_SECRET_BYTES,
    AdminSocketClient,
    AdminSocketError,
    AdminSocketServer,
    UnixPeerCredentials,
)


class _UnusedOwner:
    pass


class _Hosts:
    def list(self) -> tuple[ControlHostV1, ...]:
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


class _SecretIngress:
    def __init__(self) -> None:
        self.put_calls = 0
        self.received = b""
        self.buffer: bytearray | None = None
        self.fail = False

    def put_secret(
        self,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        principal: str,
    ) -> SecretIngressSessionV1:
        self.put_calls += 1
        self.received = bytes(secret)
        self.buffer = secret.obj if type(secret) is memoryview else secret
        assert principal == "operator-one"
        if self.fail:
            raise RuntimeError("private-marker /home/operator/auth.json")
        return SecretIngressSessionV1(session_id, "openai-one", "consumed")

    def create_session(self, **_values: object) -> SecretIngressSessionV1:
        raise AssertionError("not used")

    def resolve(self, _session: object, **_values: object) -> tuple[object, object]:
        raise AssertionError("not used")


def _service(ingress: _SecretIngress) -> MasterjetControlService:
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
        host_registry=_Hosts(),
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

    @property
    def path(self) -> Path:
        return self.socket.path


@pytest.fixture
def server(tmp_path: Path) -> Iterator[_RunningServer]:
    ingress = _SecretIngress()
    service = _service(ingress)

    def authorize(peer: UnixPeerCredentials) -> AdminPrincipalV1:
        assert peer.pid == os.getpid()
        assert peer.uid == os.getuid()
        assert peer.gid == os.getgid()
        return PRINCIPAL

    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        service,
        authorize,
    )
    adapter.start()
    try:
        yield _RunningServer(adapter, service, ingress)
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
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _send_raw(
    path: Path, payload: bytes, fds: tuple[int, ...] = ()
) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(os.fspath(path))
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


def _problem_code(reply: dict[str, object]) -> str:
    assert reply["ok"] is False
    problem = reply["problem"]
    assert type(problem) is dict
    code = problem["code"]
    assert type(code) is str
    return code


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_server_creates_owner_only_parent_and_socket(server: _RunningServer) -> None:
    parent = server.path.parent.stat()
    endpoint = server.path.stat()

    assert stat.S_IMODE(parent.st_mode) == 0o700
    assert stat.S_IMODE(endpoint.st_mode) == 0o600
    assert parent.st_uid == os.geteuid()
    assert endpoint.st_uid == os.geteuid()
    assert stat.S_ISSOCK(endpoint.st_mode)


def test_socket_rejects_oversized_request(server: _RunningServer) -> None:
    reply = _send_raw(
        server.path,
        b"{" + b"x" * (MAX_ADMIN_REQUEST_BYTES + 1),
    )

    assert _problem_code(reply) == "control.request_too_large"
    assert "x" * 32 not in json.dumps(reply)


def test_socket_result_matches_direct_service(server: _RunningServer) -> None:
    request = AdminRequestV1("hosts.list", {}, None, None, None)

    assert AdminSocketClient(server.path).call(request) == server.service.handle(
        PRINCIPAL, request
    )


def test_peer_authority_is_resolved_before_malformed_json(tmp_path: Path) -> None:
    ingress = _SecretIngress()
    path = tmp_path / "private" / "admin.sock"

    def deny(_peer: UnixPeerCredentials) -> AdminPrincipalV1:
        raise RuntimeError("private-peer-marker")

    adapter = AdminSocketServer(path, _service(ingress), deny)
    adapter.start()
    try:
        reply = _send_raw(path, b"not-json\n")
    finally:
        adapter.close()

    assert _problem_code(reply) == "authority.peer_denied"
    assert "private-peer-marker" not in json.dumps(reply)


def test_socket_rejects_more_than_one_jsonl_request(server: _RunningServer) -> None:
    request = _wire_request(AdminRequestV1("hosts.list", {}, None, None, None))

    reply = _send_raw(server.path, request + request)

    assert _problem_code(reply) == "control.request_invalid"


def test_local_secret_ingress_requires_received_fd(server: _RunningServer) -> None:
    reply = _send_raw(server.path, _secret_put_wire())

    assert _problem_code(reply) == "control.secret_fd_required"
    assert server.ingress.put_calls == 0


def test_local_secret_ingress_consumes_received_fd(
    server: _RunningServer, auth_fd: int
) -> None:
    receipt = AdminSocketClient(server.path).put_secret_fd("ingress-one", auth_fd)

    assert receipt.state == "consumed"
    assert server.ingress.received == b'{"access_token":"private-marker"}'
    assert server.ingress.buffer is not None
    assert bytes(server.ingress.buffer) == b"\0" * len(server.ingress.buffer)
    assert os.fstat(auth_fd).st_size == len(server.ingress.received)


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

    reply = _send_raw(server.path, payload)

    assert _problem_code(reply) == "control.request_invalid"
    assert "cHJpdmF0ZS1tYXJrZXI" not in json.dumps(reply)
    assert server.ingress.put_calls == 0


def test_secret_put_requires_exactly_one_received_fd(
    server: _RunningServer, auth_fd: int
) -> None:
    before = _fd_count()

    reply = _send_raw(server.path, _secret_put_wire(), (auth_fd, auth_fd))

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
            AdminSocketClient(server.path).put_secret_fd("ingress-one", read_fd)

        assert _fd_count() == before
        assert os.fstat(read_fd)
        assert server.ingress.put_calls == 0
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
        AdminSocketClient(server.path).put_secret_fd("ingress-one", auth_fd)

    after = {int(item) for item in os.listdir("/proc/self/fd")}
    leaked = after - before
    for fd in leaked:
        os.close(fd)
    assert leaked == set()


def test_secret_put_rejects_non_private_fd(
    server: _RunningServer, tmp_path: Path
) -> None:
    path = tmp_path / "shared-secret"
    path.write_bytes(b"private-marker")
    path.chmod(0o640)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminSocketError, match="control.secret_fd_invalid"):
            AdminSocketClient(server.path).put_secret_fd("ingress-one", fd)
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
            AdminSocketClient(server.path).put_secret_fd("ingress-one", fd)
    finally:
        os.close(fd)

    assert server.ingress.put_calls == 0


def test_secret_owner_failure_is_typed_and_redacted(
    server: _RunningServer, auth_fd: int
) -> None:
    server.ingress.fail = True

    with pytest.raises(AdminSocketError) as caught:
        AdminSocketClient(server.path).put_secret_fd("ingress-one", auth_fd)

    assert type(caught.value.problem) is HiveProblemV1
    assert caught.value.problem.code == "control.owner_unavailable"
    assert "private-marker" not in repr(caught.value)
    assert server.ingress.buffer is not None
    assert bytes(server.ingress.buffer) == b"\0" * len(server.ingress.buffer)
