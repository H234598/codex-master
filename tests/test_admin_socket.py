from __future__ import annotations

from array import array
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import socket
import stat
from threading import Event, Thread, enumerate as enumerate_threads
from time import monotonic
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


def test_close_finishes_active_request_before_restart(tmp_path: Path) -> None:
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
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_thread: Thread | None = None
    new_thread: Thread | None = None
    try:
        adapter.start()
        old_thread = getattr(adapter, "_thread")
        assert type(old_thread) is Thread
        connection.connect(os.fspath(adapter.path))
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

        assert AdminSocketClient(adapter.path).call(
            AdminRequestV1("hosts.list", {}, None, None, None)
        )
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
) -> None:
    entered = Event()
    release = Event()
    hosts = _BlockingHosts(entered, release)
    adapter = AdminSocketServer(
        tmp_path / "private" / "admin.sock",
        _service(_SecretIngress(), hosts),
        lambda _peer: PRINCIPAL,
    )
    client_errors: list[AdminSocketError] = []

    def call_hosts() -> None:
        try:
            AdminSocketClient(adapter.path).call(
                AdminRequestV1("hosts.list", {}, None, None, None)
            )
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


def test_secret_put_reads_from_zero_without_changing_shared_offset(
    server: _RunningServer, auth_fd: int
) -> None:
    expected = os.pread(auth_fd, MAX_ADMIN_SECRET_BYTES, 0)
    offset = len(expected) // 2
    os.lseek(auth_fd, offset, os.SEEK_SET)

    receipt = AdminSocketClient(server.path).put_secret_fd("ingress-one", auth_fd)

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

    receipt = AdminSocketClient(server.path).put_secret_fd("ingress-one", auth_fd)

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
            AdminSocketClient(server.path).put_secret_fd("ingress-one", fd)
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
            AdminSocketClient(server.path).put_secret_fd("ingress-one", fd)
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
