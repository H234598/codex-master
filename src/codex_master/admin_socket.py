"""Private Linux Unix-socket transport for Masterjet administration."""

from __future__ import annotations

from array import array
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from threading import Event, Lock, Thread, current_thread
from typing import cast
import uuid

from .admin_contracts import (
    AdminContractError,
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    parse_admin_request,
    public_admin_result,
)
from .admin_service import (
    AdminServiceError,
    MasterjetControlService,
    SecretIngressSessionV1,
)


MAX_ADMIN_REQUEST_BYTES = 64 * 1024
MAX_ADMIN_REPLY_BYTES = 1024 * 1024
MAX_ADMIN_SECRET_BYTES = 1024 * 1024

_MAX_RIGHTS_FDS = 253
_INT_BYTES = array("i").itemsize
_RIGHTS_BYTES = socket.CMSG_SPACE(_MAX_RIGHTS_FDS * _INT_BYTES)
_PEER_CREDENTIALS = struct.Struct("3i")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_PROBLEM_FIELDS = frozenset(
    {
        "schema_version",
        "code",
        "severity",
        "title",
        "detail",
        "effect",
        "action",
        "retryable",
        "retry_after_seconds",
        "correlation_id",
        "occurred_at",
    }
)


class _SocketFailure(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AdminSocketError(Exception):
    """Code-only client failure carrying one validated public problem."""

    __slots__ = ("problem",)

    def __init__(self, problem: HiveProblemV1) -> None:
        if type(problem) is not HiveProblemV1:
            problem = _problem("control.response_invalid")
        self.problem = problem
        super().__init__(problem.code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.problem.code!r})"

    def __str__(self) -> str:
        return self.problem.code


@dataclass(frozen=True, slots=True)
class UnixPeerCredentials:
    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if (
            type(self.pid) is not int
            or self.pid <= 0
            or type(self.uid) is not int
            or not 0 <= self.uid <= 2**32 - 1
            or type(self.gid) is not int
            or not 0 <= self.gid <= 2**32 - 1
        ):
            raise ValueError("invalid peer credentials")


PeerAuthorizer = Callable[[UnixPeerCredentials], AdminPrincipalV1]


@dataclass(frozen=True, slots=True)
class _PinnedParent:
    fd: int
    metadata: os.stat_result


class AdminSocketServer:
    """Owner-only AF_UNIX listener with one request per connection."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        service: MasterjetControlService,
        authorize_peer: PeerAuthorizer,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or type(service) is not MasterjetControlService
            or not callable(authorize_peer)
            or type(timeout_seconds) not in {int, float}
            or not 0 < timeout_seconds <= 60
        ):
            raise AdminSocketError(_problem("control.socket_invalid"))
        self.path = candidate
        self._service = service
        self._authorize_peer = authorize_peer
        self._timeout_seconds = float(timeout_seconds)
        self._state_lock = Lock()
        self._stop: Event | None = None
        self._listener: socket.socket | None = None
        self._active_connection: socket.socket | None = None
        self._thread: Thread | None = None
        self._parent: _PinnedParent | None = None
        self._socket_identity: tuple[int, int] | None = None

    def __enter__(self) -> AdminSocketServer:
        self.start()
        return self

    def __exit__(self, *_values: object) -> None:
        self.close()

    def start(self) -> None:
        with self._state_lock:
            if (
                self._listener is not None
                or self._active_connection is not None
                or self._thread is not None
                or self._parent is not None
            ):
                raise AdminSocketError(_problem("control.socket_invalid"))
            listener: socket.socket | None = None
            try:
                self._parent = _prepare_parent(self.path.parent)
                _verify_pinned_parent(self._parent, self.path.parent)
                try:
                    os.stat(
                        self.path.name,
                        dir_fd=self._parent.fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    raise _SocketFailure("control.socket_invalid")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.set_inheritable(False)
                pinned_path = _pinned_socket_path(self._parent.fd, self.path.name)
                listener.bind(pinned_path)
                endpoint = os.stat(
                    self.path.name,
                    dir_fd=self._parent.fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISSOCK(endpoint.st_mode)
                    or endpoint.st_uid != os.geteuid()
                ):
                    raise _SocketFailure("control.socket_invalid")
                self._socket_identity = (endpoint.st_dev, endpoint.st_ino)
                os.chmod(pinned_path, 0o600, follow_symlinks=False)
                endpoint = os.stat(
                    self.path.name,
                    dir_fd=self._parent.fd,
                    follow_symlinks=False,
                )
                if (
                    (endpoint.st_dev, endpoint.st_ino) != self._socket_identity
                    or not stat.S_ISSOCK(endpoint.st_mode)
                    or endpoint.st_uid != os.geteuid()
                    or stat.S_IMODE(endpoint.st_mode) != 0o600
                ):
                    raise _SocketFailure("control.socket_invalid")
                _verify_pinned_parent(self._parent, self.path.parent)
                listener.listen(16)
                listener.settimeout(0.1)
                stop = Event()
                thread = Thread(
                    target=self._serve,
                    args=(listener, stop),
                    name="masterjet-admin-socket",
                    daemon=False,
                )
                self._listener = listener
                self._stop = stop
                self._thread = thread
                thread.start()
            except BaseException:
                if listener is not None:
                    listener.close()
                self._listener = None
                self._stop = None
                self._thread = None
                self._remove_owned_socket()
                self._close_parent()
                raise AdminSocketError(_problem("control.socket_unavailable")) from None

    def close(self) -> None:
        with self._state_lock:
            thread = self._thread
            if thread is current_thread():
                raise AdminSocketError(_problem("control.socket_invalid"))
            stop = self._stop
            listener = self._listener
            connection = self._active_connection
            if stop is not None:
                stop.set()
        if listener is not None:
            listener.close()
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if thread is not None:
            thread.join()
        with self._state_lock:
            if self._thread is thread:
                self._remove_owned_socket()
                self._close_parent()
                self._listener = None
                self._active_connection = None
                self._stop = None
                self._thread = None

    def _remove_owned_socket(self) -> None:
        identity = self._socket_identity
        parent = self._parent
        self._socket_identity = None
        if identity is None or parent is None:
            return
        try:
            if _parent_binding(os.fstat(parent.fd)) != _parent_binding(parent.metadata):
                return
            endpoint = os.stat(
                self.path.name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            if (
                (endpoint.st_dev, endpoint.st_ino) == identity
                and endpoint.st_uid == os.geteuid()
                and stat.S_ISSOCK(endpoint.st_mode)
            ):
                os.unlink(self.path.name, dir_fd=parent.fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _close_parent(self) -> None:
        parent = self._parent
        self._parent = None
        if parent is not None:
            try:
                os.close(parent.fd)
            except OSError:
                pass

    def _serve(self, listener: socket.socket, stop: Event) -> None:
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if stop.is_set():
                    return
                continue
            with connection:
                connection.set_inheritable(False)
                connection.settimeout(self._timeout_seconds)
                with self._state_lock:
                    if stop.is_set():
                        return
                    self._active_connection = connection
                try:
                    self._handle(connection)
                finally:
                    with self._state_lock:
                        if self._active_connection is connection:
                            self._active_connection = None

    def _handle(self, connection: socket.socket) -> None:
        received_fds: list[int] = []
        problem: HiveProblemV1 | None = None
        result: dict[str, object] | None = None
        try:
            peer = _peer_credentials(connection)
            principal = self._principal(peer)
            payload, received_fds = _receive_frame(connection)
            value = _decode_json(payload)
            result = self._dispatch(principal, peer, value, received_fds)
        except AdminServiceError as error:
            problem = error.problem
        except _SocketFailure as error:
            problem = _problem(error.code)
        except BaseException:
            problem = _problem("control.internal_error")
        try:
            _send_reply(connection, result=result, problem=problem)
        except BaseException:
            pass
        finally:
            _drain_input(connection)
            _close_fds(received_fds)

    def _principal(self, peer: UnixPeerCredentials) -> AdminPrincipalV1:
        try:
            principal = self._authorize_peer(peer)
        except BaseException:
            raise _SocketFailure("authority.peer_denied") from None
        if type(principal) is not AdminPrincipalV1:
            raise _SocketFailure("authority.peer_denied")
        return principal

    def _dispatch(
        self,
        principal: AdminPrincipalV1,
        peer: UnixPeerCredentials,
        value: dict[str, object],
        received_fds: list[int],
    ) -> dict[str, object]:
        if value.get("transport") == "secret.put":
            if set(value) != {"schema_version", "transport", "session_id"}:
                raise _SocketFailure("control.request_invalid")
            if value.get("schema_version") != 1:
                raise _SocketFailure("control.request_invalid")
            if len(received_fds) != 1:
                raise _SocketFailure("control.secret_fd_required")
            session_id = value.get("session_id")
            if type(session_id) is not str:
                raise _SocketFailure("control.request_invalid")
            return self._put_secret(principal, peer, session_id, received_fds[0])
        if received_fds:
            raise _SocketFailure("control.secret_fd_unexpected")
        try:
            request = parse_admin_request(value)
        except AdminContractError:
            raise _SocketFailure("control.request_invalid") from None
        return self._service.handle(principal, request)

    def _put_secret(
        self,
        principal: AdminPrincipalV1,
        peer: UnixPeerCredentials,
        session_id: str,
        fd: int,
    ) -> dict[str, object]:
        snapshot = _validate_secret_fd(fd, peer)
        buffer = bytearray(snapshot.st_size + 1)
        view = memoryview(buffer)
        secret: memoryview | None = None
        used = 0
        eof = False
        try:
            while used < len(buffer):
                count = os.preadv(fd, [view[used:]], used)
                if count == 0:
                    eof = True
                    break
                used += count
            if not eof or used != snapshot.st_size:
                raise _SocketFailure("control.secret_fd_invalid")
            _recheck_secret_fd(fd, snapshot)
            secret = view[:used]
            return self._service.put_secret(principal, session_id, secret)
        except _SocketFailure:
            raise
        except AdminServiceError:
            raise
        except BaseException:
            raise _SocketFailure("control.secret_fd_invalid") from None
        finally:
            if secret is not None:
                secret.release()
            view.release()
            buffer[:used] = b"\0" * used


class AdminSocketClient:
    """Bounded client for the private JSONL and SCM_RIGHTS transport."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
        expected_server_uid: int | None = None,
    ) -> None:
        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or type(timeout_seconds) not in {int, float}
            or not 0 < timeout_seconds <= 60
            or (
                expected_server_uid is not None
                and (
                    type(expected_server_uid) is not int
                    or not 0 <= expected_server_uid <= 2**32 - 1
                )
            )
        ):
            raise AdminSocketError(_problem("control.socket_invalid"))
        self.path = candidate
        self._timeout_seconds = float(timeout_seconds)
        self._expected_server_uid = (
            os.geteuid() if expected_server_uid is None else expected_server_uid
        )

    def call(self, request: AdminRequestV1) -> dict[str, object]:
        if type(request) is not AdminRequestV1:
            raise AdminSocketError(_problem("control.request_invalid"))
        return self._exchange(public_admin_result(request), None)

    def put_secret_fd(self, session_id: str, fd: int) -> SecretIngressSessionV1:
        if (
            type(session_id) is not str
            or _TOKEN.fullmatch(session_id) is None
            or type(fd) is not int
            or fd < 0
        ):
            raise AdminSocketError(_problem("control.request_invalid"))
        result = self._exchange(
            {
                "schema_version": 1,
                "transport": "secret.put",
                "session_id": session_id,
            },
            fd,
        )
        if set(result) != {"id", "account_ref", "state"} or any(
            type(result.get(field)) is not str
            or _TOKEN.fullmatch(cast(str, result[field])) is None
            for field in ("id", "account_ref", "state")
        ):
            raise AdminSocketError(_problem("control.response_invalid"))
        return SecretIngressSessionV1(
            cast(str, result["id"]),
            cast(str, result["account_ref"]),
            cast(str, result["state"]),
        )

    def _exchange(
        self, request: dict[str, object], fd: int | None
    ) -> dict[str, object]:
        try:
            payload = _encode_json(request, MAX_ADMIN_REQUEST_BYTES)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.set_inheritable(False)
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self.path))
                self._verify_server(connection)
                if fd is None:
                    connection.sendall(payload)
                else:
                    rights = array("i", [fd])
                    sent = connection.sendmsg(
                        [payload],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    )
                    if sent < len(payload):
                        connection.sendall(payload[sent:])
                connection.shutdown(socket.SHUT_WR)
                response = _receive_reply(connection)
            return _decode_reply(response)
        except AdminSocketError:
            raise
        except BaseException:
            raise AdminSocketError(_problem("control.socket_unavailable")) from None

    def _verify_server(self, connection: socket.socket) -> None:
        try:
            peer = _peer_credentials(connection)
        except _SocketFailure:
            raise AdminSocketError(_problem("authority.peer_denied")) from None
        if peer.uid != self._expected_server_uid:
            raise AdminSocketError(_problem("authority.peer_denied"))


def _prepare_parent(parent: Path) -> _PinnedParent:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_fd = os.open("/", flags)
    try:
        for component in parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise _SocketFailure("control.socket_invalid")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=current_fd)
                next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        metadata = os.fstat(current_fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise _SocketFailure("control.socket_invalid")
        os.fchmod(current_fd, 0o700)
        metadata = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _SocketFailure("control.socket_invalid")
        return _PinnedParent(current_fd, metadata)
    except BaseException:
        os.close(current_fd)
        raise


def _verify_pinned_parent(pinned: _PinnedParent, canonical: Path) -> None:
    try:
        current = os.fstat(pinned.fd)
        by_path = canonical.lstat()
    except OSError:
        raise _SocketFailure("control.socket_invalid") from None
    expected = _parent_binding(pinned.metadata)
    if _parent_binding(current) != expected or _parent_binding(by_path) != expected:
        raise _SocketFailure("control.socket_invalid")


def _parent_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _pinned_socket_path(parent_fd: int, name: str) -> str:
    return f"/proc/self/fd/{parent_fd}/{name}"


def _peer_credentials(connection: socket.socket) -> UnixPeerCredentials:
    try:
        connection.getpeername()
        value = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            _PEER_CREDENTIALS.size,
        )
        if type(value) is not bytes or len(value) != _PEER_CREDENTIALS.size:
            raise ValueError
        return UnixPeerCredentials(*_PEER_CREDENTIALS.unpack(value))
    except BaseException:
        raise _SocketFailure("authority.peer_denied") from None


def _receive_frame(connection: socket.socket) -> tuple[bytes, list[int]]:
    payload = bytearray()
    received_fds: list[int] = []
    cloexec = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    try:
        while True:
            remaining = MAX_ADMIN_REQUEST_BYTES + 1 - len(payload)
            data, ancillary, flags, _address = connection.recvmsg(
                max(1, remaining),
                _RIGHTS_BYTES,
                cloexec,
            )
            _collect_fds(ancillary, received_fds)
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise _SocketFailure("control.request_invalid")
            if data:
                payload.extend(data)
                if len(payload) > MAX_ADMIN_REQUEST_BYTES:
                    raise _SocketFailure("control.request_too_large")
                continue
            break
        if (
            not payload
            or payload[-1:] != b"\n"
            or payload.count(b"\n") != 1
            or len(payload) == 1
        ):
            raise _SocketFailure("control.request_invalid")
        return bytes(payload[:-1]), received_fds
    except _SocketFailure:
        _close_fds(received_fds)
        raise
    except BaseException:
        _close_fds(received_fds)
        raise _SocketFailure("control.request_invalid") from None


def _collect_fds(
    ancillary: list[tuple[int, int, bytes]], received_fds: list[int]
) -> None:
    if type(ancillary) is not list:
        raise _SocketFailure("control.request_invalid")
    first_new_fd = len(received_fds)
    invalid = False
    for item in ancillary:
        if type(item) is not tuple or len(item) != 3:
            invalid = True
            continue
        level, kind, data = item
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            invalid = True
            continue
        if type(data) is not bytes:
            invalid = True
            continue
        complete_bytes = len(data) - len(data) % _INT_BYTES
        if not data or complete_bytes != len(data):
            invalid = True
        if complete_bytes:
            values = array("i")
            values.frombytes(data[:complete_bytes])
            received_fds.extend(values)
    for fd in received_fds[first_new_fd:]:
        if fd < 0:
            invalid = True
            continue
        try:
            os.set_inheritable(fd, False)
        except (OSError, ValueError):
            invalid = True
    if invalid:
        raise _SocketFailure("control.request_invalid")


def _close_fds(fds: list[int]) -> None:
    while fds:
        fd = fds.pop()
        try:
            os.close(fd)
        except OSError:
            pass


def _drain_input(connection: socket.socket) -> None:
    remaining = MAX_ADMIN_REQUEST_BYTES + 1
    cloexec = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    discarded_fds: list[int] = []
    try:
        while remaining:
            data, ancillary, _flags, _address = connection.recvmsg(
                min(65536, remaining),
                _RIGHTS_BYTES,
                cloexec,
            )
            _collect_fds(ancillary, discarded_fds)
            if not data:
                return
            remaining -= len(data)
    except BaseException:
        pass
    finally:
        _close_fds(discarded_fds)


def _validate_secret_fd(fd: int, peer: UnixPeerCredentials) -> os.stat_result:
    try:
        metadata = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except (OSError, ValueError):
        raise _SocketFailure("control.secret_fd_invalid") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != peer.uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or (hasattr(os, "O_PATH") and flags & os.O_PATH)
        or flags & os.O_ACCMODE != os.O_RDONLY
    ):
        raise _SocketFailure("control.secret_fd_invalid")
    if metadata.st_size > MAX_ADMIN_SECRET_BYTES:
        raise _SocketFailure("control.secret_too_large")
    return metadata


def _recheck_secret_fd(fd: int, expected: os.stat_result) -> None:
    try:
        metadata = os.fstat(fd)
    except OSError:
        raise _SocketFailure("control.secret_fd_invalid") from None
    if _secret_stat_binding(metadata) != _secret_stat_binding(expected):
        raise _SocketFailure("control.secret_fd_invalid")


def _secret_stat_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _decode_json(payload: bytes) -> dict[str, object]:
    try:
        text = payload.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: _raise_value_error(),
        )
    except BaseException:
        raise _SocketFailure("control.request_invalid") from None
    if type(value) is not dict:
        raise _SocketFailure("control.request_invalid")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _raise_value_error() -> None:
    raise ValueError


def _encode_json(value: object, limit: int) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except BaseException:
        raise _SocketFailure("control.request_invalid") from None
    if len(payload) > limit:
        raise _SocketFailure("control.request_too_large")
    return payload


def _send_reply(
    connection: socket.socket,
    *,
    result: dict[str, object] | None,
    problem: HiveProblemV1 | None,
) -> None:
    if problem is None and type(result) is dict:
        envelope: dict[str, object] = {
            "schema_version": 1,
            "ok": True,
            "result": result,
        }
        try:
            payload = _encode_json(envelope, MAX_ADMIN_REPLY_BYTES)
        except _SocketFailure:
            problem = _problem("control.response_too_large")
        else:
            connection.sendall(payload)
            return
    if type(problem) is not HiveProblemV1:
        problem = _problem("control.internal_error")
    payload = _encode_json(
        {
            "schema_version": 1,
            "ok": False,
            "problem": public_admin_result(problem),
        },
        MAX_ADMIN_REPLY_BYTES,
    )
    connection.sendall(payload)


def _receive_reply(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(min(65536, MAX_ADMIN_REPLY_BYTES + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > MAX_ADMIN_REPLY_BYTES:
            raise AdminSocketError(_problem("control.response_too_large"))
    if (
        not payload
        or payload[-1:] != b"\n"
        or payload.count(b"\n") != 1
        or len(payload) == 1
    ):
        raise AdminSocketError(_problem("control.response_invalid"))
    return bytes(payload[:-1])


def _decode_reply(payload: bytes) -> dict[str, object]:
    try:
        value = _decode_json(payload)
    except _SocketFailure:
        raise AdminSocketError(_problem("control.response_invalid")) from None
    if value.get("schema_version") != 1 or type(value.get("ok")) is not bool:
        raise AdminSocketError(_problem("control.response_invalid"))
    if value["ok"] is True:
        if set(value) != {"schema_version", "ok", "result"}:
            raise AdminSocketError(_problem("control.response_invalid"))
        result = value.get("result")
        if type(result) is not dict:
            raise AdminSocketError(_problem("control.response_invalid"))
        return cast(dict[str, object], result)
    if set(value) != {"schema_version", "ok", "problem"}:
        raise AdminSocketError(_problem("control.response_invalid"))
    raise AdminSocketError(_parse_problem(value.get("problem")))


def _parse_problem(value: object) -> HiveProblemV1:
    if type(value) is not dict or set(value) != _PROBLEM_FIELDS:
        return _problem("control.response_invalid")
    problem = cast(dict[str, object], value)
    try:
        occurred_at = problem["occurred_at"]
        if type(occurred_at) is not str:
            raise ValueError
        timestamp = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        return HiveProblemV1(
            code=cast(str, problem["code"]),
            severity=cast(str, problem["severity"]),
            title=cast(str, problem["title"]),
            detail=cast(str, problem["detail"]),
            effect=cast(str, problem["effect"]),
            action=cast(str, problem["action"]),
            retryable=cast(bool, problem["retryable"]),
            retry_after_seconds=cast(int | None, problem["retry_after_seconds"]),
            correlation_id=cast(str, problem["correlation_id"]),
            occurred_at=timestamp,
        )
    except BaseException:
        return _problem("control.response_invalid")


def _problem(code: str) -> HiveProblemV1:
    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect="No action was started",
        action="Review access and retry",
        retryable=False,
        retry_after_seconds=None,
        correlation_id="corr-" + uuid.uuid4().hex,
        occurred_at=datetime.now(UTC),
    )


__all__ = (
    "MAX_ADMIN_REQUEST_BYTES",
    "MAX_ADMIN_REPLY_BYTES",
    "MAX_ADMIN_SECRET_BYTES",
    "AdminSocketClient",
    "AdminSocketError",
    "AdminSocketServer",
    "PeerAuthorizer",
    "UnixPeerCredentials",
)
