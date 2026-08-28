import ast
from dataclasses import replace
from hashlib import sha256
import socket
from pathlib import Path

import struct

import pytest

import codex_master.fleet_home_broker_seqpacket as seqpacket
import codex_master.fleet_home_broker_wal as wal
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import (
    MAX_CHPB_MESSAGE_BYTES,
    CHPB_PROTOCOL,
    AttestHomeRequest,
    BindingExpectation,
    BrokerReply,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbTransactionOperation,
    ChpbMessageKind,
    ChpbValidationCode,
    ChpbValidationError,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    encode_chpb_message,
)
from codex_master.fleet_home_broker_runtime import BrokerReleaseSpec, KernelPeerEvidence
from codex_master.fleet_home_broker_seqpacket import (
    SeqpacketPeerError,
    reattest_seqpacket_peer,
)
from codex_master.fleet_home_broker_wal import append_status, encode_status_payload


PEER_PID = 1234
PID_FD = 73
PROC_FD = 83
CGROUP_FD = 97
START_TIME = 7
PRINCIPAL = PrincipalBinding(
    "bee_1", 3, 9, 17, 29, "1" * 32, "c0,c1", 4
)
EXPECTED_LABEL = b"system_u:system_r:codex_master_agent_t:s0:c0,c1\0"
SO_PEERSEC_NAME_MAX_BYTES = 255
WAL_MAGIC = b"CHPB/2-WAL-Magic"


def release_spec(**changes: object) -> BrokerReleaseSpec:
    values = {
        "joint_release_version": 1,
        "release_id": "0.11.0",
        "server_digest": "d" * 64,
        "broker_manifest_digest": "e" * 64,
        "chpb_abi": "CHPB/2",
        "policy_abi": "policy-v1",
        "provider_abi": "provider-v1",
        "unit_digest": "f" * 64,
        "selinux_digest": "0" * 64,
        "socket_unit": "codex-master-home-broker.socket",
        "service_unit": "codex-master-home-broker.service",
        "system_bus_name": "org.codex_master.HomeBrokerControl",
        "system_bus_path": "/org/codex_master/HomeBrokerControl",
        "system_bus_interface": "org.codex_master.HomeBrokerControl1",
        "broker_domain": "codex_master_home_broker_t",
        "gateway_domain": "codex_master_control_t",
        "socket_type": "codex_master_home_broker_runtime_t",
        "agent_domain": "codex_master_agent_t",
    }
    values.update(changes)
    return BrokerReleaseSpec(**values)


class RecordingOperations:
    def __init__(
        self,
        events: list[tuple[object, ...]],
        *,
        family: object = socket.AF_UNIX,
        kind: object = socket.SOCK_SEQPACKET,
        credentials: object = (PEER_PID, 1000, 1000),
        enforcing: object = True,
        context: object = EXPECTED_LABEL,
    ) -> None:
        self.events = events
        self.family = family
        self.kind = kind
        self.credentials = credentials
        self.enforcing = enforcing
        self.context = context

    def socket_family(self) -> socket.AddressFamily:
        self.events.append(("socket_family",))
        return self.family

    def socket_type(self) -> socket.SocketKind:
        self.events.append(("socket_type",))
        return self.kind

    def peer_credentials(self) -> tuple[int, int, int]:
        self.events.append(("peer_credentials",))
        return self.credentials

    def selinux_enforcing(self) -> bool:
        self.events.append(("selinux_enforcing",))
        return self.enforcing

    def peer_security_context(self) -> bytes:
        self.events.append(("peer_security_context",))
        return self.context


class RecordingConnectedSocket:
    def __init__(
        self,
        events: list[tuple[object, ...]],
        *,
        family: object = socket.AF_UNIX,
        kind: object = socket.SOCK_SEQPACKET,
        peername: object = ("ignored",),
        peercred: object = struct.Struct("3i").pack(PEER_PID, 1000, 1000),
        peersec: object = EXPECTED_LABEL,
        peername_error: BaseException | None = None,
        peercred_error: BaseException | None = None,
        peersec_error: BaseException | None = None,
        recv_result: object = (b"raw-chpb2-candidate", [], 0, object()),
        recv_error: BaseException | None = None,
    ) -> None:
        self._events = events
        self._family = family
        self._kind = kind
        self._peername = peername
        self._peercred = peercred
        self._peersec = peersec
        self._peername_error = peername_error
        self._peercred_error = peercred_error
        self._peersec_error = peersec_error
        self._recv_result = recv_result
        self._recv_error = recv_error

    @property
    def family(self) -> object:
        self._events.append(("family",))
        return self._family

    @property
    def type(self) -> object:
        self._events.append(("type",))
        return self._kind

    def getpeername(self) -> object:
        self._events.append(("getpeername",))
        if self._peername_error is not None:
            raise self._peername_error
        return self._peername

    def getsockopt(self, level: object, option: object, buflen: object) -> object:
        self._events.append(("getsockopt", level, option, buflen))
        if option is socket.SO_PEERCRED:
            if self._peercred_error is not None:
                raise self._peercred_error
            return self._peercred
        if option is socket.SO_PEERSEC:
            if self._peersec_error is not None:
                raise self._peersec_error
            return self._peersec
        raise AssertionError(option)

    def recvmsg(self, bufsize: object, ancbufsize: object) -> object:
        self._events.append(("recvmsg", bufsize, ancbufsize))
        if self._recv_error is not None:
            raise self._recv_error
        return self._recv_result


class RecordingEnforcementOperations:
    def __init__(
        self,
        events: list[tuple[object, ...]],
        *,
        value: object = True,
        error: BaseException | None = None,
    ) -> None:
        self._events = events
        self._value = value
        self._error = error

    def selinux_enforcing(self) -> bool:
        self._events.append(("enforcing",))
        if self._error is not None:
            raise self._error
        return self._value


class RecordingLinuxOperations:
    def __init__(self, events: list[tuple[object, ...]], **values: object) -> None:
        self.events = events
        self.reuse_checks = 0
        self.drift_at = values.pop("drift_at", None)
        self.fresh_identity_per_reuse = values.pop(
            "fresh_identity_per_reuse", False
        )
        self.observed_identities: list[PidfdIdentity] = []
        self.values = {
            "pid_identity": PidfdIdentity(PEER_PID, START_TIME),
            "cgroup_stat": FdStat(17, 29, 0o40755, 1000, 1000),
            "proc_control_group": "/user.slice/user-1000.slice/session-7.scope",
            "pid1_unit_name": "session-7.scope",
            "pid1_control_group": "/user.slice/user-1000.slice/session-7.scope",
            "pid1_unit_generation": 9,
            "pid1_invocation_id": "1" * 32,
            "peer_mcs_pair": "c0,c1",
        }
        self.values.update(values)

    def pidfd_open(self, pid: int, flags: int) -> int:
        self.events.append(("pidfd_open", pid, flags))
        return PID_FD

    def pidfd_reuse_check(
        self,
        pidfd: int,
        pid: int,
        proc_fd: int | None,
        cgroup_fd: int | None,
        identity: PidfdIdentity | None,
    ) -> PidfdIdentity:
        self.events.append(("pidfd_reuse_check", pidfd, pid, proc_fd, cgroup_fd))
        self.reuse_checks += 1
        if self.drift_at is not None and self.reuse_checks >= self.drift_at:
            observed = PidfdIdentity(PEER_PID, START_TIME + 1)
        elif self.fresh_identity_per_reuse:
            observed = PidfdIdentity(PEER_PID, START_TIME)
        else:
            observed = self.values["pid_identity"]
        self.observed_identities.append(observed)
        return observed

    def open_pinned_proc_pid(
        self, pidfd: int, pid: int, identity: PidfdIdentity
    ) -> int:
        self.events.append(("open_pinned_proc_pid", pidfd, pid))
        return PROC_FD

    def open_proc_cgroup(
        self, pidfd: int, proc_fd: int, identity: PidfdIdentity
    ) -> int:
        self.events.append(("open_proc_cgroup", pidfd, proc_fd))
        return CGROUP_FD

    def fstat(self, fd: int) -> FdStat:
        self.events.append(("fstat", fd))
        return self.values["cgroup_stat"]

    def read_proc_control_group(
        self,
        pidfd: int,
        proc_fd: int,
        cgroup_fd: int,
        cgroup_dev: int,
        cgroup_ino: int,
    ) -> str:
        self.events.append(("read_proc_control_group",))
        return self.values["proc_control_group"]

    def read_pid1_unit_name(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        self.events.append(("read_pid1_unit_name",))
        return self.values["pid1_unit_name"]

    def read_pid1_unit_generation(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> int:
        self.events.append(("read_pid1_unit_generation",))
        return self.values["pid1_unit_generation"]

    def read_pid1_invocation_id(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        self.events.append(("read_pid1_invocation_id",))
        return self.values["pid1_invocation_id"]

    def read_pid1_control_group(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        self.events.append(("read_pid1_control_group",))
        return self.values["pid1_control_group"]

    def read_peer_mcs_pair(
        self,
        pidfd: int,
        proc_fd: int,
        cgroup_fd: int,
        cgroup_dev: int,
        cgroup_ino: int,
    ) -> str:
        self.events.append(("read_peer_mcs_pair",))
        return self.values["peer_mcs_pair"]

    def close(self, fd: int) -> None:
        self.events.append(("close", fd))


class RecordingWalOperations:
    def __init__(self, records: tuple[bytes, ...] = ()) -> None:
        self.records = list(records)
        self.events: list[str] = []

    def read_all(self) -> tuple[bytes, ...]:
        self.events.append("read")
        return tuple(self.records)

    def append(self, record: bytes) -> None:
        self.events.append("append")
        self.records.append(record)

    def fsync_wal(self) -> None:
        self.events.append("fsync_wal")

    def fsync_parent(self) -> None:
        self.events.append("fsync_parent")


def wal_status(
    principal: PrincipalBinding,
    checkpoint: BrokerCheckpoint = BrokerCheckpoint.CREATE_INTENT,
) -> TransactionStatus:
    terminal = (
        BrokerResultCode.BLOCKED_DRIFT
        if checkpoint is BrokerCheckpoint.BLOCKED_DRIFT
        else None
    )
    return TransactionStatus(
        TransactionBinding(
            ChpbTransactionOperation.PROVISION,
            "2" * 32,
            "3" * 32,
            principal,
            PolicyBinding(7, "a" * 64),
        ),
        b2a_phase_for_checkpoint(checkpoint),
        checkpoint,
        BrokerObservation(
            BrokerObjectState.ABSENT,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        ),
        1,
        terminal,
    )


def seeded_active_wal(principal: PrincipalBinding) -> RecordingWalOperations:
    operations = RecordingWalOperations()
    append_status(operations, wal_status(principal))
    operations.events.clear()
    return operations


def wal_wire(sequence: int, previous_digest: str, payload: bytes) -> bytes:
    preimage = (
        WAL_MAGIC
        + sequence.to_bytes(8, "big")
        + previous_digest.encode("ascii")
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return preimage + sha256(preimage).hexdigest().encode("ascii")


def assert_denied(
    operations: RecordingOperations,
    linux_operations: RecordingLinuxOperations,
    *,
    expected: PrincipalBinding = PRINCIPAL,
    release: BrokerReleaseSpec | object = None,
) -> SeqpacketPeerError:
    if release is None:
        release = release_spec()
    with pytest.raises(SeqpacketPeerError) as caught:
        reattest_seqpacket_peer(operations, linux_operations, expected, release)
    assert str(caught.value) == "seqpacket peer attestation failed"
    assert repr(caught.value) == "SeqpacketPeerError('seqpacket peer attestation failed')"
    assert caught.value.__cause__ is None
    return caught.value


def assert_wal_composition_denied(
    operations: RecordingOperations,
    linux_operations: RecordingLinuxOperations,
    wal_operations: RecordingWalOperations,
) -> SeqpacketPeerError:
    with pytest.raises(SeqpacketPeerError) as caught:
        seqpacket._reattest_seqpacket_peer_from_active_wal_binding(
            operations,
            linux_operations,
            wal_operations,
            release_spec(),
        )
    assert str(caught.value) == "seqpacket peer attestation failed"
    assert repr(caught.value) == "SeqpacketPeerError('seqpacket peer attestation failed')"
    assert caught.value.__cause__ is None
    return caught.value


def test_connected_socket_adapter_init_is_inert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events)
    enforcement_operations = RecordingEnforcementOperations(events)

    adapter = adapter_type(connection, enforcement_operations)

    assert adapter._connection is connection
    assert adapter._enforcement_operations is enforcement_operations
    assert events == []

    linux_operations = RecordingLinuxOperations(events)
    wal_operations = seeded_active_wal(PRINCIPAL)
    with pytest.raises(SeqpacketPeerError) as caught:
        getattr(seqpacket, "admit_connected_seqpacket_peer")(
            connection,
            enforcement_operations,
            linux_operations,
            wal_operations,
            release_spec(agent_domain=None),
        )
    assert caught.value.__cause__ is None
    assert events == []
    assert wal_operations.events == []


def test_connected_socket_adapter_socket_family_requires_exact_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events)
    enforcement_operations = RecordingEnforcementOperations(events)

    assert adapter_type(connection, enforcement_operations).socket_family() is socket.AF_UNIX
    assert events == [("family",)]

    class SocketProxy:
        def __init__(self, target: object) -> None:
            self._target = target

        def __getattr__(self, name: str) -> object:
            return getattr(self._target, name)

    class SocketSubclass(RecordingConnectedSocket):
        pass

    for invalid in (SocketProxy(connection), SocketSubclass(events), object()):
        with pytest.raises(ValueError):
            adapter_type(invalid, enforcement_operations).socket_family()
    assert events == [("family",)]


def test_connected_socket_adapter_socket_type_returns_kernel_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events, kind=socket.SOCK_STREAM)
    enforcement_operations = RecordingEnforcementOperations(events)

    assert adapter_type(connection, enforcement_operations).socket_type() is socket.SOCK_STREAM
    assert events == [("type",)]

    events.clear()
    connection = RecordingConnectedSocket(events, kind=socket.SOCK_STREAM)
    linux_operations = RecordingLinuxOperations(events)
    wal_operations = seeded_active_wal(PRINCIPAL)
    with pytest.raises(SeqpacketPeerError):
        getattr(seqpacket, "admit_connected_seqpacket_peer")(
            connection,
            RecordingEnforcementOperations(events),
            linux_operations,
            wal_operations,
            release_spec(),
        )
    assert events == [("family",), ("type",)]
    assert wal_operations.events == []


def test_connected_socket_adapter_peer_credentials_requires_connected_exact_peercred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    peercred_size = struct.Struct("3i").size
    assert peercred_size == 12

    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events)
    enforcement_operations = RecordingEnforcementOperations(events)
    assert adapter_type(connection, enforcement_operations).peer_credentials() == (
        PEER_PID,
        1000,
        1000,
    )
    assert events == [
        ("getpeername",),
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
    ]

    events.clear()
    disconnected = RecordingConnectedSocket(events, peername_error=OSError())
    with pytest.raises(OSError):
        adapter_type(disconnected, enforcement_operations).peer_credentials()
    assert events == [("getpeername",)]

    for invalid_peercred in (object(), b"\0" * 11, b"\0" * 13):
        events.clear()
        connection = RecordingConnectedSocket(events, peercred=invalid_peercred)
        linux_operations = RecordingLinuxOperations(events)
        wal_operations = seeded_active_wal(PRINCIPAL)
        with pytest.raises(SeqpacketPeerError) as caught:
            getattr(seqpacket, "admit_connected_seqpacket_peer")(
                connection,
                RecordingEnforcementOperations(events),
                linux_operations,
                wal_operations,
                release_spec(),
            )
        assert caught.value.__cause__ is None
        assert events == [
            ("family",),
            ("type",),
            ("getpeername",),
            ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
        ]
        assert linux_operations.reuse_checks == 0
        assert wal_operations.events == []


def test_connected_socket_adapter_selinux_enforcing_delegates_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events)
    enforcement_operations = RecordingEnforcementOperations(events, value=True)

    assert adapter_type(connection, enforcement_operations).selinux_enforcing() is True
    assert events == [("enforcing",)]

    admit = getattr(seqpacket, "admit_connected_seqpacket_peer")
    events.clear()
    connection = RecordingConnectedSocket(events)
    linux_operations = RecordingLinuxOperations(events)
    wal_operations = seeded_active_wal(PRINCIPAL)
    admit(
        connection,
        RecordingEnforcementOperations(events, value=True),
        linux_operations,
        wal_operations,
        release_spec(),
    )
    assert ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255) in events

    for value, error in (
        (False, None),
        (0, None),
        (1, None),
        (True, RuntimeError("enforcement unavailable")),
    ):
        events.clear()
        connection = RecordingConnectedSocket(events)
        linux_operations = RecordingLinuxOperations(events)
        wal_operations = seeded_active_wal(PRINCIPAL)
        with pytest.raises(SeqpacketPeerError) as caught:
            admit(
                connection,
                RecordingEnforcementOperations(events, value=value, error=error),
                linux_operations,
                wal_operations,
                release_spec(),
            )
        assert caught.value.__cause__ is None
        assert ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255) not in events
        assert wal_operations.events == ["read"]


def test_connected_socket_adapter_peer_security_context_reads_exact_peersec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    raw_context = b"opaque\0bytes"
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events, peersec=raw_context)
    enforcement_operations = RecordingEnforcementOperations(events)

    assert (
        adapter_type(connection, enforcement_operations).peer_security_context()
        is raw_context
    )
    assert events == [
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255),
    ]

    admit = getattr(seqpacket, "admit_connected_seqpacket_peer")
    for peersec, peersec_error in (
        ("not-bytes", None),
        (EXPECTED_LABEL, OSError("peer security unavailable")),
    ):
        events.clear()
        connection = RecordingConnectedSocket(
            events, peersec=peersec, peersec_error=peersec_error
        )
        wal_operations = seeded_active_wal(PRINCIPAL)
        with pytest.raises(SeqpacketPeerError) as caught:
            admit(
                connection,
                RecordingEnforcementOperations(events),
                RecordingLinuxOperations(events),
                wal_operations,
                release_spec(),
            )
        assert caught.value.__cause__ is None
        assert events[-1] == (
            "getsockopt",
            socket.SOL_SOCKET,
            socket.SO_PEERSEC,
            255,
        )


def test_admit_connected_seqpacket_peer_is_real_single_caller_and_returns_wal_bound_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_type = getattr(seqpacket, "_ConnectedSeqpacketSocketOptions")
    admit = getattr(seqpacket, "admit_connected_seqpacket_peer")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    connection = RecordingConnectedSocket(events)
    enforcement_operations = RecordingEnforcementOperations(events)
    linux_operations = RecordingLinuxOperations(
        events, fresh_identity_per_reuse=True
    )
    wal_operations = seeded_active_wal(PRINCIPAL)
    calls: list[tuple[object, ...]] = []
    original = seqpacket._reattest_seqpacket_peer_from_active_wal_binding

    def capture(*args: object) -> KernelPeerEvidence:
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(
        seqpacket, "_reattest_seqpacket_peer_from_active_wal_binding", capture
    )

    evidence_one = admit(
        connection,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release_spec(),
    )
    evidence_two = admit(
        connection,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release_spec(),
    )

    expected_evidence = KernelPeerEvidence(
        PEER_PID,
        1000,
        1000,
        START_TIME,
        PRINCIPAL.cgroup_dev,
        PRINCIPAL.cgroup_ino,
        PRINCIPAL.unit_generation,
        PRINCIPAL.invocation_id,
        PRINCIPAL.mcs_pair,
    )
    assert evidence_one == expected_evidence
    assert evidence_two == expected_evidence
    assert len(calls) == 2
    assert all(type(call[0]) is adapter_type for call in calls)
    assert all(call[0]._connection is connection for call in calls)
    assert linux_operations.reuse_checks == 32
    assert wal_operations.events == ["read", "read"]
    socket_events = [
        event
        for event in events
        if event[0] in {"family", "type", "getpeername", "getsockopt", "enforcing"}
    ]
    one_socket_observation = [
        ("family",),
        ("type",),
        ("getpeername",),
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
        ("enforcing",),
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255),
    ]
    assert socket_events == one_socket_observation + one_socket_observation


def test_private_wal_composition_uses_one_root_owned_key_and_original_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    linux_operations = RecordingLinuxOperations(
        events, fresh_identity_per_reuse=True
    )
    wal_operations = seeded_active_wal(PRINCIPAL)
    observed_keys: list[tuple[object, int, int, str, int, str]] = []
    returned_principals: list[PrincipalBinding | None] = []
    validated_records = []
    original = seqpacket._lookup_active_principal_binding
    original_validated_chain = wal._validated_chain

    def capture_validated_chain(raw_records):
        records = original_validated_chain(raw_records)
        validated_records.append(records)
        return records

    def capture(*args: object) -> PrincipalBinding | None:
        observed_keys.append(args)
        principal = original(*args)
        returned_principals.append(principal)
        return principal

    monkeypatch.setattr(wal, "_validated_chain", capture_validated_chain)
    monkeypatch.setattr(seqpacket, "_lookup_active_principal_binding", capture)
    evidence = seqpacket._reattest_seqpacket_peer_from_active_wal_binding(
        RecordingOperations(events), linux_operations, wal_operations, release_spec()
    )

    assert len(observed_keys) == 1
    assert observed_keys[0][1:] == (17, 29, "1" * 32, 9, "c0,c1")
    assert returned_principals[0] is validated_records[0][-1].status.binding.principal
    assert wal_operations.events == ["read"]
    assert linux_operations.reuse_checks == 16
    assert evidence == KernelPeerEvidence(
        PEER_PID, 1000, 1000, START_TIME, 17, 29, 9, "1" * 32, "c0,c1"
    )


@pytest.mark.parametrize(
    "values",
    [
        {"cgroup_stat": FdStat(18, 29, 0o40755, 1000, 1000)},
        {"cgroup_stat": FdStat(17, 30, 0o40755, 1000, 1000)},
        {"pid1_invocation_id": "2" * 32},
        {"pid1_unit_generation": 10},
        {"peer_mcs_pair": "c0,c2"},
    ],
)
def test_wal_composition_denies_each_drifting_root_owned_key(
    values: dict[str, object],
) -> None:
    events: list[tuple[object, ...]] = []
    wal_operations = seeded_active_wal(PRINCIPAL)

    assert_wal_composition_denied(
        RecordingOperations(events),
        RecordingLinuxOperations(events, **values),
        wal_operations,
    )

    assert wal_operations.events == ["read"]
    assert ("selinux_enforcing",) not in events
    assert ("peer_security_context",) not in events


def invalid_wal(kind: str) -> RecordingWalOperations:
    if kind == "empty":
        return RecordingWalOperations()
    if kind == "terminal":
        operations = seeded_active_wal(PRINCIPAL)
        append_status(
            operations,
            wal_status(PRINCIPAL, BrokerCheckpoint.BLOCKED_DRIFT),
        )
        operations.events.clear()
        return operations
    if kind == "foreign":
        return RecordingWalOperations((b"foreign",))
    active = seeded_active_wal(PRINCIPAL)
    if kind == "truncated":
        return RecordingWalOperations((active.records[0][:-1],))
    if kind == "gap":
        return RecordingWalOperations(
            (
                wal_wire(
                    2,
                    "f" * 64,
                    encode_status_payload(wal_status(PRINCIPAL)),
                ),
            )
        )
    if kind == "fork":
        return RecordingWalOperations(
            (
                active.records[0],
                wal_wire(
                    2,
                    "f" * 64,
                    encode_status_payload(
                        wal_status(PRINCIPAL, BrokerCheckpoint.BLOCKED_DRIFT)
                    ),
                ),
            )
        )
    raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind", ["empty", "terminal", "foreign", "truncated", "gap", "fork"]
)
def test_wal_composition_denies_inactive_or_invalid_wal(kind: str) -> None:
    events: list[tuple[object, ...]] = []
    linux_operations = RecordingLinuxOperations(events)
    wal_operations = invalid_wal(kind)

    assert_wal_composition_denied(
        RecordingOperations(events), linux_operations, wal_operations
    )

    assert linux_operations.reuse_checks == 16
    assert wal_operations.events == ["read"]
    assert ("selinux_enforcing",) not in events
    assert ("peer_security_context",) not in events


def test_wal_composition_does_not_use_peersec_mcs_as_root_owned_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    wal_operations = seeded_active_wal(PRINCIPAL)
    observed_keys: list[tuple[object, ...]] = []
    original = seqpacket._lookup_active_principal_binding

    def capture(*args: object) -> PrincipalBinding | None:
        observed_keys.append(args)
        return original(*args)

    monkeypatch.setattr(seqpacket, "_lookup_active_principal_binding", capture)
    assert_wal_composition_denied(
        RecordingOperations(
            events,
            context=b"system_u:system_r:codex_master_agent_t:s0:c0,c2\0",
        ),
        RecordingLinuxOperations(events),
        wal_operations,
    )

    assert observed_keys[0][5] == "c0,c1"
    assert wal_operations.events == ["read"]
    assert events[-2:] == [("selinux_enforcing",), ("peer_security_context",)]


@pytest.mark.parametrize(
    "operation_values",
    [
        {"family": socket.AF_INET},
        {"kind": socket.SOCK_STREAM},
        {"credentials": (0, 1000, 1000)},
    ],
)
def test_wal_composition_stops_before_root_owned_key_and_wal_on_socket_rejection(
    operation_values: dict[str, object],
) -> None:
    events: list[tuple[object, ...]] = []
    wal_operations = seeded_active_wal(PRINCIPAL)
    linux_operations = RecordingLinuxOperations(events)

    assert_wal_composition_denied(
        RecordingOperations(events, **operation_values),
        linux_operations,
        wal_operations,
    )

    assert linux_operations.reuse_checks == 0
    assert wal_operations.events == []


def test_wal_composition_final_root_owned_key_guard_precedes_wal_and_selinux() -> None:
    events: list[tuple[object, ...]] = []
    wal_operations = seeded_active_wal(PRINCIPAL)
    linux_operations = RecordingLinuxOperations(events, drift_at=16)

    assert_wal_composition_denied(
        RecordingOperations(events), linux_operations, wal_operations
    )

    assert linux_operations.reuse_checks == 16
    assert wal_operations.events == []
    assert ("selinux_enforcing",) not in events
    assert ("peer_security_context",) not in events


def test_wal_composition_source_keeps_private_api_and_single_authority() -> None:
    source = Path(seqpacket.__file__).read_text()
    tree = ast.parse(source)
    coordinators = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_reattest_seqpacket_peer_from_active_wal_binding"
    ]

    assert len(coordinators) == 1
    coordinator = coordinators[0]
    calls = [node for node in ast.walk(coordinator) if isinstance(node, ast.Call)]
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "_observe_peer_snapshot_with_identity"
        for node in calls
    ) == 1
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "_lookup_active_principal_binding"
        for node in calls
    ) == 1
    assert not any(
        isinstance(node.func, ast.Name) and node.func.id == "PrincipalBinding"
        for node in calls
    )
    assert not any(
        (node.func.attr if isinstance(node.func, ast.Attribute) else None)
        in {
            "socket",
            "socketpair",
            "bind",
            "listen",
            "accept",
            "connect",
            "recv",
            "recvmsg",
            "send",
            "sendmsg",
            "append",
            "append_status",
            "fsync_wal",
            "fsync_parent",
            "recover_status",
            "dispatch_request",
        }
        for node in calls
    )
    assert "_reattest_seqpacket_peer_from_active_wal_binding" not in seqpacket.__all__

    admissions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "admit_connected_seqpacket_peer"
    ]
    assert len(admissions) == 1
    admission = admissions[0]
    admission_calls = [
        node for node in ast.walk(admission) if isinstance(node, ast.Call)
    ]
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "_ConnectedSeqpacketSocketOptions"
        for node in admission_calls
    ) == 1
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "_reattest_seqpacket_peer_from_active_wal_binding"
        for node in admission_calls
    ) == 1

    production_calls = {"coordinator": 0, "lookup": 0, "admission": 0}
    coordinator_callers: list[str] = []
    admission_callers: list[str] = []
    for path in Path(seqpacket.__file__).parent.glob("*.py"):
        module_tree = ast.parse(path.read_text())
        functions = [
            node
            for node in ast.walk(module_tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for node in ast.walk(module_tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "_reattest_seqpacket_peer_from_active_wal_binding":
                production_calls["coordinator"] += 1
                coordinator_callers.extend(
                    function.name
                    for function in functions
                    if node in ast.walk(function)
                )
            elif node.func.id == "admit_connected_seqpacket_peer":
                production_calls["admission"] += 1
                admission_callers.extend(
                    function.name
                    for function in functions
                    if node in ast.walk(function)
                )
            elif node.func.id == "_lookup_active_principal_binding":
                production_calls["lookup"] += 1
    assert production_calls == {"coordinator": 1, "lookup": 1, "admission": 1}
    assert coordinator_callers == ["admit_connected_seqpacket_peer"]
    assert admission_callers == ["receive_admitted_seqpacket_request"]

    entries = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "receive_admitted_seqpacket_request"
    ]
    assert len(entries) == 1
    entry_calls = [node for node in ast.walk(entries[0]) if isinstance(node, ast.Call)]
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "admit_connected_seqpacket_peer"
        for node in entry_calls
    ) == 1
    assert sum(
        isinstance(node.func, ast.Name)
        and node.func.id == "decode_chpb_message"
        for node in entry_calls
    ) == 1
    assert "receive_admitted_seqpacket_packet" not in source


def test_legal_order_and_evidence_conversion() -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events)
    linux_operations = RecordingLinuxOperations(events)

    evidence = reattest_seqpacket_peer(
        operations, linux_operations, PRINCIPAL, release_spec()
    )

    assert evidence == KernelPeerEvidence(
        pid=PEER_PID,
        uid=1000,
        gid=1000,
        start_time=START_TIME,
        cgroup_dev=PRINCIPAL.cgroup_dev,
        cgroup_ino=PRINCIPAL.cgroup_ino,
        unit_generation=PRINCIPAL.unit_generation,
        invocation_id=PRINCIPAL.invocation_id,
        mcs_pair=PRINCIPAL.mcs_pair,
    )
    assert events[:3] == [
        ("socket_family",),
        ("socket_type",),
        ("peer_credentials",),
    ]
    assert events[3] == ("pidfd_open", PEER_PID, 0)
    assert events[-2:] == [("selinux_enforcing",), ("peer_security_context",)]


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_UNIX.value])
def test_wrong_socket_family_is_denied_before_credentials(family: object) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events, family=family)
    assert_denied(operations, RecordingLinuxOperations(events))
    assert events == [("socket_family",)]


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_SEQPACKET.value])
def test_wrong_socket_type_is_denied_before_credentials(kind: object) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events, kind=kind)
    assert_denied(operations, RecordingLinuxOperations(events))
    assert events == [("socket_family",), ("socket_type",)]


@pytest.mark.parametrize(
    "credentials",
    [
        (0, 1000, 1000),
        (PEER_PID, -1, 1000),
        (PEER_PID, 2**32, 1000),
        (PEER_PID, 1000, -1),
        (PEER_PID, 1000, 2**32),
        (True, 1000, 1000),
        (PEER_PID, True, 1000),
        (PEER_PID, 1000, True),
        [PEER_PID, 1000, 1000],
        (PEER_PID, 1000),
        (PEER_PID, 1000, 1000, 1),
    ],
)
def test_invalid_peer_credentials_are_denied_without_linux_access(
    credentials: object,
) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events, credentials=credentials)
    assert_denied(operations, RecordingLinuxOperations(events))
    assert events == [
        ("socket_family",),
        ("socket_type",),
        ("peer_credentials",),
    ]


@pytest.mark.parametrize(
    "values",
    [
        {"drift_at": 2},
        {"cgroup_stat": FdStat(18, 29, 0o40755, 1000, 1000)},
        {"pid1_unit_name": "session-8.scope"},
        {"pid1_unit_generation": 10},
        {"pid1_invocation_id": "2" * 32},
        {"peer_mcs_pair": "c0,c2"},
    ],
)
def test_linux_reattestation_drift_is_denied(values: dict[str, object]) -> None:
    events: list[tuple[object, ...]] = []
    assert_denied(
        RecordingOperations(events), RecordingLinuxOperations(events, **values)
    )
    assert ("selinux_enforcing",) not in events


def test_seqpacket_binds_one_final_pidfd_identity_without_capture_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    linux_operations = RecordingLinuxOperations(
        events, fresh_identity_per_reuse=True
    )
    captured: list[tuple[object, object]] = []
    original = seqpacket._attest_peer_principal_with_identity

    def counted(*args: object) -> tuple[object, object]:
        result = original(*args)
        captured.append(result)
        return result

    monkeypatch.setattr(seqpacket, "_attest_peer_principal_with_identity", counted)
    evidence = reattest_seqpacket_peer(
        RecordingOperations(events), linux_operations, PRINCIPAL, release_spec()
    )

    _, final_identity = captured[0]
    assert len(captured) == 1
    assert linux_operations.reuse_checks == 16
    assert final_identity is linux_operations.observed_identities[-1]
    assert evidence.start_time == final_identity.start_time


def test_last_pidfd_reuse_drift_returns_no_evidence_before_selinux() -> None:
    events: list[tuple[object, ...]] = []
    linux_operations = RecordingLinuxOperations(events, drift_at=16)

    assert_denied(RecordingOperations(events), linux_operations)
    assert linux_operations.reuse_checks == 16
    assert ("selinux_enforcing",) not in events
    assert ("peer_security_context",) not in events


@pytest.mark.parametrize("enforcing", [False, 0, 1, "true", None])
def test_non_enforcing_or_non_bool_selinux_state_is_denied(enforcing: object) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events, enforcing=enforcing)
    assert_denied(operations, RecordingLinuxOperations(events))
    assert events[-1] == ("selinux_enforcing",)


@pytest.mark.parametrize(
    "context",
    [
        None,
        "system_u:system_r:codex_master_agent_t:s0:c0,c1\0",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c1",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c1\0\0",
        b"system_u:system_r:codex_master_agent_t\0:s0:c0,c1\0",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c1\0extra",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c1\0\xff",
        b"system_u::codex_master_agent_t:s0:c0,c1\0",
        b"system_u:system_r:wrong_agent_t:s0:c0,c1\0",
        b"system_u:system_r:codex_master_agent_t:s1:c0,c1\0",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c2\0",
        b"system_u:system_r:codex_master_agent_t:s0:\0",
        b"system_u:system_r:codex_master_agent_t:s0:c0,c1\xff",
    ],
)
def test_malformed_or_unbound_peer_security_context_is_denied(
    context: object,
) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events, context=context)
    assert_denied(operations, RecordingLinuxOperations(events))
    assert events[-2:] == [("selinux_enforcing",), ("peer_security_context",)]
    assert repr(context) not in repr(SeqpacketPeerError("seqpacket peer attestation failed"))


def test_peer_security_context_accepts_linux_name_max_bytes() -> None:
    events: list[tuple[object, ...]] = []
    fixed = b":system_r:codex_master_agent_t:s0:c1022,c1023\0"
    context = b"u" * (SO_PEERSEC_NAME_MAX_BYTES - len(fixed)) + fixed
    expected = replace(PRINCIPAL, mcs_pair="c1022,c1023")

    assert len(context) == SO_PEERSEC_NAME_MAX_BYTES
    evidence = reattest_seqpacket_peer(
        RecordingOperations(events, context=context),
        RecordingLinuxOperations(events, peer_mcs_pair=expected.mcs_pair),
        expected,
        release_spec(),
    )

    assert evidence.mcs_pair == "c1022,c1023"


def test_peer_security_context_rejects_linux_name_max_plus_one_before_decode() -> None:
    events: list[tuple[object, ...]] = []
    fixed = b":system_r:codex_master_agent_t:s0:c1022,c1023\0"
    context = b"u" + b"u" * (SO_PEERSEC_NAME_MAX_BYTES - len(fixed)) + fixed
    expected = replace(PRINCIPAL, mcs_pair="c1022,c1023")

    assert len(context) == SO_PEERSEC_NAME_MAX_BYTES + 1
    error = assert_denied(
        RecordingOperations(events, context=context),
        RecordingLinuxOperations(events, peer_mcs_pair=expected.mcs_pair),
        expected=expected,
    )

    assert events[-2:] == [("selinux_enforcing",), ("peer_security_context",)]
    marker = context[:-1].decode("ascii")
    assert marker not in str(error)
    assert marker not in repr(error)
    assert error.__cause__ is None


def test_peer_security_context_checks_size_before_decode() -> None:
    source = Path(seqpacket.__file__).read_text()
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_peer_security_context"
    )
    function_source = ast.get_source_segment(source, function)
    assert function_source is not None
    decode_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decode"
    ]
    size_checks = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Compare)
        and any(
            isinstance(child, ast.Name) and child.id == "_MAX_SO_PEERSEC_BYTES"
            for child in ast.walk(node)
        )
    ]

    assert len(decode_calls) == 1
    assert len(size_checks) == 1
    assert size_checks[0].lineno < decode_calls[0].lineno
    assert function_source.index("_MAX_SO_PEERSEC_BYTES") < function_source.index(
        ".decode("
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_domain", "codex_master_agent_exec_t"),
        ("agent_domain", "unconfined_t"),
        ("agent_domain", None),
        ("socket_type", "untrusted_runtime_t"),
    ],
)
def test_release_or_principal_validation_is_bounded_before_evidence(
    field: str, value: object
) -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events)
    release = replace(release_spec(), **{field: value})
    assert_denied(operations, RecordingLinuxOperations(events), release=release)
    assert events == []


def test_principal_binding_validation_is_bounded_before_evidence() -> None:
    events: list[tuple[object, ...]] = []
    operations = RecordingOperations(events)
    invalid = replace(PRINCIPAL, mcs_pair="not-mcs")
    assert_denied(operations, RecordingLinuxOperations(events), expected=invalid)
    assert events == []


def test_public_surface_is_exact() -> None:
    assert seqpacket.__all__ == (
        "SeqpacketPacketCode",
        "SeqpacketPacketError",
        "SeqpacketRequestCode",
        "SeqpacketRequestError",
        "SeqpacketPeerError",
        "SeqpacketPeerOperations",
        "admit_connected_seqpacket_peer",
        "receive_admitted_seqpacket_request",
        "reattest_seqpacket_peer",
    )


def test_seqpacket_source_has_no_live_transport_or_authority_calls() -> None:
    source = Path(seqpacket.__file__).read_text()
    tree = ast.parse(source)

    forbidden_imports = (
        "fleet_home_broker_transport",
        "fleet_home_broker_dispatch",
        "fleet_home_broker_client",
        "subprocess",
        "systemd",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                not any(fragment in alias.name for fragment in forbidden_imports)
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            assert not any(
                fragment in (node.module or "") for fragment in forbidden_imports
            )

    wal_imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "codex_master.fleet_home_broker_wal"
    ]
    assert len(wal_imports) == 1
    assert [alias.name for alias in wal_imports[0].names] == [
        "WalOperations",
        "_lookup_active_principal_binding",
    ]

    forbidden_call_names = {
        "socket",
        "socketpair",
        "bind",
        "listen",
        "accept",
        "connect",
        "recv",
        "recvfrom",
        "recv_into",
        "recvmsg_into",
        "peek",
        "read",
        "makefile",
        "send",
        "sendmsg",
        "settimeout",
        "gettimeout",
        "setblocking",
        "getblocking",
        "shutdown",
        "close",
        "detach",
        "dup",
        "fileno",
        "select",
        "poll",
        "thread",
        "lock",
        "serve_once",
        "dispatch_request",
        "receive_attested_home",
        "append_status",
        "begin_offline_transaction",
        "openat2",
        "mkdirat",
        "recovery",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called_name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else None
            )
            assert called_name not in forbidden_call_names

    receive_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "receive_admitted_seqpacket_request"
    ]
    assert len(receive_functions) == 1
    assert not any(
        isinstance(node, ast.FunctionDef)
        and node.name == "receive_admitted_seqpacket_packet"
        for node in tree.body
    )
    receive_function = receive_functions[0]
    receive_source = ast.get_source_segment(source, receive_function)
    assert receive_source is not None
    assert ast.unparse(receive_function.returns) == (
        "tuple[KernelPeerEvidence, BrokerRequest]"
    )

    admission_calls = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "admit_connected_seqpacket_peer"
    ]
    assert len(admission_calls) == 1
    assert len(admission_calls[0].args) == 5
    assert ast.unparse(admission_calls[0].args[0]) == "connection"

    recvmsg_calls = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "recvmsg"
    ]
    assert len(recvmsg_calls) == 1
    recvmsg_call = recvmsg_calls[0]
    assert isinstance(recvmsg_call.func.value, ast.Name)
    assert recvmsg_call.func.value.id == "connection"
    assert len(recvmsg_call.args) == 2
    assert not recvmsg_call.keywords
    assert ast.unparse(recvmsg_call) == (
        "connection.recvmsg(MAX_CHPB_MESSAGE_BYTES + 1, 0)"
    )
    assert admission_calls[0].lineno < recvmsg_call.lineno

    decode_calls = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "decode_chpb_message"
    ]
    assert len(decode_calls) == 1
    assert len(decode_calls[0].args) == 1
    assert not decode_calls[0].keywords
    assert ast.unparse(decode_calls[0].args[0]) == "payload"
    assert recvmsg_call.lineno < decode_calls[0].lineno

    packet_raises = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Raise)
        and node.exc is not None
        and "SeqpacketPacketError" in ast.unparse(node.exc)
    ]
    assert packet_raises
    assert recvmsg_call.lineno < min(node.lineno for node in packet_raises)
    assert max(node.lineno for node in packet_raises) < decode_calls[0].lineno

    role_gates = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "type(message) is BrokerReply"
    ]
    request_raises = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Raise)
        and node.exc is not None
        and ast.unparse(node.exc)
        == "SeqpacketRequestError(SeqpacketRequestCode.NOT_REQUEST)"
    ]
    returns = [
        node
        for node in ast.walk(receive_function)
        if isinstance(node, ast.Return)
        and node.value is not None
        and ast.unparse(node.value) == "(evidence, message)"
    ]
    assert len(role_gates) == len(request_raises) == len(returns) == 1
    assert decode_calls[0].lineno < role_gates[0].lineno
    assert role_gates[0].lineno <= request_raises[0].lineno
    assert request_raises[0].lineno < returns[0].lineno

    receive_callers = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and recvmsg_call in ast.walk(node)
    ]
    assert receive_callers == ["receive_admitted_seqpacket_request"]

    assert not any(
        isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.Await, ast.Yield, ast.YieldFrom))
        for node in ast.walk(receive_function)
    )
    forbidden_receive_call_names = {
        "recv",
        "recvfrom",
        "recv_into",
        "recvmsg_into",
        "peek",
        "read",
        "makefile",
        "send",
        "sendmsg",
        "settimeout",
        "gettimeout",
        "setblocking",
        "getblocking",
        "shutdown",
        "close",
        "detach",
        "dup",
        "fileno",
        "select",
        "poll",
        "thread",
        "lock",
        "decode",
        "loads",
        "dumps",
        "validate_chpb_message",
        "dispatch_request",
    }
    for node in ast.walk(receive_function):
        if not isinstance(node, ast.Call):
            continue
        called_name = node.func.attr if isinstance(node.func, ast.Attribute) else (
            node.func.id if isinstance(node.func, ast.Name) else None
        )
        assert called_name not in forbidden_receive_call_names
    for term in ("SCM_RIGHTS", "CMSG_", "schema", "request_type"):
        assert term not in receive_source


    getpeername_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "getpeername"
    ]
    getsockopt_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "getsockopt"
    ]
    assert len(getpeername_calls) == 1
    assert len(getsockopt_calls) == 2
    assert [ast.unparse(node) for node in getsockopt_calls] == [
        "self._connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size)",
        "self._connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, _MAX_SO_PEERSEC_BYTES)",
    ]

    source_terms = (
        "ScmFrame",
        "BrokerPeer",
        "BrokerTransportResponse",
        "ChpbMessage",
        "SCM_RIGHTS",
        "WAL",
        "Home",
    )
    assert not any(term in source for term in source_terms)
    assert "receive_admitted_seqpacket_message" not in source
    assert not any(
        request_type in source
        for request_type in (
            "AttestHomeRequest",
            "QueryTransactionRequest",
            "GetTerminalResultRequest",
            "ProvisionHomeRequest",
            "ReplaceHomeRequest",
            "DeprovisionHomeRequest",
        )
    )
    assert "receive_admitted_seqpacket_packet" not in source
    assert "_PidfdIdentityCapture" not in source
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"__getattr__", "pidfd_reuse_check"}
        for node in ast.walk(tree)
    )
    private_attestation_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_attest_peer_principal_with_identity"
    ]
    assert len(private_attestation_calls) == 1


def test_seqpacket_packet_error_codes_are_stable() -> None:
    code_type = getattr(seqpacket, "SeqpacketPacketCode")
    error_type = getattr(seqpacket, "SeqpacketPacketError")
    expected = (
        ("RECEIVE_FAILED", "seqpacket_packet_receive_failed"),
        ("CONTROL_TRUNCATED", "seqpacket_packet_control_truncated"),
        ("ANCILLARY_PRESENT", "seqpacket_packet_ancillary_present"),
        ("PAYLOAD_TRUNCATED", "seqpacket_packet_payload_truncated"),
        ("ZERO_LENGTH_OR_EOF", "seqpacket_packet_zero_length_or_eof"),
        ("TOO_LARGE", "seqpacket_packet_too_large"),
    )

    assert [(code.name, code.value) for code in code_type] == list(expected)
    for name, value in expected:
        code = getattr(code_type, name)
        error = error_type(code)
        assert type(error) is error_type
        assert error.code is code
        assert str(error) == value
        assert error.args == (value,)
        assert error.__cause__ is None


def test_seqpacket_request_error_codes_are_stable() -> None:
    code_type = getattr(seqpacket, "SeqpacketRequestCode")
    error_type = getattr(seqpacket, "SeqpacketRequestError")
    expected = (("NOT_REQUEST", "seqpacket_request_not_request"),)

    assert [(code.name, code.value) for code in code_type] == list(expected)
    code = getattr(code_type, "NOT_REQUEST")
    error = error_type(code)
    assert type(error) is error_type
    assert error.code is code
    assert str(error) == code.value
    assert error.args == (code.value,)
    assert error.__cause__ is None


def test_receive_admitted_seqpacket_request_admits_reads_once_then_decodes_canonical_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    request = AttestHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.ATTEST_HOME,
        "2" * 32,
        "3" * 32,
        BindingExpectation(
            PRINCIPAL.agent_id,
            PRINCIPAL.manifest_generation,
            PRINCIPAL.unit_generation,
            7,
            "a" * 64,
            PRINCIPAL.fencing_epoch,
        ),
    )
    payload = encode_chpb_message(request)
    canonical_decode = seqpacket.decode_chpb_message

    def recording_decode(raw: bytes):
        events.append(("decode", raw))
        return canonical_decode(raw)

    monkeypatch.setattr(seqpacket, "decode_chpb_message", recording_decode)
    connection = RecordingConnectedSocket(
        events, recv_result=(payload, [], 0, object())
    )
    enforcement_operations = RecordingEnforcementOperations(events)
    linux_operations = RecordingLinuxOperations(events)
    wal_operations = seeded_active_wal(PRINCIPAL)

    evidence, received_request = receive(
        connection,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release_spec(),
    )

    assert evidence == KernelPeerEvidence(
        PEER_PID,
        1000,
        1000,
        START_TIME,
        PRINCIPAL.cgroup_dev,
        PRINCIPAL.cgroup_ino,
        PRINCIPAL.unit_generation,
        PRINCIPAL.invocation_id,
        PRINCIPAL.mcs_pair,
    )
    assert type(received_request) is AttestHomeRequest
    assert received_request == request
    recv_events = [event for event in events if event[0] == "recvmsg"]
    assert recv_events == [("recvmsg", MAX_CHPB_MESSAGE_BYTES + 1, 0)]
    assert [event for event in events if event[0] == "decode"] == [
        ("decode", payload)
    ]
    assert events.index(
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255)
    ) < events.index(recv_events[0])
    assert events.index(recv_events[0]) < events.index(("decode", payload))
    assert events[-1] == ("decode", payload)


def test_receive_admitted_seqpacket_request_rejects_canonical_reply_after_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    code_type = getattr(seqpacket, "SeqpacketRequestCode")
    error_type = getattr(seqpacket, "SeqpacketRequestError")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    reply = BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        "2" * 32,
        BrokerResultCode.INVALID_MESSAGE,
        None,
        None,
    )
    payload = encode_chpb_message(reply)
    canonical_decode = seqpacket.decode_chpb_message

    def recording_decode(raw: bytes):
        events.append(("decode", raw))
        return canonical_decode(raw)

    monkeypatch.setattr(seqpacket, "decode_chpb_message", recording_decode)
    connection = RecordingConnectedSocket(
        events, recv_result=(payload, [], 0, object())
    )

    with pytest.raises(error_type) as caught:
        receive(
            connection,
            RecordingEnforcementOperations(events),
            RecordingLinuxOperations(events),
            seeded_active_wal(PRINCIPAL),
            release_spec(),
        )

    expected_code = getattr(code_type, "NOT_REQUEST")
    error = caught.value
    assert type(error) is error_type
    assert error.code is expected_code
    assert str(error) == expected_code.value
    assert error.args == (expected_code.value,)
    assert error.__cause__ is None
    recv_event = ("recvmsg", MAX_CHPB_MESSAGE_BYTES + 1, 0)
    decode_event = ("decode", payload)
    assert [event for event in events if event[0] == "recvmsg"] == [recv_event]
    assert [event for event in events if event[0] == "decode"] == [decode_event]
    assert events.index(
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255)
    ) < events.index(recv_event)
    assert events.index(recv_event) < events.index(decode_event)
    assert events[-1] == decode_event


def test_receive_admitted_seqpacket_request_stops_before_read_and_decode_when_admission_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)

    def unreachable_decode(raw: bytes):
        raise AssertionError(raw)

    monkeypatch.setattr(
        seqpacket, "decode_chpb_message", unreachable_decode, raising=False
    )
    cases = (
        {"release": release_spec(agent_domain=None)},
        {"connection": {"peername_error": OSError("disconnected")}},
        {"linux": {"drift_at": 2}},
        {"wal": RecordingWalOperations()},
        {"enforcement": {"value": False}},
        {"connection": {"peersec": b"bad\0"}},
    )

    for case in cases:
        events: list[tuple[object, ...]] = []
        connection = RecordingConnectedSocket(
            events, **case.get("connection", {})
        )
        enforcement_operations = RecordingEnforcementOperations(
            events, **case.get("enforcement", {})
        )
        linux_operations = RecordingLinuxOperations(
            events, **case.get("linux", {})
        )
        wal_operations = case.get("wal", seeded_active_wal(PRINCIPAL))
        release = case.get("release", release_spec())

        with pytest.raises(SeqpacketPeerError) as caught:
            receive(
                connection,
                enforcement_operations,
                linux_operations,
                wal_operations,
                release,
            )
        assert type(caught.value) is SeqpacketPeerError
        assert str(caught.value) == "seqpacket peer attestation failed"
        assert repr(caught.value) == (
            "SeqpacketPeerError('seqpacket peer attestation failed')"
        )
        assert caught.value.__cause__ is None
        assert not any(event[0] == "recvmsg" for event in events)


def test_receive_admitted_seqpacket_request_maps_recvmsg_failures_and_malformed_results_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    code_type = getattr(seqpacket, "SeqpacketPacketCode")
    error_type = getattr(seqpacket, "SeqpacketPacketError")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)

    def unreachable_decode(raw: bytes):
        raise AssertionError(raw)

    monkeypatch.setattr(
        seqpacket, "decode_chpb_message", unreachable_decode, raising=False
    )
    marker = "recvmsg-secret-marker"
    cases = (
        {"recv_error": OSError(marker)},
        {"recv_result": object()},
        {"recv_result": (b"payload", [], 0)},
        {"recv_result": (bytearray(b"payload"), [], 0, object())},
        {"recv_result": (b"payload", (), 0, object())},
        {"recv_result": (b"payload", [], True, object())},
        {"recv_result": (b"payload", [], object(), object())},
    )
    expected_code = getattr(code_type, "RECEIVE_FAILED")

    for case in cases:
        events: list[tuple[object, ...]] = []
        connection = RecordingConnectedSocket(events, **case)
        with pytest.raises(error_type) as caught:
            receive(
                connection,
                RecordingEnforcementOperations(events),
                RecordingLinuxOperations(events),
                seeded_active_wal(PRINCIPAL),
                release_spec(),
            )
        assert caught.value.code is expected_code
        assert str(caught.value) == expected_code.value
        assert repr(caught.value) == (
            "SeqpacketPacketError('seqpacket_packet_receive_failed')"
        )
        assert caught.value.__cause__ is None
        assert marker not in str(caught.value)
        assert marker not in repr(caught.value)
        assert [event for event in events if event[0] == "recvmsg"] == [
            ("recvmsg", MAX_CHPB_MESSAGE_BYTES + 1, 0)
        ]


def test_receive_admitted_seqpacket_request_rejects_ancillary_and_truncation_before_decode_in_stable_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    code_type = getattr(seqpacket, "SeqpacketPacketCode")
    error_type = getattr(seqpacket, "SeqpacketPacketError")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)

    def unreachable_decode(raw: bytes):
        raise AssertionError(raw)

    monkeypatch.setattr(
        seqpacket, "decode_chpb_message", unreachable_decode, raising=False
    )
    cases = (
        (
            (
                b"x",
                [("inert",)],
                int(socket.MSG_CTRUNC) | int(socket.MSG_TRUNC),
                object(),
            ),
            "CONTROL_TRUNCATED",
        ),
        (
            (b"x", [("inert",)], int(socket.MSG_TRUNC), object()),
            "ANCILLARY_PRESENT",
        ),
        ((b"x", [], int(socket.MSG_TRUNC), object()), "PAYLOAD_TRUNCATED"),
    )

    for recv_result, expected_name in cases:
        events: list[tuple[object, ...]] = []
        connection = RecordingConnectedSocket(events, recv_result=recv_result)
        with pytest.raises(error_type) as caught:
            receive(
                connection,
                RecordingEnforcementOperations(events),
                RecordingLinuxOperations(events),
                seeded_active_wal(PRINCIPAL),
                release_spec(),
            )
        expected_code = getattr(code_type, expected_name)
        assert caught.value.code is expected_code
        assert caught.value.__cause__ is None
        assert len([event for event in events if event[0] == "recvmsg"]) == 1


def test_receive_admitted_seqpacket_request_enforces_packet_size_boundaries_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    code_type = getattr(seqpacket, "SeqpacketPacketCode")
    error_type = getattr(seqpacket, "SeqpacketPacketError")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    request = AttestHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.ATTEST_HOME,
        "2" * 32,
        "3" * 32,
        BindingExpectation(
            PRINCIPAL.agent_id,
            PRINCIPAL.manifest_generation,
            PRINCIPAL.unit_generation,
            7,
            "a" * 64,
            PRINCIPAL.fencing_epoch,
        ),
    )
    decode_calls: list[bytes] = []

    def recording_decode(raw: bytes):
        decode_calls.append(raw)
        return request

    monkeypatch.setattr(
        seqpacket, "decode_chpb_message", recording_decode, raising=False
    )
    expected_evidence = KernelPeerEvidence(
        PEER_PID,
        1000,
        1000,
        START_TIME,
        PRINCIPAL.cgroup_dev,
        PRINCIPAL.cgroup_ino,
        PRINCIPAL.unit_generation,
        PRINCIPAL.invocation_id,
        PRINCIPAL.mcs_pair,
    )

    for payload in (b"x", b"x" * MAX_CHPB_MESSAGE_BYTES):
        events: list[tuple[object, ...]] = []
        result = receive(
            RecordingConnectedSocket(
                events, recv_result=(payload, [], 0, object())
            ),
            RecordingEnforcementOperations(events),
            RecordingLinuxOperations(events),
            seeded_active_wal(PRINCIPAL),
            release_spec(),
        )
        assert result[0] == expected_evidence
        assert result[1] is request
        assert decode_calls == [payload]
        decode_calls.clear()

    cases = (
        (b"", 0, "ZERO_LENGTH_OR_EOF"),
        (b"x" * (MAX_CHPB_MESSAGE_BYTES + 1), 0, "TOO_LARGE"),
        (
            b"x" * (MAX_CHPB_MESSAGE_BYTES + 1),
            int(socket.MSG_TRUNC),
            "PAYLOAD_TRUNCATED",
        ),
    )
    for payload, flags, expected_name in cases:
        events: list[tuple[object, ...]] = []
        with pytest.raises(error_type) as caught:
            receive(
                RecordingConnectedSocket(
                    events, recv_result=(payload, [], flags, object())
                ),
                RecordingEnforcementOperations(events),
                RecordingLinuxOperations(events),
                seeded_active_wal(PRINCIPAL),
                release_spec(),
            )
        assert caught.value.code is getattr(code_type, expected_name)
        assert caught.value.__cause__ is None
        assert decode_calls == []


def test_receive_admitted_seqpacket_request_repeats_fresh_admission_read_and_decode_without_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    events: list[tuple[object, ...]] = []
    request_one = AttestHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.ATTEST_HOME,
        "2" * 32,
        "3" * 32,
        BindingExpectation(
            PRINCIPAL.agent_id,
            PRINCIPAL.manifest_generation,
            PRINCIPAL.unit_generation,
            7,
            "a" * 64,
            PRINCIPAL.fencing_epoch,
        ),
    )
    request_two = AttestHomeRequest(
        CHPB_PROTOCOL,
        ChpbMessageKind.ATTEST_HOME,
        "4" * 32,
        "3" * 32,
        BindingExpectation(
            PRINCIPAL.agent_id,
            PRINCIPAL.manifest_generation,
            PRINCIPAL.unit_generation,
            7,
            "a" * 64,
            PRINCIPAL.fencing_epoch,
        ),
    )
    payload_one = encode_chpb_message(request_one)
    payload_two = encode_chpb_message(request_two)
    canonical_decode = seqpacket.decode_chpb_message

    def recording_decode(raw: bytes):
        events.append(("decode", raw))
        return canonical_decode(raw)

    monkeypatch.setattr(seqpacket, "decode_chpb_message", recording_decode)
    connection_one = RecordingConnectedSocket(
        events, recv_result=(payload_one, [], 0, object())
    )
    connection_two = RecordingConnectedSocket(
        events, recv_result=(payload_two, [], 0, object())
    )
    enforcement_operations = RecordingEnforcementOperations(events)
    linux_operations = RecordingLinuxOperations(
        events, fresh_identity_per_reuse=True
    )
    wal_operations = seeded_active_wal(PRINCIPAL)

    result_one = receive(
        connection_one,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release_spec(),
    )
    result_two = receive(
        connection_two,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release_spec(),
    )

    expected_evidence = KernelPeerEvidence(
        PEER_PID,
        1000,
        1000,
        START_TIME,
        PRINCIPAL.cgroup_dev,
        PRINCIPAL.cgroup_ino,
        PRINCIPAL.unit_generation,
        PRINCIPAL.invocation_id,
        PRINCIPAL.mcs_pair,
    )
    assert result_one[0] == expected_evidence
    assert result_two[0] == expected_evidence
    assert type(result_one[1]) is AttestHomeRequest
    assert type(result_two[1]) is AttestHomeRequest
    assert result_one[1] == request_one
    assert result_two[1] == request_two
    assert linux_operations.reuse_checks == 32
    assert len(linux_operations.observed_identities) == 32
    assert wal_operations.events == ["read", "read"]
    socket_events = [
        event
        for event in events
        if event[0]
        in {"family", "type", "getpeername", "getsockopt", "enforcing", "recvmsg"}
    ]
    one_sequence = [
        ("family",),
        ("type",),
        ("getpeername",),
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
        ("enforcing",),
        ("getsockopt", socket.SOL_SOCKET, socket.SO_PEERSEC, 255),
        ("recvmsg", MAX_CHPB_MESSAGE_BYTES + 1, 0),
    ]
    assert socket_events == one_sequence + one_sequence
    assert len([event for event in events if event[0] == "recvmsg"]) == 2
    decode_events = [event for event in events if event[0] == "decode"]
    assert decode_events == [("decode", payload_one), ("decode", payload_two)]
    recv_positions = [
        index for index, event in enumerate(events) if event[0] == "recvmsg"
    ]
    decode_positions = [
        index for index, event in enumerate(events) if event[0] == "decode"
    ]
    assert recv_positions[0] < decode_positions[0]
    assert decode_positions[0] < recv_positions[1]
    assert recv_positions[1] < decode_positions[1]
    assert events[-1] == decode_events[1]
    assert not any(
        event[0]
        in {
            "settimeout",
            "gettimeout",
            "setblocking",
            "getblocking",
            "shutdown",
            "detach",
            "dup",
            "fileno",
            "makefile",
            "recv",
            "recvfrom",
            "recv_into",
            "recvmsg_into",
            "send",
            "sendmsg",
        }
        for event in events
    )


def test_receive_admitted_seqpacket_request_propagates_canonical_decode_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receive = getattr(seqpacket, "receive_admitted_seqpacket_request")
    monkeypatch.setattr(seqpacket.socket, "socket", RecordingConnectedSocket)
    message = BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        "2" * 32,
        BrokerResultCode.INVALID_MESSAGE,
        None,
        None,
    )
    canonical_decode = seqpacket.decode_chpb_message
    cases = (
        (b"\xff", ChpbValidationCode.INVALID_UTF8),
        (encode_chpb_message(message)[:-1], ChpbValidationCode.NON_CANONICAL),
    )

    for payload, expected_code in cases:
        events: list[tuple[object, ...]] = []

        def recording_decode(raw: bytes):
            events.append(("decode", raw))
            return canonical_decode(raw)

        monkeypatch.setattr(seqpacket, "decode_chpb_message", recording_decode)
        connection = RecordingConnectedSocket(
            events, recv_result=(payload, [], 0, object())
        )
        with pytest.raises(ChpbValidationError) as caught:
            receive(
                connection,
                RecordingEnforcementOperations(events),
                RecordingLinuxOperations(events),
                seeded_active_wal(PRINCIPAL),
                release_spec(),
            )

        error = caught.value
        assert type(error) is ChpbValidationError
        assert error.code is expected_code
        assert str(error) == expected_code.value
        assert error.args == (expected_code.value,)
        assert error.__cause__ is None
        recv_events = [event for event in events if event[0] == "recvmsg"]
        assert recv_events == [("recvmsg", MAX_CHPB_MESSAGE_BYTES + 1, 0)]
        assert [event for event in events if event[0] == "decode"] == [
            ("decode", payload)
        ]
        assert events.index(recv_events[0]) < events.index(("decode", payload))
        assert events[-1] == ("decode", payload)
