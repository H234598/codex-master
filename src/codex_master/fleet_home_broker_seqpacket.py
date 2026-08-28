"""Offline peer reattestation seam for one injected Unix seqpacket endpoint."""

from __future__ import annotations

from enum import Enum
import socket
import struct
from typing import Protocol

from codex_master.fleet_home_broker_linux import (
    LinuxOperations,
    PeerSnapshot,
    _attest_peer_principal_with_identity,
    _observe_peer_snapshot_with_identity,
)
from codex_master.fleet_home_broker_protocol import (
    ChpbMessage,
    MAX_CHPB_MESSAGE_BYTES,
    PrincipalBinding,
    decode_chpb_message,
    validate_principal_binding,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    KernelPeerEvidence,
    _validate_release_spec,
)
from codex_master.fleet_home_broker_wal import (
    WalOperations,
    _lookup_active_principal_binding,
)


class SeqpacketPacketCode(str, Enum):
    RECEIVE_FAILED = "seqpacket_packet_receive_failed"
    CONTROL_TRUNCATED = "seqpacket_packet_control_truncated"
    ANCILLARY_PRESENT = "seqpacket_packet_ancillary_present"
    PAYLOAD_TRUNCATED = "seqpacket_packet_payload_truncated"
    ZERO_LENGTH_OR_EOF = "seqpacket_packet_zero_length_or_eof"
    TOO_LARGE = "seqpacket_packet_too_large"


class SeqpacketPacketError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: SeqpacketPacketCode) -> None:
        self.code = code
        super().__init__(code.value)


class SeqpacketPeerError(ValueError):
    """Bounded failure for an unconnected seqpacket peer observation."""

    __slots__ = ()


class SeqpacketPeerOperations(Protocol):
    def socket_family(self) -> socket.AddressFamily: ...

    def socket_type(self) -> socket.SocketKind: ...

    def peer_credentials(self) -> tuple[int, int, int]: ...

    def selinux_enforcing(self) -> bool: ...

    def peer_security_context(self) -> bytes: ...


class _SeqpacketEnforcementOperations(Protocol):
    def selinux_enforcing(self) -> bool: ...


_MAX_UINT32 = 2**32 - 1
# Linux SO_PEERSEC recommends an initial buffer of NAME_MAX bytes.
_MAX_SO_PEERSEC_BYTES = 255
_PEER_CREDENTIALS = struct.Struct("3i")


class _ConnectedSeqpacketSocketOptions:
    __slots__ = ("_connection", "_enforcement_operations")

    def __init__(
        self,
        connection: socket.socket,
        enforcement_operations: _SeqpacketEnforcementOperations,
    ) -> None:
        self._connection = connection
        self._enforcement_operations = enforcement_operations

    def socket_family(self) -> socket.AddressFamily:
        if type(self._connection) is not socket.socket:
            raise ValueError
        return self._connection.family

    def socket_type(self) -> socket.SocketKind:
        return self._connection.type

    def peer_credentials(self) -> tuple[int, int, int]:
        self._connection.getpeername()
        value = self._connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size
        )
        if type(value) is not bytes or len(value) != _PEER_CREDENTIALS.size:
            raise ValueError
        return _PEER_CREDENTIALS.unpack(value)

    def selinux_enforcing(self) -> bool:
        return self._enforcement_operations.selinux_enforcing()

    def peer_security_context(self) -> bytes:
        return self._connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERSEC, _MAX_SO_PEERSEC_BYTES
        )


def _credentials(value: object) -> tuple[int, int, int]:
    if type(value) is not tuple or len(value) != 3:
        raise ValueError
    pid, uid, gid = value
    if (
        type(pid) is not int
        or pid <= 0
        or type(uid) is not int
        or not 0 <= uid <= _MAX_UINT32
        or type(gid) is not int
        or not 0 <= gid <= _MAX_UINT32
    ):
        raise ValueError
    return pid, uid, gid


def _peer_security_context(
    value: object, agent_domain: str, expected_mcs_pair: str
) -> None:
    if type(value) is not bytes or not 1 <= len(value) <= _MAX_SO_PEERSEC_BYTES:
        raise ValueError
    if not value.endswith(b"\0"):
        raise ValueError
    context = value[:-1]
    if b"\0" in context:
        raise ValueError
    try:
        label = context.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise ValueError from None
    fields = label.split(":", 3)
    if (
        len(fields) != 4
        or any(not field for field in fields)
        or fields[2] != agent_domain
        or fields[3] != f"s0:{expected_mcs_pair}"
    ):
        raise ValueError


def _snapshot_matches(value: object, pid: int, expected: PrincipalBinding) -> PeerSnapshot:
    if type(value) is not PeerSnapshot:
        raise ValueError
    if (
        value.pid != pid
        or value.cgroup_dev != expected.cgroup_dev
        or value.cgroup_ino != expected.cgroup_ino
        or value.unit_generation != expected.unit_generation
        or value.invocation_id != expected.invocation_id
        or value.mcs_pair != expected.mcs_pair
    ):
        raise ValueError
    return value


def _reattest_seqpacket_peer_from_active_wal_binding(
    operations: SeqpacketPeerOperations,
    linux_operations: LinuxOperations,
    wal_operations: WalOperations,
    release: BrokerReleaseSpec,
) -> KernelPeerEvidence:
    """Private composition used by connected peer admission."""

    try:
        _validate_release_spec(release)
        family = operations.socket_family()
        if type(family) is not socket.AddressFamily or family is not socket.AF_UNIX:
            raise ValueError
        kind = operations.socket_type()
        if type(kind) is not socket.SocketKind or kind is not socket.SOCK_SEQPACKET:
            raise ValueError
        pid, uid, gid = _credentials(operations.peer_credentials())
        snapshot, identity = _observe_peer_snapshot_with_identity(
            linux_operations, pid
        )
        expected = _lookup_active_principal_binding(
            wal_operations,
            snapshot.cgroup_dev,
            snapshot.cgroup_ino,
            snapshot.invocation_id,
            snapshot.unit_generation,
            snapshot.mcs_pair,
        )
        if expected is None:
            raise ValueError
        validate_principal_binding(expected)
        snapshot = _snapshot_matches(snapshot, pid, expected)
        if operations.selinux_enforcing() is not True:
            raise ValueError
        _peer_security_context(
            operations.peer_security_context(), release.agent_domain, expected.mcs_pair
        )
        return KernelPeerEvidence(
            pid,
            uid,
            gid,
            identity.start_time,
            snapshot.cgroup_dev,
            snapshot.cgroup_ino,
            snapshot.unit_generation,
            snapshot.invocation_id,
            snapshot.mcs_pair,
        )
    except Exception:
        raise SeqpacketPeerError("seqpacket peer attestation failed") from None


def admit_connected_seqpacket_peer(
    connection: socket.socket,
    enforcement_operations: _SeqpacketEnforcementOperations,
    linux_operations: LinuxOperations,
    wal_operations: WalOperations,
    release: BrokerReleaseSpec,
) -> KernelPeerEvidence:
    return _reattest_seqpacket_peer_from_active_wal_binding(
        _ConnectedSeqpacketSocketOptions(connection, enforcement_operations),
        linux_operations,
        wal_operations,
        release,
    )


def receive_admitted_seqpacket_message(
    connection: socket.socket,
    enforcement_operations: _SeqpacketEnforcementOperations,
    linux_operations: LinuxOperations,
    wal_operations: WalOperations,
    release: BrokerReleaseSpec,
) -> tuple[KernelPeerEvidence, ChpbMessage]:
    evidence = admit_connected_seqpacket_peer(
        connection,
        enforcement_operations,
        linux_operations,
        wal_operations,
        release,
    )
    try:
        received = connection.recvmsg(MAX_CHPB_MESSAGE_BYTES + 1, 0)
    except Exception:
        raise SeqpacketPacketError(SeqpacketPacketCode.RECEIVE_FAILED) from None
    if type(received) is not tuple or len(received) != 4:
        raise SeqpacketPacketError(SeqpacketPacketCode.RECEIVE_FAILED) from None
    payload, ancillary, flags, _address = received
    if (
        type(payload) is not bytes
        or type(ancillary) is not list
        or type(flags) is not int
    ):
        raise SeqpacketPacketError(SeqpacketPacketCode.RECEIVE_FAILED) from None
    if flags & socket.MSG_CTRUNC:
        raise SeqpacketPacketError(SeqpacketPacketCode.CONTROL_TRUNCATED) from None
    if ancillary:
        raise SeqpacketPacketError(SeqpacketPacketCode.ANCILLARY_PRESENT) from None
    if flags & socket.MSG_TRUNC:
        raise SeqpacketPacketError(SeqpacketPacketCode.PAYLOAD_TRUNCATED) from None
    if not payload:
        raise SeqpacketPacketError(SeqpacketPacketCode.ZERO_LENGTH_OR_EOF) from None
    if len(payload) > MAX_CHPB_MESSAGE_BYTES:
        raise SeqpacketPacketError(SeqpacketPacketCode.TOO_LARGE) from None
    message = decode_chpb_message(payload)
    return evidence, message


def reattest_seqpacket_peer(
    operations: SeqpacketPeerOperations,
    linux_operations: LinuxOperations,
    expected: PrincipalBinding,
    release: BrokerReleaseSpec,
) -> KernelPeerEvidence:
    try:
        _validate_release_spec(release)
        validate_principal_binding(expected)
        family = operations.socket_family()
        if type(family) is not socket.AddressFamily or family is not socket.AF_UNIX:
            raise ValueError
        kind = operations.socket_type()
        if type(kind) is not socket.SocketKind or kind is not socket.SOCK_SEQPACKET:
            raise ValueError
        pid, uid, gid = _credentials(operations.peer_credentials())
        snapshot, identity = _attest_peer_principal_with_identity(
            linux_operations, pid, expected
        )
        snapshot = _snapshot_matches(snapshot, pid, expected)
        if operations.selinux_enforcing() is not True:
            raise ValueError
        _peer_security_context(
            operations.peer_security_context(), release.agent_domain, expected.mcs_pair
        )
        return KernelPeerEvidence(
            pid,
            uid,
            gid,
            identity.start_time,
            snapshot.cgroup_dev,
            snapshot.cgroup_ino,
            snapshot.unit_generation,
            snapshot.invocation_id,
            snapshot.mcs_pair,
        )
    except Exception:
        raise SeqpacketPeerError("seqpacket peer attestation failed") from None


__all__ = (
    "SeqpacketPacketCode",
    "SeqpacketPacketError",
    "SeqpacketPeerError",
    "SeqpacketPeerOperations",
    "admit_connected_seqpacket_peer",
    "receive_admitted_seqpacket_message",
    "reattest_seqpacket_peer",
)
