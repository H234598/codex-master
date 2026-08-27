"""Offline peer reattestation seam for one injected Unix seqpacket endpoint."""

from __future__ import annotations

import socket
from typing import Protocol

from codex_master.fleet_home_broker_linux import (
    LinuxOperations,
    PeerSnapshot,
    attest_peer_principal,
)
from codex_master.fleet_home_broker_protocol import (
    PrincipalBinding,
    validate_principal_binding,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    KernelPeerEvidence,
    _validate_release_spec,
)


class SeqpacketPeerError(ValueError):
    """Bounded failure for an unconnected seqpacket peer observation."""

    __slots__ = ()


class SeqpacketPeerOperations(Protocol):
    def socket_family(self) -> socket.AddressFamily: ...

    def socket_type(self) -> socket.SocketKind: ...

    def peer_credentials(self) -> tuple[int, int, int]: ...

    def selinux_enforcing(self) -> bool: ...

    def peer_security_context(self) -> bytes: ...


_MAX_UINT32 = 2**32 - 1


class _PidfdIdentityCapture:
    __slots__ = ("_operations", "identity")

    def __init__(self, operations: LinuxOperations) -> None:
        self._operations = operations
        self.identity = None

    def pidfd_reuse_check(
        self,
        pidfd: int,
        pid: int,
        proc_fd: int | None,
        cgroup_fd: int | None,
        identity: object,
    ) -> object:
        observed = self._operations.pidfd_reuse_check(
            pidfd, pid, proc_fd, cgroup_fd, identity
        )
        self.identity = observed
        return observed

    def __getattr__(self, name: str) -> object:
        return getattr(self._operations, name)


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
    if type(value) is not bytes or not value.endswith(b"\0"):
        raise ValueError
    context = value[:-1]
    if b"\0" in context:
        raise ValueError
    try:
        label = context.decode("utf-8")
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
        tracked_operations = _PidfdIdentityCapture(linux_operations)
        snapshot = _snapshot_matches(
            attest_peer_principal(tracked_operations, pid, expected), pid, expected
        )
        identity = tracked_operations.identity
        if identity is None or type(identity.start_time) is not int:
            raise ValueError
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
    "SeqpacketPeerError",
    "SeqpacketPeerOperations",
    "reattest_seqpacket_peer",
)
