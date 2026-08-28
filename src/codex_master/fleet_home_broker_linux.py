"""Injected Linux boundary checks for CHPB/2 broker peers and directories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_home_broker_protocol import (
    AgentStartEnvelope,
    agent_unit_name_for_mcs,
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    DirectoryIdentity,
    PrincipalBinding,
    _digest,
    _mcs,
    validate_chpb_message,
    validate_principal_binding,
)


SAFE_DIRECTORY_MODE = 0o40700
_FILE_TYPE_MASK = 0o170000
_DIRECTORY_FILE_TYPE = 0o040000
_MAX_FILE_MODE = 0o177777


class LinuxBoundaryError(ValueError):
    """Raised when an injected Linux boundary observation is unsafe."""


@dataclass(frozen=True, slots=True)
class FdStat:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class PidfdIdentity:
    pid: int
    start_time: int


@dataclass(frozen=True, slots=True)
class PeerSnapshot:
    pid: int
    cgroup_dev: int
    cgroup_ino: int
    invocation_id: str
    unit_generation: int
    mcs_pair: str


@dataclass(frozen=True, slots=True)
class AgentStartPeerObservation:
    pid: int
    uid: int
    gid: int
    start_time: int
    cgroup_dev: int
    cgroup_ino: int
    unit_name: str
    invocation_id: str
    service_generation: int
    mcs_pair: str


class LinuxOperations(Protocol):
    def openat2(self, parent_fd: int, child_name: str, flags: int, resolve: int) -> int:
        ...

    def fstat(self, fd: int) -> FdStat:
        ...

    def close(self, fd: int) -> None:
        ...

    def pidfd_open(self, pid: int, flags: int) -> int:
        ...

    def pidfd_reuse_check(
        self,
        pidfd: int,
        pid: int,
        proc_fd: int | None,
        cgroup_fd: int | None,
        identity: PidfdIdentity | None,
    ) -> PidfdIdentity:
        ...

    def open_pinned_proc_pid(
        self, pidfd: int, pid: int, identity: PidfdIdentity
    ) -> int:
        ...

    def open_proc_cgroup(
        self, pidfd: int, proc_fd: int, identity: PidfdIdentity
    ) -> int:
        ...

    def read_proc_control_group(
        self,
        pidfd: int,
        proc_fd: int,
        cgroup_fd: int,
        cgroup_dev: int,
        cgroup_ino: int,
    ) -> str:
        ...

    def read_pid1_unit_name(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        ...

    def read_pid1_unit_generation(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> int:
        ...

    def read_pid1_invocation_id(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        ...

    def read_pid1_control_group(
        self, pidfd: int, cgroup_fd: int, cgroup_dev: int, cgroup_ino: int
    ) -> str:
        ...

    def read_peer_mcs_pair(
        self,
        pidfd: int,
        proc_fd: int,
        cgroup_fd: int,
        cgroup_dev: int,
        cgroup_ino: int,
    ) -> str:
        ...


_OPENAT2_FLAGS = 0o10000000 | 0o200000 | 0o400000 | 0o2000000
_OPENAT2_RESOLVE = 0x08 | 0x04 | 0x02


def _strict_integer(value: object, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise LinuxBoundaryError(f"{field} is outside strict integer bounds")
    return value


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise LinuxBoundaryError(f"{field} is not a positive integer")
    return value


def _strict_text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise LinuxBoundaryError(f"{field} is not non-empty text")
    return value


def _validate_directory_identity(value: object) -> DirectoryIdentity:
    if type(value) is not DirectoryIdentity:
        raise LinuxBoundaryError("expected directory identity is invalid")
    _strict_integer(value.dev, "directory dev", 0, MAX_CHPB_DEVICE)
    _strict_integer(value.ino, "directory ino", 1, MAX_CHPB_INODE)
    _strict_integer(value.mode, "directory mode", SAFE_DIRECTORY_MODE, SAFE_DIRECTORY_MODE)
    return value


def _validate_fd_stat(value: object) -> FdStat:
    if type(value) is not FdStat:
        raise LinuxBoundaryError("observed fd stat is invalid")
    _strict_integer(value.dev, "fd dev", 0, MAX_CHPB_DEVICE)
    _strict_integer(value.ino, "fd ino", 1, MAX_CHPB_INODE)
    _strict_integer(value.mode, "fd mode", SAFE_DIRECTORY_MODE, SAFE_DIRECTORY_MODE)
    if type(value.uid) is not int or value.uid != 0:
        raise LinuxBoundaryError("fd uid is not exactly root")
    if type(value.gid) is not int or value.gid != 0:
        raise LinuxBoundaryError("fd gid is not exactly root")
    return value


def _validate_cgroup_stat(value: object) -> FdStat:
    if type(value) is not FdStat:
        raise LinuxBoundaryError("cgroup stat is invalid")
    _strict_integer(value.dev, "cgroup dev", 0, MAX_CHPB_DEVICE)
    _strict_integer(value.ino, "cgroup ino", 1, MAX_CHPB_INODE)
    _strict_integer(value.mode, "cgroup mode", 0, _MAX_FILE_MODE)
    if value.mode & _FILE_TYPE_MASK != _DIRECTORY_FILE_TYPE:
        raise LinuxBoundaryError("cgroup stat is not a directory")
    return value


def _validate_principal(value: object) -> PrincipalBinding:
    if type(value) is not PrincipalBinding:
        raise LinuxBoundaryError("expected principal binding is invalid")
    try:
        return validate_principal_binding(value)
    except Exception as exc:
        raise LinuxBoundaryError("expected principal binding is invalid") from exc


def _validate_pidfd_identity(value: object, expected_pid: int) -> PidfdIdentity:
    if type(value) is not PidfdIdentity:
        raise LinuxBoundaryError("pidfd identity is invalid")
    _positive_integer(value.pid, "pidfd identity pid")
    _strict_integer(
        value.start_time,
        "pidfd identity start time",
        1,
        MAX_CHPB_GENERATION,
    )
    if value.pid != expected_pid:
        raise LinuxBoundaryError("pidfd identity pid was reused or exited")
    return value


def _pidfd_guard(
    operations: LinuxOperations,
    pidfd: int,
    peer_pid: int,
    proc_fd: int | None,
    cgroup_fd: int | None,
    identity: PidfdIdentity | None,
) -> PidfdIdentity:
    observed = _validate_pidfd_identity(
        operations.pidfd_reuse_check(
            pidfd,
            peer_pid,
            proc_fd,
            cgroup_fd,
            identity,
        ),
        peer_pid,
    )
    if identity is not None and observed != identity:
        raise LinuxBoundaryError("pidfd identity drifted")
    return observed


def _validate_observed_peer_snapshot(
    value: object, peer_pid: int
) -> PeerSnapshot:
    if type(value) is not PeerSnapshot:
        raise LinuxBoundaryError("peer snapshot is invalid")
    _positive_integer(value.pid, "snapshot pid")
    if value.pid != peer_pid:
        raise LinuxBoundaryError("snapshot pid was reused or exited")
    _strict_integer(value.cgroup_dev, "snapshot cgroup dev", 0, MAX_CHPB_DEVICE)
    _strict_integer(value.cgroup_ino, "snapshot cgroup ino", 1, MAX_CHPB_INODE)
    _strict_integer(
        value.unit_generation,
        "snapshot unit generation",
        1,
        MAX_CHPB_GENERATION,
    )
    try:
        _digest(value.invocation_id, 32)
        _mcs(value.mcs_pair)
    except Exception as exc:
        raise LinuxBoundaryError("peer snapshot fields are invalid") from exc
    return value


def _validate_peer_snapshot(
    value: object, peer_pid: int, expected: PrincipalBinding
) -> PrincipalBinding:
    snapshot = _validate_observed_peer_snapshot(value, peer_pid)
    if (
        snapshot.cgroup_dev != expected.cgroup_dev
        or snapshot.cgroup_ino != expected.cgroup_ino
        or snapshot.unit_generation != expected.unit_generation
        or snapshot.invocation_id != expected.invocation_id
        or snapshot.mcs_pair != expected.mcs_pair
    ):
        raise LinuxBoundaryError("peer principal does not match")
    return expected


def _close_all(operations: LinuxOperations, fds: tuple[int | None, ...]) -> None:
    first_error = None
    for fd in fds:
        if fd is None:
            continue
        try:
            operations.close(fd)
        except Exception as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise LinuxBoundaryError("fd close failed") from first_error


def _fail_with_cleanup(
    operations: LinuxOperations,
    fds: tuple[int | None, ...],
    message: str,
    cause=None,
) -> None:
    try:
        _close_all(operations, fds)
    except LinuxBoundaryError as exc:
        raise LinuxBoundaryError(f"{message}; close failed") from exc
    error = LinuxBoundaryError(message)
    if cause is None:
        raise error
    raise error from cause


def _valid_child_name(child_name: object) -> bool:
    return (
        type(child_name) is str
        and child_name == child_name.strip()
        and child_name not in {"", ".", ".."}
        and not child_name.startswith("/")
        and "/" not in child_name
        and "\\" not in child_name
        and "\x00" not in child_name
    )


def open_pinned_child_directory(
    operations: LinuxOperations,
    parent_fd: int,
    child_name: str,
    expected: DirectoryIdentity,
) -> int:
    """Open and verify one pinned child directory using injected operations."""

    if not _valid_child_name(child_name):
        raise LinuxBoundaryError("child name is not one canonical relative component")
    _validate_directory_identity(expected)

    try:
        fd = operations.openat2(parent_fd, child_name, _OPENAT2_FLAGS, _OPENAT2_RESOLVE)
    except Exception as exc:
        raise LinuxBoundaryError("openat2 failed") from exc

    try:
        observed = _validate_fd_stat(operations.fstat(fd))
        if (
            observed.dev != expected.dev
            or observed.ino != expected.ino
            or observed.mode != expected.mode
        ):
            raise LinuxBoundaryError("directory identity drifted")
    except LinuxBoundaryError as exc:
        _fail_with_cleanup(operations, (fd,), str(exc), exc)
    except Exception as exc:
        _fail_with_cleanup(operations, (fd,), "fstat failed", exc)
    return fd


def _observe_peer_snapshot_with_identity(
    operations: LinuxOperations,
    peer_pid: int,
) -> tuple[PeerSnapshot, PidfdIdentity]:
    """Private extraction of the existing complete pidfd-bound observation body."""

    _positive_integer(peer_pid, "peer pid")
    pidfd = None
    proc_fd = None
    cgroup_fd = None
    try:
        pidfd = operations.pidfd_open(peer_pid, 0)
        identity = _pidfd_guard(operations, pidfd, peer_pid, None, None, None)

        proc_fd = operations.open_pinned_proc_pid(pidfd, peer_pid, identity)
        identity = _pidfd_guard(operations, pidfd, peer_pid, proc_fd, None, identity)
        cgroup_fd = operations.open_proc_cgroup(pidfd, proc_fd, identity)
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        cgroup_stat = _validate_cgroup_stat(operations.fstat(cgroup_fd))
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        cgroup_dev = cgroup_stat.dev
        cgroup_ino = cgroup_stat.ino

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        proc_control_group = _strict_text(
            operations.read_proc_control_group(
                pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "proc control group",
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        unit_name = _strict_text(
            operations.read_pid1_unit_name(
                pidfd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "PID-1 unit name",
        )
        if "/" in unit_name:
            raise LinuxBoundaryError("PID-1 unit name is not canonical")
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        unit_generation = operations.read_pid1_unit_generation(
            pidfd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        invocation_id = operations.read_pid1_invocation_id(
            pidfd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        pid1_control_group = _strict_text(
            operations.read_pid1_control_group(
                pidfd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "PID-1 control group",
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        mcs_pair = operations.read_peer_mcs_pair(
            pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )

        if proc_control_group != pid1_control_group:
            raise LinuxBoundaryError("PID-1 control group does not match proc")
        if not pid1_control_group.endswith(f"/{unit_name}"):
            raise LinuxBoundaryError("PID-1 unit does not match cgroup")
        snapshot = PeerSnapshot(
            identity.pid,
            cgroup_dev,
            cgroup_ino,
            invocation_id,
            unit_generation,
            mcs_pair,
        )
        _validate_observed_peer_snapshot(snapshot, peer_pid)
    except LinuxBoundaryError as exc:
        _fail_with_cleanup(operations, (cgroup_fd, proc_fd, pidfd), str(exc), exc)
    except Exception as exc:
        _fail_with_cleanup(
            operations,
            (cgroup_fd, proc_fd, pidfd),
            "peer boundary operation failed",
            exc,
        )

    _close_all(operations, (cgroup_fd, proc_fd, pidfd))
    return snapshot, identity


def _attest_peer_principal_with_identity(
    operations: LinuxOperations,
    peer_pid: int,
    expected_principal: PrincipalBinding,
) -> tuple[PeerSnapshot, PidfdIdentity]:
    """Attest a peer with explicit PID-FD-bound proc and cgroup reads."""

    _positive_integer(peer_pid, "peer pid")
    expected = _validate_principal(expected_principal)
    snapshot, identity = _observe_peer_snapshot_with_identity(operations, peer_pid)
    _validate_peer_snapshot(snapshot, peer_pid, expected)
    return snapshot, identity


def attest_peer_principal(
    operations: LinuxOperations,
    peer_pid: int,
    expected_principal: PrincipalBinding,
) -> PeerSnapshot:
    """Attest a peer with explicit PID-FD-bound proc and cgroup reads."""

    snapshot, _ = _attest_peer_principal_with_identity(
        operations, peer_pid, expected_principal
    )
    return snapshot


def _validate_agent_start_peer_observation(
    value: object,
    peer_pid: int,
    peer_uid: int,
    peer_gid: int,
    expected: AgentStartEnvelope,
) -> AgentStartPeerObservation:
    if type(value) is not AgentStartPeerObservation:
        raise LinuxBoundaryError("agent start peer observation is invalid")
    _positive_integer(peer_pid, "peer pid")
    _strict_integer(peer_uid, "peer uid", 0, 2**32 - 1)
    _strict_integer(peer_gid, "peer gid", 0, 2**32 - 1)
    _positive_integer(value.pid, "observation pid")
    _positive_integer(value.start_time, "observation start time")
    _strict_integer(value.cgroup_dev, "observation cgroup dev", 0, MAX_CHPB_DEVICE)
    _strict_integer(value.cgroup_ino, "observation cgroup ino", 1, MAX_CHPB_INODE)
    _positive_integer(value.service_generation, "observation service generation")
    _strict_text(value.unit_name, "observation unit name")
    try:
        _digest(value.invocation_id, 32)
        _mcs(value.mcs_pair)
    except Exception as exc:
        raise LinuxBoundaryError("agent start peer fields are invalid") from exc
    if (
        value.pid != peer_pid
        or value.uid != peer_uid
        or value.gid != peer_gid
        or value.cgroup_dev != expected.principal.cgroup_dev
        or value.cgroup_ino != expected.principal.cgroup_ino
        or value.unit_name != agent_unit_name_for_mcs(expected.principal.mcs_pair)
        or value.invocation_id != expected.principal.invocation_id
        or value.service_generation != expected.principal.unit_generation
        or value.mcs_pair != expected.principal.mcs_pair
    ):
        raise LinuxBoundaryError("agent start peer observation drifted")
    return value


def _observe_agent_start_peer_with_identity(
    operations: LinuxOperations,
    peer_pid: int,
    peer_uid: int,
    peer_gid: int,
    expected: AgentStartEnvelope,
) -> tuple[AgentStartPeerObservation, PidfdIdentity]:
    """Read one envelope-bound peer using only injected Linux operations."""

    if type(expected) is not AgentStartEnvelope:
        raise LinuxBoundaryError("agent start envelope is invalid")
    try:
        validate_chpb_message(expected)
    except Exception as exc:
        raise LinuxBoundaryError("agent start envelope is invalid") from exc
    _positive_integer(peer_pid, "peer pid")
    _strict_integer(peer_uid, "peer uid", 0, 2**32 - 1)
    _strict_integer(peer_gid, "peer gid", 0, 2**32 - 1)
    pidfd = None
    proc_fd = None
    cgroup_fd = None
    try:
        pidfd = operations.pidfd_open(peer_pid, 0)
        identity = _pidfd_guard(operations, pidfd, peer_pid, None, None, None)
        proc_fd = operations.open_pinned_proc_pid(pidfd, peer_pid, identity)
        identity = _pidfd_guard(operations, pidfd, peer_pid, proc_fd, None, identity)
        cgroup_fd = operations.open_proc_cgroup(pidfd, proc_fd, identity)
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        cgroup_stat = _validate_cgroup_stat(operations.fstat(cgroup_fd))
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        cgroup_dev = cgroup_stat.dev
        cgroup_ino = cgroup_stat.ino
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        proc_control_group = _strict_text(
            operations.read_proc_control_group(
                pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "proc control group",
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        unit_name = _strict_text(
            operations.read_pid1_unit_name(
                pidfd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "PID-1 unit name",
        )
        if "/" in unit_name:
            raise LinuxBoundaryError("PID-1 unit name is not canonical")
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        service_generation = operations.read_pid1_unit_generation(
            pidfd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        invocation_id = operations.read_pid1_invocation_id(
            pidfd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        pid1_control_group = _strict_text(
            operations.read_pid1_control_group(
                pidfd, cgroup_fd, cgroup_dev, cgroup_ino
            ),
            "PID-1 control group",
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        mcs_pair = operations.read_peer_mcs_pair(
            pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
        )
        identity = _pidfd_guard(
            operations, pidfd, peer_pid, proc_fd, cgroup_fd, identity
        )
        if proc_control_group != pid1_control_group:
            raise LinuxBoundaryError("PID-1 control group does not match proc")
        if not pid1_control_group.endswith(f"/{unit_name}"):
            raise LinuxBoundaryError("PID-1 unit does not match cgroup")
        observation = AgentStartPeerObservation(
            identity.pid,
            peer_uid,
            peer_gid,
            identity.start_time,
            cgroup_dev,
            cgroup_ino,
            unit_name,
            invocation_id,
            service_generation,
            mcs_pair,
        )
        _validate_agent_start_peer_observation(
            observation, peer_pid, peer_uid, peer_gid, expected
        )
    except LinuxBoundaryError as exc:
        _fail_with_cleanup(operations, (cgroup_fd, proc_fd, pidfd), str(exc), exc)
    except Exception as exc:
        _fail_with_cleanup(
            operations,
            (cgroup_fd, proc_fd, pidfd),
            "agent start peer boundary operation failed",
            exc,
        )
    _close_all(operations, (cgroup_fd, proc_fd, pidfd))
    return observation, identity


def observe_agent_start_peer(
    operations: LinuxOperations,
    peer_pid: int,
    peer_uid: int,
    peer_gid: int,
    expected: AgentStartEnvelope,
) -> AgentStartPeerObservation:
    """Return one fully validated, pidfd-bound V2 peer observation."""

    observation, _ = _observe_agent_start_peer_with_identity(
        operations, peer_pid, peer_uid, peer_gid, expected
    )
    return observation


__all__ = [
    "AgentStartPeerObservation",
    "FdStat",
    "LinuxBoundaryError",
    "LinuxOperations",
    "PeerSnapshot",
    "PidfdIdentity",
    "SAFE_DIRECTORY_MODE",
    "attest_peer_principal",
    "open_pinned_child_directory",
    "observe_agent_start_peer",
]
