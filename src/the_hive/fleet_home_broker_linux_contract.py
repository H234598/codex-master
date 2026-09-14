"""Fail-closed Linux boundary for the offline home broker.

This module deliberately has no live Linux implementation.  Every operation
is supplied by a narrow adapter so that the broker's identity decisions can
be tested without root, filesystems, or processes.
"""

from __future__ import annotations

import errno
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .fleet_home_broker_identity_contract import (
    ObjectIdentity,
    PeerCgroupEvidence,
    validate_peer_cgroup_evidence,
)
from .fleet_home_broker_protocol import (
    CANONICAL_AGENT_HOME,
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
)


# Linux UAPI values.  Keeping these as constants avoids importing or invoking
# an OS/path API; the injected adapter owns the eventual syscall boundary.
O_CLOEXEC = 0o2000000
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
REQUIRED_RESOLVE_FLAGS = (
    RESOLVE_BENEATH
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_XDEV
)

_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_MCS = re.compile(r"c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z", re.ASCII)
_UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,255}\Z", re.ASCII)
_TYPE_MASK = 0o170000
_DIRECTORY_TYPE = 0o040000
_NO_GROUP_OTHER_WRITE = 0o0022


class LinuxBrokerCode(str, Enum):
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    UNSAFE_PATH = "unsafe_path"
    STALE_PEER = "stale_peer"
    IDENTITY_MISMATCH = "identity_mismatch"
    CROSS_DEVICE = "cross_device"
    ALREADY_EXISTS = "already_exists"
    IO_FAILURE = "io_failure"


class LinuxBrokerError(OSError):
    """Stable error surface for every Linux-boundary rejection."""

    __slots__ = ("code",)
    code: LinuxBrokerCode

    def __init__(self, code: LinuxBrokerCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class LinuxPlatformContract:
    openat2: bool
    pidfd: bool
    cgroup_v2: bool
    renameat2_noreplace: bool


@dataclass(frozen=True, slots=True)
class OpenHow:
    flags: int
    mode: int
    resolve: int


@dataclass(frozen=True, slots=True)
class PinnedFd:
    fd: int
    identity: ObjectIdentity


@dataclass(frozen=True, slots=True)
class SystemdUnitEvidence:
    unit_name: str
    invocation_id: str
    cgroup: ObjectIdentity
    unit_generation: int
    mcs_pair: str


@dataclass(frozen=True, slots=True)
class IdmappedMountContract:
    source: ObjectIdentity
    target_path: str
    mcs_pair: str
    dynamic_user: bool
    idmapped: bool


class LinuxBrokerOps(Protocol):
    """The only operations a Linux adapter may expose to this boundary."""

    def pidfd_open(self, pid: int) -> int: ...

    def pidfd_alive(self, pidfd: int) -> bool: ...

    def open_proc_directory(self, pidfd: int) -> int: ...

    def read_cgroup_v2(self, proc_fd: int) -> str: ...

    def open_cgroup_directory(self, proc_fd: int, name: str) -> int: ...

    def stat_fd(self, fd: int) -> ObjectIdentity: ...

    def openat2(self, parent_fd: int, name: str, how: OpenHow) -> PinnedFd: ...

    def mkdirat(self, parent_fd: int, name: str, mode: int) -> int: ...

    def write_all(self, fd: int, data: bytes) -> None: ...

    def fsync(self, fd: int) -> None: ...

    def renameat2_noreplace(self, parent_fd: int, staging_name: str, final_name: str) -> None: ...

    def unlinkat(self, parent_fd: int, name: str) -> None: ...

    def sha256_fd(self, fd: int) -> str: ...

    def close(self, fd: int) -> None: ...


def _fail(code: LinuxBrokerCode) -> None:
    raise LinuxBrokerError(code)


def _integer(value: object, low: int, high: int, code: LinuxBrokerCode) -> int:
    if type(value) is not int:
        _fail(code)
    if value < low or value > high:
        _fail(code)
    return value


def _fd(value: object) -> int:
    return _integer(value, 0, MAX_CHPB_INODE, LinuxBrokerCode.IDENTITY_MISMATCH)


def _identity(value: object, code: LinuxBrokerCode = LinuxBrokerCode.IDENTITY_MISMATCH) -> ObjectIdentity:
    if type(value) is not ObjectIdentity:
        _fail(code)
    _integer(value.dev, 0, MAX_CHPB_DEVICE, code)
    _integer(value.ino, 1, MAX_CHPB_INODE, code)
    _integer(value.mode, 0, 0o177777, code)
    _integer(value.uid, 0, MAX_CHPB_GENERATION, code)
    _integer(value.gid, 0, MAX_CHPB_GENERATION, code)
    _integer(value.nlink, 1, MAX_CHPB_INODE, code)
    return value


def _component(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(LinuxBrokerCode.UNSAFE_PATH)
    if value in (".", "..") or "/" in value:
        _fail(LinuxBrokerCode.UNSAFE_PATH)
    return value


def _mcs(value: object) -> str:
    if type(value) is not str or _MCS.fullmatch(value) is None:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    left, right = (int(part[1:]) for part in value.split(","))
    if not 0 <= left < right <= 1023:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    return value


def _unit_evidence(value: object) -> SystemdUnitEvidence:
    if type(value) is not SystemdUnitEvidence:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if type(value.unit_name) is not str or _UNIT.fullmatch(value.unit_name) is None:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if type(value.invocation_id) is not str or _HEX32.fullmatch(value.invocation_id) is None:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    cgroup = _identity(value.cgroup)
    if cgroup.mode & _TYPE_MASK != _DIRECTORY_TYPE or cgroup.nlink < 2:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if cgroup.uid != 0 or cgroup.gid != 0 or cgroup.mode & _NO_GROUP_OTHER_WRITE:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    _integer(value.unit_generation, 1, MAX_CHPB_GENERATION, LinuxBrokerCode.IDENTITY_MISMATCH)
    _mcs(value.mcs_pair)
    return value


def _map_operation_error(error: BaseException, *, rename: bool = False) -> None:
    if isinstance(error, NotImplementedError) or (
        isinstance(error, OSError)
        and error.errno in (errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP)
    ):
        _fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
    if isinstance(error, OSError) and error.errno == errno.EEXIST:
        _fail(LinuxBrokerCode.ALREADY_EXISTS)
    if isinstance(error, OSError) and error.errno == errno.EXDEV:
        _fail(LinuxBrokerCode.CROSS_DEVICE)
    if isinstance(error, OSError) and error.errno == errno.ELOOP:
        _fail(LinuxBrokerCode.UNSAFE_PATH)
    _fail(LinuxBrokerCode.IO_FAILURE)


def _call(function, *args, rename: bool = False):
    try:
        return function(*args)
    except LinuxBrokerError:
        raise
    except (NotImplementedError, OSError) as error:
        _map_operation_error(error, rename=rename)
    except Exception as error:
        _map_operation_error(error, rename=rename)
    raise AssertionError("unreachable")


def _validate_pinned(value: object) -> PinnedFd:
    if type(value) is not PinnedFd:
        _fail(LinuxBrokerCode.IO_FAILURE)
    _fd(value.fd)
    _identity(value.identity, LinuxBrokerCode.IO_FAILURE)
    return value


def require_linux_platform(value: object) -> LinuxPlatformContract:
    """Require every primitive explicitly; partial platforms are unusable."""

    if type(value) is not LinuxPlatformContract:
        _fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
    fields = (value.openat2, value.pidfd, value.cgroup_v2, value.renameat2_noreplace)
    if any(type(field) is not bool for field in fields) or not all(fields):
        _fail(LinuxBrokerCode.UNSUPPORTED_PLATFORM)
    return value


def open_beneath_no_symlink(
    ops: LinuxBrokerOps,
    parent_fd: int,
    name: str,
    *,
    flags: int,
    mode: int = 0,
) -> PinnedFd:
    """Open one safe relative component with one fully constrained openat2."""

    _fd(parent_fd)
    _component(name)
    _integer(flags, 0, MAX_CHPB_GENERATION, LinuxBrokerCode.UNSAFE_PATH)
    _integer(mode, 0, 0o177777, LinuxBrokerCode.UNSAFE_PATH)
    how = OpenHow(flags | O_CLOEXEC, mode, REQUIRED_RESOLVE_FLAGS)
    result = _call(ops.openat2, parent_fd, name, how)
    return _validate_pinned(result)


def pin_peer_cgroup(
    ops: LinuxBrokerOps,
    peer_pid: int,
    unit: SystemdUnitEvidence,
) -> PeerCgroupEvidence:
    """Pin a peer identity around a cgroup-v2 observation."""

    _integer(peer_pid, 1, MAX_CHPB_GENERATION, LinuxBrokerCode.STALE_PEER)
    _unit_evidence(unit)
    pidfd: int | None = None
    proc_fd: int | None = None
    cgroup_fd: int | None = None
    try:
        pidfd_value = _call(ops.pidfd_open, peer_pid)
        if type(pidfd_value) is not int or pidfd_value < 0:
            _fail(LinuxBrokerCode.IO_FAILURE)
        pidfd = pidfd_value

        alive = _call(ops.pidfd_alive, pidfd)
        if type(alive) is not bool:
            _fail(LinuxBrokerCode.IO_FAILURE)
        if not alive:
            _fail(LinuxBrokerCode.STALE_PEER)

        proc_value = _call(ops.open_proc_directory, pidfd)
        if type(proc_value) is not int or proc_value < 0:
            _fail(LinuxBrokerCode.IO_FAILURE)
        proc_fd = proc_value

        cgroup_name = _call(ops.read_cgroup_v2, proc_fd)
        _component(cgroup_name)
        cgroup_value = _call(ops.open_cgroup_directory, proc_fd, cgroup_name)
        if type(cgroup_value) is not int or cgroup_value < 0:
            _fail(LinuxBrokerCode.IO_FAILURE)
        cgroup_fd = cgroup_value

        observed = _call(ops.stat_fd, cgroup_fd)
        _identity(observed)
        if observed.dev != unit.cgroup.dev or observed.ino != unit.cgroup.ino:
            _fail(LinuxBrokerCode.IDENTITY_MISMATCH)

        alive_after = _call(ops.pidfd_alive, pidfd)
        if type(alive_after) is not bool:
            _fail(LinuxBrokerCode.IO_FAILURE)
        if not alive_after:
            _fail(LinuxBrokerCode.STALE_PEER)

        evidence = PeerCgroupEvidence(
            peer_pid,
            observed,
            unit.invocation_id,
            unit.unit_name,
            unit.unit_generation,
            unit.mcs_pair,
        )
        try:
            validate_peer_cgroup_evidence(evidence)
        except ValueError:
            _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
        return evidence
    finally:
        for fd in (cgroup_fd, proc_fd, pidfd):
            if fd is not None:
                try:
                    ops.close(fd)
                except Exception:
                    # Cleanup must not turn a validated observation into a
                    # different result, nor may it trigger another adapter
                    # operation or fallback.
                    pass


def validate_idmapped_mount_contract(value: object) -> IdmappedMountContract:
    """Validate immutable mount/MCS evidence without performing mount work."""

    if type(value) is not IdmappedMountContract:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    _identity(value.source)
    if type(value.target_path) is not str or value.target_path != CANONICAL_AGENT_HOME:
        _fail(LinuxBrokerCode.UNSAFE_PATH)
    _mcs(value.mcs_pair)
    if type(value.dynamic_user) is not bool or type(value.idmapped) is not bool:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    if value.dynamic_user is not True or value.idmapped is not True:
        _fail(LinuxBrokerCode.IDENTITY_MISMATCH)
    return value


def rename_noreplace_and_fsync_parent(
    ops: LinuxBrokerOps,
    parent_fd: int,
    staging_name: str,
    final_name: str,
) -> None:
    """Publish exactly once, then durably sync the containing directory."""

    _fd(parent_fd)
    _component(staging_name)
    _component(final_name)
    _call(
        ops.renameat2_noreplace,
        parent_fd,
        staging_name,
        final_name,
        rename=True,
    )
    _call(ops.fsync, parent_fd, rename=True)
