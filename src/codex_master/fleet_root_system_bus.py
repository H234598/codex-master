"""Concrete fail-closed system-bus ingress for root-host admission."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import os
import re
import select
from threading import Lock
from typing import Callable, Protocol

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from codex_master.fleet_home_broker_protocol import (
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    MAX_CHPB_MCS_CATEGORY,
    MAX_CHPB_MESSAGE_BYTES,
    MAX_CHPB_OBJECT_FIELDS,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    _validate_release_spec,
)
from codex_master.fleet_root_runtime_host import (
    FleetRootRuntimeHost,
    FleetRootRuntimeHostError,
    RootHostParticipant,
    RootHostParticipantBinding,
    RootRuntimeActivityOwnership,
)


BUS_NAME = "org.codex_master.HomeBrokerControl"
BUS_PATH = "/org/codex_master/HomeBrokerControl"
BUS_INTERFACE = "org.codex_master.HomeBrokerControl1"
BUS_METHOD = "StartDynamicTeamlead"

_DBUS_NAME = "org.freedesktop.DBus"
_DBUS_PATH = "/org/freedesktop/DBus"
_DBUS_INTERFACE = "org.freedesktop.DBus"
_SYSTEMD_NAME = "org.freedesktop.systemd1"
_SYSTEMD_PATH = "/org/freedesktop/systemd1"
_SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager"
_PROPERTIES = "org.freedesktop.DBus.Properties"
_UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"
_UINT32_MAX = 2**32 - 1
_RESOLVE = 0x08 | 0x04 | 0x02
_DIRECTORY_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


class RootSystemBusError(dbus.DBusException):
    """Sparse system-bus ingress failure."""

    __slots__ = ("code",)
    _dbus_error_name = BUS_INTERFACE + ".Error.Failed"

    def __init__(self, code: str) -> None:
        self.code = code
        Exception.__init__(self, code)

    def __repr__(self) -> str:
        return "<RootSystemBusError redacted>"


class _NonTransferable:
    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("root_system_bus_attestation_factory_required")

    def __copy__(self):
        raise TypeError("root_system_bus_attestation_not_cloneable")

    def __deepcopy__(self, _memo):
        raise TypeError("root_system_bus_attestation_not_cloneable")

    def __reduce_ex__(self, _protocol):
        raise TypeError("root_system_bus_attestation_not_serializable")

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootSystemBusPeerAttestation(_NonTransferable):
    bus_unique_name: str
    pid: int
    uid: int
    effective_gid: int
    groups: tuple[int, ...]
    start_time: int
    cgroup_device: int
    cgroup_inode: int
    unit_name: str
    invocation_id: str
    selinux_context: bytes
    mcs_pair: str
    service_generation: int


@dataclass(frozen=True, slots=True)
class _BusCredentials:
    pid: int
    uid: int
    groups: tuple[int, ...]
    security_label: bytes


@dataclass(frozen=True, slots=True)
class _ProcObservation:
    start_time: int
    effective_gid: int
    cgroup_path: str
    security_label: bytes


@dataclass(frozen=True, slots=True)
class _UnitObservation:
    object_path: str
    name: str
    invocation_id: bytes
    control_group: str


@dataclass(frozen=True, slots=True)
class _PeerObservation:
    pid: int
    uid: int
    effective_gid: int
    groups: tuple[int, ...]
    start_time: int
    cgroup_device: int
    cgroup_inode: int
    unit_name: str
    invocation_id: str
    selinux_context: bytes
    mcs_pair: str


@dataclass(frozen=True, slots=True, init=False, repr=False)
class _IssuedAttestation(_NonTransferable):
    issuer: object
    attestation: RootSystemBusPeerAttestation
    ownership: RootRuntimeActivityOwnership


class _PeerOperations(Protocol):
    def pidfd_open(self, pid: int) -> int: ...
    def require_alive(self, pidfd: int) -> None: ...
    def open_proc_root(self) -> int: ...
    def open_cgroup_root(self) -> int: ...
    def open_proc_pid(self, proc_root: int, pid: int) -> int: ...
    def read_proc(self, proc_fd: int) -> _ProcObservation: ...
    def open_cgroup(self, cgroup_root: int, path: str) -> int: ...
    def cgroup_identity(self, cgroup_fd: int) -> tuple[int, int]: ...
    def read_unit(self, pidfd: int) -> _UnitObservation: ...
    def read_enforcing(self) -> bool: ...
    def read_self_label(self, proc_root: int) -> bytes: ...
    def close(self, fd: int) -> None: ...


class _OpenHow(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    )


_LIBC = ctypes.CDLL(None, use_errno=True)
_OPENAT2 = _LIBC.openat2
_OPENAT2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(_OpenHow),
    ctypes.c_size_t,
)
_OPENAT2.restype = ctypes.c_int


def _fail(code: str) -> None:
    raise RootSystemBusError(code) from None


def _openat2(parent_fd: int, name: str, flags: int) -> int:
    if (
        type(parent_fd) is not int
        or type(name) is not str
        or not name
        or name.startswith("/")
        or "\x00" in name
    ):
        _fail("path_binding_invalid")
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_CHPB_MESSAGE_BYTES:
        _fail("path_binding_invalid")
    how = _OpenHow(flags, 0, _RESOLVE)
    fd = _OPENAT2(parent_fd, encoded, ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        _fail("path_binding_invalid")
    return fd


def _read_bounded(fd: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(fd, min(4096, MAX_CHPB_MESSAGE_BYTES + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_CHPB_MESSAGE_BYTES:
            _fail("observation_too_large")


def _read_at(parent_fd: int, name: str) -> bytes:
    fd = _openat2(parent_fd, name, _FILE_FLAGS)
    try:
        return _read_bounded(fd)
    finally:
        os.close(fd)


def _strict_text(value: object, code: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        _fail(code)
    if len(value.encode("utf-8")) > MAX_CHPB_MESSAGE_BYTES:
        _fail(code)
    return value


def _canonical_cgroup(value: object) -> str:
    text = _strict_text(value, "cgroup_binding_invalid")
    if not text.startswith("/") or "//" in text:
        _fail("cgroup_binding_invalid")
    if any(part in {".", ".."} for part in text.split("/")):
        _fail("cgroup_binding_invalid")
    return text


def _validate_credentials(value: object) -> _BusCredentials:
    if type(value) is not dbus.Dictionary:
        _fail("credentials_invalid")
    try:
        pid = value["ProcessID"]
        uid = value["UnixUserID"]
        groups_value = value["UnixGroupIDs"]
        label_value = value["LinuxSecurityLabel"]
    except (KeyError, TypeError):
        _fail("credentials_invalid")
    if type(pid) is not dbus.UInt32 or not 1 <= int(pid) <= _UINT32_MAX:
        _fail("credentials_invalid")
    if type(uid) is not dbus.UInt32 or not 0 <= int(uid) <= _UINT32_MAX:
        _fail("credentials_invalid")
    if (
        type(groups_value) is not dbus.Array
        or str(groups_value.signature) != "u"
        or not 1 <= len(groups_value) <= MAX_CHPB_OBJECT_FIELDS
        or any(type(group) is not dbus.UInt32 for group in groups_value)
    ):
        _fail("credentials_invalid")
    groups = tuple(int(group) for group in groups_value)
    if len(groups) != len(set(groups)):
        _fail("credentials_invalid")
    if type(label_value) is not dbus.Array or str(label_value.signature) != "y":
        _fail("credentials_invalid")
    label = bytes(label_value)
    if (
        not 2 <= len(label) <= MAX_CHPB_MESSAGE_BYTES
        or not label.endswith(b"\0")
        or b"\0" in label[:-1]
    ):
        _fail("credentials_invalid")
    return _BusCredentials(int(pid), int(uid), groups, label[:-1])


def _read_credentials(sender: str, reader: Callable[[str], object]) -> _BusCredentials:
    if (
        type(sender) not in (str, dbus.String)
        or not str(sender).startswith(":")
        or len(str(sender).encode("utf-8")) > MAX_CHPB_MESSAGE_BYTES
    ):
        _fail("sender_invalid")
    try:
        return _validate_credentials(reader(str(sender)))
    except RootSystemBusError:
        raise
    except Exception:
        _fail("credentials_unavailable")


_SELINUX_PART = re.compile(rb"[A-Za-z0-9_.-]+\Z")
_SELINUX_RANGE = re.compile(rb"s0:c(0|[1-9][0-9]{0,3}),c(0|[1-9][0-9]{0,3})\Z")


def _selinux_context(value: bytes, *, peer: bool) -> tuple[str, str]:
    if type(value) is not bytes or not value or len(value) > MAX_CHPB_MESSAGE_BYTES:
        _fail("selinux_peer_invalid" if peer else "selinux_gateway_invalid")
    parts = value.split(b":", 3)
    code = "selinux_peer_invalid" if peer else "selinux_gateway_invalid"
    if len(parts) != 4 or any(
        _SELINUX_PART.fullmatch(part) is None for part in parts[:3]
    ):
        _fail(code)
    domain = parts[2].decode("ascii")
    if not peer:
        if parts[3] != b"s0":
            _fail(code)
        return domain, ""
    match = _SELINUX_RANGE.fullmatch(parts[3])
    if match is None:
        _fail(code)
    low, high = int(match[1]), int(match[2])
    if not 0 <= low < high <= MAX_CHPB_MCS_CATEGORY:
        _fail(code)
    if peer and (domain == "unconfined_t" or "permissive" in domain):
        _fail(code)
    return domain, f"c{low},c{high}"


def _validate_proc(value: object) -> _ProcObservation:
    if type(value) is not _ProcObservation:
        _fail("proc_binding_invalid")
    if (
        type(value.start_time) is not int
        or not 1 <= value.start_time <= MAX_CHPB_GENERATION
        or type(value.effective_gid) is not int
        or not 0 <= value.effective_gid <= _UINT32_MAX
        or type(value.security_label) is not bytes
    ):
        _fail("proc_binding_invalid")
    _canonical_cgroup(value.cgroup_path)
    return value


def _validate_unit(value: object) -> _UnitObservation:
    if type(value) is not _UnitObservation:
        _fail("unit_binding_invalid")
    path = _strict_text(value.object_path, "unit_binding_invalid")
    name = _strict_text(value.name, "unit_binding_invalid")
    if (
        not path.startswith("/org/freedesktop/systemd1/unit/")
        or "/" in name
        or type(value.invocation_id) is not bytes
        or len(value.invocation_id) != 16
    ):
        _fail("unit_binding_invalid")
    _canonical_cgroup(value.control_group)
    return value


def _attest_peer(
    sender: str,
    credential_reader: Callable[[str], object],
    operations: _PeerOperations,
    release: BrokerReleaseSpec,
) -> _PeerObservation:
    try:
        _validate_release_spec(release)
    except Exception:
        _fail("release_invalid")
    first = _read_credentials(sender, credential_reader)
    opened: list[int] = []

    def take(fd: int) -> int:
        if type(fd) is not int or fd < 0:
            _fail("fd_invalid")
        opened.append(fd)
        return fd

    try:
        pidfd = take(operations.pidfd_open(first.pid))
        operations.require_alive(pidfd)
        second = _read_credentials(sender, credential_reader)
        if second != first:
            _fail("credential_drift")
        operations.require_alive(pidfd)
        proc_root = take(operations.open_proc_root())
        cgroup_root = take(operations.open_cgroup_root())
        proc_fd = take(operations.open_proc_pid(proc_root, first.pid))
        operations.require_alive(pidfd)
        proc_before = _validate_proc(operations.read_proc(proc_fd))
        operations.require_alive(pidfd)
        if proc_before.effective_gid not in first.groups:
            _fail("credentials_invalid")
        cgroup_fd = take(operations.open_cgroup(cgroup_root, proc_before.cgroup_path))
        cgroup_before = operations.cgroup_identity(cgroup_fd)
        operations.require_alive(pidfd)
        unit_before = _validate_unit(operations.read_unit(pidfd))
        operations.require_alive(pidfd)
        if unit_before.control_group != proc_before.cgroup_path:
            _fail("cgroup_binding_drift")
        operations.require_alive(pidfd)
        if not operations.read_enforcing():
            _fail("selinux_not_enforcing")
        own_label = operations.read_self_label(proc_root)
        operations.require_alive(pidfd)
        operations.require_alive(pidfd)
        proc_after = _validate_proc(operations.read_proc(proc_fd))
        cgroup_after = operations.cgroup_identity(cgroup_fd)
        operations.require_alive(pidfd)
        operations.require_alive(pidfd)
        unit_after = _validate_unit(operations.read_unit(pidfd))
        operations.require_alive(pidfd)
        third = _read_credentials(sender, credential_reader)
        operations.require_alive(pidfd)
        if third != first:
            _fail("credential_drift")
        if proc_after.start_time != proc_before.start_time:
            _fail("pid_identity_drift")
        if (
            proc_after.effective_gid != proc_before.effective_gid
            or proc_after.effective_gid not in first.groups
        ):
            _fail("credential_drift")
        if proc_after.security_label != proc_before.security_label:
            _fail("security_label_drift")
        if proc_after.cgroup_path != proc_before.cgroup_path:
            _fail("cgroup_binding_drift")
        if cgroup_after != cgroup_before:
            _fail("cgroup_binding_drift")
        if unit_after != unit_before:
            _fail("unit_binding_drift")
        if unit_after.control_group != proc_after.cgroup_path:
            _fail("cgroup_binding_drift")
        if proc_before.security_label != first.security_label:
            _fail("security_label_drift")
        if (
            type(cgroup_before) is not tuple
            or len(cgroup_before) != 2
            or type(cgroup_before[0]) is not int
            or type(cgroup_before[1]) is not int
            or not 0 <= cgroup_before[0] <= MAX_CHPB_DEVICE
            or not 1 <= cgroup_before[1] <= MAX_CHPB_INODE
        ):
            _fail("cgroup_binding_invalid")
        own_domain, _own_mcs = _selinux_context(own_label, peer=False)
        if own_domain != release.gateway_domain:
            _fail("selinux_gateway_invalid")
        _peer_domain, mcs = _selinux_context(first.security_label, peer=True)
        return _PeerObservation(
            first.pid,
            first.uid,
            proc_before.effective_gid,
            first.groups,
            proc_before.start_time,
            cgroup_before[0],
            cgroup_before[1],
            unit_before.name,
            unit_before.invocation_id.hex(),
            first.security_label,
            mcs,
        )
    except RootSystemBusError:
        raise
    except Exception:
        _fail("peer_attestation_failed")
    finally:
        cleanup_failed = False
        while opened:
            fd = opened.pop()
            try:
                operations.close(fd)
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            _fail("peer_cleanup_failed")


def _parse_stat(value: bytes) -> int:
    close = value.rfind(b") ")
    open_at = value.find(b" (")
    if open_at <= 0 or close <= open_at:
        _fail("proc_binding_invalid")
    fields = value[close + 2 :].split()
    try:
        start = int(fields[19])
    except (IndexError, ValueError):
        _fail("proc_binding_invalid")
    if not 1 <= start <= MAX_CHPB_GENERATION:
        _fail("proc_binding_invalid")
    return start


def _parse_status(value: bytes) -> int:
    lines = [line for line in value.splitlines() if line.startswith(b"Gid:")]
    if len(lines) != 1:
        _fail("proc_binding_invalid")
    fields = lines[0].split()
    try:
        effective = int(fields[2])
    except (IndexError, ValueError):
        _fail("proc_binding_invalid")
    if not 0 <= effective <= _UINT32_MAX:
        _fail("proc_binding_invalid")
    return effective


def _parse_cgroup(value: bytes) -> str:
    lines = [line for line in value.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith(b"0::"):
        _fail("cgroup_binding_invalid")
    try:
        return _canonical_cgroup(lines[0][3:].decode("utf-8"))
    except UnicodeDecodeError:
        _fail("cgroup_binding_invalid")


class _LinuxPeerOperations:
    """Concrete pidfd/proc/cgroup/systemd/SELinux observations."""

    __slots__ = ("_manager", "_system_bus")

    def __init__(self, system_bus: dbus.bus.BusConnection) -> None:
        self._system_bus = system_bus
        self._manager = dbus.Interface(
            system_bus.get_object(_SYSTEMD_NAME, _SYSTEMD_PATH),
            _SYSTEMD_MANAGER,
        )

    def pidfd_open(self, pid: int) -> int:
        try:
            return os.pidfd_open(pid, 0)
        except OSError:
            _fail("peer_exited")

    def require_alive(self, pidfd: int) -> None:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            _fail("peer_exited")

    def open_proc_root(self) -> int:
        try:
            return os.open("/proc", _DIRECTORY_FLAGS)
        except OSError:
            _fail("proc_binding_invalid")

    def open_cgroup_root(self) -> int:
        try:
            return os.open("/sys/fs/cgroup", _DIRECTORY_FLAGS)
        except OSError:
            _fail("cgroup_binding_invalid")

    def open_proc_pid(self, proc_root: int, pid: int) -> int:
        return _openat2(proc_root, str(pid), _DIRECTORY_FLAGS)

    def read_proc(self, proc_fd: int) -> _ProcObservation:
        stat = _read_at(proc_fd, "stat")
        status = _read_at(proc_fd, "status")
        cgroup = _read_at(proc_fd, "cgroup")
        label = _read_at(proc_fd, "attr/current").rstrip(b"\0\n")
        return _ProcObservation(
            _parse_stat(stat),
            _parse_status(status),
            _parse_cgroup(cgroup),
            label,
        )

    def open_cgroup(self, cgroup_root: int, path: str) -> int:
        canonical = _canonical_cgroup(path)
        return _openat2(
            cgroup_root,
            canonical.removeprefix("/") or ".",
            _DIRECTORY_FLAGS,
        )

    def cgroup_identity(self, cgroup_fd: int) -> tuple[int, int]:
        try:
            stat_result = os.fstat(cgroup_fd)
        except OSError:
            _fail("cgroup_binding_invalid")
        return stat_result.st_dev, stat_result.st_ino

    def read_unit(self, pidfd: int) -> _UnitObservation:
        try:
            object_path, name, invocation = self._manager.GetUnitByPIDFD(
                dbus.types.UnixFd(pidfd)
            )
            properties = dbus.Interface(
                self._system_bus.get_object(_SYSTEMD_NAME, object_path),
                _PROPERTIES,
            )
            control_group = properties.Get(_UNIT_INTERFACE, "ControlGroup")
        except dbus.DBusException:
            _fail("unit_binding_invalid")
        if (
            type(object_path) is not dbus.ObjectPath
            or type(name) is not dbus.String
            or type(control_group) is not dbus.String
        ):
            _fail("unit_binding_invalid")
        if type(invocation) is dbus.ByteArray:
            invocation_bytes = bytes(invocation)
        elif type(invocation) is dbus.Array and str(invocation.signature) == "y":
            invocation_bytes = bytes(invocation)
        else:
            _fail("unit_binding_invalid")
        if len(invocation_bytes) != 16:
            _fail("unit_binding_invalid")
        return _UnitObservation(
            str(object_path),
            str(name),
            invocation_bytes,
            str(control_group),
        )

    def read_enforcing(self) -> bool:
        try:
            root = os.open("/sys/fs/selinux", _DIRECTORY_FLAGS)
        except OSError:
            _fail("selinux_not_enforcing")
        try:
            return _read_at(root, "enforce") == b"1"
        finally:
            os.close(root)

    def read_self_label(self, proc_root: int) -> bytes:
        own = _openat2(proc_root, str(os.getpid()), _DIRECTORY_FLAGS)
        try:
            return _read_at(own, "attr/current").rstrip(b"\0\n")
        finally:
            os.close(own)

    def close(self, fd: int) -> None:
        os.close(fd)


def _issue_attestation(
    sender: str, evidence: _PeerObservation, generation: int
) -> RootSystemBusPeerAttestation:
    attestation = object.__new__(RootSystemBusPeerAttestation)
    values = (
        ("bus_unique_name", str(sender)),
        ("pid", evidence.pid),
        ("uid", evidence.uid),
        ("effective_gid", evidence.effective_gid),
        ("groups", evidence.groups),
        ("start_time", evidence.start_time),
        ("cgroup_device", evidence.cgroup_device),
        ("cgroup_inode", evidence.cgroup_inode),
        ("unit_name", evidence.unit_name),
        ("invocation_id", evidence.invocation_id),
        ("selinux_context", evidence.selinux_context),
        ("mcs_pair", evidence.mcs_pair),
        ("service_generation", generation),
    )
    for field, value in values:
        object.__setattr__(attestation, field, value)
    return attestation


class HomeBrokerControlService(dbus.service.Object):
    """Canonical synchronous system-bus admission service."""

    __slots__ = (
        "_active",
        "_bus",
        "_closed",
        "_consumer",
        "_credential_reader",
        "_generation",
        "_host",
        "_issuance_lock",
        "_issued",
        "_loop",
        "_name",
        "_operations",
        "_release",
        "_signal",
        "_system_bus",
    )

    def __init__(
        self,
        host: FleetRootRuntimeHost,
        generation: int,
        release: BrokerReleaseSpec,
        consumer: Callable[
            [RootSystemBusPeerAttestation, RootRuntimeActivityOwnership], object
        ],
        *,
        private_bus_address: str | None = None,
        _operations: _PeerOperations | None = None,
        _credential_reader: Callable[[str], object] | None = None,
    ) -> None:
        if (
            type(host) is not FleetRootRuntimeHost
            or type(generation) is not int
            or not 1 <= generation <= MAX_CHPB_GENERATION
            or not callable(consumer)
        ):
            _fail("service_configuration_invalid")
        try:
            _validate_release_spec(release)
        except Exception:
            _fail("service_configuration_invalid")
        if (
            release.system_bus_name != BUS_NAME
            or release.system_bus_path != BUS_PATH
            or release.system_bus_interface != BUS_INTERFACE
        ):
            _fail("service_configuration_invalid")
        mainloop = DBusGMainLoop()
        self._system_bus = None
        try:
            if private_bus_address is None:
                bus = dbus.SystemBus(private=True, mainloop=mainloop)
            else:
                bus = dbus.bus.BusConnection(private_bus_address, mainloop=mainloop)
            name = dbus.service.BusName(
                BUS_NAME,
                bus=bus,
                allow_replacement=False,
                replace_existing=False,
                do_not_queue=True,
            )
        except dbus.DBusException:
            try:
                bus.close()
            except Exception:
                pass
            _fail("name_unavailable")
        self._bus = bus
        self._name = name
        self._host = host
        self._generation = generation
        self._release = release
        self._consumer = consumer
        self._issuance_lock = Lock()
        self._issued: _IssuedAttestation | None = None
        self._loop = GLib.MainLoop()
        self._active = True
        self._closed = False
        daemon = dbus.Interface(bus.get_object(_DBUS_NAME, _DBUS_PATH), _DBUS_INTERFACE)
        self._credential_reader = (
            _credential_reader
            if _credential_reader is not None
            else daemon.GetConnectionCredentials
        )
        if _operations is None:
            self._system_bus = dbus.SystemBus(private=True)
            self._operations = _LinuxPeerOperations(self._system_bus)
        else:
            self._operations = _operations
        super().__init__(bus_name=name, object_path=BUS_PATH)
        self._signal = bus.add_signal_receiver(
            self._name_owner_changed,
            signal_name="NameOwnerChanged",
            dbus_interface=_DBUS_INTERFACE,
            bus_name=_DBUS_NAME,
            path=_DBUS_PATH,
            arg0=BUS_NAME,
        )

    def run(self) -> None:
        if not self._active:
            _fail("service_stale")
        self._loop.run()

    def _name_owner_changed(self, _name, old_owner, new_owner) -> None:
        if str(old_owner) == self._bus.get_unique_name() and not str(new_owner):
            self._lose_participant()

    def _lose_participant(self) -> None:
        if not self._active:
            return
        self._active = False
        self._clear_issuance()
        try:
            self._host.mark_participant_lost(
                RootHostParticipantBinding(
                    RootHostParticipant.SYSTEM_BUS_ADMISSION,
                    self._generation,
                )
            )
        except FleetRootRuntimeHostError:
            pass

    def close(self) -> None:
        if self._closed:
            self._loop.quit()
            return
        self._closed = True
        if self._active:
            self._lose_participant()
        try:
            self._signal.remove()
        except Exception:
            pass
        try:
            self.remove_from_connection()
        except Exception:
            pass
        try:
            self._bus.release_name(BUS_NAME)
        except Exception:
            pass
        self._name = None
        self._loop.quit()
        try:
            self._bus.close()
        except Exception:
            pass
        if self._system_bus is not None:
            try:
                self._system_bus.close()
            except Exception:
                pass

    def _handoff(
        self,
        attestation: RootSystemBusPeerAttestation,
        ownership: RootRuntimeActivityOwnership,
        issued: object,
    ) -> None:
        with self._issuance_lock:
            pending = self._issued
            self._issued = None
            valid = (
                type(attestation) is RootSystemBusPeerAttestation
                and type(ownership) is RootRuntimeActivityOwnership
                and type(issued) is _IssuedAttestation
                and pending is issued
                and issued.issuer is self
                and issued.attestation is attestation
                and issued.ownership is ownership
            )
        if not valid:
            _fail("handoff_invalid")
        try:
            result = self._consumer(attestation, ownership)
        except Exception:
            _fail("consumer_failed")
        if result is not None:
            _fail("consumer_failed")

    def _issue_handoff(
        self,
        sender: str,
        evidence: _PeerObservation,
        ownership: RootRuntimeActivityOwnership,
    ) -> tuple[RootSystemBusPeerAttestation, _IssuedAttestation]:
        attestation = _issue_attestation(sender, evidence, self._generation)
        issued = object.__new__(_IssuedAttestation)
        object.__setattr__(issued, "issuer", self)
        object.__setattr__(issued, "attestation", attestation)
        object.__setattr__(issued, "ownership", ownership)
        with self._issuance_lock:
            if not self._active or self._closed or self._issued is not None:
                _fail("handoff_invalid")
            self._issued = issued
        return attestation, issued

    def _clear_issuance(
        self, ownership: RootRuntimeActivityOwnership | None = None
    ) -> None:
        with self._issuance_lock:
            if (
                ownership is None
                or self._issued is not None
                and self._issued.ownership is ownership
            ):
                self._issued = None

    def _handle_start(self, sender: str) -> None:
        if not self._active:
            _fail("service_stale")
        state = self._host.snapshot()
        if not state.reconciled or state.participant_generation != self._generation:
            _fail("host_unavailable")
        try:
            ownership = self._host.begin_principal_or_agent()
        except FleetRootRuntimeHostError as exc:
            if exc.code == "admission_stopped":
                _fail("admission_stopped")
            _fail("host_unavailable")
        transferred = False
        try:
            evidence = _attest_peer(
                sender,
                self._credential_reader,
                self._operations,
                self._release,
            )
            attestation, issued = self._issue_handoff(sender, evidence, ownership)
            self._handoff(attestation, ownership, issued)
            transferred = True
        finally:
            if not transferred:
                self._clear_issuance(ownership)
                try:
                    self._host.end_principal_or_agent(ownership)
                except FleetRootRuntimeHostError:
                    pass

    @dbus.service.method(
        BUS_INTERFACE,
        in_signature="",
        out_signature="",
        sender_keyword="sender",
        message_keyword="_message",
    )
    def StartDynamicTeamlead(
        self, sender: str | None = None, _message: object | None = None
    ) -> None:
        if (
            sender is None
            or _message is None
            or _message.get_signature()
            or _message.get_args_list()
        ):
            _fail("sender_invalid")
        self._handle_start(sender)


__all__ = (
    "BUS_INTERFACE",
    "BUS_METHOD",
    "BUS_NAME",
    "BUS_PATH",
    "HomeBrokerControlService",
    "RootSystemBusError",
    "RootSystemBusPeerAttestation",
)
