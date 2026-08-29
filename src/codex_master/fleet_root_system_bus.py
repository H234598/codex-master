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

import codex_master.fleet_home_broker_runtime as broker_runtime
from codex_master.dynamic_teamlead import (
    DynamicTeamleadRequest,
    ProfileBinding,
    require_committed_home_attestation,
)
from codex_master.dynamic_teamlead_a3_runner import (
    DynamicTeamleadRunnerOperations,
    RootDynamicTeamleadRunnerBindingEvidence,
    RootDynamicTeamleadRunnerPermit,
    RootDynamicTeamleadStartComposition,
)
from codex_master.dynamic_teamlead_a3_registry import FleetV2RegistryOperations
from codex_master.dynamic_teamlead_a3_runtime_provider import (
    DynamicTeamleadA3RuntimeContext,
    build_root_owned_dynamic_teamlead_start_port,
    validate_dynamic_teamlead_a3_runtime_context,
)
from codex_master.dynamic_teamlead_start import dynamic_teamlead_start
from codex_master.fleet_home_broker_client import AttestedHome
from codex_master.fleet_home_broker_client_seqpacket import (
    SeqpacketBrokerClientOperations,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_system import (
    BrokerStartReceipt,
    BrokerSystemBoundary,
    BrokerSystemError,
    build_broker_system_plan,
)
from codex_master.fleet_home_broker_protocol import (
    BindingExpectation,
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    MAX_CHPB_MCS_CATEGORY,
    MAX_CHPB_MESSAGE_BYTES,
    MAX_CHPB_OBJECT_FIELDS,
    PrincipalBinding,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    CredentialProjectionProvider,
    KernelPeerEvidence,
    RuntimePrincipalResolver,
    TrustedPrincipalGrantContext,
    _validate_release_spec,
)
from codex_master.fleet_home_broker_transport import BrokerPeer
from codex_master.fleet_registry import FleetRuntimePrincipalV2, FleetSnapshotV2
from codex_master.fleet_root_runtime_host import (
    FleetRootRuntimeHost,
    FleetRootRuntimeHostError,
    RootHostParticipant,
    RootHostParticipantBinding,
    RootRuntimeActivityOwnership,
)
from codex_master.fleet_runners import DynamicTeamleadRunnerPlan


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
    sender: str
    attestation: RootSystemBusPeerAttestation
    ownership: RootRuntimeActivityOwnership


@dataclass(frozen=True, slots=True)
class _ActiveStart:
    receipt: BrokerStartReceipt
    ownership: RootRuntimeActivityOwnership
    attestation: RootSystemBusPeerAttestation


@dataclass(frozen=True, slots=True)
class _DynamicTeamleadRunnerBinding:
    runtime_principal: tuple[object, ...]
    expected_principal: tuple[object, ...]
    expectation: tuple[object, ...]
    identity: tuple[object, ...]
    selection: tuple[object, ...]
    profile_binding: tuple[object, ...]
    snapshot_generation: int
    release: tuple[object, ...]
    root_generation: int
    receipt: tuple[object, ...]
    ownership: tuple[int, int]


@dataclass(slots=True)
class _DynamicTeamleadRunnerRecord:
    permit: RootDynamicTeamleadRunnerPermit
    reference: object
    executor: object
    evidence: RootDynamicTeamleadRunnerBindingEvidence
    operations: DynamicTeamleadRunnerOperations
    active: _ActiveStart
    binding: _DynamicTeamleadRunnerBinding
    composition: RootDynamicTeamleadStartComposition | None = None
    terminal: bool = False


class _ConsumerDynamicTeamleadRunnerExecutor:
    __slots__ = ("_binding_evidence", "_consumer", "_permit", "_operations")

    def __init__(self) -> None:
        raise TypeError("root_dynamic_teamlead_runner_executor_factory_required")

    def execute_dynamic_teamlead_runner(
        self, plan: DynamicTeamleadRunnerPlan
    ) -> None:
        try:
            consumer = self._consumer
        except AttributeError:
            _fail("dynamic_teamlead_runner_permit_invalid")
        if type(consumer) is not TrustedPrincipalGrantConsumer:
            _fail("dynamic_teamlead_runner_permit_invalid")
        consumer._execute_issued_dynamic_teamlead_runner(self, plan)

    @property
    def binding_evidence(self) -> RootDynamicTeamleadRunnerBindingEvidence:
        try:
            return self._binding_evidence
        except AttributeError:
            _fail("dynamic_teamlead_runner_permit_invalid")


def _unavailable_dynamic_teamlead_result() -> dict[str, int | str]:
    return {
        "schema_version": 1,
        "status": "unavailable",
        "reason": "dynamic_teamlead_runtime_unavailable",
        "raw_output": "not_returned",
    }


def _normalize_dynamic_teamlead_result(value: object) -> dict[str, int | str]:
    if type(value) is not dict:
        return _unavailable_dynamic_teamlead_result()
    if any(type(key) is not str for key in value):
        return _unavailable_dynamic_teamlead_result()
    if type(value.get("schema_version")) is not int:
        return _unavailable_dynamic_teamlead_result()
    if (
        value["schema_version"] != 1
        or type(value.get("status")) is not str
        or type(value.get("raw_output")) is not str
    ):
        return _unavailable_dynamic_teamlead_result()
    if value["status"] == "started":
        if set(value) != {"schema_version", "status", "raw_output"}:
            return _unavailable_dynamic_teamlead_result()
    elif value["status"] == "unavailable":
        if set(value) != {
            "schema_version",
            "status",
            "reason",
            "raw_output",
        }:
            return _unavailable_dynamic_teamlead_result()
        if (
            type(value.get("reason")) is not str
            or value.get("reason") != "dynamic_teamlead_runtime_unavailable"
        ):
            return _unavailable_dynamic_teamlead_result()
    else:
        return _unavailable_dynamic_teamlead_result()
    if value.get("raw_output") != "not_returned":
        return _unavailable_dynamic_teamlead_result()
    if value["status"] == "started":
        return {
            "schema_version": 1,
            "status": "started",
            "raw_output": "not_returned",
        }
    return _unavailable_dynamic_teamlead_result()


_CONTROL2_UNAVAILABLE_REASON = "dynamic_teamlead_runtime_unavailable"


def _started_dynamic_teamlead_control2_result() -> tuple[int, str, str]:
    return (2, "started", "none")


def _unavailable_dynamic_teamlead_control2_result() -> tuple[int, str, str]:
    return (2, "unavailable", _CONTROL2_UNAVAILABLE_REASON)


class _RootDynamicTeamleadStartControl(_NonTransferable):
    __slots__ = (
        "_consumer",
        "_context",
        "_registry_operations",
        "_broker_operations",
        "_operations",
        "_used",
        "_lock",
    )

    def __init__(
        self,
        consumer: TrustedPrincipalGrantConsumer,
        context: DynamicTeamleadA3RuntimeContext,
        registry_operations: FleetV2RegistryOperations,
        broker_operations: SeqpacketBrokerClientOperations,
        operations: DynamicTeamleadRunnerOperations,
    ) -> None:
        self._consumer = consumer
        self._context = context
        self._registry_operations = registry_operations
        self._broker_operations = broker_operations
        self._operations = operations
        self._used = False
        self._lock = Lock()

    def start_dynamic_teamlead(self) -> dict[str, int | str]:
        with self._lock:
            if self._used:
                return _unavailable_dynamic_teamlead_result()
            self._used = True
            consumer = self._consumer
            context = self._context
            registry_operations = self._registry_operations
            broker_operations = self._broker_operations
            operations = self._operations
            self._consumer = None
            self._context = None
            self._registry_operations = None
            self._broker_operations = None
            self._operations = None
        try:
            if type(consumer) is not TrustedPrincipalGrantConsumer:
                raise ValueError
            service = consumer._bound_service
            if (
                type(service) is not HomeBrokerControlService
                or consumer._closed is not False
                or service._active is not True
                or service._closed is not False
                or service._consumer is not consumer
            ):
                raise ValueError
            active = consumer._active_start
            if (
                type(active) is not _ActiveStart
                or type(active.receipt) is not BrokerStartReceipt
                or type(active.ownership) is not RootRuntimeActivityOwnership
                or active.receipt.ownership is not active.ownership
                or type(active.attestation) is not RootSystemBusPeerAttestation
                or active.attestation.service_generation != service._generation
            ):
                raise ValueError
            state = service._host.snapshot()
            if (
                state.reconciled is not True
                or state.participant_generation != service._generation
                or state.host_generation != active.ownership.host_generation
                or state.active_principals_or_agents < 1
            ):
                raise ValueError
            with consumer._boundary._lock:
                receipt_record = consumer._boundary._receipts.get(id(active.receipt))
                if (
                    receipt_record is None
                    or receipt_record.receipt is not active.receipt
                    or receipt_record.terminal
                ):
                    raise ValueError
            if (
                active.receipt.release_id != service._release.release_id
                or active.receipt.socket_unit != service._release.socket_unit
            ):
                raise ValueError
            if type(context) is not DynamicTeamleadA3RuntimeContext:
                raise ValueError
            if (
                validate_dynamic_teamlead_a3_runtime_context(context) is not context
                or context.context is not consumer._context
                or context.release is not service._release
                or type(registry_operations) is not FleetV2RegistryOperations
                or registry_operations._snapshot is not context.context.snapshot
                or type(broker_operations) is not SeqpacketBrokerClientOperations
                or broker_operations.a3_context_identity is not context
                or broker_operations.release_identity is not service._release
                or not callable(operations.execute)
            ):
                raise ValueError
            with consumer._runner_lock:
                if any(
                    record.active is active
                    for record in consumer._runner_records.values()
                ):
                    raise ValueError
            composition = (
                consumer.issue_root_owned_dynamic_teamlead_start_composition(
                    context,
                    registry_operations,
                    broker_operations,
                    operations,
                )
            )
            port = build_root_owned_dynamic_teamlead_start_port(composition)
            return _normalize_dynamic_teamlead_result(dynamic_teamlead_start(port))
        except BaseException:
            return _unavailable_dynamic_teamlead_result()

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


class TrustedPrincipalGrantConsumer:
    """Trusted follow-up consumer for one authenticated system-bus handoff."""

    __slots__ = (
        "_bound_service",
        "_closed",
        "_context",
        "_credential_bus",
        "_credential_reader",
        "_operations",
        "_principal_resolver",
        "_projection_provider",
        "_boundary",
        "_active_start",
        "_runner_lock",
        "_runner_records",
        "_system_bus",
    )

    def __init__(
        self,
        context: TrustedPrincipalGrantContext,
        principal_resolver: RuntimePrincipalResolver,
        projection_provider: CredentialProjectionProvider,
        boundary: BrokerSystemBoundary,
        *,
        private_bus_address: str | None = None,
        _operations: _PeerOperations | None = None,
        _credential_reader: Callable[[str], object] | None = None,
    ) -> None:
        if (
            type(context) is not TrustedPrincipalGrantContext
            or type(boundary) is not BrokerSystemBoundary
        ):
            _fail("trusted_consumer_configuration_invalid")
        credential_bus = None
        system_bus = None
        try:
            if _credential_reader is None:
                credential_bus = (
                    dbus.SystemBus(private=True)
                    if private_bus_address is None
                    else dbus.bus.BusConnection(private_bus_address)
                )
                daemon = dbus.Interface(
                    credential_bus.get_object(_DBUS_NAME, _DBUS_PATH),
                    _DBUS_INTERFACE,
                )
                credential_reader = daemon.GetConnectionCredentials
            else:
                credential_reader = _credential_reader
            if _operations is None:
                system_bus = dbus.SystemBus(private=True)
                operations = _LinuxPeerOperations(system_bus)
            else:
                operations = _operations
        except Exception:
            for bus in (system_bus, credential_bus):
                if bus is not None:
                    try:
                        bus.close()
                    except Exception:
                        pass
            _fail("trusted_consumer_configuration_invalid")
        self._context = context
        self._principal_resolver = principal_resolver
        self._projection_provider = projection_provider
        self._boundary = boundary
        self._active_start: _ActiveStart | None = None
        self._runner_lock = Lock()
        self._runner_records: dict[int, _DynamicTeamleadRunnerRecord] = {}
        self._credential_bus = credential_bus
        self._system_bus = system_bus
        self._credential_reader = credential_reader
        self._operations = operations
        self._bound_service: HomeBrokerControlService | None = None
        self._closed = False

    def _bind_service(self, service: HomeBrokerControlService) -> None:
        if (
            self._closed
            or self._bound_service is not None
            or type(service) is not HomeBrokerControlService
        ):
            _fail("trusted_consumer_configuration_invalid")
        self._bound_service = service

    def _ensure_start_available(self, service: HomeBrokerControlService) -> None:
        with self._runner_lock:
            if (
                self._closed
                or service is not self._bound_service
                or self._active_start is not None
            ):
                _fail("trusted_consumer_start_active")

    def _reattest(
        self,
        service: HomeBrokerControlService,
        attestation: RootSystemBusPeerAttestation,
    ) -> KernelPeerEvidence:
        if (
            self._closed
            or service is not self._bound_service
            or type(attestation) is not RootSystemBusPeerAttestation
            or attestation.service_generation != service._generation
        ):
            _fail("trusted_consumer_attestation_invalid")
        observed = _attest_peer(
            attestation.bus_unique_name,
            self._credential_reader,
            self._operations,
            service._release,
        )
        if (
            observed.pid != attestation.pid
            or observed.uid != attestation.uid
            or observed.effective_gid != attestation.effective_gid
            or observed.groups != attestation.groups
            or observed.start_time != attestation.start_time
            or observed.cgroup_device != attestation.cgroup_device
            or observed.cgroup_inode != attestation.cgroup_inode
            or observed.unit_name != attestation.unit_name
            or observed.invocation_id != attestation.invocation_id
            or observed.selinux_context != attestation.selinux_context
            or observed.mcs_pair != attestation.mcs_pair
        ):
            _fail("trusted_consumer_attestation_drifted")
        return KernelPeerEvidence(
            observed.pid,
            observed.uid,
            observed.effective_gid,
            observed.start_time,
            observed.cgroup_device,
            observed.cgroup_inode,
            service._generation,
            observed.invocation_id,
            observed.mcs_pair,
        )

    def _dynamic_teamlead_runner_binding(
        self,
        service: HomeBrokerControlService,
        active: _ActiveStart,
    ) -> _DynamicTeamleadRunnerBinding:
        try:
            context = self._context
            snapshot = context.snapshot
            selection = context.selection
            profile_binding = context.profile_binding
            expected = context.expected_principal
            identity = context.identity
            release = service._release
            receipt = active.receipt
            ownership = active.ownership
            state = service._host.snapshot()
            runtime_principals = snapshot.runtime_principals
            if (
                self._closed
                or service is not self._bound_service
                or type(active) is not _ActiveStart
                or active is not self._active_start
                or type(active.attestation) is not RootSystemBusPeerAttestation
                or active.attestation.service_generation != service._generation
                or type(context) is not TrustedPrincipalGrantContext
                or type(snapshot) is not FleetSnapshotV2
                or type(selection) is not DynamicTeamleadRequest
                or type(profile_binding) is not ProfileBinding
                or type(expected) is not PrincipalBinding
                or type(identity) is not BrokerIdentity
                or type(release) is not BrokerReleaseSpec
                or type(receipt) is not BrokerStartReceipt
                or type(ownership) is not RootRuntimeActivityOwnership
                or receipt.ownership is not ownership
                or receipt.release_id != release.release_id
                or receipt.socket_unit != release.socket_unit
                or type(runtime_principals) is not tuple
                or len(runtime_principals) != 1
                or type(runtime_principals[0]) is not FleetRuntimePrincipalV2
                or runtime_principals[0].principal_id != selection.agent_id
                or runtime_principals[0].account_id != selection.account_id
                or runtime_principals[0].profile_id != profile_binding.profile_id
                or runtime_principals[0].credential_binding_id
                != profile_binding.credential_binding_id
                or selection.registry_generation != snapshot.generation
                or selection.agent_id != expected.agent_id
                or runtime_principals[0].principal_id != expected.agent_id
                or identity.agent_id != expected.agent_id
                or identity.manifest_generation != expected.manifest_generation
                or identity.mcs_pair != expected.mcs_pair
                or identity.fencing_epoch != expected.fencing_epoch
                or expected.unit_generation != service._generation
                or state.reconciled is not True
                or state.participant_generation != service._generation
                or state.host_generation != ownership.host_generation
                or state.active_principals_or_agents < 1
            ):
                raise ValueError
            _validate_release_spec(release)
            with self._boundary._lock:
                receipt_record = self._boundary._receipts.get(id(receipt))
                if (
                    receipt_record is None
                    or receipt_record.receipt is not receipt
                    or receipt_record.terminal
                ):
                    raise ValueError
            runtime_principal = runtime_principals[0]
            expectation = (
                expected.agent_id,
                expected.manifest_generation,
                expected.unit_generation,
                identity.policy_generation,
                identity.projection_digest,
                expected.fencing_epoch,
            )
            return _DynamicTeamleadRunnerBinding(
                tuple(
                    getattr(runtime_principal, name)
                    for name in FleetRuntimePrincipalV2.__slots__
                ),
                tuple(getattr(expected, name) for name in PrincipalBinding.__slots__),
                expectation,
                tuple(getattr(identity, name) for name in BrokerIdentity.__slots__),
                tuple(
                    getattr(selection, name) for name in DynamicTeamleadRequest.__slots__
                ),
                tuple(
                    getattr(profile_binding, name) for name in ProfileBinding.__slots__
                ),
                snapshot.generation,
                tuple(getattr(release, name) for name in BrokerReleaseSpec.__slots__),
                state.host_generation,
                (receipt.release_id, receipt.socket_unit),
                (ownership.host_generation, ownership.begin_epoch),
            )
        except RootSystemBusError:
            raise
        except Exception:
            _fail("dynamic_teamlead_runner_permit_invalid")

    def _dynamic_teamlead_runner_plan_matches(
        self,
        plan: object,
        binding: _DynamicTeamleadRunnerBinding,
    ) -> bool:
        try:
            if (
                type(plan) is not DynamicTeamleadRunnerPlan
                or type(binding) is not _DynamicTeamleadRunnerBinding
                or type(plan.runtime_principal) is not FleetRuntimePrincipalV2
                or type(plan.expected_principal) is not PrincipalBinding
                or type(plan.expectation) is not BindingExpectation
                or type(plan.identity) is not BrokerIdentity
                or type(plan.home) is not AttestedHome
                or type(plan.home.fd) is not int
                or plan.home.fd < 0
            ):
                return False
            committed = require_committed_home_attestation(
                plan.home.reply, plan.expectation
            )
            if (
                tuple(
                    getattr(plan.runtime_principal, name)
                    for name in FleetRuntimePrincipalV2.__slots__
                )
                != binding.runtime_principal
                or tuple(
                    getattr(plan.expected_principal, name)
                    for name in PrincipalBinding.__slots__
                )
                != binding.expected_principal
                or tuple(
                    getattr(plan.expectation, name)
                    for name in BindingExpectation.__slots__
                )
                != binding.expectation
                or tuple(
                    getattr(plan.identity, name) for name in BrokerIdentity.__slots__
                )
                != binding.identity
                or committed != plan.home.attestation
                or plan.home.reply.attestation != plan.home.attestation
                or tuple(
                    getattr(committed.binding.principal, name)
                    for name in PrincipalBinding.__slots__
                )
                != binding.expected_principal
                or (
                    committed.binding.policy.policy_generation,
                    committed.binding.policy.projection_digest,
                )
                != (binding.expectation[3], binding.expectation[4])
            ):
                return False
            return True
        except Exception:
            return False

    def _issue_dynamic_teamlead_runner_record(
        self,
        operations: DynamicTeamleadRunnerOperations,
        active: _ActiveStart,
        binding: _DynamicTeamleadRunnerBinding,
    ) -> _DynamicTeamleadRunnerRecord:
        reference = object()
        permit = object.__new__(RootDynamicTeamleadRunnerPermit)
        values = (
            ("opaque_reference", reference),
            ("principal_diagnostic", "<redacted>"),
            ("identity_diagnostic", "<redacted>"),
            ("snapshot_generation", binding.snapshot_generation),
            ("policy_generation", binding.expectation[3]),
            ("release_diagnostic", "<redacted>"),
            ("root_generation", binding.root_generation),
        )
        for name, value in values:
            object.__setattr__(permit, name, value)
        executor = object.__new__(_ConsumerDynamicTeamleadRunnerExecutor)
        object.__setattr__(executor, "_consumer", self)
        object.__setattr__(executor, "_permit", permit)
        object.__setattr__(executor, "_operations", operations)
        evidence = object.__new__(RootDynamicTeamleadRunnerBindingEvidence)
        evidence_values = (
            ("executor_identity", executor),
            ("context_identity", self._context),
            ("snapshot_identity", self._context.snapshot),
            ("release_identity", self._bound_service._release),
        )
        for name, value in evidence_values:
            object.__setattr__(evidence, name, value)
        object.__setattr__(executor, "_binding_evidence", evidence)
        record = _DynamicTeamleadRunnerRecord(
            permit,
            reference,
            executor,
            evidence,
            operations,
            active,
            binding,
        )
        self._runner_records[id(permit)] = record
        return record

    def issue_dynamic_teamlead_runner(
        self,
        operations: DynamicTeamleadRunnerOperations,
    ) -> tuple[
        RootDynamicTeamleadRunnerPermit,
        _ConsumerDynamicTeamleadRunnerExecutor,
    ]:
        try:
            execute = operations.execute
        except Exception:
            _fail("dynamic_teamlead_runner_operations_invalid")
        service = self._bound_service
        active = self._active_start
        if (
            self._closed
            or type(service) is not HomeBrokerControlService
            or type(active) is not _ActiveStart
            or not callable(execute)
        ):
            _fail("dynamic_teamlead_runner_operations_invalid")
        with self._runner_lock:
            if active is not self._active_start or any(
                record.active is active for record in self._runner_records.values()
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
        self._reattest(service, active.attestation)
        with self._runner_lock:
            if active is not self._active_start or any(
                record.active is active for record in self._runner_records.values()
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
            binding = self._dynamic_teamlead_runner_binding(service, active)
            record = self._issue_dynamic_teamlead_runner_record(
                operations, active, binding
            )
            return record.permit, record.executor

    def issue_root_owned_dynamic_teamlead_start_composition(
        self,
        context: DynamicTeamleadA3RuntimeContext,
        registry_operations: FleetV2RegistryOperations,
        broker_operations: SeqpacketBrokerClientOperations,
        operations: DynamicTeamleadRunnerOperations,
    ) -> RootDynamicTeamleadStartComposition:
        service = self._bound_service
        if (
            self._closed
            or type(service) is not HomeBrokerControlService
        ):
            _fail("dynamic_teamlead_runner_permit_invalid")
        try:
            execute = operations.execute
        except Exception:
            _fail("dynamic_teamlead_runner_operations_invalid")
        if not callable(execute):
            _fail("dynamic_teamlead_runner_operations_invalid")
        try:
            validated_context = validate_dynamic_teamlead_a3_runtime_context(context)
            registry_snapshot = registry_operations._snapshot
            broker_context_identity = broker_operations.a3_context_identity
            broker_release_identity = broker_operations.release_identity
        except RootSystemBusError:
            raise
        except Exception:
            _fail("dynamic_teamlead_runner_permit_invalid")
        if (
            validated_context is not context
            or type(registry_operations) is not FleetV2RegistryOperations
            or type(broker_operations) is not SeqpacketBrokerClientOperations
            or context.context is not self._context
            or context.release is not service._release
            or registry_snapshot is not context.context.snapshot
            or broker_context_identity is not context
            or broker_release_identity is not service._release
        ):
            _fail("dynamic_teamlead_runner_permit_invalid")
        active = self._active_start
        if type(active) is not _ActiveStart:
            _fail("dynamic_teamlead_runner_permit_invalid")
        with self._runner_lock:
            if active is not self._active_start or any(
                record.active is active for record in self._runner_records.values()
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
        self._reattest(service, active.attestation)
        with self._runner_lock:
            if active is not self._active_start or any(
                record.active is active for record in self._runner_records.values()
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
            binding = self._dynamic_teamlead_runner_binding(service, active)
            record = self._issue_dynamic_teamlead_runner_record(
                operations, active, binding
            )
            composition = object.__new__(RootDynamicTeamleadStartComposition)
            values = (
                ("request", context.request),
                ("registry_operations", registry_operations),
                ("broker_operations", broker_operations),
                ("executor", record.executor),
                ("evidence", record.evidence),
                ("context_identity", context),
                ("snapshot_identity", context.context.snapshot),
                ("release_identity", service._release),
            )
            for name, value in values:
                object.__setattr__(composition, name, value)
            record.composition = composition
            return composition

    def _execute_issued_dynamic_teamlead_runner(
        self,
        executor: _ConsumerDynamicTeamleadRunnerExecutor,
        plan: DynamicTeamleadRunnerPlan,
    ) -> None:
        try:
            permit = executor._permit
            operations = executor._operations
            reference = permit.opaque_reference
            evidence = executor.binding_evidence
        except Exception:
            _fail("dynamic_teamlead_runner_permit_invalid")
        with self._runner_lock:
            record = (
                self._runner_records.get(id(permit))
                if type(permit) is RootDynamicTeamleadRunnerPermit
                else None
            )
            if (
                type(executor) is not _ConsumerDynamicTeamleadRunnerExecutor
                or record is None
                or record.permit is not permit
                or record.reference is not reference
                or record.executor is not executor
                or type(evidence) is not RootDynamicTeamleadRunnerBindingEvidence
                or record.evidence is not evidence
                or evidence.executor_identity is not executor
                or evidence.context_identity is not self._context
                or evidence.snapshot_identity is not self._context.snapshot
                or type(self._bound_service) is not HomeBrokerControlService
                or evidence.release_identity is not self._bound_service._release
                or record.operations is not operations
                or record.terminal
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
            record.terminal = True
            if (
                self._closed
                or self._active_start is not record.active
                or self._dynamic_teamlead_runner_binding(
                    self._bound_service, record.active
                )
                != record.binding
                or not self._dynamic_teamlead_runner_plan_matches(plan, record.binding)
            ):
                _fail("dynamic_teamlead_runner_permit_invalid")
        operations.execute(plan, permit=permit)

    def _consume_from_service(
        self,
        service: HomeBrokerControlService,
        attestation: RootSystemBusPeerAttestation,
        ownership: RootRuntimeActivityOwnership,
    ) -> None:
        if type(ownership) is not RootRuntimeActivityOwnership:
            _fail("trusted_consumer_ownership_invalid")
        self._ensure_start_available(service)
        evidence = self._reattest(service, attestation)
        try:
            peer = BrokerPeer(evidence.pid)
        except Exception:
            _fail("trusted_consumer_attestation_invalid")
        grant = broker_runtime._issue_trusted_start_grant(
            peer,
            evidence,
            self._context,
            service._release,
            self._principal_resolver,
            self._projection_provider,
            lambda: self._reattest(service, attestation),
            self._operations,
        )
        try:
            plan = build_broker_system_plan(grant)
            snapshot = self._boundary.snapshot()
        except Exception:
            try:
                broker_runtime._close_projection(self._operations, grant.projection)
            except Exception:
                _fail("trusted_consumer_cleanup_failed")
            _fail("trusted_consumer_start_failed")
        try:
            receipt = self._boundary.compare_and_start(
                plan, snapshot.token, ownership
            )
        except BrokerSystemError:
            _fail("trusted_consumer_start_failed")
        except Exception:
            _fail("trusted_consumer_start_failed")
        if (
            type(receipt) is not BrokerStartReceipt
            or receipt.ownership is not ownership
            or receipt.projection is not grant.projection
        ):
            _fail("trusted_consumer_start_failed")
        with self._runner_lock:
            if self._closed or self._active_start is not None:
                _fail("trusted_consumer_start_failed")
            self._active_start = _ActiveStart(receipt, ownership, attestation)

    def _release_active(self, service: HomeBrokerControlService) -> None:
        if service is not self._bound_service:
            _fail("trusted_consumer_configuration_invalid")
        with self._runner_lock:
            active = self._active_start
            if active is None:
                return
            self._active_start = None
            for record in self._runner_records.values():
                if record.active is active:
                    record.terminal = True
        failed = False
        try:
            self._boundary.close_start_receipt(active.receipt)
        except Exception:
            failed = True
        try:
            service._host.end_principal_or_agent(active.ownership)
        except FleetRootRuntimeHostError:
            failed = True
        if failed:
            _fail("trusted_consumer_cleanup_failed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failed = False
        if self._bound_service is not None:
            try:
                self._release_active(self._bound_service)
            except RootSystemBusError:
                failed = True
        for bus in (self._system_bus, self._credential_bus):
            if bus is not None:
                try:
                    bus.close()
                except Exception:
                    failed = True
        self._system_bus = None
        self._credential_bus = None
        if failed:
            _fail("trusted_consumer_cleanup_failed")


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
        consumer: TrustedPrincipalGrantConsumer,
        *,
        private_bus_address: str | None = None,
        _operations: _PeerOperations | None = None,
        _credential_reader: Callable[[str], object] | None = None,
    ) -> None:
        if (
            type(host) is not FleetRootRuntimeHost
            or type(generation) is not int
            or not 1 <= generation <= MAX_CHPB_GENERATION
            or type(consumer) is not TrustedPrincipalGrantConsumer
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
        consumer._bind_service(self)

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
        cleanup_failed = False
        try:
            self._consumer._release_active(self)
        except RootSystemBusError:
            cleanup_failed = True
        try:
            self._host.mark_participant_lost(
                RootHostParticipantBinding(
                    RootHostParticipant.SYSTEM_BUS_ADMISSION,
                    self._generation,
                )
            )
        except FleetRootRuntimeHostError:
            pass
        if cleanup_failed:
            _fail("trusted_consumer_cleanup_failed")

    def close(self) -> None:
        if self._closed:
            self._loop.quit()
            return
        self._closed = True
        participant_cleanup_failed = False
        if self._active:
            try:
                self._lose_participant()
            except RootSystemBusError:
                participant_cleanup_failed = True
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
        consumer_cleanup_failed = False
        try:
            self._consumer.close()
        except RootSystemBusError:
            consumer_cleanup_failed = True
        if self._system_bus is not None:
            try:
                self._system_bus.close()
            except Exception:
                pass
            self._system_bus = None
        if participant_cleanup_failed or consumer_cleanup_failed:
            _fail("trusted_consumer_cleanup_failed")

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
                and issued.sender == attestation.bus_unique_name
                and issued.attestation is attestation
                and issued.ownership is ownership
            )
        if not valid:
            _fail("handoff_invalid")
        try:
            self._consumer._consume_from_service(
                self,
                attestation,
                ownership,
            )
        except RootSystemBusError:
            raise
        except Exception:
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
        object.__setattr__(issued, "sender", sender)
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
            self._consumer._ensure_start_available(self)
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
    "TrustedPrincipalGrantConsumer",
)
