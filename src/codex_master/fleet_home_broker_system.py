"""Typed, offline system boundary for one issued home-broker start grant."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import socket

from codex_master.fleet_home_broker_runtime import (
    CredentialProjection,
    OneShotGrantConsumer,
    StartGrant,
    _start_grant_binding,
    _start_grant_state,
)
from codex_master.fleet_root_runtime_host import RootRuntimeActivityOwnership


DIRECTORY_PATH = "/run/codex-master-home-broker"
SOCKET_PATH = "/run/codex-master-home-broker/broker.sock"
BROKER_OWNER = "root"
BROKER_GROUP = "codex-master-broker"
DIRECTORY_MODE = 0o750
SOCKET_MODE = 0o660


class BrokerSystemError(ValueError):
    """Raised when typed broker-system evidence is unsafe or inconsistent."""

    __slots__ = ()


class BrokerNodeType(Enum):
    DIRECTORY = "directory"
    SOCKET = "socket"


def _fail(message: str) -> None:
    raise BrokerSystemError(message) from None


def _nonempty_text(value: object, field: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        _fail(f"{field} is invalid")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{field} is invalid")
    return value


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class BrokerDirectoryExpectation:
    path: str
    node_type: BrokerNodeType
    owner: str
    group: str
    mode: int

    def __post_init__(self) -> None:
        if (
            self.path != DIRECTORY_PATH
            or type(self.node_type) is not BrokerNodeType
            or self.node_type is not BrokerNodeType.DIRECTORY
            or self.owner != BROKER_OWNER
            or self.group != BROKER_GROUP
            or type(self.mode) is not int
            or self.mode != DIRECTORY_MODE
        ):
            _fail("directory topology is invalid")


@dataclass(frozen=True, slots=True)
class BrokerSocketExpectation:
    path: str
    node_type: BrokerNodeType
    owner: str
    group: str
    mode: int
    address_family: socket.AddressFamily
    socket_type: socket.SocketKind

    def __post_init__(self) -> None:
        if (
            self.path != SOCKET_PATH
            or type(self.node_type) is not BrokerNodeType
            or self.node_type is not BrokerNodeType.SOCKET
            or self.owner != BROKER_OWNER
            or self.group != BROKER_GROUP
            or type(self.mode) is not int
            or self.mode != SOCKET_MODE
            or self.address_family is not socket.AF_UNIX
            or self.socket_type is not socket.SOCK_SEQPACKET
        ):
            _fail("socket topology is invalid")


@dataclass(frozen=True, slots=True)
class BrokerDirectoryEvidence:
    path: str
    node_type: BrokerNodeType
    owner: str
    group: str
    mode: int
    device: int
    inode: int

    def __post_init__(self) -> None:
        BrokerDirectoryExpectation(
            self.path, self.node_type, self.owner, self.group, self.mode
        )
        _nonnegative_integer(self.device, "directory device")
        _positive_integer(self.inode, "directory inode")


@dataclass(frozen=True, slots=True)
class BrokerSocketEvidence:
    path: str
    node_type: BrokerNodeType
    owner: str
    group: str
    mode: int
    address_family: socket.AddressFamily
    socket_type: socket.SocketKind
    device: int
    inode: int

    def __post_init__(self) -> None:
        BrokerSocketExpectation(
            self.path,
            self.node_type,
            self.owner,
            self.group,
            self.mode,
            self.address_family,
            self.socket_type,
        )
        _nonnegative_integer(self.device, "socket device")
        _positive_integer(self.inode, "socket inode")


@dataclass(frozen=True, slots=True)
class BrokerSystemBusEvidence:
    name: str
    path: str
    interface: str

    def __post_init__(self) -> None:
        _nonempty_text(self.name, "system bus name")
        _nonempty_text(self.path, "system bus path")
        _nonempty_text(self.interface, "system bus interface")


@dataclass(frozen=True, slots=True)
class BrokerSelinuxEvidence:
    broker_domain: str
    gateway_domain: str
    socket_type: str

    def __post_init__(self) -> None:
        _nonempty_text(self.broker_domain, "broker SELinux domain")
        _nonempty_text(self.gateway_domain, "gateway SELinux domain")
        _nonempty_text(self.socket_type, "socket SELinux type")


@dataclass(frozen=True, slots=True)
class BrokerFedoraEnforcingEvidence:
    enforcing: bool

    def __post_init__(self) -> None:
        if type(self.enforcing) is not bool:
            _fail("Fedora enforcing evidence is invalid")


@dataclass(frozen=True, slots=True)
class BrokerMcsEvidence:
    pair: str

    def __post_init__(self) -> None:
        _nonempty_text(self.pair, "MCS pair")


@dataclass(frozen=True, slots=True)
class BrokerUnitEvidence:
    socket_unit: str
    service_unit: str
    accept: bool
    remove_on_stop: bool

    def __post_init__(self) -> None:
        _nonempty_text(self.socket_unit, "socket unit")
        _nonempty_text(self.service_unit, "service unit")
        if type(self.accept) is not bool or type(self.remove_on_stop) is not bool:
            _fail("unit evidence is invalid")


@dataclass(frozen=True, slots=True)
class BrokerJointReleaseEvidence:
    joint_release_version: int
    release_id: str
    server_digest: str
    broker_manifest_digest: str
    chpb_abi: str
    policy_abi: str
    provider_abi: str
    unit_digest: str
    selinux_digest: str

    def __post_init__(self) -> None:
        _positive_integer(self.joint_release_version, "joint release version")
        for value, label in (
            (self.release_id, "release id"),
            (self.server_digest, "server digest"),
            (self.broker_manifest_digest, "broker manifest digest"),
            (self.chpb_abi, "CHPB ABI"),
            (self.policy_abi, "policy ABI"),
            (self.provider_abi, "provider ABI"),
            (self.unit_digest, "unit digest"),
            (self.selinux_digest, "SELinux digest"),
        ):
            _nonempty_text(value, label)


class _BrokerSystemPlanCarrier:
    __slots__ = ("_plan_state",)


@dataclass(frozen=True, slots=True)
class BrokerSystemPlan(_BrokerSystemPlanCarrier):
    grant: StartGrant
    directory: BrokerDirectoryExpectation
    socket: BrokerSocketExpectation
    system_bus: BrokerSystemBusEvidence
    selinux: BrokerSelinuxEvidence
    enforcing: BrokerFedoraEnforcingEvidence
    mcs: BrokerMcsEvidence
    service: BrokerUnitEvidence
    joint_release: BrokerJointReleaseEvidence


class _BrokerSystemPlanState:
    __slots__ = ("_binding",)

    def __init__(self, binding: tuple[object, ...]) -> None:
        self._binding = binding

    def matches(self, binding: tuple[object, ...]) -> bool:
        return self._binding == binding


def _plan_binding(plan: BrokerSystemPlan) -> tuple[object, ...]:
    return (
        plan.grant,
        plan.directory,
        plan.socket,
        plan.system_bus,
        plan.selinux,
        plan.enforcing,
        plan.mcs,
        plan.service,
        plan.joint_release,
    )


def _issue_plan(
    grant: StartGrant,
    directory: BrokerDirectoryExpectation,
    socket_expectation: BrokerSocketExpectation,
    system_bus: BrokerSystemBusEvidence,
    selinux: BrokerSelinuxEvidence,
    enforcing: BrokerFedoraEnforcingEvidence,
    mcs: BrokerMcsEvidence,
    service: BrokerUnitEvidence,
    joint_release: BrokerJointReleaseEvidence,
) -> BrokerSystemPlan:
    plan = BrokerSystemPlan(
        grant,
        directory,
        socket_expectation,
        system_bus,
        selinux,
        enforcing,
        mcs,
        service,
        joint_release,
    )
    object.__setattr__(plan, "_plan_state", _BrokerSystemPlanState(_plan_binding(plan)))
    return plan


def _require_issued_grant(value: object) -> StartGrant:
    if type(value) is not StartGrant:
        _fail("issued start grant required")
    try:
        state = _start_grant_state(value)
        if state.matches(_start_grant_binding(value)) is not True:
            _fail("issued start grant required")
    except BrokerSystemError:
        raise
    except Exception:
        _fail("issued start grant required")
    return value


def _require_issued_plan(value: object) -> BrokerSystemPlan:
    if type(value) is not BrokerSystemPlan:
        _fail("broker system plan is invalid")
    try:
        state = value._plan_state
        if type(state) is not _BrokerSystemPlanState or not state.matches(
            _plan_binding(value)
        ):
            _fail("broker system plan is invalid")
        _require_issued_grant(value.grant)
    except BrokerSystemError:
        raise
    except Exception:
        _fail("broker system plan is invalid")
    return value


def build_broker_system_plan(grant: StartGrant) -> BrokerSystemPlan:
    """Build fixed broker-system expectations from one issuer-bound grant."""

    grant = _require_issued_grant(grant)
    release = grant.release
    return _issue_plan(
        grant,
        BrokerDirectoryExpectation(
            DIRECTORY_PATH,
            BrokerNodeType.DIRECTORY,
            BROKER_OWNER,
            BROKER_GROUP,
            DIRECTORY_MODE,
        ),
        BrokerSocketExpectation(
            SOCKET_PATH,
            BrokerNodeType.SOCKET,
            BROKER_OWNER,
            BROKER_GROUP,
            SOCKET_MODE,
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
        ),
        BrokerSystemBusEvidence(
            release.system_bus_name,
            release.system_bus_path,
            release.system_bus_interface,
        ),
        BrokerSelinuxEvidence(
            release.broker_domain,
            release.gateway_domain,
            release.socket_type,
        ),
        BrokerFedoraEnforcingEvidence(True),
        BrokerMcsEvidence(grant.identity.mcs_pair),
        BrokerUnitEvidence(release.socket_unit, release.service_unit, False, True),
        BrokerJointReleaseEvidence(
            release.joint_release_version,
            release.release_id,
            release.server_digest,
            release.broker_manifest_digest,
            release.chpb_abi,
            release.policy_abi,
            release.provider_abi,
            release.unit_digest,
            release.selinux_digest,
        ),
    )


def _validated_directory(value: object) -> BrokerDirectoryEvidence:
    if type(value) is not BrokerDirectoryEvidence:
        _fail("directory evidence is invalid")
    return BrokerDirectoryEvidence(
        value.path,
        value.node_type,
        value.owner,
        value.group,
        value.mode,
        value.device,
        value.inode,
    )


def _validated_socket(value: object) -> BrokerSocketEvidence:
    if type(value) is not BrokerSocketEvidence:
        _fail("socket evidence is invalid")
    return BrokerSocketEvidence(
        value.path,
        value.node_type,
        value.owner,
        value.group,
        value.mode,
        value.address_family,
        value.socket_type,
        value.device,
        value.inode,
    )


def _validated_system_bus(value: object) -> BrokerSystemBusEvidence:
    if type(value) is not BrokerSystemBusEvidence:
        _fail("system bus evidence is invalid")
    return BrokerSystemBusEvidence(value.name, value.path, value.interface)


def _validated_selinux(value: object) -> BrokerSelinuxEvidence:
    if type(value) is not BrokerSelinuxEvidence:
        _fail("SELinux evidence is invalid")
    return BrokerSelinuxEvidence(
        value.broker_domain, value.gateway_domain, value.socket_type
    )


def _validated_enforcing(value: object) -> BrokerFedoraEnforcingEvidence:
    if type(value) is not BrokerFedoraEnforcingEvidence:
        _fail("Fedora enforcing evidence is invalid")
    return BrokerFedoraEnforcingEvidence(value.enforcing)


def _validated_mcs(value: object) -> BrokerMcsEvidence:
    if type(value) is not BrokerMcsEvidence:
        _fail("MCS evidence is invalid")
    return BrokerMcsEvidence(value.pair)


def _validated_unit(value: object) -> BrokerUnitEvidence:
    if type(value) is not BrokerUnitEvidence:
        _fail("unit evidence is invalid")
    return BrokerUnitEvidence(
        value.socket_unit, value.service_unit, value.accept, value.remove_on_stop
    )


def _validated_joint_release(value: object) -> BrokerJointReleaseEvidence:
    if type(value) is not BrokerJointReleaseEvidence:
        _fail("joint release evidence is invalid")
    return BrokerJointReleaseEvidence(
        value.joint_release_version,
        value.release_id,
        value.server_digest,
        value.broker_manifest_digest,
        value.chpb_abi,
        value.policy_abi,
        value.provider_abi,
        value.unit_digest,
        value.selinux_digest,
    )


@dataclass(frozen=True, slots=True)
class BrokerSystemEvidence:
    directory: BrokerDirectoryEvidence
    socket: BrokerSocketEvidence
    system_bus: BrokerSystemBusEvidence
    selinux: BrokerSelinuxEvidence
    enforcing: BrokerFedoraEnforcingEvidence
    mcs: BrokerMcsEvidence
    unit: BrokerUnitEvidence
    joint_release: BrokerJointReleaseEvidence

    def __post_init__(self) -> None:
        _validated_directory(self.directory)
        _validated_socket(self.socket)
        _validated_system_bus(self.system_bus)
        _validated_selinux(self.selinux)
        _validated_enforcing(self.enforcing)
        _validated_mcs(self.mcs)
        _validated_unit(self.unit)
        _validated_joint_release(self.joint_release)


@dataclass(frozen=True, slots=True)
class BrokerSnapshotToken:
    _marker: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class BrokerSystemSnapshot:
    directory: BrokerDirectoryEvidence
    socket: BrokerSocketEvidence
    system_bus: BrokerSystemBusEvidence
    selinux: BrokerSelinuxEvidence
    enforcing: BrokerFedoraEnforcingEvidence
    mcs: BrokerMcsEvidence
    unit: BrokerUnitEvidence
    joint_release: BrokerJointReleaseEvidence
    token: BrokerSnapshotToken

    def __post_init__(self) -> None:
        BrokerSystemEvidence(
            self.directory,
            self.socket,
            self.system_bus,
            self.selinux,
            self.enforcing,
            self.mcs,
            self.unit,
            self.joint_release,
        )
        if type(self.token) is not BrokerSnapshotToken:
            _fail("snapshot token is invalid")


@dataclass(frozen=True, slots=True)
class BrokerStartReceipt:
    token: BrokerSnapshotToken
    release_id: str
    socket_unit: str
    projection: CredentialProjection
    ownership: RootRuntimeActivityOwnership

    def __post_init__(self) -> None:
        if type(self.token) is not BrokerSnapshotToken:
            _fail("start receipt token is invalid")
        _nonempty_text(self.release_id, "start receipt release id")
        _nonempty_text(self.socket_unit, "start receipt socket unit")
        if type(self.projection) is not CredentialProjection:
            _fail("start receipt projection is invalid")
        if type(self.ownership) is not RootRuntimeActivityOwnership:
            _fail("start receipt ownership is invalid")


class _SnapshotRecord:
    __slots__ = ("token", "snapshot", "consumed")

    def __init__(self, token: BrokerSnapshotToken, snapshot: BrokerSystemSnapshot):
        self.token = token
        self.snapshot = snapshot
        self.consumed = False


class _ReceiptRecord:
    __slots__ = ("receipt", "terminal")

    def __init__(self, receipt: BrokerStartReceipt):
        self.receipt = receipt
        self.terminal = False


class BrokerSystemBoundary:
    """Serialize trusted observation, grant claim, and exactly one unit start."""

    __slots__ = ("_operations", "_lock", "_records", "_receipts")

    def __init__(self, operations: object, lock: object = None) -> None:
        self._operations = operations
        if lock is None:
            from threading import Lock

            lock = Lock()
        self._lock = lock
        self._records: dict[int, _SnapshotRecord] = {}
        self._receipts: dict[int, _ReceiptRecord] = {}

    def _capture(self, token: BrokerSnapshotToken) -> BrokerSystemSnapshot:
        try:
            evidence = self._operations._observe_broker_system()
        except Exception:
            _fail("broker system observation failed")
        if type(evidence) is not BrokerSystemEvidence:
            _fail("broker system observation failed")
        return BrokerSystemSnapshot(
            evidence.directory,
            evidence.socket,
            evidence.system_bus,
            evidence.selinux,
            evidence.enforcing,
            evidence.mcs,
            evidence.unit,
            evidence.joint_release,
            token,
        )

    def snapshot(self) -> BrokerSystemSnapshot:
        with self._lock:
            token = BrokerSnapshotToken(object())
            snapshot = self._capture(token)
            self._records[id(token)] = _SnapshotRecord(token, snapshot)
            return snapshot

    def compare_and_start(
        self,
        expected: BrokerSystemPlan,
        token: BrokerSnapshotToken,
        ownership: RootRuntimeActivityOwnership,
    ) -> BrokerStartReceipt:
        with self._lock:
            record = (
                self._records.get(id(token))
                if type(token) is BrokerSnapshotToken
                else None
            )
            if record is None or record.token is not token or record.consumed:
                _fail("snapshot token is invalid")
            if type(ownership) is not RootRuntimeActivityOwnership:
                _fail("ownership is invalid")
            record.consumed = True
            expected = _require_issued_plan(expected)
            if not _snapshot_matches_plan(record.snapshot, expected):
                _fail("snapshot does not match plan")
            try:
                projection = OneShotGrantConsumer(expected.grant, self).consume(
                    expected.grant.peer,
                    expected.grant.evidence,
                    expected.grant.principal,
                    expected.grant.identity,
                )
            except Exception:
                _fail("start grant claim failed")
            try:
                observed = self._capture(token)
                if observed != record.snapshot:
                    _fail("system snapshot drifted")
                if not _snapshot_matches_plan(observed, expected):
                    _fail("snapshot does not match plan")
            except BrokerSystemError:
                _close_projection(self, projection)
                raise
            except Exception:
                _close_projection(self, projection)
                _fail("post-claim system observation failed")
            try:
                self._operations._start_bound_socket_unit(expected.service.socket_unit)
            except Exception:
                _close_projection(self, projection)
                _fail("bound socket start failed")
            receipt = BrokerStartReceipt(
                token,
                expected.joint_release.release_id,
                expected.service.socket_unit,
                projection,
                ownership,
            )
            self._receipts[id(receipt)] = _ReceiptRecord(receipt)
            return receipt

    def close_start_receipt(self, receipt: BrokerStartReceipt) -> None:
        with self._lock:
            record = (
                self._receipts.get(id(receipt))
                if type(receipt) is BrokerStartReceipt
                else None
            )
            if record is None or record.receipt is not receipt:
                _fail("start receipt is invalid")
            if record.terminal:
                return
            record.terminal = True
            cleanup_failed = False
            for fd in receipt.projection.fds:
                try:
                    self.close(fd)
                except Exception:
                    cleanup_failed = True
            if cleanup_failed:
                _fail("start receipt cleanup failed")

    def close(self, fd: int) -> None:
        if type(fd) is not int or fd < 0:
            _fail("file descriptor is invalid")
        self._operations.close(fd)


def _close_projection(
    boundary: BrokerSystemBoundary, projection: CredentialProjection
) -> None:
    for fd in projection.fds:
        try:
            boundary.close(fd)
        except Exception:
            pass


def _snapshot_matches_plan(
    snapshot: BrokerSystemSnapshot, expected: BrokerSystemPlan
) -> bool:
    return (
        (
            snapshot.directory.path,
            snapshot.directory.node_type,
            snapshot.directory.owner,
            snapshot.directory.group,
            snapshot.directory.mode,
        )
        == (
            expected.directory.path,
            expected.directory.node_type,
            expected.directory.owner,
            expected.directory.group,
            expected.directory.mode,
        )
        and (
            snapshot.socket.path,
            snapshot.socket.node_type,
            snapshot.socket.owner,
            snapshot.socket.group,
            snapshot.socket.mode,
            snapshot.socket.address_family,
            snapshot.socket.socket_type,
        )
        == (
            expected.socket.path,
            expected.socket.node_type,
            expected.socket.owner,
            expected.socket.group,
            expected.socket.mode,
            expected.socket.address_family,
            expected.socket.socket_type,
        )
        and snapshot.system_bus == expected.system_bus
        and snapshot.selinux == expected.selinux
        and snapshot.enforcing == expected.enforcing
        and snapshot.mcs == expected.mcs
        and snapshot.unit == expected.service
        and snapshot.joint_release == expected.joint_release
    )


__all__ = (
    "BrokerDirectoryEvidence",
    "BrokerDirectoryExpectation",
    "BrokerFedoraEnforcingEvidence",
    "BrokerJointReleaseEvidence",
    "BrokerMcsEvidence",
    "BrokerNodeType",
    "BrokerSelinuxEvidence",
    "BrokerSocketEvidence",
    "BrokerSocketExpectation",
    "BrokerSnapshotToken",
    "BrokerStartReceipt",
    "BrokerSystemBoundary",
    "BrokerSystemBusEvidence",
    "BrokerSystemEvidence",
    "BrokerSystemError",
    "BrokerSystemPlan",
    "BrokerSystemSnapshot",
    "BrokerUnitEvidence",
    "build_broker_system_plan",
)
