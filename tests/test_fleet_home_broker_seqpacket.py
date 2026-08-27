import ast
from dataclasses import replace
from hashlib import sha256
import socket
from pathlib import Path

import pytest

import codex_master.fleet_home_broker_seqpacket as seqpacket
import codex_master.fleet_home_broker_wal as wal
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import (
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
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

    production_calls = {"coordinator": 0, "lookup": 0}
    for path in Path(seqpacket.__file__).parent.glob("*.py"):
        module_tree = ast.parse(path.read_text())
        for node in ast.walk(module_tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "_reattest_seqpacket_peer_from_active_wal_binding":
                production_calls["coordinator"] += 1
            elif node.func.id == "_lookup_active_principal_binding":
                production_calls["lookup"] += 1
    assert production_calls == {"coordinator": 0, "lookup": 1}


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
        "SeqpacketPeerError",
        "SeqpacketPeerOperations",
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
        "bind",
        "listen",
        "accept",
        "connect",
        "recv",
        "recvmsg",
        "send",
        "sendmsg",
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

    source_terms = (
        "ScmFrame",
        "BrokerPeer",
        "BrokerTransportResponse",
        "SCM_RIGHTS",
        "WAL",
        "Home",
    )
    assert not any(term in source for term in source_terms)
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
