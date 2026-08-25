import dataclasses
from dataclasses import FrozenInstanceError
import socket

import pytest

import codex_master.fleet_home_broker_runtime as broker_runtime
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import PrincipalBinding
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    CredentialProjection,
    KernelPeerEvidence,
    StartGrant,
    attest_kernel_peer,
)
from codex_master.fleet_home_broker_system import (
    BrokerDirectoryEvidence,
    BrokerDirectoryExpectation,
    BrokerFedoraEnforcingEvidence,
    BrokerJointReleaseEvidence,
    BrokerMcsEvidence,
    BrokerNodeType,
    BrokerSelinuxEvidence,
    BrokerSocketEvidence,
    BrokerSocketExpectation,
    BrokerSnapshotToken,
    BrokerStartReceipt,
    BrokerSystemBusEvidence,
    BrokerSystemBoundary,
    BrokerSystemEvidence,
    BrokerSystemError,
    BrokerSystemSnapshot,
    BrokerUnitEvidence,
    build_broker_system_plan,
)
from codex_master.fleet_home_broker_transport import BrokerPeer


PEER = BrokerPeer(1234)
IDENTITY = BrokerIdentity(
    "bee_1", 3, "c0,c1", "slot.snapshot.v1", 9, "b" * 64, "c" * 64, 4
)
EVIDENCE = KernelPeerEvidence(1234, 1000, 1000, 7, 17, 29, 9, "1" * 32, "c0,c1")
PRINCIPAL = PrincipalBinding("bee_1", 3, 9, 17, 29, "1" * 32, "c0,c1", 4)
RELEASE = BrokerReleaseSpec(
    1,
    "0.11.0",
    "d" * 64,
    "e" * 64,
    "CHPB/2",
    "policy-v1",
    "provider-v1",
    "f" * 64,
    "0" * 64,
    "codex-master-home-broker.socket",
    "codex-master-home-broker.service",
    "org.codex_master.HomeBrokerControl",
    "/org/codex_master/HomeBrokerControl",
    "org.codex_master.HomeBrokerControl1",
    "codex_master_home_broker_t",
    "codex_master_control_t",
    "codex_master_home_broker_runtime_t",
)


class _Runtime:
    def __init__(self) -> None:
        self.closed: list[int] = []

    def is_root_system_bus_gateway(self) -> bool:
        return True

    def read_kernel_peer_evidence(self, peer: BrokerPeer) -> KernelPeerEvidence:
        assert peer == PEER
        return EVIDENCE

    def close(self, fd: int) -> None:
        self.closed.append(fd)


class _Resolver:
    def resolve_principal(self, evidence: KernelPeerEvidence) -> PrincipalBinding:
        assert evidence == EVIDENCE
        return PRINCIPAL


class _Provider:
    def project(
        self, profile_id: str, binding_id: str, generation: int, provider: str
    ) -> CredentialProjection:
        return CredentialProjection(
            profile_id, binding_id, generation, provider, (101, 102)
        )


class _Linux:
    def __init__(self) -> None:
        self.identity = PidfdIdentity(PEER.pid, 7)

    def pidfd_open(self, pid: int, flags: int) -> int:
        assert (pid, flags) == (PEER.pid, 0)
        return 73

    def pidfd_reuse_check(self, *args: object) -> PidfdIdentity:
        return self.identity

    def open_pinned_proc_pid(self, *args: object) -> int:
        return 83

    def open_proc_cgroup(self, *args: object) -> int:
        return 97

    def fstat(self, fd: int) -> FdStat:
        assert fd == 97
        return FdStat(17, 29, 0o40755, 1000, 1000)

    def read_proc_control_group(self, *args: object) -> str:
        return "/user.slice/user-1000.slice/session-7.scope"

    def read_pid1_unit_name(self, *args: object) -> str:
        return "session-7.scope"

    def read_pid1_unit_generation(self, *args: object) -> int:
        return 9

    def read_pid1_invocation_id(self, *args: object) -> str:
        return "1" * 32

    def read_pid1_control_group(self, *args: object) -> str:
        return "/user.slice/user-1000.slice/session-7.scope"

    def read_peer_mcs_pair(self, *args: object) -> str:
        return "c0,c1"

    def close(self, _fd: int) -> None:
        pass


def _issued_grant() -> StartGrant:
    return attest_kernel_peer(
        PEER,
        IDENTITY,
        RELEASE,
        "profile.one",
        "hmac-sha256:" + "a" * 64,
        9,
        "openai_chatgpt",
        _Runtime(),
        _Linux(),
        _Resolver(),
        _Provider(),
    )


def test_builder_accepts_only_real_issued_a3a1_grants() -> None:
    issued = _issued_grant()
    unissued = StartGrant(
        issued.peer,
        issued.evidence,
        issued.principal,
        issued.identity,
        issued.profile_id,
        issued.binding_id,
        issued.generation,
        issued.provider,
        issued.projection,
        issued.release,
    )

    assert build_broker_system_plan(issued).grant is issued
    with pytest.raises(BrokerSystemError, match="issued start grant required"):
        build_broker_system_plan(unissued)
    with pytest.raises(BrokerSystemError, match="issued start grant required"):
        build_broker_system_plan(object())  # type: ignore[arg-type]


def test_builder_derives_only_fixed_topology_and_issued_release_binding() -> None:
    plan = build_broker_system_plan(_issued_grant())

    assert plan.directory == BrokerDirectoryExpectation(
        "/run/codex-master-home-broker",
        BrokerNodeType.DIRECTORY,
        "root",
        "codex-master-broker",
        0o750,
    )
    assert plan.socket == BrokerSocketExpectation(
        "/run/codex-master-home-broker/broker.sock",
        BrokerNodeType.SOCKET,
        "root",
        "codex-master-broker",
        0o660,
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET,
    )
    assert plan.system_bus == BrokerSystemBusEvidence(
        RELEASE.system_bus_name, RELEASE.system_bus_path, RELEASE.system_bus_interface
    )
    assert plan.selinux == BrokerSelinuxEvidence(
        RELEASE.broker_domain, RELEASE.gateway_domain, RELEASE.socket_type
    )
    assert plan.mcs == BrokerMcsEvidence("c0,c1")
    assert plan.service == BrokerUnitEvidence(
        RELEASE.socket_unit, RELEASE.service_unit, False, True
    )
    assert plan.joint_release == BrokerJointReleaseEvidence(
        RELEASE.joint_release_version,
        RELEASE.release_id,
        RELEASE.server_digest,
        RELEASE.broker_manifest_digest,
        RELEASE.chpb_abi,
        RELEASE.policy_abi,
        RELEASE.provider_abi,
        RELEASE.unit_digest,
        RELEASE.selinux_digest,
    )


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    [
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "path",
            "/run/wrong",
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                29,
            ),
            "socket_type",
            socket.SOCK_STREAM,
        ),
    ],
)
def test_node_evidence_rejects_typed_boundary_drift(factory, field, value) -> None:
    with pytest.raises(BrokerSystemError):
        dataclasses.replace(factory(), **{field: value})


def test_all_public_evidence_is_frozen_and_slotted() -> None:
    values = (
        BrokerDirectoryEvidence(
            "/run/codex-master-home-broker",
            BrokerNodeType.DIRECTORY,
            "root",
            "codex-master-broker",
            0o750,
            17,
            29,
        ),
        BrokerSocketEvidence(
            "/run/codex-master-home-broker/broker.sock",
            BrokerNodeType.SOCKET,
            "root",
            "codex-master-broker",
            0o660,
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
            17,
            29,
        ),
    )

    for value in values:
        assert dataclasses.is_dataclass(value)
        assert type(value).__dataclass_params__.frozen
        assert hasattr(type(value), "__slots__")
        assert not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(value, type(value).__slots__[0], None)


def _system_evidence(**changes: object) -> BrokerSystemEvidence:
    values = {
        "directory": BrokerDirectoryEvidence(
            "/run/codex-master-home-broker",
            BrokerNodeType.DIRECTORY,
            "root",
            "codex-master-broker",
            0o750,
            17,
            29,
        ),
        "socket": BrokerSocketEvidence(
            "/run/codex-master-home-broker/broker.sock",
            BrokerNodeType.SOCKET,
            "root",
            "codex-master-broker",
            0o660,
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
            17,
            31,
        ),
        "system_bus": BrokerSystemBusEvidence(
            RELEASE.system_bus_name,
            RELEASE.system_bus_path,
            RELEASE.system_bus_interface,
        ),
        "selinux": BrokerSelinuxEvidence(
            RELEASE.broker_domain, RELEASE.gateway_domain, RELEASE.socket_type
        ),
        "enforcing": BrokerFedoraEnforcingEvidence(True),
        "mcs": BrokerMcsEvidence("c0,c1"),
        "unit": BrokerUnitEvidence(
            RELEASE.socket_unit, RELEASE.service_unit, False, True
        ),
        "joint_release": BrokerJointReleaseEvidence(
            RELEASE.joint_release_version,
            RELEASE.release_id,
            RELEASE.server_digest,
            RELEASE.broker_manifest_digest,
            RELEASE.chpb_abi,
            RELEASE.policy_abi,
            RELEASE.provider_abi,
            RELEASE.unit_digest,
            RELEASE.selinux_digest,
        ),
    }
    values.update(changes)
    return BrokerSystemEvidence(**values)


class _FakeLock:
    def __init__(self) -> None:
        self.events: list[str] = []

    def __enter__(self) -> "_FakeLock":
        self.events.append("enter")
        return self

    def __exit__(self, *args: object) -> None:
        self.events.append("exit")


class _TrustedSystemOperations:
    def __init__(
        self,
        observations: tuple[BrokerSystemEvidence, ...] = (),
        start_error: Exception | None = None,
    ) -> None:
        self.observations = observations or (_system_evidence(),)
        self.start_error = start_error
        self.calls: list[object] = []
        self.closed: list[int] = []

    def _observe_broker_system(self) -> BrokerSystemEvidence:
        self.calls.append("observe")
        index = min(self.calls.count("observe") - 1, len(self.observations) - 1)
        return self.observations[index]

    def _start_bound_socket_unit(self, socket_unit: str) -> None:
        self.calls.append(("start", socket_unit))
        if self.start_error is not None:
            raise self.start_error

    def close(self, fd: int) -> None:
        self.closed.append(fd)


def test_snapshot_returns_complete_typed_evidence_with_registered_opaque_token() -> (
    None
):
    operations = _TrustedSystemOperations()
    boundary = BrokerSystemBoundary(operations)

    snapshot = boundary.snapshot()

    assert type(snapshot) is BrokerSystemSnapshot
    assert snapshot.directory.device == 17
    assert snapshot.socket.inode == 31
    assert snapshot.enforcing.enforcing is True
    assert type(snapshot.token) is BrokerSnapshotToken
    assert dataclasses.is_dataclass(snapshot)
    assert type(snapshot).__dataclass_params__.frozen
    assert hasattr(type(snapshot), "__slots__")


def test_missing_fedora_enforcing_fails_before_claim_without_start_or_close() -> None:
    operations = _TrustedSystemOperations(
        (_system_evidence(enforcing=BrokerFedoraEnforcingEvidence(False)),)
    )
    boundary = BrokerSystemBoundary(operations)
    snapshot = boundary.snapshot()

    with pytest.raises(BrokerSystemError, match="snapshot does not match plan"):
        boundary.compare_and_start(
            build_broker_system_plan(_issued_grant()), snapshot.token
        )

    assert operations.calls == ["observe"]
    assert operations.closed == []


@pytest.mark.parametrize(
    "field,changed",
    [
        (
            "directory",
            lambda evidence: dataclasses.replace(evidence.directory, device=18),
        ),
        ("socket", lambda evidence: dataclasses.replace(evidence.socket, inode=32)),
        (
            "system_bus",
            lambda evidence: dataclasses.replace(
                evidence.system_bus, interface="org.codex_master.Wrong"
            ),
        ),
        (
            "selinux",
            lambda evidence: dataclasses.replace(
                evidence.selinux, gateway_domain="wrong_t"
            ),
        ),
        ("enforcing", lambda evidence: BrokerFedoraEnforcingEvidence(False)),
        ("mcs", lambda evidence: BrokerMcsEvidence("c2,c3")),
        (
            "unit",
            lambda evidence: dataclasses.replace(evidence.unit, remove_on_stop=False),
        ),
        (
            "joint_release",
            lambda evidence: dataclasses.replace(
                evidence.joint_release, release_id="0.11.1"
            ),
        ),
    ],
)
def test_every_snapshot_evidence_field_drifting_after_claim_causes_zero_starts(
    field, changed
) -> None:
    initial = _system_evidence()
    operations = _TrustedSystemOperations(
        (initial, dataclasses.replace(initial, **{field: changed(initial)}))
    )
    boundary = BrokerSystemBoundary(operations)
    snapshot = boundary.snapshot()

    with pytest.raises(BrokerSystemError, match="system snapshot drifted"):
        boundary.compare_and_start(
            build_broker_system_plan(_issued_grant()), snapshot.token
        )

    assert operations.calls == ["observe", "observe"]
    assert operations.closed == [101, 102]


def test_foreign_or_reused_tokens_cannot_start_a_unit() -> None:
    operations = _TrustedSystemOperations()
    boundary = BrokerSystemBoundary(operations)
    plan = build_broker_system_plan(_issued_grant())
    snapshot = boundary.snapshot()

    with pytest.raises(BrokerSystemError, match="snapshot token is invalid"):
        boundary.compare_and_start(plan, BrokerSnapshotToken(object()))
    assert operations.calls == ["observe"]

    receipt = boundary.compare_and_start(plan, snapshot.token)
    with pytest.raises(BrokerSystemError, match="snapshot token is invalid"):
        boundary.compare_and_start(plan, snapshot.token)

    assert receipt.token is snapshot.token
    assert operations.calls == [
        "observe",
        "observe",
        ("start", RELEASE.socket_unit),
    ]


def test_reconstructed_plan_cannot_introduce_a_free_socket_unit() -> None:
    plan = build_broker_system_plan(_issued_grant())
    forged_unit = BrokerUnitEvidence(
        "untrusted.socket", "untrusted.service", False, True
    )
    forged = dataclasses.replace(plan, service=forged_unit)
    operations = _TrustedSystemOperations((_system_evidence(unit=forged_unit),))
    boundary = BrokerSystemBoundary(operations)
    snapshot = boundary.snapshot()

    with pytest.raises(BrokerSystemError, match="broker system plan is invalid"):
        boundary.compare_and_start(forged, snapshot.token)

    assert operations.calls == ["observe"]
    assert operations.closed == []


def test_compare_and_start_reobserves_starts_bound_socket_under_one_lock_and_receipts_projection() -> (
    None
):
    operations = _TrustedSystemOperations()
    lock = _FakeLock()
    boundary = BrokerSystemBoundary(operations, lock)
    plan = build_broker_system_plan(_issued_grant())
    snapshot = boundary.snapshot()

    receipt = boundary.compare_and_start(plan, snapshot.token)

    assert type(receipt) is BrokerStartReceipt
    assert receipt.token is snapshot.token
    assert receipt.release_id == RELEASE.release_id
    assert receipt.socket_unit == RELEASE.socket_unit
    assert receipt.projection is plan.grant.projection
    assert not hasattr(receipt, "started")
    assert lock.events == ["enter", "exit", "enter", "exit"]
    assert plan.service.socket_unit == RELEASE.socket_unit
    assert operations.calls == [
        "observe",
        "observe",
        ("start", RELEASE.socket_unit),
    ]
    assert operations.closed == []


def test_after_claim_start_failure_closes_transferred_fds_once() -> None:
    operations = _TrustedSystemOperations(start_error=RuntimeError("start failed"))
    boundary = BrokerSystemBoundary(operations)
    snapshot = boundary.snapshot()

    with pytest.raises(BrokerSystemError, match="bound socket start failed"):
        boundary.compare_and_start(
            build_broker_system_plan(_issued_grant()), snapshot.token
        )

    assert operations.calls == [
        "observe",
        "observe",
        ("start", RELEASE.socket_unit),
    ]
    assert operations.closed == [101, 102]


def test_post_claim_enforcing_drift_stops_start_and_closes_transferred_fds_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations = _TrustedSystemOperations()
    boundary = BrokerSystemBoundary(operations)
    snapshot = boundary.snapshot()
    original_claim = broker_runtime._StartGrantState.claim

    def claim_after_which_enforcing_drifts(
        state: broker_runtime._StartGrantState,
    ) -> bool:
        claimed = original_claim(state)
        operations.observations = (
            _system_evidence(enforcing=BrokerFedoraEnforcingEvidence(False)),
        )
        return claimed

    monkeypatch.setattr(
        broker_runtime._StartGrantState,
        "claim",
        claim_after_which_enforcing_drifts,
    )

    with pytest.raises(BrokerSystemError, match="system snapshot drifted"):
        boundary.compare_and_start(
            build_broker_system_plan(_issued_grant()), snapshot.token
        )

    assert operations.calls == ["observe", "observe"]
    assert operations.closed == [101, 102]


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    [
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "path",
            "/run/other",
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "node_type",
            BrokerNodeType.SOCKET,
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "owner",
            "broker",
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "group",
            "wheel",
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "mode",
            0o755,
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "device",
            -1,
        ),
        (
            lambda: BrokerDirectoryEvidence(
                "/run/codex-master-home-broker",
                BrokerNodeType.DIRECTORY,
                "root",
                "codex-master-broker",
                0o750,
                17,
                29,
            ),
            "inode",
            0,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "path",
            "/run/other.sock",
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "node_type",
            BrokerNodeType.DIRECTORY,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "owner",
            "broker",
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "group",
            "wheel",
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "mode",
            0o600,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "address_family",
            socket.AF_INET,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "socket_type",
            socket.SOCK_STREAM,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "device",
            -1,
        ),
        (
            lambda: BrokerSocketEvidence(
                "/run/codex-master-home-broker/broker.sock",
                BrokerNodeType.SOCKET,
                "root",
                "codex-master-broker",
                0o660,
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
                17,
                31,
            ),
            "inode",
            0,
        ),
    ],
)
def test_directory_and_socket_evidence_reject_every_typed_field_mutation(
    factory, field, value
) -> None:
    with pytest.raises(BrokerSystemError):
        dataclasses.replace(factory(), **{field: value})


@pytest.mark.parametrize(
    "factory",
    [
        lambda: BrokerSystemBusEvidence(
            "", RELEASE.system_bus_path, RELEASE.system_bus_interface
        ),
        lambda: BrokerSystemBusEvidence(
            RELEASE.system_bus_name, "", RELEASE.system_bus_interface
        ),
        lambda: BrokerSystemBusEvidence(
            RELEASE.system_bus_name, RELEASE.system_bus_path, ""
        ),
        lambda: BrokerSelinuxEvidence("", RELEASE.gateway_domain, RELEASE.socket_type),
        lambda: BrokerSelinuxEvidence(RELEASE.broker_domain, "", RELEASE.socket_type),
        lambda: BrokerSelinuxEvidence(
            RELEASE.broker_domain, RELEASE.gateway_domain, ""
        ),
        lambda: BrokerFedoraEnforcingEvidence("true"),
        lambda: BrokerMcsEvidence(""),
        lambda: BrokerUnitEvidence("", RELEASE.service_unit, False, True),
        lambda: BrokerUnitEvidence(RELEASE.socket_unit, "", False, True),
        lambda: BrokerUnitEvidence(RELEASE.socket_unit, RELEASE.service_unit, 0, True),
        lambda: BrokerUnitEvidence(RELEASE.socket_unit, RELEASE.service_unit, False, 1),
        lambda: BrokerJointReleaseEvidence(
            0,
            RELEASE.release_id,
            RELEASE.server_digest,
            RELEASE.broker_manifest_digest,
            RELEASE.chpb_abi,
            RELEASE.policy_abi,
            RELEASE.provider_abi,
            RELEASE.unit_digest,
            RELEASE.selinux_digest,
        ),
    ],
)
def test_other_snapshot_evidence_requires_nominal_typed_values(factory) -> None:
    with pytest.raises(BrokerSystemError):
        factory()


def test_complete_snapshot_plan_and_receipt_values_are_frozen_and_slotted() -> None:
    plan = build_broker_system_plan(_issued_grant())
    snapshot = BrokerSystemBoundary(_TrustedSystemOperations()).snapshot()
    receipt = BrokerStartReceipt(
        snapshot.token, RELEASE.release_id, RELEASE.socket_unit, plan.grant.projection
    )

    for value in (plan, _system_evidence(), snapshot, receipt):
        assert dataclasses.is_dataclass(value)
        assert type(value).__dataclass_params__.frozen
        assert hasattr(type(value), "__slots__")
        assert not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(value, type(value).__slots__[0], None)
