import ast
import runpy
import socket
import stat
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import PrincipalBinding
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    CredentialProjection,
    KernelPeerEvidence,
    RuntimeBoundaryError,
)
from codex_master.fleet_home_broker_system import (
    BrokerDirectoryEvidence,
    BrokerFedoraEnforcingEvidence,
    BrokerJointReleaseEvidence,
    BrokerMcsEvidence,
    BrokerNodeType,
    BrokerSelinuxEvidence,
    BrokerSocketEvidence,
    BrokerStartReceipt,
    BrokerSystemBoundary,
    BrokerSystemBusEvidence,
    BrokerSystemError,
    BrokerSystemEvidence,
    BrokerUnitEvidence,
)
from codex_master.fleet_home_broker_transport import BrokerPeer


SCRIPT = Path(__file__).parents[1] / "bin" / "codex-master-home-broker"
PEER = BrokerPeer(1234)
PRINCIPAL = PrincipalBinding("bee_1", 3, 9, 17, 29, "1" * 32, "c0,c1", 4)
IDENTITY = BrokerIdentity(
    PRINCIPAL.agent_id,
    PRINCIPAL.manifest_generation,
    PRINCIPAL.mcs_pair,
    "slot.snapshot.v1",
    9,
    "b" * 64,
    "c" * 64,
    PRINCIPAL.fencing_epoch,
)
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
EVIDENCE = KernelPeerEvidence(1234, 1000, 1000, 7, 17, 29, 9, "1" * 32, "c0,c1")


def _adapter() -> dict[str, object]:
    assert SCRIPT.is_file(), "broker adapter is missing"
    return runpy.run_path(str(SCRIPT), run_name="a3c_adapter_test")


class _Runtime:
    def __init__(self, events: list[str], gateway: bool = True) -> None:
        self.events = events
        self.gateway = gateway
        self.closed: list[int] = []

    def is_root_system_bus_gateway(self) -> bool:
        self.events.append("gateway")
        return self.gateway

    def read_kernel_peer_evidence(self, peer: BrokerPeer) -> KernelPeerEvidence:
        assert peer == PEER
        self.events.append("evidence")
        return EVIDENCE

    def close(self, fd: int) -> None:
        self.closed.append(fd)


class _Resolver:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def resolve_principal(self, evidence: KernelPeerEvidence) -> PrincipalBinding:
        assert evidence == EVIDENCE
        self.events.append("resolver")
        return PRINCIPAL


class _Provider:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def project(
        self, profile_id: str, binding_id: str, generation: int, provider: str
    ) -> CredentialProjection:
        self.events.append("projection")
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


class _SystemOperations:
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


class _RecordingBoundary:
    def __init__(self, boundary: BrokerSystemBoundary, events: list[str]) -> None:
        self.boundary = boundary
        self.events = events

    def snapshot(self):
        self.events.append("snapshot")
        return self.boundary.snapshot()

    def compare_and_start(self, expected, token):
        self.events.append("compare_and_start")
        return self.boundary.compare_and_start(expected, token)


def _invoke(
    namespace: dict[str, object],
    *,
    runtime: _Runtime,
    boundary: object,
    events: list[str],
) -> BrokerStartReceipt:
    start_broker = namespace["start_broker"]
    return start_broker(
        peer=PEER,
        identity=IDENTITY,
        release=RELEASE,
        profile_id="profile.one",
        binding_id="hmac-sha256:" + "a" * 64,
        generation=9,
        provider="openai_chatgpt",
        peer_operations=runtime,
        linux_operations=_Linux(),
        principal_resolver=_Resolver(events),
        projection_provider=_Provider(events),
        boundary=boundary,
    )


def test_adapter_attests_builds_snapshots_and_starts_once_in_order() -> None:
    namespace = _adapter()
    events: list[str] = []
    runtime = _Runtime(events)
    system = _SystemOperations()
    boundary = _RecordingBoundary(BrokerSystemBoundary(system), events)
    function_globals = namespace["start_broker"].__globals__
    real_attest = function_globals["attest_kernel_peer"]
    real_build = function_globals["build_broker_system_plan"]

    def attest(*args: object, **kwargs: object):
        events.append("attest")
        return real_attest(*args, **kwargs)

    def build(*args: object, **kwargs: object):
        events.append("build")
        return real_build(*args, **kwargs)

    function_globals["attest_kernel_peer"] = attest
    function_globals["build_broker_system_plan"] = build

    receipt = _invoke(namespace, runtime=runtime, boundary=boundary, events=events)

    assert type(receipt) is BrokerStartReceipt
    assert receipt.release_id == RELEASE.release_id
    assert receipt.socket_unit == RELEASE.socket_unit
    assert events == [
        "attest",
        "gateway",
        "evidence",
        "resolver",
        "evidence",
        "projection",
        "evidence",
        "build",
        "snapshot",
        "compare_and_start",
    ]
    assert system.calls == [
        "observe",
        "observe",
        ("start", RELEASE.socket_unit),
    ]
    assert system.closed == []


def test_runtime_attestation_failure_stops_before_snapshot_or_start() -> None:
    namespace = _adapter()
    events: list[str] = []
    system = _SystemOperations()

    with pytest.raises(RuntimeBoundaryError, match="root system bus gateway required"):
        _invoke(
            namespace,
            runtime=_Runtime(events, gateway=False),
            boundary=BrokerSystemBoundary(system),
            events=events,
        )

    assert system.calls == []
    assert system.closed == []


def test_snapshot_drift_stops_before_start_and_closes_projection_once() -> None:
    namespace = _adapter()
    events: list[str] = []
    initial = _system_evidence()
    drifted = _system_evidence(enforcing=BrokerFedoraEnforcingEvidence(False))
    system = _SystemOperations((initial, drifted))

    with pytest.raises(BrokerSystemError, match="system snapshot drifted"):
        _invoke(
            namespace,
            runtime=_Runtime(events),
            boundary=BrokerSystemBoundary(system),
            events=events,
        )

    assert system.calls == ["observe", "observe"]
    assert system.closed == [101, 102]


def test_start_failure_does_not_retry_and_closes_projection_once() -> None:
    namespace = _adapter()
    events: list[str] = []
    system = _SystemOperations(start_error=RuntimeError("start failed"))

    with pytest.raises(BrokerSystemError, match="bound socket start failed"):
        _invoke(
            namespace,
            runtime=_Runtime(events),
            boundary=BrokerSystemBoundary(system),
            events=events,
        )

    assert system.calls == [
        "observe",
        "observe",
        ("start", RELEASE.socket_unit),
    ]
    assert system.closed == [101, 102]


def test_binary_is_inert_outside_injected_adapter_and_rejects_live_primitives() -> None:
    namespace = _adapter()

    assert callable(namespace["start_broker"])
    assert SCRIPT.read_text(encoding="utf-8").splitlines()[0] == "#!/usr/bin/python3"
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    forbidden_modules = {
        "importlib",
        "os",
        "pathlib",
        "socket",
        "subprocess",
        "sys",
        "urllib",
    }
    imported = {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert imported.isdisjoint(forbidden_modules)
    assert called.isdisjoint({"__import__", "eval", "exec", "open"})
    with pytest.raises(SystemExit) as exited:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exited.value.code == 78
