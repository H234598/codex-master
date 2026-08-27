from __future__ import annotations

import ast
import copy
import dataclasses
from dataclasses import replace
import gc
import inspect
import os
from pathlib import Path
import pickle
import select
import socket
import subprocess
import sys
from threading import Event, Thread
from typing import Callable
import xml.etree.ElementTree as ET

import dbus
from gi.repository import GLib
import pytest

import codex_master.fleet_root_system_bus as system_bus
import codex_master.fleet_home_broker_runtime as runtime
import codex_master.fleet_home_broker_system as broker_system
from codex_master.dynamic_teamlead import DynamicTeamleadRequest, ProfileBinding
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_protocol import PrincipalBinding
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    CredentialProjection,
    TrustedPrincipalGrantContext,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccountV2,
    FleetRuntimePrincipalV2,
    FleetSnapshotV2,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)
from codex_master.fleet_root_runtime_host import (
    FleetRootRuntimeHost,
    FleetRootRuntimeHostError,
    RootHostParticipant,
    RootHostParticipantBinding,
    RootRuntimeActivityOwnership,
)
from codex_master.fleet_root_system_bus import (
    BUS_INTERFACE,
    BUS_METHOD,
    BUS_NAME,
    BUS_PATH,
    HomeBrokerControlService,
    RootSystemBusError,
    RootSystemBusPeerAttestation,
    TrustedPrincipalGrantConsumer,
    _IssuedAttestation,
    _LinuxPeerOperations,
    _ProcObservation,
    _UnitObservation,
    _attest_peer,
    _openat2,
    _parse_cgroup,
    _selinux_context,
    _parse_stat,
)


GENERATION = 7
PEER_LABEL = b"system_u:system_r:codex_master_control_t:s0:c1,c2"
GATEWAY_LABEL = b"system_u:system_r:codex_master_control_t:s0"
INVOCATION = bytes.fromhex("11" * 16)
TL_AGENT_ID = "tl-" + "a" * 32
PROFILE_ID = "profile.one"
BINDING_ID = "hmac-sha256:" + "b" * 64
POLICY_GENERATION = 9
REGISTRY_GENERATION = 13


def release_spec() -> BrokerReleaseSpec:
    return BrokerReleaseSpec(
        1,
        "0.11.0",
        "1" * 64,
        "2" * 64,
        "CHPB/2",
        "policy-v1",
        "provider-v1",
        "3" * 64,
        "4" * 64,
        "codex-master-home-broker.socket",
        "codex-master-home-broker.service",
        "org.codex_master.HomeBrokerControl",
        "/org/codex_master/HomeBrokerControl",
        "org.codex_master.HomeBrokerControl1",
        "codex_master_home_broker_t",
        "codex_master_control_t",
        "codex_master_home_broker_runtime_t",
    )


def reconciled_host(generation: int = GENERATION) -> FleetRootRuntimeHost:
    host = FleetRootRuntimeHost()
    host.reconcile(
        tuple(
            RootHostParticipantBinding(participant, generation)
            for participant in RootHostParticipant
        )
    )
    return host


def expected_principal(**changes: object) -> PrincipalBinding:
    values = {
        "agent_id": TL_AGENT_ID,
        "manifest_generation": 3,
        "unit_generation": GENERATION,
        "cgroup_dev": 9,
        "cgroup_ino": 10,
        "invocation_id": "11" * 16,
        "mcs_pair": "c1,c2",
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


def trusted_context(**changes: object) -> TrustedPrincipalGrantContext:
    principal = changes.pop("expected_principal", expected_principal())
    account = changes.pop(
        "account",
        FleetAccountV2(
            "account-one",
            "Account One",
            Provider.OPENAI_CHATGPT,
            AuthKind.CHATGPT_SESSION,
            SecretState.CONFIGURED,
            LimitState.READY,
            True,
            None,
            None,
            None,
            credential_binding_id=BINDING_ID,
        ),
    )
    runtime_principal = changes.pop(
        "runtime_principal",
        FleetRuntimePrincipalV2(
            TL_AGENT_ID,
            account.account_id,
            PROFILE_ID,
            BINDING_ID,
            "teamleiterin",
            "persistent",
            Provider.OPENAI_CHATGPT,
            RunnerKind.CODEX_CLI,
            "gpt-5.6-terra",
            "xhigh",
            True,
        ),
    )
    values = {
        "snapshot": FleetSnapshotV2(
            2,
            REGISTRY_GENERATION,
            (account,),
            (),
            (runtime_principal,),
        ),
        "selection": DynamicTeamleadRequest(
            TL_AGENT_ID,
            account.account_id,
            REGISTRY_GENERATION,
            "gpt-5.6-terra",
            "xhigh",
        ),
        "profile_binding": ProfileBinding(PROFILE_ID, BINDING_ID),
        "expected_principal": principal,
        "identity": BrokerIdentity(
            TL_AGENT_ID,
            principal.manifest_generation,
            principal.mcs_pair,
            "slot.snapshot.v1",
            POLICY_GENERATION,
            "c" * 64,
            "d" * 64,
            principal.fencing_epoch,
        ),
    }
    values.update(changes)
    return TrustedPrincipalGrantContext(**values)


class RecordingResolver:
    def __init__(self, value: object | None = None) -> None:
        self.value = expected_principal() if value is None else value
        self.calls: list[object] = []

    def resolve_principal(self, evidence: object) -> object:
        self.calls.append(evidence)
        return self.value


class RecordingProjectionProvider:
    def __init__(
        self, value: object | None = None, error: Exception | None = None
    ) -> None:
        self.value = (
            CredentialProjection(
                PROFILE_ID,
                BINDING_ID,
                POLICY_GENERATION,
                Provider.OPENAI_CHATGPT.value,
                (101, 102),
            )
            if value is None
            else value
        )
        self.calls: list[tuple[object, ...]] = []
        self.error = error

    def project(self, *values: object) -> object:
        self.calls.append(values)
        if self.error is not None:
            raise self.error
        return self.value


class ProjectionObject:
    def __init__(self, fds: object) -> None:
        self.fds = fds


def raw_credentials(
    *,
    pid: int = 1234,
    uid: int = 1000,
    groups: tuple[int, ...] = (1000, 1001),
    label: bytes = PEER_LABEL,
) -> dbus.Dictionary:
    return dbus.Dictionary(
        {
            "ProcessID": dbus.UInt32(pid),
            "UnixUserID": dbus.UInt32(uid),
            "UnixGroupIDs": dbus.Array(
                (dbus.UInt32(group) for group in groups), signature="u"
            ),
            "LinuxSecurityLabel": dbus.Array(
                (dbus.Byte(byte) for byte in label + b"\0"), signature="y"
            ),
        },
        signature="sv",
    )


class ScriptedOperations:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.open_fds: set[int] = set()
        self._next_fd = 10
        self.alive = [True] * 16
        self.proc = [
            _ProcObservation(444, 1000, "/user.slice/example.scope", PEER_LABEL),
            _ProcObservation(444, 1000, "/user.slice/example.scope", PEER_LABEL),
        ]
        self.stats = [(9, 10), (9, 10)]
        self.units = [
            _UnitObservation(
                "/org/freedesktop/systemd1/unit/example_2escope",
                "example.scope",
                INVOCATION,
                "/user.slice/example.scope",
            ),
            _UnitObservation(
                "/org/freedesktop/systemd1/unit/example_2escope",
                "example.scope",
                INVOCATION,
                "/user.slice/example.scope",
            ),
        ]
        self.enforcing = True
        self.self_label = GATEWAY_LABEL

    def _fd(self, call: str) -> int:
        self.calls.append(call)
        fd = self._next_fd
        self._next_fd += 1
        self.open_fds.add(fd)
        return fd

    def pidfd_open(self, pid: int) -> int:
        assert type(pid) is int
        return self._fd("pidfd_open")

    def require_alive(self, pidfd: int) -> None:
        assert pidfd in self.open_fds
        self.calls.append("require_alive")
        if not self.alive.pop(0):
            raise RootSystemBusError("peer_exited")

    def open_proc_root(self) -> int:
        return self._fd("open_proc_root")

    def open_cgroup_root(self) -> int:
        return self._fd("open_cgroup_root")

    def open_proc_pid(self, proc_root: int, pid: int) -> int:
        assert proc_root in self.open_fds and type(pid) is int
        return self._fd("open_proc_pid")

    def read_proc(self, proc_fd: int) -> _ProcObservation:
        assert proc_fd in self.open_fds
        self.calls.append("read_proc")
        return self.proc.pop(0)

    def open_cgroup(self, cgroup_root: int, path: str) -> int:
        assert cgroup_root in self.open_fds and type(path) is str
        return self._fd("open_cgroup")

    def cgroup_identity(self, cgroup_fd: int) -> tuple[int, int]:
        assert cgroup_fd in self.open_fds
        self.calls.append("cgroup_identity")
        return self.stats.pop(0)

    def read_unit(self, pidfd: int) -> _UnitObservation:
        assert pidfd in self.open_fds
        self.calls.append("read_unit")
        return self.units.pop(0)

    def read_enforcing(self) -> bool:
        self.calls.append("read_enforcing")
        return self.enforcing

    def read_self_label(self, proc_root: int) -> bytes:
        assert proc_root in self.open_fds
        self.calls.append("read_self_label")
        return self.self_label

    def close(self, fd: int) -> None:
        assert fd in self.open_fds
        self.calls.append("close")
        self.open_fds.remove(fd)


class GrantOperations(ScriptedOperations):
    def __init__(self) -> None:
        super().__init__()
        self.projection_fds: set[int] = {101, 102}
        self.closed_projection: list[int] = []
        self.fail_projection_close = False

    def close(self, fd: int) -> None:
        if fd in self.projection_fds:
            self.projection_fds.remove(fd)
            self.closed_projection.append(fd)
            if self.fail_projection_close:
                self.fail_projection_close = False
                raise OSError("private close detail")
            return
        super().close(fd)


def r2a_evidence(**changes: object) -> broker_system.BrokerSystemEvidence:
    values = {
        "directory": broker_system.BrokerDirectoryEvidence(
            "/run/codex-master-home-broker",
            broker_system.BrokerNodeType.DIRECTORY,
            "root",
            "codex-master-broker",
            0o750,
            17,
            29,
        ),
        "socket": broker_system.BrokerSocketEvidence(
            "/run/codex-master-home-broker/broker.sock",
            broker_system.BrokerNodeType.SOCKET,
            "root",
            "codex-master-broker",
            0o660,
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
            17,
            31,
        ),
        "system_bus": broker_system.BrokerSystemBusEvidence(
            BUS_NAME, BUS_PATH, BUS_INTERFACE
        ),
        "selinux": broker_system.BrokerSelinuxEvidence(
            "codex_master_home_broker_t",
            "codex_master_control_t",
            "codex_master_home_broker_runtime_t",
        ),
        "enforcing": broker_system.BrokerFedoraEnforcingEvidence(True),
        "mcs": broker_system.BrokerMcsEvidence("c1,c2"),
        "unit": broker_system.BrokerUnitEvidence(
            "codex-master-home-broker.socket",
            "codex-master-home-broker.service",
            False,
            True,
        ),
        "joint_release": broker_system.BrokerJointReleaseEvidence(
            1,
            "0.11.0",
            "1" * 64,
            "2" * 64,
            "CHPB/2",
            "policy-v1",
            "provider-v1",
            "3" * 64,
            "4" * 64,
        ),
    }
    values.update(changes)
    return broker_system.BrokerSystemEvidence(**values)


class R2AOperations:
    def __init__(
        self,
        observations: tuple[broker_system.BrokerSystemEvidence, ...] = (),
        start_error: Exception | None = None,
        fail_close: bool = False,
    ) -> None:
        self.observations = observations or (r2a_evidence(),)
        self.start_error = start_error
        self.fail_close = fail_close
        self.calls: list[object] = []
        self.closed: list[int] = []

    def _observe_broker_system(self) -> broker_system.BrokerSystemEvidence:
        self.calls.append("observe")
        index = min(self.calls.count("observe") - 1, len(self.observations) - 1)
        return self.observations[index]

    def _start_bound_socket_unit(self, socket_unit: str) -> None:
        self.calls.append(("start", socket_unit))
        if self.start_error is not None:
            raise self.start_error

    def close(self, fd: int) -> None:
        self.closed.append(fd)
        if self.fail_close:
            raise OSError("private close detail")


def reattest_operations() -> GrantOperations:
    operations = GrantOperations()
    operations.alive *= 2
    operations.proc *= 2
    operations.stats *= 2
    operations.units *= 2
    return operations


def _trusted_service(
    private_bus: PrivateBus,
    *,
    context: TrustedPrincipalGrantContext | None = None,
    resolver: RecordingResolver | None = None,
    provider: RecordingProjectionProvider | None = None,
    operations: GrantOperations | None = None,
    boundary: broker_system.BrokerSystemBoundary | None = None,
    r2a_operations: R2AOperations | None = None,
    credential_reader: Callable[[str], object] | None = None,
) -> tuple[
    FleetRootRuntimeHost,
    RecordingResolver,
    RecordingProjectionProvider,
    GrantOperations,
    broker_system.BrokerSystemBoundary,
    TrustedPrincipalGrantConsumer,
    HomeBrokerControlService,
]:
    host = reconciled_host()
    resolver = resolver or RecordingResolver()
    provider = provider or RecordingProjectionProvider()
    operations = operations or reattest_operations()
    r2a_operations = r2a_operations or R2AOperations()
    boundary = boundary or broker_system.BrokerSystemBoundary(r2a_operations)
    consumer = TrustedPrincipalGrantConsumer(
        context or trusted_context(),
        resolver,
        provider,
        boundary,
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=credential_reader or (lambda _sender: raw_credentials()),
    )
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    return host, resolver, provider, operations, boundary, consumer, service


def _consumer_for(private_bus: PrivateBus) -> TrustedPrincipalGrantConsumer:
    return TrustedPrincipalGrantConsumer(
        trusted_context(),
        RecordingResolver(),
        RecordingProjectionProvider(),
        broker_system.BrokerSystemBoundary(R2AOperations()),
        private_bus_address=private_bus.address,
        _operations=reattest_operations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )


def mutate_recheck(
    operations: GrantOperations,
    credentials: list[dbus.Dictionary],
    mutation: str,
    *,
    post_projection: bool = False,
) -> None:
    offset = 2 if post_projection else 0
    credential_offset = 3 if post_projection else 0
    if mutation == "exit":
        operations.alive[13 if post_projection else 0] = False
    elif mutation in {"pid", "uid", "groups"}:
        changes = {
            "pid": {"pid": 1235},
            "uid": {"uid": 1001},
            "groups": {"groups": (1000, 1002)},
        }[mutation]
        for index in range(credential_offset, credential_offset + 3):
            credentials[index] = raw_credentials(**changes)
    elif mutation == "effective_gid":
        for index in range(offset, offset + 2):
            operations.proc[index] = replace(operations.proc[index], effective_gid=1001)
    elif mutation == "start_time":
        for index in range(offset, offset + 2):
            operations.proc[index] = replace(operations.proc[index], start_time=445)
    elif mutation in {"cgroup_device", "cgroup_inode"}:
        replacement = (11, 10) if mutation == "cgroup_device" else (9, 11)
        for index in range(offset, offset + 2):
            operations.stats[index] = replacement
    elif mutation == "unit_name":
        for index in range(offset, offset + 2):
            operations.units[index] = replace(
                operations.units[index], name="other.scope"
            )
    elif mutation == "invocation_id":
        for index in range(offset, offset + 2):
            operations.units[index] = replace(
                operations.units[index], invocation_id=bytes.fromhex("22" * 16)
            )
    elif mutation in {"label", "mcs"}:
        label = (
            b"system_u:system_r:peer_t:s0:c1,c2"
            if mutation == "label"
            else b"system_u:system_r:peer_t:s0:c1,c3"
        )
        for index in range(credential_offset, credential_offset + 3):
            credentials[index] = raw_credentials(label=label)
        for index in range(offset, offset + 2):
            operations.proc[index] = replace(
                operations.proc[index], security_label=label
            )
    else:
        raise AssertionError("unknown test mutation")


class CleanupFailingOperations(ScriptedOperations):
    def __init__(self) -> None:
        super().__init__()
        self.close_attempts: list[int] = []
        self._failed_once = False

    def close(self, fd: int) -> None:
        assert fd in self.open_fds
        self.calls.append("close")
        self.close_attempts.append(fd)
        self.open_fds.remove(fd)
        if not self._failed_once:
            self._failed_once = True
            raise OSError("private close detail")


class ProvenanceLinuxOperations(_LinuxPeerOperations):
    def __init__(self, system_bus: dbus.bus.BusConnection) -> None:
        super().__init__(system_bus)
        self.pid_events: list[tuple[str, int]] = []

    def pidfd_open(self, pid: int) -> int:
        self.pid_events.append(("pidfd_open", pid))
        return super().pidfd_open(pid)

    def open_proc_pid(self, proc_root: int, pid: int) -> int:
        self.pid_events.append(("open_proc_pid", pid))
        return super().open_proc_pid(proc_root, pid)


class PrivateBus:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [
                "dbus-daemon",
                "--session",
                "--nofork",
                "--print-address=1",
                "--print-pid=1",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.process.stdout is not None
        self.address = self.process.stdout.readline().strip()
        assert self.address
        assert self.process.stdout.readline().strip().isdigit()

    def close(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=5)
        assert self.process.returncode is not None


@pytest.fixture
def private_bus() -> PrivateBus:
    bus = PrivateBus()
    try:
        yield bus
    finally:
        bus.close()


def assert_code(code: str, operation: Callable[[], object]) -> None:
    with pytest.raises(RootSystemBusError) as caught:
        operation()
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert code not in repr(caught.value)


def test_trusted_principal_grant_consumer_surface_is_narrow() -> None:
    assert tuple(inspect.signature(TrustedPrincipalGrantConsumer).parameters) == (
        "context",
        "principal_resolver",
        "projection_provider",
        "boundary",
        "private_bus_address",
        "_operations",
        "_credential_reader",
    )
    assert "__call__" not in TrustedPrincipalGrantConsumer.__dict__
    assert tuple(inspect.signature(HomeBrokerControlService).parameters) == (
        "host",
        "generation",
        "release",
        "consumer",
        "private_bus_address",
        "_operations",
        "_credential_reader",
    )


def test_trusted_consumer_composes_r2b_to_r2a_with_same_ownership_once(
    private_bus: PrivateBus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = reconciled_host()
    resolver = RecordingResolver()
    provider = RecordingProjectionProvider()
    operations = reattest_operations()
    issuer_calls: list[tuple[object, ...]] = []
    claim_calls = 0
    real_issuer = runtime._issue_start_grant
    real_claim = runtime._StartGrantState.claim

    def observing_issuer(binding: tuple[object, ...]) -> object:
        issuer_calls.append(binding)
        return real_issuer(binding)

    def observing_claim(state: runtime._StartGrantState) -> bool:
        nonlocal claim_calls
        claim_calls += 1
        return real_claim(state)

    monkeypatch.setattr(runtime, "_issue_start_grant", observing_issuer)
    monkeypatch.setattr(runtime._StartGrantState, "claim", observing_claim)
    r2a_operations = R2AOperations()
    boundary = broker_system.BrokerSystemBoundary(r2a_operations)
    consumer = TrustedPrincipalGrantConsumer(
        trusted_context(),
        resolver,
        provider,
        boundary,
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert service._handle_start(":1.1") is None
        assert len(resolver.calls) == 1
        assert provider.calls == [
            (
                PROFILE_ID,
                BINDING_ID,
                POLICY_GENERATION,
                Provider.OPENAI_CHATGPT.value,
            )
        ]
        assert len(issuer_calls) == 1
        assert claim_calls == 1
        assert len(boundary._receipts) == 1
        active = consumer._active_start
        assert active is not None
        receipt = active.receipt
        ownership = active.ownership
        assert receipt.ownership is ownership
        assert receipt.projection is provider.value
        assert operations.calls.count("pidfd_open") == 2
        assert operations.open_fds == set()
        assert r2a_operations.calls == [
            "observe",
            "observe",
            ("start", "codex-master-home-broker.socket"),
        ]
        assert host.snapshot().active_principals_or_agents == 1
        service.close()
        assert r2a_operations.closed == [101, 102]
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        service.close()


@pytest.mark.parametrize("failure", ("drift", "start"))
def test_trusted_consumer_r2a_drift_or_start_failure_ends_same_ownership_and_closes_once(
    private_bus: PrivateBus,
    failure: str,
) -> None:
    initial = r2a_evidence()
    if failure == "drift":
        r2a_operations = R2AOperations(
            (initial, replace(initial, enforcing=broker_system.BrokerFedoraEnforcingEvidence(False)))
        )
    else:
        r2a_operations = R2AOperations(start_error=RuntimeError("start failed"))
    host, _resolver, _provider, operations, boundary, consumer, service = (
        _trusted_service(private_bus, r2a_operations=r2a_operations)
    )
    before = host.snapshot()
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert operations.open_fds == set()
        assert boundary._receipts == {}
        assert r2a_operations.closed == [101, 102]
        assert r2a_operations.calls.count(("start", "codex-master-home-broker.socket")) <= 1
        assert host.snapshot().active_principals_or_agents == 0
        assert host.snapshot().runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        service.close()


def test_trusted_consumer_r2a_preclaim_snapshot_mismatch_closes_projection_once_and_ends_ownership(
    private_bus: PrivateBus,
) -> None:
    r2a_operations = R2AOperations(
        (r2a_evidence(enforcing=broker_system.BrokerFedoraEnforcingEvidence(False)),)
    )
    host, _resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(private_bus, r2a_operations=r2a_operations)
    )
    before = host.snapshot()
    try:
        with pytest.raises(RootSystemBusError) as caught:
            service._handle_start(":1.1")
        assert caught.value.code == "trusted_consumer_start_failed"
        assert len(provider.calls) == 1
        assert r2a_operations.calls == ["observe"]
        assert r2a_operations.closed == [101, 102]
        assert operations.closed_projection == []
        assert operations.projection_fds == {101, 102}
        assert boundary._receipts == {}
        assert consumer._active_start is None
        assert host.snapshot().active_principals_or_agents == 0
        assert host.snapshot().runtime_broker_epoch == before.runtime_broker_epoch + 2
        service.close()
        assert r2a_operations.closed == [101, 102]
    finally:
        service.close()


def test_trusted_consumer_name_loss_releases_success_receipt_and_ownership_once(
    private_bus: PrivateBus,
) -> None:
    r2a_operations = R2AOperations()
    host, _resolver, _provider, _operations, boundary, consumer, service = (
        _trusted_service(private_bus, r2a_operations=r2a_operations)
    )

    try:
        service._handle_start(":1.1")
        owner = service._bus.get_unique_name()
        service._name_owner_changed(BUS_NAME, owner, "")

        assert r2a_operations.closed == [101, 102]
        assert host.snapshot().active_principals_or_agents == 0
        assert host.snapshot().reconciled is False
        assert len(boundary._receipts) == 1
        service.close()
        assert r2a_operations.closed == [101, 102]
        assert consumer._active_start is None
    finally:
        service.close()


def test_second_start_while_trusted_receipt_is_active_fails_before_projection(
    private_bus: PrivateBus,
) -> None:
    r2a_operations = R2AOperations()
    host, _resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(private_bus, r2a_operations=r2a_operations)
    )

    try:
        service._handle_start(":1.1")
        provider_calls = list(provider.calls)
        r2a_calls = list(r2a_operations.calls)

        with pytest.raises(RootSystemBusError) as caught:
            service._handle_start(":1.1")

        assert caught.value.code == "trusted_consumer_start_active"
        assert provider.calls == provider_calls
        assert r2a_operations.calls == r2a_calls
        assert len(boundary._receipts) == 1
        assert operations.calls.count("pidfd_open") == 2
        assert host.snapshot().active_principals_or_agents == 1
    finally:
        service.close()


def test_r2b_service_and_consumer_have_no_generic_sink_surface() -> None:
    source_path = Path(__file__).parents[1] / "src/codex_master/fleet_root_system_bus.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))

    assert "sink" not in inspect.signature(TrustedPrincipalGrantConsumer).parameters
    assert "Callable[[StartGrant" not in source
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TrustedPrincipalGrantConsumer"
        and any(isinstance(argument, ast.Lambda) for argument in node.args)
        for node in ast.walk(tree)
    )
    handoff = inspect.getsource(HomeBrokerControlService._handoff)
    assert "self._consumer(" not in handoff
    assert "else:" not in handoff


def test_trusted_handoff_forge_or_replay_never_reaches_r2a(
    private_bus: PrivateBus,
) -> None:
    def make_service() -> tuple[
        FleetRootRuntimeHost,
        R2AOperations,
        TrustedPrincipalGrantConsumer,
        HomeBrokerControlService,
    ]:
        r2a_operations = R2AOperations()
        host, _resolver, _provider, _operations, _boundary, consumer, service = (
            _trusted_service(private_bus, r2a_operations=r2a_operations)
        )
        return host, r2a_operations, consumer, service

    def issue(
        host: FleetRootRuntimeHost, service: HomeBrokerControlService
    ) -> tuple[RootSystemBusPeerAttestation, object, RootRuntimeActivityOwnership]:
        ownership = host.begin_principal_or_agent()
        evidence = system_bus._attest_peer(
            ":1.1",
            service._credential_reader,
            service._operations,
            service._release,
        )
        attestation, issued = service._issue_handoff(":1.1", evidence, ownership)
        return attestation, issued, ownership

    host, r2a_operations, consumer, service = make_service()
    attestation, issued, ownership = issue(host, service)
    forged_attestation = object.__new__(RootSystemBusPeerAttestation)
    for field in dataclasses.fields(attestation):
        object.__setattr__(forged_attestation, field.name, getattr(attestation, field.name))
    with pytest.raises(RootSystemBusError) as caught:
        service._handoff(forged_attestation, ownership, issued)
    assert caught.value.code == "handoff_invalid"
    assert r2a_operations.calls == []
    host.end_principal_or_agent(ownership)
    service.close()
    consumer.close()

    host, r2a_operations, consumer, service = make_service()
    attestation, issued, ownership = issue(host, service)
    forged_issued = object.__new__(_IssuedAttestation)
    for field in dataclasses.fields(issued):
        object.__setattr__(forged_issued, field.name, getattr(issued, field.name))
    with pytest.raises(RootSystemBusError) as caught:
        service._handoff(attestation, ownership, forged_issued)
    assert caught.value.code == "handoff_invalid"
    assert r2a_operations.calls == []
    host.end_principal_or_agent(ownership)
    service.close()
    consumer.close()

    host, r2a_operations, consumer, service = make_service()
    attestation, issued, ownership = issue(host, service)
    other_ownership = host.begin_principal_or_agent()
    with pytest.raises(RootSystemBusError) as caught:
        service._handoff(attestation, other_ownership, issued)
    assert caught.value.code == "handoff_invalid"
    assert r2a_operations.calls == []
    host.end_principal_or_agent(ownership)
    host.end_principal_or_agent(other_ownership)
    service.close()
    consumer.close()

    host, r2a_operations, consumer, service = make_service()
    attestation, issued, ownership = issue(host, service)
    service._handoff(attestation, ownership, issued)
    calls_after_legal_handoff = list(r2a_operations.calls)
    with pytest.raises(RootSystemBusError) as caught:
        service._handoff(attestation, ownership, issued)
    assert caught.value.code == "handoff_invalid"
    assert r2a_operations.calls == calls_after_legal_handoff
    service.close()
    consumer.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "exit",
        "pid",
        "uid",
        "effective_gid",
        "groups",
        "start_time",
        "cgroup_device",
        "cgroup_inode",
        "unit_name",
        "invocation_id",
        "label",
        "mcs",
    ),
)
def test_trusted_consumer_blocks_preprojection_reattestation_drift(
    private_bus: PrivateBus,
    mutation: str,
) -> None:
    operations = reattest_operations()
    credentials = [raw_credentials() for _ in range(6)]
    mutate_recheck(operations, credentials, mutation)
    reader_calls: list[str] = []

    def reader(sender: str) -> object:
        reader_calls.append(sender)
        return credentials.pop(0)

    host, resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(
            private_bus,
            operations=operations,
            credential_reader=reader,
        )
    )
    before = host.snapshot()
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert resolver.calls == []
        assert provider.calls == []
        assert boundary._operations.calls == []
        assert operations.closed_projection == []
        assert operations.open_fds == set()
        assert len(set(reader_calls)) == 1
        after = host.snapshot()
        assert after.active_principals_or_agents == 0
        assert after.runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        consumer.close()
        service.close()


def test_trusted_consumer_binds_original_method_sender_before_recheck(
    private_bus: PrivateBus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(private_bus)
    )
    original = HomeBrokerControlService._issue_handoff

    def mutate_attestation_sender(
        bound_service: HomeBrokerControlService,
        sender: str,
        evidence: object,
        ownership: RootRuntimeActivityOwnership,
    ) -> tuple[RootSystemBusPeerAttestation, object]:
        attestation, issued = original(bound_service, sender, evidence, ownership)
        object.__setattr__(attestation, "bus_unique_name", ":1.999")
        return attestation, issued

    monkeypatch.setattr(
        HomeBrokerControlService,
        "_issue_handoff",
        mutate_attestation_sender,
    )
    try:
        with pytest.raises(RootSystemBusError) as caught:
            service._handle_start(":1.1")
        assert caught.value.code == "handoff_invalid"
        assert resolver.calls == []
        assert provider.calls == []
        assert boundary._operations.calls == []
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        consumer.close()
        service.close()


def test_trusted_consumer_binds_service_generation_before_projection(
    private_bus: PrivateBus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, resolver, provider, _operations, boundary, consumer, service = (
        _trusted_service(private_bus)
    )
    original = HomeBrokerControlService._issue_handoff

    def mutate_service_generation(
        bound_service: HomeBrokerControlService,
        sender: str,
        evidence: object,
        ownership: RootRuntimeActivityOwnership,
    ) -> tuple[RootSystemBusPeerAttestation, object]:
        attestation, issued = original(bound_service, sender, evidence, ownership)
        object.__setattr__(attestation, "service_generation", GENERATION + 1)
        return attestation, issued

    monkeypatch.setattr(
        HomeBrokerControlService,
        "_issue_handoff",
        mutate_service_generation,
    )
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert resolver.calls == []
        assert provider.calls == []
        assert boundary._operations.calls == []
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        consumer.close()
        service.close()


def test_postprojection_reattestation_drift_closes_projection_and_ownership(
    private_bus: PrivateBus,
) -> None:
    operations = reattest_operations()
    credentials = [raw_credentials() for _ in range(6)]
    mutate_recheck(
        operations,
        credentials,
        "start_time",
        post_projection=True,
    )
    host, resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(
            private_bus,
            operations=operations,
            credential_reader=lambda _sender: credentials.pop(0),
        )
    )
    before = host.snapshot()
    try:
        with pytest.raises(RootSystemBusError) as caught:
            service._handle_start(":1.1")
        assert caught.value.code == "consumer_failed"
        assert len(resolver.calls) == 1
        assert len(provider.calls) == 1
        assert boundary._operations.calls == []
        assert operations.closed_projection == [101, 102]
        assert operations.projection_fds == set()
        assert operations.open_fds == set()
        after = host.snapshot()
        assert after.active_principals_or_agents == 0
        assert after.runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        consumer.close()
        service.close()


@pytest.mark.parametrize(
    "case",
    (
        "unknown_resolver",
        "duplicate_principal",
        "extra_active_principal",
        "disabled_principal",
        "wrong_account",
        "duplicate_account",
        "wrong_profile",
        "wrong_principal_binding",
        "wrong_account_binding",
        "wrong_provider",
        "wrong_class",
        "wrong_lifecycle",
        "wrong_model",
        "wrong_reasoning",
        "snapshot_generation",
        "principal_cgroup",
        "principal_invocation",
        "principal_mcs",
        "principal_unit_generation",
        "identity_agent",
        "identity_manifest",
        "identity_mcs",
        "identity_fencing",
        "identity_policy_generation",
    ),
)
def test_trusted_principal_registry_and_identity_drift_block_before_projection(
    private_bus: PrivateBus,
    case: str,
) -> None:
    context = trusted_context()
    resolver = RecordingResolver()
    principal = context.snapshot.runtime_principals[0]
    account = context.snapshot.accounts[0]
    if case == "unknown_resolver":
        resolver = RecordingResolver(object())
    elif case == "duplicate_principal":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(principal, principal),
            ),
        )
    elif case == "extra_active_principal":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(
                    principal,
                    replace(principal, principal_id="tl-" + "f" * 32),
                ),
            ),
        )
    elif case == "disabled_principal":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(replace(principal, enabled=False),),
            ),
        )
    elif case == "wrong_account":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(replace(principal, account_id="missing"),),
            ),
        )
    elif case == "duplicate_account":
        context = replace(
            context,
            snapshot=replace(context.snapshot, accounts=(account, account)),
        )
    elif case == "wrong_profile":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(replace(principal, profile_id="profile.two"),),
            ),
        )
    elif case == "wrong_principal_binding":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(
                    replace(principal, credential_binding_id="hmac-sha256:" + "e" * 64),
                ),
            ),
        )
    elif case == "wrong_account_binding":
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                accounts=(
                    replace(account, credential_binding_id="hmac-sha256:" + "e" * 64),
                ),
            ),
        )
    elif case in {
        "wrong_provider",
        "wrong_class",
        "wrong_lifecycle",
        "wrong_model",
        "wrong_reasoning",
    }:
        changes = {
            "wrong_provider": {"provider": Provider.OPENAI_API},
            "wrong_class": {"class_id": "workerin"},
            "wrong_lifecycle": {"lifecycle": "ephemeral"},
            "wrong_model": {"model": "gpt-5.6"},
            "wrong_reasoning": {"reasoning": "high"},
        }[case]
        context = replace(
            context,
            snapshot=replace(
                context.snapshot,
                runtime_principals=(replace(principal, **changes),),
            ),
        )
    elif case == "snapshot_generation":
        context = replace(
            context,
            snapshot=replace(context.snapshot, generation=REGISTRY_GENERATION + 1),
        )
    elif case.startswith("principal_"):
        changes = {
            "principal_cgroup": {"cgroup_ino": 11},
            "principal_invocation": {"invocation_id": "22" * 16},
            "principal_mcs": {"mcs_pair": "c1,c3"},
            "principal_unit_generation": {"unit_generation": GENERATION + 1},
        }[case]
        context = replace(
            context,
            expected_principal=replace(context.expected_principal, **changes),
        )
        resolver = RecordingResolver(context.expected_principal)
    elif case.startswith("identity_"):
        changes = {
            "identity_agent": {"agent_id": "tl-" + "e" * 32},
            "identity_manifest": {"manifest_generation": 4},
            "identity_mcs": {"mcs_pair": "c1,c3"},
            "identity_fencing": {"fencing_epoch": 5},
        }.get(case)
        if changes is None:
            object.__setattr__(context.identity, "policy_generation", 0)
        else:
            context = replace(context, identity=replace(context.identity, **changes))
    else:
        raise AssertionError("unknown context case")

    host, _resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(
            private_bus,
            context=context,
            resolver=resolver,
        )
    )
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert provider.calls == []
        assert boundary._operations.calls == []
        assert operations.closed_projection == []
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        consumer.close()
        service.close()


@pytest.mark.parametrize(
    ("case", "expected_closed"),
    (
        ("provider_exception", ()),
        ("wrong_type", (101, 102)),
        ("empty", ()),
        ("duplicate", (101,)),
        ("negative", (101,)),
        ("profile", (101, 102)),
        ("binding", (101, 102)),
        ("generation", (101, 102)),
        ("provider", (101, 102)),
    ),
)
def test_projection_failures_close_only_returned_valid_fds_once(
    private_bus: PrivateBus,
    case: str,
    expected_closed: tuple[int, ...],
) -> None:
    values = {
        "profile_id": PROFILE_ID,
        "binding_id": BINDING_ID,
        "generation": POLICY_GENERATION,
        "provider": Provider.OPENAI_CHATGPT.value,
        "fds": (101, 102),
    }
    if case == "provider_exception":
        provider = RecordingProjectionProvider(error=RuntimeError("private detail"))
    elif case == "wrong_type":
        provider = RecordingProjectionProvider(ProjectionObject((101, 102)))
    else:
        changes = {
            "empty": {"fds": ()},
            "duplicate": {"fds": (101, 101)},
            "negative": {"fds": (101, -1)},
            "profile": {"profile_id": "profile.two"},
            "binding": {"binding_id": "hmac-sha256:" + "e" * 64},
            "generation": {"generation": POLICY_GENERATION + 1},
            "provider": {"provider": Provider.OPENAI_API.value},
        }[case]
        values.update(changes)
        provider = RecordingProjectionProvider(CredentialProjection(**values))
    operations = reattest_operations()
    operations.projection_fds = set(expected_closed)
    host, _resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(
            private_bus,
            provider=provider,
            operations=operations,
        )
    )
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert len(provider.calls) == 1
        assert boundary._operations.calls == []
        assert operations.closed_projection == list(expected_closed)
        assert operations.projection_fds == set()
        assert operations.open_fds == set()
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        consumer.close()
        service.close()


@pytest.mark.parametrize("issuer_result", ("exception", "wrong_type"))
def test_grant_issuer_failure_closes_projection_before_sink(
    private_bus: PrivateBus,
    monkeypatch: pytest.MonkeyPatch,
    issuer_result: str,
) -> None:
    def broken_issuer(_binding: tuple[object, ...]) -> object:
        if issuer_result == "exception":
            raise RuntimeError("private issuer detail")
        return object()

    monkeypatch.setattr(runtime, "_issue_start_grant", broken_issuer)
    host, _resolver, provider, operations, boundary, consumer, service = (
        _trusted_service(private_bus)
    )
    try:
        with pytest.raises(RootSystemBusError):
            service._handle_start(":1.1")
        assert len(provider.calls) == 1
        assert boundary._operations.calls == []
        assert operations.closed_projection == [101, 102]
        assert operations.projection_fds == set()
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        consumer.close()
        service.close()


def test_projection_close_failure_is_sparse_terminal_and_not_retried(
    private_bus: PrivateBus,
) -> None:
    r2a_operations = R2AOperations(fail_close=True)
    host, _resolver, _provider, _operations, _boundary, consumer, service = (
        _trusted_service(private_bus, r2a_operations=r2a_operations)
    )
    try:
        service._handle_start(":1.1")
        with pytest.raises(RootSystemBusError) as caught:
            service.close()
        assert caught.value.code == "trusted_consumer_cleanup_failed"
        assert caught.value.args == ("trusted_consumer_cleanup_failed",)
        assert r2a_operations.closed == [101, 102]
        assert host.snapshot().active_principals_or_agents == 0
        service.close()
        assert r2a_operations.closed == [101, 102]
    finally:
        service.close()


def test_service_close_closes_bound_trusted_consumer_idempotently(
    private_bus: PrivateBus,
) -> None:
    _host, _resolver, _provider, _operations, _boundary, consumer, service = (
        _trusted_service(private_bus)
    )

    service.close()
    service.close()
    assert consumer._closed is True
    consumer.close()


def test_trusted_consumer_connection_close_failure_is_terminal_without_retry(
    private_bus: PrivateBus,
) -> None:
    class CloseFailingBus:
        def __init__(self) -> None:
            self.calls = 0

        def close(self) -> None:
            self.calls += 1
            raise OSError("private close detail")

    _host, _resolver, _provider, _operations, _boundary, consumer, service = (
        _trusted_service(private_bus)
    )
    first = CloseFailingBus()
    second = CloseFailingBus()
    consumer._system_bus = first
    consumer._credential_bus = second
    try:
        with pytest.raises(RootSystemBusError) as caught:
            consumer.close()
        assert caught.value.code == "trusted_consumer_cleanup_failed"
        assert first.calls == second.calls == 1
        consumer.close()
        assert first.calls == second.calls == 1
    finally:
        service.close()


def test_service_close_continues_after_trusted_consumer_cleanup_failure(
    private_bus: PrivateBus,
) -> None:
    class CloseBus:
        def __init__(self, *, fail: bool) -> None:
            self.fail = fail
            self.calls = 0

        def close(self) -> None:
            self.calls += 1
            if self.fail:
                raise OSError("private close detail")

    _host, _resolver, _provider, _operations, _boundary, consumer, service = (
        _trusted_service(private_bus)
    )
    consumer_bus = CloseBus(fail=True)
    service_bus = CloseBus(fail=False)
    consumer._system_bus = consumer_bus
    service._system_bus = service_bus

    with pytest.raises(RootSystemBusError) as caught:
        service.close()

    assert caught.value.code == "trusted_consumer_cleanup_failed"
    assert consumer_bus.calls == service_bus.calls == 1
    service.close()
    assert consumer_bus.calls == service_bus.calls == 1


def test_private_bus_surface_name_and_empty_signature(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    loop_thread = Thread(target=service.run)
    loop_thread.start()
    try:
        bus = dbus.bus.BusConnection(private_bus.address)
        xml = dbus.Interface(
            bus.get_object(BUS_NAME, BUS_PATH),
            "org.freedesktop.DBus.Introspectable",
        ).Introspect()
        root = ET.fromstring(str(xml))
        methods = root.findall(f".//interface[@name='{BUS_INTERFACE}']/method")
        assert [method.attrib["name"] for method in methods] == [BUS_METHOD]
        assert methods[0].findall("arg") == []

        assert_code(
            "name_unavailable",
            lambda: HomeBrokerControlService(
                reconciled_host(),
                GENERATION,
                release_spec(),
                _consumer_for(private_bus),
                private_bus_address=private_bus.address,
                _operations=ScriptedOperations(),
                _credential_reader=lambda _sender: raw_credentials(),
            ),
        )
        bus.close()
    finally:
        service.close()
        service.close()
        loop_thread.join(5)
        assert not loop_thread.is_alive()


def test_unknown_bus_boundary_blocks_before_begin(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    credential_calls: list[None] = []
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
    )
    real_reader = service._credential_reader

    def observing_reader(sender: str) -> object:
        credential_calls.append(None)
        return real_reader(sender)

    service._credential_reader = observing_reader
    loop_ready = Event()
    GLib.idle_add(lambda: loop_ready.set() and False)
    loop_thread = Thread(target=service.run)
    loop_thread.start()
    assert loop_ready.wait(5)
    client = dbus.bus.BusConnection(private_bus.address)
    try:
        messages = (
            dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH + "/Unknown",
                interface=BUS_INTERFACE,
                method=BUS_METHOD,
            ),
            dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH,
                interface=BUS_INTERFACE + ".Unknown",
                method=BUS_METHOD,
            ),
            dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH,
                interface=BUS_INTERFACE,
                method=BUS_METHOD + "Unknown",
            ),
            dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH,
                interface=BUS_INTERFACE,
                method=BUS_METHOD,
            ),
        )
        messages[-1].append("forbidden", signature="s")
        for message in messages:
            before = host.snapshot()
            with pytest.raises(dbus.DBusException):
                client.send_message_with_reply_and_block(message)
            assert host.snapshot() == before
            assert operations.calls == []
            assert credential_calls == []
    finally:
        client.close()
        service.close()
        loop_thread.join(5)
        assert not loop_thread.is_alive()


def test_real_private_sender_credentials_and_bad_payload_blocked(
    private_bus: PrivateBus,
) -> None:
    GLib.MainLoop()
    host = reconciled_host()
    host_before = host.snapshot()
    system_bus = dbus.SystemBus(private=True)
    operations = ProvenanceLinuxOperations(system_bus)
    consumer_system_bus = dbus.SystemBus(private=True)
    consumer_operations = ProvenanceLinuxOperations(consumer_system_bus)
    resolver = RecordingResolver()
    provider = RecordingProjectionProvider()
    boundary = broker_system.BrokerSystemBoundary(R2AOperations())
    consumer = TrustedPrincipalGrantConsumer(
        trusted_context(),
        resolver,
        provider,
        boundary,
        private_bus_address=private_bus.address,
        _operations=consumer_operations,
    )
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=operations,
    )
    real_reader = service._credential_reader
    reader_entered = Event()
    reader_release = Event()
    observed_credentials: list[tuple[str, object]] = []

    def observing_reader(sender: str) -> object:
        value = real_reader(sender)
        observed_credentials.append((str(sender), value))
        if len(observed_credentials) == 1:
            reader_entered.set()
            if not reader_release.wait(5):
                raise RuntimeError("credential observation timeout")
        return value

    service._credential_reader = observing_reader
    loop_ready = Event()
    GLib.idle_add(lambda: loop_ready.set() and False)
    loop_thread = Thread(target=service.run)
    loop_thread.start()
    assert loop_ready.wait(5)
    fd_ceiling = len(os.listdir("/proc/self/fd"))
    child: subprocess.Popen[bytes] | None = None
    identity_read, identity_write = os.pipe()

    def require(condition: bool, code: str) -> None:
        if not condition:
            pytest.fail(code, pytrace=False)

    try:
        script = """
import dbus, os, sys
bus = dbus.bus.BusConnection(sys.argv[1])
os.write(int(sys.argv[6]), (str(bus.get_unique_name()) + chr(10)).encode('ascii'))
os.close(int(sys.argv[6]))
sys.stdin.buffer.read(1)
obj = bus.get_object(sys.argv[2], sys.argv[3])
method = obj.get_dbus_method(sys.argv[4], sys.argv[5])
try:
    method()
except dbus.DBusException as exc:
    detail = str(exc)
    status = 0 if ('unit_binding_invalid' in detail or 'selinux_gateway_invalid' in detail) else 4
else:
    status = 3
bus.close()
raise SystemExit(status)
"""
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                private_bus.address,
                BUS_NAME,
                BUS_PATH,
                BUS_METHOD,
                BUS_INTERFACE,
                str(identity_write),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(identity_write,),
        )
        os.close(identity_write)
        identity_write = -1
        ready, _, _ = select.select((identity_read,), (), (), 5)
        require(bool(ready), "private sender identity timeout")
        unique_name = os.read(identity_read, 256).strip().decode("ascii")
        os.close(identity_read)
        identity_read = -1
        require(unique_name.startswith(":"), "private sender identity invalid")
        require(child.stdin is not None, "private sender control unavailable")
        child.stdin.write(b"1")
        child.stdin.flush()
        require(reader_entered.wait(5), "credential reader timeout")
        require(child.poll() is None, "private sender disconnected during read")

        status_lines = Path(f"/proc/{child.pid}/status").read_bytes().splitlines()
        uid_line = next(line for line in status_lines if line.startswith(b"Uid:"))
        groups_line = next(line for line in status_lines if line.startswith(b"Groups:"))
        expected_uid = int(uid_line.split()[1])
        expected_groups = tuple(sorted(int(value) for value in groups_line.split()[1:]))
        expected_label = (
            Path(f"/proc/{child.pid}/attr/current").read_bytes().rstrip(b"\0\n")
        )
        observed_sender, raw = observed_credentials[0]
        require(type(raw) is dbus.Dictionary, "credential container invalid")
        require(observed_sender == unique_name, "method sender provenance mismatch")
        require(int(raw["ProcessID"]) == child.pid, "sender PID provenance mismatch")
        require(
            int(raw["UnixUserID"]) == expected_uid == os.getuid(),
            "sender UID provenance mismatch",
        )
        require(
            tuple(sorted(int(value) for value in raw["UnixGroupIDs"]))
            == expected_groups,
            "sender groups provenance mismatch",
        )
        require(
            bytes(raw["LinuxSecurityLabel"]).rstrip(b"\0") == expected_label,
            "sender label provenance mismatch",
        )
        reader_release.set()
        require(child.wait(timeout=10) == 0, "private sender negative gate mismatch")
        require(
            all(sender == unique_name for sender, _raw in observed_credentials),
            "credential sender drift",
        )
        require(
            bool(operations.pid_events)
            and operations.pid_events[0] == ("pidfd_open", child.pid),
            "pidfd provenance mismatch",
        )
        require(consumer._active_start is None, "negative sender reached consumer")
        require(not resolver.calls, "negative sender reached resolver")
        require(not provider.calls, "negative sender reached projection")
        after_negative = host.snapshot()
        require(
            after_negative.active_principals_or_agents == 0
            and after_negative.runtime_broker_epoch
            == host_before.runtime_broker_epoch + 2,
            "negative sender ownership mismatch",
        )

        client = dbus.bus.BusConnection(private_bus.address)
        before = host.snapshot()
        operations_before = len(operations.pid_events)
        credentials_before = len(observed_credentials)
        for payload in (
            "principal",
            "account",
            "profile",
            "binding",
            "agent",
            "generation",
            "path",
            "mcs",
            "release",
            "unit",
            "model",
            "operations",
        ):
            message = dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH,
                interface=BUS_INTERFACE,
                method=BUS_METHOD,
            )
            message.append(payload, signature="s")
            with pytest.raises(dbus.DBusException):
                client.send_message_with_reply_and_block(message)
        assert len(operations.pid_events) == operations_before
        assert len(observed_credentials) == credentials_before
        assert host.snapshot() == before
        client.close()
    finally:
        reader_release.set()
        if identity_read >= 0:
            os.close(identity_read)
        if identity_write >= 0:
            os.close(identity_write)
        if child is not None:
            if child.stdin is not None and not child.stdin.closed:
                try:
                    child.stdin.write(b"1")
                    child.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        service.close()
        consumer.close()
        loop_thread.join(5)
        assert not loop_thread.is_alive()
        system_bus.close()
        consumer_system_bus.close()
    assert len(os.listdir("/proc/self/fd")) <= fd_ceiling


def test_attestation_binds_credentials_kernel_pid1_and_closes_all_fds() -> None:
    operations = ScriptedOperations()
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]
    evidence = _attest_peer(
        ":1.22",
        lambda _sender: reads.pop(0),
        operations,
        release_spec(),
    )
    assert evidence.pid == 1234
    assert evidence.uid == 1000
    assert evidence.effective_gid == 1000
    assert evidence.groups == (1000, 1001)
    assert evidence.start_time == 444
    assert evidence.cgroup_device == 9
    assert evidence.cgroup_inode == 10
    assert evidence.unit_name == "example.scope"
    assert evidence.invocation_id == "11" * 16
    assert evidence.selinux_context == PEER_LABEL
    assert evidence.mcs_pair == "c1,c2"
    assert operations.calls[0] == "pidfd_open"
    assert operations.calls.count("require_alive") == 13
    assert operations.open_fds == set()
    assert reads == []


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("exit", "peer_exited"),
        ("credential_pid", "credential_drift"),
        ("starttime", "pid_identity_drift"),
        ("proc_label", "security_label_drift"),
        ("cgroup_path", "cgroup_binding_drift"),
        ("cgroup_inode", "cgroup_binding_drift"),
        ("unit", "unit_binding_drift"),
        ("invocation", "unit_binding_drift"),
        ("control_group", "unit_binding_drift"),
        ("not_enforcing", "selinux_not_enforcing"),
        ("gateway", "selinux_gateway_invalid"),
        ("unconfined", "selinux_peer_invalid"),
        ("mcs", "selinux_peer_invalid"),
    ),
)
def test_attestation_drift_and_policy_fail_closed(mutation: str, code: str) -> None:
    operations = ScriptedOperations()
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]
    if mutation == "exit":
        operations.alive[0] = False
    elif mutation == "credential_pid":
        reads[1] = raw_credentials(pid=1235)
    elif mutation == "starttime":
        operations.proc[1] = replace(operations.proc[1], start_time=445)
    elif mutation == "proc_label":
        operations.proc[1] = replace(
            operations.proc[1],
            security_label=b"system_u:system_r:other_t:s0:c1,c2",
        )
    elif mutation == "cgroup_path":
        operations.proc[1] = replace(
            operations.proc[1], cgroup_path="/user.slice/other.scope"
        )
    elif mutation == "cgroup_inode":
        operations.stats[1] = (9, 11)
    elif mutation == "unit":
        operations.units[1] = replace(operations.units[1], name="other.scope")
    elif mutation == "invocation":
        operations.units[1] = replace(
            operations.units[1], invocation_id=bytes.fromhex("22" * 16)
        )
    elif mutation == "control_group":
        operations.units[1] = replace(
            operations.units[1], control_group="/user.slice/other.scope"
        )
    elif mutation == "not_enforcing":
        operations.enforcing = False
    elif mutation == "gateway":
        operations.self_label = b"system_u:system_r:other_t:s0"
    elif mutation == "unconfined":
        label = b"unconfined_u:unconfined_r:unconfined_t:s0:c1,c2"
        reads = [raw_credentials(label=label)] * 3
        operations.proc = [
            replace(item, security_label=label) for item in operations.proc
        ]
    else:
        label = b"system_u:system_r:peer_t:s0:c2,c1"
        reads = [raw_credentials(label=label)] * 3
        operations.proc = [
            replace(item, security_label=label) for item in operations.proc
        ]

    assert_code(
        code,
        lambda: _attest_peer(
            ":1.22",
            lambda _sender: reads.pop(0),
            operations,
            release_spec(),
        ),
    )
    assert operations.open_fds == set()


@pytest.mark.parametrize("effective_gid", (1001, 2000))
def test_effective_gid_drift_is_bound_before_and_after(effective_gid: int) -> None:
    operations = ScriptedOperations()
    operations.proc[1] = replace(
        operations.proc[1],
        effective_gid=effective_gid,
    )
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]

    assert_code(
        "credential_drift",
        lambda: _attest_peer(
            ":1.22",
            lambda _sender: reads.pop(0),
            operations,
            release_spec(),
        ),
    )
    assert operations.open_fds == set()


@pytest.mark.parametrize("prior_failure", (False, True))
def test_cleanup_failure_overrides_success_and_attestation_error(
    prior_failure: bool,
) -> None:
    operations = CleanupFailingOperations()
    operations.enforcing = not prior_failure
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]

    assert_code(
        "peer_cleanup_failed",
        lambda: _attest_peer(
            ":1.22",
            lambda _sender: reads.pop(0),
            operations,
            release_spec(),
        ),
    )
    assert operations.close_attempts == [14, 13, 12, 11, 10]
    assert operations.open_fds == set()


@pytest.mark.parametrize("prior_failure", (False, True))
def test_service_cleanup_failure_ends_ownership_without_consumer(
    private_bus: PrivateBus,
    prior_failure: bool,
) -> None:
    host = reconciled_host()
    before = host.snapshot()
    operations = CleanupFailingOperations()
    operations.enforcing = not prior_failure
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("peer_cleanup_failed", lambda: service._handle_start(":1.1"))
        after = host.snapshot()
        assert operations.close_attempts == [14, 13, 12, 11, 10]
        assert operations.open_fds == set()
        assert after.active_principals_or_agents == 0
        assert after.active_leases_or_reservations == 0
        assert after.pending_registry_or_broker_transactions == 0
        assert after.pending_recoveries == 0
        assert after.runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        service.close()


def test_gateway_s0_and_peer_mcs_are_validated_separately() -> None:
    assert _selinux_context(GATEWAY_LABEL, peer=False) == (
        "codex_master_control_t",
        "",
    )
    assert _selinux_context(PEER_LABEL, peer=True) == (
        "codex_master_control_t",
        "c1,c2",
    )
    operations = ScriptedOperations()
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]

    evidence = _attest_peer(
        ":1.22",
        lambda _sender: reads.pop(0),
        operations,
        release_spec(),
    )

    assert evidence.mcs_pair == "c1,c2"
    assert operations.open_fds == set()


@pytest.mark.parametrize(
    "gateway_label",
    (
        b"system_u:system_r:other_t:s0",
        b"system_u:system_r:codex_master_control_t:s0:c1,c2",
        b"system_u:system_r:codex_master_control_t:s1",
        b"system_u:system_r:codex_master_control_t:",
        b"malformed",
    ),
)
def test_invalid_gateway_selinux_contexts_fail_closed(gateway_label: bytes) -> None:
    operations = ScriptedOperations()
    operations.self_label = gateway_label
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]

    assert_code(
        "selinux_gateway_invalid",
        lambda: _attest_peer(
            ":1.22",
            lambda _sender: reads.pop(0),
            operations,
            release_spec(),
        ),
    )
    assert operations.open_fds == set()


@pytest.mark.parametrize(
    "peer_label",
    (
        b"system_u:system_r:peer_t:s0",
        b"system_u:system_r:peer_t:s0:c2,c1",
        b"system_u:system_r:peer_t:s0:c1,c1",
        b"system_u:system_r:peer_t:s0:c1,c1024",
        b"system_u:system_r:permissive_peer_t:s0:c1,c2",
        b"unconfined_u:unconfined_r:unconfined_t:s0:c1,c2",
    ),
)
def test_invalid_peer_selinux_contexts_fail_closed(peer_label: bytes) -> None:
    assert_code(
        "selinux_peer_invalid",
        lambda: _selinux_context(peer_label, peer=True),
    )


class UnitManagerDouble:
    def __init__(self, invocation: object) -> None:
        self.invocation = invocation
        self.received_unix_fd = False

    def GetUnitByPIDFD(self, pidfd: object) -> tuple[object, object, object]:
        self.received_unix_fd = type(pidfd) is dbus.types.UnixFd
        return (
            dbus.ObjectPath("/org/freedesktop/systemd1/unit/example_2escope"),
            dbus.String("example.scope"),
            self.invocation,
        )


class UnitPropertiesDouble:
    def Get(self, interface: str, name: str) -> dbus.String:
        assert interface == "org.freedesktop.systemd1.Unit"
        assert name == "ControlGroup"
        return dbus.String("/user.slice/example.scope")


class UnitBusDouble:
    def __init__(self, manager: UnitManagerDouble) -> None:
        self.manager = manager
        self.properties = UnitPropertiesDouble()

    def get_object(self, name: str, path: object) -> object:
        assert name == "org.freedesktop.systemd1"
        if str(path) == "/org/freedesktop/systemd1":
            return self.manager
        return self.properties


@pytest.mark.parametrize(
    "invocation",
    (
        dbus.ByteArray(INVOCATION),
        dbus.Array((dbus.Byte(value) for value in INVOCATION), signature="y"),
    ),
)
def test_invocation_id_accepts_only_dbus_byte_arrays(
    invocation: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = UnitManagerDouble(invocation)
    monkeypatch.setattr(system_bus.dbus, "Interface", lambda value, _name: value)
    operations = _LinuxPeerOperations(UnitBusDouble(manager))
    read_fd, write_fd = os.pipe()
    try:
        observation = operations.read_unit(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)

    assert manager.received_unix_fd
    assert len(observation.invocation_id) == 16


@pytest.mark.parametrize(
    "invocation",
    (
        dbus.Array((dbus.UInt32(value) for value in INVOCATION), signature="u"),
        dbus.Array((dbus.Byte(value) for value in INVOCATION[:-1]), signature="y"),
        INVOCATION,
        dbus.Array((dbus.Int16(value) for value in INVOCATION), signature="n"),
    ),
)
def test_invocation_id_rejects_wrong_dbus_type_or_signature(
    invocation: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = UnitManagerDouble(invocation)
    monkeypatch.setattr(system_bus.dbus, "Interface", lambda value, _name: value)
    operations = _LinuxPeerOperations(UnitBusDouble(manager))
    read_fd, write_fd = os.pipe()
    try:
        assert_code("unit_binding_invalid", lambda: operations.read_unit(read_fd))
    finally:
        os.close(read_fd)
        os.close(write_fd)

    assert manager.received_unix_fd


@pytest.mark.parametrize(
    "credentials",
    (
        {},
        {"ProcessID": True},
        {"ProcessID": dbus.UInt32(0)},
        {
            "ProcessID": dbus.UInt32(1),
            "UnixUserID": dbus.UInt32(1),
            "UnixGroupIDs": dbus.Array([], signature="u"),
            "LinuxSecurityLabel": dbus.Array([], signature="y"),
        },
        raw_credentials(groups=(1000, 1000)),
    ),
)
def test_invalid_bus_credentials_block_before_pidfd(credentials: object) -> None:
    operations = ScriptedOperations()
    assert_code(
        "credentials_invalid",
        lambda: _attest_peer(
            ":1.22", lambda _sender: credentials, operations, release_spec()
        ),
    )
    assert operations.calls == []
    assert operations.open_fds == set()


def test_proc_stat_and_cgroup_parsers_are_unambiguous() -> None:
    fields = [b"S"] + [b"1"] * 18 + [b"444"]
    assert _parse_stat(b"123 (name with ) spaces) " + b" ".join(fields)) == 444
    assert _parse_cgroup(b"0::/user.slice/example.scope\n") == (
        "/user.slice/example.scope"
    )
    for malformed in (
        b"123 no-parentheses",
        b"123 (name) S 1",
    ):
        assert_code("proc_binding_invalid", lambda value=malformed: _parse_stat(value))
    for malformed in (
        b"",
        b"1:name:/legacy\n",
        b"0::/one\n0::/two\n",
        b"0::/../escape\n",
    ):
        assert_code(
            "cgroup_binding_invalid",
            lambda value=malformed: _parse_cgroup(value),
        )


def test_openat2_rejects_symlink_and_non_directory(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    (tmp_path / "link").symlink_to(directory, target_is_directory=True)
    (tmp_path / "file").write_bytes(b"x")
    root = os.open(tmp_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        assert_code(
            "path_binding_invalid",
            lambda: _openat2(
                root,
                "link",
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            ),
        )
        assert_code(
            "path_binding_invalid",
            lambda: _openat2(
                root,
                "file",
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            ),
        )
    finally:
        os.close(root)


def test_host_coordination_failure_and_success_ownership(
    private_bus: PrivateBus,
) -> None:
    operations = ScriptedOperations()

    service = HomeBrokerControlService(
        FleetRootRuntimeHost(),
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("host_unavailable", lambda: service._handle_start(":1.1"))
        assert operations.calls == []
    finally:
        service.close()

    host = reconciled_host()
    service = HomeBrokerControlService(
        host,
        GENERATION + 1,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("host_unavailable", lambda: service._handle_start(":1.1"))
        assert operations.calls == []
    finally:
        service.close()

    host = reconciled_host()
    r2a_operations = R2AOperations()
    consumer = TrustedPrincipalGrantConsumer(
        trusted_context(),
        RecordingResolver(),
        RecordingProjectionProvider(),
        broker_system.BrokerSystemBoundary(r2a_operations),
        private_bus_address=private_bus.address,
        _operations=reattest_operations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        service._handle_start(":1.1")
        active = consumer._active_start
        assert active is not None
        assert host.snapshot().active_principals_or_agents == 1
        service.close()
        assert r2a_operations.closed == [101, 102]
        assert host.snapshot().active_principals_or_agents == 0
    finally:
        service.close()


def test_admission_stop_preserves_snapshot_and_window(
    private_bus: PrivateBus,
) -> None:
    helpers = __import__("test_fleet_root_runtime_host", fromlist=["source_snapshot"])
    host = reconciled_host()
    admission = host.stop_admission()
    window = host.open_quiescence_window(admission, helpers.source_snapshot())
    before = host.snapshot()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("admission_stopped", lambda: service._handle_start(":1.1"))
        assert host.snapshot() == before
        evidence = host.probe_quiescence(window)
        assert evidence.runtime_broker_epoch == before.runtime_broker_epoch
        assert operations.calls == []
    finally:
        service.close()


@pytest.mark.parametrize("failure", ("attestation",))
def test_local_failure_ends_ownership_once(
    private_bus: PrivateBus, failure: str
) -> None:
    host = reconciled_host()
    before = host.snapshot()
    operations = ScriptedOperations()
    if failure == "attestation":
        operations.enforcing = False

    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("selinux_not_enforcing", lambda: service._handle_start(":1.1"))
        after = host.snapshot()
        assert after.active_principals_or_agents == 0
        assert after.active_leases_or_reservations == 0
        assert after.pending_registry_or_broker_transactions == 0
        assert after.pending_recoveries == 0
        assert after.runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        service.close()


def test_close_marks_system_bus_participant_lost_and_stale_calls_block(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service.close()
    assert host.snapshot().reconciled is False
    assert_code("service_stale", lambda: service._handle_start(":1.1"))
    assert operations.calls == []


def test_external_name_loss_marks_participant_lost_and_close_cleans(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    GLib.MainLoop()
    gc.collect()
    before = len(os.listdir("/proc/self/fd"))
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        _consumer_for(private_bus),
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service._name_owner_changed(BUS_NAME, service._bus.get_unique_name(), "")
    assert host.snapshot().reconciled is False
    assert_code("service_stale", lambda: service._handle_start(":1.1"))
    service.close()
    assert len(os.listdir("/proc/self/fd")) == before


def test_successful_nonprincipal_activity_invalidates_existing_window() -> None:
    helpers = __import__("test_fleet_root_runtime_host", fromlist=["source_snapshot"])
    host = reconciled_host()
    admission = host.stop_admission()
    window = host.open_quiescence_window(admission, helpers.source_snapshot())
    ownership = host.begin_recovery()
    with pytest.raises(FleetRootRuntimeHostError) as caught:
        host.probe_quiescence(window)
    assert caught.value.code == "quiescence_epoch_drift"
    host.end_recovery(ownership)


def test_handoff_is_nontransferable_and_forge_never_reaches_consumer(
    private_bus: PrivateBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = reconciled_host()
    r2a_operations = R2AOperations()
    consumer = TrustedPrincipalGrantConsumer(
        trusted_context(),
        RecordingResolver(),
        RecordingProjectionProvider(),
        broker_system.BrokerSystemBoundary(r2a_operations),
        private_bus_address=private_bus.address,
        _operations=reattest_operations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    original_handoff = HomeBrokerControlService._handoff

    def capture_handoff(
        service: HomeBrokerControlService,
        attestation: RootSystemBusPeerAttestation,
        ownership: RootRuntimeActivityOwnership,
        issued: object,
    ) -> None:
        original_handoff(service, attestation, ownership, issued)

    monkeypatch.setattr(HomeBrokerControlService, "_handoff", capture_handoff)
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        ownership = host.begin_principal_or_agent()
        evidence = _attest_peer(
            ":1.1",
            service._credential_reader,
            service._operations,
            service._release,
        )
        attestation, issued = service._issue_handoff(":1.1", evidence, ownership)
        assert repr(attestation) == "<RootSystemBusPeerAttestation redacted>"
        assert str(attestation) == repr(attestation)
        for operation in (
            lambda: RootSystemBusPeerAttestation(),
            lambda: copy.copy(attestation),
            lambda: copy.deepcopy(attestation),
            lambda: pickle.dumps(attestation),
            lambda: dataclasses.replace(attestation),
        ):
            with pytest.raises(TypeError):
                operation()

        forged = object.__new__(RootSystemBusPeerAttestation)
        for field in dataclasses.fields(attestation):
            object.__setattr__(forged, field.name, getattr(attestation, field.name))

        forged_carrier = object.__new__(_IssuedAttestation)
        for field in dataclasses.fields(issued):
            object.__setattr__(forged_carrier, field.name, getattr(issued, field.name))
        with pytest.raises(RootSystemBusError) as caught:
            service._handoff(forged, ownership, forged_carrier)
        assert caught.value.code == "handoff_invalid"
        assert r2a_operations.calls == []

        with pytest.raises(TypeError):
            _IssuedAttestation(attestation)
        forged_record = object.__new__(_IssuedAttestation)
        for field in dataclasses.fields(issued):
            object.__setattr__(forged_record, field.name, getattr(issued, field.name))
        with service._issuance_lock:
            service._issued = issued
        with pytest.raises(RootSystemBusError) as caught:
            service._handoff(attestation, ownership, forged_record)
        assert caught.value.code == "handoff_invalid"
        assert r2a_operations.calls == []

        for operation in (
            lambda: copy.copy(issued),
            lambda: copy.deepcopy(issued),
            lambda: pickle.dumps(issued),
            lambda: dataclasses.replace(issued),
        ):
            with pytest.raises(TypeError):
                operation()

        with service._issuance_lock:
            service._issued = issued
        service._handoff(attestation, ownership, issued)
        calls_after_legal_handoff = list(r2a_operations.calls)
        with pytest.raises(RootSystemBusError) as caught:
            service._handoff(attestation, ownership, issued)
        assert caught.value.code == "handoff_invalid"
        assert r2a_operations.calls == calls_after_legal_handoff
        with service._issuance_lock:
            service._issued = issued
        with pytest.raises(RootSystemBusError) as caught:
            service._handoff(forged, ownership, issued)
        assert caught.value.code == "handoff_invalid"
        other_ownership = host.begin_principal_or_agent()
        try:
            with service._issuance_lock:
                service._issued = issued
            with pytest.raises(RootSystemBusError) as caught:
                service._handoff(attestation, other_ownership, issued)
            assert caught.value.code == "handoff_invalid"
        finally:
            host.end_principal_or_agent(other_ownership)
    finally:
        service.close()


def test_real_pidfd_proc_cgroup_systemd_selinux_negative_has_no_fd_leak() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
    )
    try:
        groups = tuple(sorted(set(os.getgroups() + [os.getegid()])))
        label = Path(f"/proc/{child.pid}/attr/current").read_bytes().rstrip(b"\0\n")
        credentials = raw_credentials(
            pid=child.pid, uid=os.getuid(), groups=groups, label=label
        )
        system_bus = dbus.SystemBus(private=True)
        operations = _LinuxPeerOperations(system_bus)
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(RootSystemBusError) as caught:
            _attest_peer(
                ":1.1",
                lambda _sender: credentials,
                operations,
                release_spec(),
            )
        assert caught.value.code in {
            "unit_binding_invalid",
            "selinux_gateway_invalid",
        }
        after = len(os.listdir("/proc/self/fd"))
        assert after == before
        system_bus.close()
    finally:
        assert child.stdin is not None
        child.stdin.write(b"x")
        child.stdin.close()
        child.wait(timeout=5)
