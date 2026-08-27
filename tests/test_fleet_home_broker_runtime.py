import ast
import copy
from concurrent.futures import ThreadPoolExecutor
import dataclasses
from dataclasses import FrozenInstanceError
import gc
import inspect
from pathlib import Path
import pickle
from threading import Barrier
import weakref

import pytest

from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat, PidfdIdentity
from codex_master.fleet_home_broker_protocol import PrincipalBinding
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    CredentialProjection,
    CredentialProjectionProvider,
    KernelPeerEvidence,
    OneShotGrantConsumer,
    RuntimeBoundaryError,
    RuntimePeerOperations,
    RuntimePrincipalResolver,
    StartGrant,
    TrustedPrincipalGrantContext,
    attest_kernel_peer,
)
from codex_master.fleet_home_broker_transport import BrokerPeer


PEER = BrokerPeer(1234)
PID_FD = 73
PROC_FD = 83
CGROUP_FD = 97
START_TIME = 7
PROFILE_ID = "profile.one"
BINDING_ID = "hmac-sha256:" + "a" * 64
PROVIDER = "openai_chatgpt"
GENERATION = 9


def release_spec(**changes):
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
    }
    values.update(changes)
    return BrokerReleaseSpec(**values)


RELEASE = release_spec()


def principal(**changes):
    values = {
        "agent_id": "bee_1",
        "manifest_generation": 3,
        "unit_generation": 9,
        "cgroup_dev": 17,
        "cgroup_ino": 29,
        "invocation_id": "1" * 32,
        "mcs_pair": "c0,c1",
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


PRINCIPAL = principal()
IDENTITY = BrokerIdentity(
    PRINCIPAL.agent_id,
    PRINCIPAL.manifest_generation,
    PRINCIPAL.mcs_pair,
    "slot.snapshot.v1",
    GENERATION,
    "b" * 64,
    "c" * 64,
    PRINCIPAL.fencing_epoch,
)


def evidence(**changes):
    values = {
        "pid": PEER.pid,
        "uid": 1000,
        "gid": 1000,
        "start_time": START_TIME,
        "cgroup_dev": 17,
        "cgroup_ino": 29,
        "unit_generation": 9,
        "invocation_id": "1" * 32,
        "mcs_pair": "c0,c1",
    }
    values.update(changes)
    return KernelPeerEvidence(**values)


EVIDENCE = evidence()


class FakeRuntimeOperations:
    def __init__(self, *, gateway=True, evidence_values=(), evidence_error=None):
        self.gateway = gateway
        self.evidence_values = list(evidence_values) or [EVIDENCE]
        self.evidence_error = evidence_error
        self.evidence_calls = []
        self.closed = []

    def is_root_system_bus_gateway(self):
        self.evidence_calls.append(("gateway",))
        return self.gateway

    def read_kernel_peer_evidence(self, peer):
        self.evidence_calls.append(("evidence", peer))
        if self.evidence_error is not None:
            raise self.evidence_error
        index = min(
            sum(call[0] == "evidence" for call in self.evidence_calls) - 1,
            len(self.evidence_values) - 1,
        )
        return self.evidence_values[index]

    def close(self, fd):
        self.closed.append(fd)


class FakeLinuxOperations:
    def __init__(self, *, drift_at=None, drift_pid=None, **values):
        self.calls = []
        self.drift_at = drift_at
        self.drift_pid = drift_pid
        self.reuse_checks = 0
        self.pid_identity = PidfdIdentity(PEER.pid, START_TIME)
        self.values = {
            "cgroup_stat": FdStat(17, 29, 0o40755, 1000, 1000),
            "proc_control_group": "/user.slice/user-1000.slice/session-7.scope",
            "pid1_unit_name": "session-7.scope",
            "pid1_control_group": "/user.slice/user-1000.slice/session-7.scope",
            "pid1_unit_generation": 9,
            "pid1_invocation_id": "1" * 32,
            "peer_mcs_pair": "c0,c1",
        }
        self.values.update(values)
        self.closed = []

    def pidfd_open(self, pid, flags):
        self.calls.append(("pidfd_open", pid, flags))
        return PID_FD

    def pidfd_reuse_check(self, pidfd, pid, proc_fd, cgroup_fd, identity):
        self.calls.append(
            ("pidfd_reuse_check", pidfd, pid, proc_fd, cgroup_fd, identity)
        )
        self.reuse_checks += 1
        if self.drift_at is not None and self.reuse_checks >= self.drift_at:
            return PidfdIdentity(self.drift_pid or pid, START_TIME + 1)
        return self.pid_identity

    def open_pinned_proc_pid(self, pidfd, pid, identity):
        self.calls.append(("open_pinned_proc_pid", pidfd, pid, identity))
        return PROC_FD

    def open_proc_cgroup(self, pidfd, proc_fd, identity):
        self.calls.append(("open_proc_cgroup", pidfd, proc_fd, identity))
        return CGROUP_FD

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        return self.values["cgroup_stat"]

    def read_proc_control_group(
        self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
    ):
        self.calls.append(
            (
                "read_proc_control_group",
                pidfd,
                proc_fd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        return self.values["proc_control_group"]

    def read_pid1_unit_name(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_pid1_unit_name", pidfd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        return self.values["pid1_unit_name"]

    def read_pid1_unit_generation(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_pid1_unit_generation", pidfd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        return self.values["pid1_unit_generation"]

    def read_pid1_invocation_id(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_pid1_invocation_id", pidfd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        return self.values["pid1_invocation_id"]

    def read_pid1_control_group(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_pid1_control_group", pidfd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        return self.values["pid1_control_group"]

    def read_peer_mcs_pair(self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_peer_mcs_pair", pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        return self.values["peer_mcs_pair"]

    def close(self, fd):
        self.closed.append(fd)


class FakeResolver:
    def __init__(self, value=PRINCIPAL, error=None):
        self.value = value
        self.error = error
        self.calls = []

    def resolve_principal(self, evidence_value):
        self.calls.append(evidence_value)
        if self.error is not None:
            raise self.error
        return self.value


class FakeProvider:
    def __init__(self, value=None, error=None):
        self.value = value or CredentialProjection(
            PROFILE_ID, BINDING_ID, GENERATION, PROVIDER, (101, 102)
        )
        self.error = error
        self.calls = []

    def project(self, profile_id, binding_id, generation, provider):
        self.calls.append((profile_id, binding_id, generation, provider))
        if self.error is not None:
            raise self.error
        return self.value


def _attest(
    *,
    runtime=None,
    linux=None,
    resolver=None,
    provider=None,
    **values,
):
    return attest_kernel_peer(
        peer=PEER,
        identity=values.pop("identity", IDENTITY),
        release=values.pop("release", RELEASE),
        profile_id=values.pop("profile_id", PROFILE_ID),
        binding_id=values.pop("binding_id", BINDING_ID),
        generation=values.pop("generation", GENERATION),
        provider=values.pop("provider", PROVIDER),
        peer_operations=runtime or FakeRuntimeOperations(),
        linux_operations=linux or FakeLinuxOperations(),
        principal_resolver=resolver or FakeResolver(),
        projection_provider=provider or FakeProvider(),
        **values,
    )


def test_public_types_are_frozen_slotted_and_protocols_are_narrow():
    for type_ in (
        KernelPeerEvidence,
        CredentialProjection,
        StartGrant,
        TrustedPrincipalGrantContext,
    ):
        assert dataclasses.is_dataclass(type_)
        assert type_.__dataclass_params__.frozen
        assert hasattr(type_, "__slots__")

    with pytest.raises(FrozenInstanceError):
        dataclasses.replace(EVIDENCE, pid=PEER.pid + 1).pid = PEER.pid

    assert getattr(RuntimePeerOperations, "_is_protocol", False)
    assert getattr(RuntimePrincipalResolver, "_is_protocol", False)
    assert getattr(CredentialProjectionProvider, "_is_protocol", False)
    assert tuple(
        inspect.signature(RuntimePeerOperations.is_root_system_bus_gateway).parameters
    ) == ("self",)
    assert tuple(
        inspect.signature(RuntimePeerOperations.read_kernel_peer_evidence).parameters
    ) == ("self", "peer")
    assert tuple(inspect.signature(RuntimePeerOperations.close).parameters) == (
        "self",
        "fd",
    )
    assert tuple(
        inspect.signature(RuntimePrincipalResolver.resolve_principal).parameters
    ) == (
        "self",
        "evidence",
    )
    assert tuple(
        inspect.signature(CredentialProjectionProvider.project).parameters
    ) == (
        "self",
        "profile_id",
        "binding_id",
        "generation",
        "provider",
    )
    assert tuple(
        field.name for field in dataclasses.fields(TrustedPrincipalGrantContext)
    ) == (
        "snapshot",
        "selection",
        "profile_binding",
        "expected_principal",
        "identity",
    )


def test_release_spec_is_frozen_slotted_and_has_only_root_release_fields():
    expected_fields = (
        "joint_release_version",
        "release_id",
        "server_digest",
        "broker_manifest_digest",
        "chpb_abi",
        "policy_abi",
        "provider_abi",
        "unit_digest",
        "selinux_digest",
        "socket_unit",
        "service_unit",
        "system_bus_name",
        "system_bus_path",
        "system_bus_interface",
        "broker_domain",
        "gateway_domain",
        "socket_type",
    )

    assert dataclasses.is_dataclass(BrokerReleaseSpec)
    assert BrokerReleaseSpec.__dataclass_params__.frozen
    assert hasattr(BrokerReleaseSpec, "__slots__")
    assert tuple(field.name for field in dataclasses.fields(RELEASE)) == expected_fields
    assert "mcs_pair" not in expected_fields
    assert "enforcing" not in expected_fields
    with pytest.raises(FrozenInstanceError):
        RELEASE.release_id = "0.10.5"


def test_attestation_has_one_explicit_trusted_release_input_and_no_payload_input():
    parameters = inspect.signature(attest_kernel_peer).parameters

    assert tuple(parameters) == (
        "peer",
        "identity",
        "release",
        "profile_id",
        "binding_id",
        "generation",
        "provider",
        "peer_operations",
        "linux_operations",
        "principal_resolver",
        "projection_provider",
    )
    assert parameters["release"].annotation == "BrokerReleaseSpec"
    assert parameters["release"].default is inspect.Parameter.empty
    assert {"request", "payload", "module", "callable"}.isdisjoint(parameters)


@pytest.mark.parametrize(
    "field,value",
    [
        ("joint_release_version", True),
        ("joint_release_version", 2),
        ("release_id", "0.10.5"),
        ("server_digest", "D" * 64),
        ("broker_manifest_digest", "short"),
        ("chpb_abi", "CHPB/1"),
        ("policy_abi", ""),
        ("provider_abi", ""),
        ("unit_digest", "g" * 64),
        ("selinux_digest", object()),
        ("socket_unit", "untrusted.socket"),
        ("service_unit", "untrusted.service"),
        ("system_bus_name", "org.example.Untrusted"),
        ("system_bus_path", "/org/example/Untrusted"),
        ("system_bus_interface", "org.example.Untrusted1"),
        ("broker_domain", "untrusted_broker_t"),
        ("gateway_domain", "untrusted_control_t"),
        ("socket_type", "untrusted_runtime_t"),
    ],
)
def test_release_drift_is_rejected_before_projection(field, value):
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="broker release is invalid"):
        _attest(release=release_spec(**{field: value}), provider=provider)

    assert provider.calls == []


@pytest.mark.parametrize("release", [None, object()])
def test_non_release_object_is_rejected_before_projection(release):
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="broker release is invalid"):
        _attest(release=release, provider=provider)

    assert provider.calls == []


def test_start_grant_dataclass_surface_has_exactly_ten_public_fields():
    public_fields = (
        "peer",
        "evidence",
        "principal",
        "identity",
        "profile_id",
        "binding_id",
        "generation",
        "provider",
        "projection",
        "release",
    )
    grant = _attest()
    public_clone = StartGrant(*(getattr(grant, name) for name in public_fields))

    assert tuple(inspect.signature(StartGrant).parameters) == public_fields
    assert (
        tuple(field.name for field in dataclasses.fields(StartGrant)) == public_fields
    )
    assert tuple(dataclasses.asdict(grant)) == public_fields
    assert "grant_state" not in repr(grant)
    assert grant == public_clone
    assert hash(grant) == hash(public_clone)
    with pytest.raises(TypeError, match="missing 1 required positional argument"):
        StartGrant(*(getattr(grant, name) for name in public_fields[:-1]))


def test_attestation_reconstructs_root_side_principal_and_returns_bound_opaque_grant():
    runtime = FakeRuntimeOperations()
    resolver = FakeResolver()
    provider = FakeProvider()

    grant = _attest(runtime=runtime, resolver=resolver, provider=provider)

    assert type(grant) is StartGrant
    assert grant.peer == PEER
    assert grant.evidence == EVIDENCE
    assert grant.principal == PRINCIPAL
    assert grant.identity == IDENTITY
    assert grant.projection == provider.value
    assert grant.release == RELEASE
    assert resolver.calls == [EVIDENCE]
    assert provider.calls == [(PROFILE_ID, BINDING_ID, GENERATION, PROVIDER)]
    assert runtime.closed == []


def test_missing_root_system_bus_gateway_denies_before_peer_or_provider_work():
    runtime = FakeRuntimeOperations(gateway=False)
    resolver = FakeResolver()
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="root system bus gateway required"):
        _attest(runtime=runtime, resolver=resolver, provider=provider)

    assert runtime.evidence_calls == [("gateway",)]
    assert resolver.calls == []
    assert provider.calls == []


@pytest.mark.parametrize(
    "changed",
    [
        {"pid": PEER.pid + 1},
        {"uid": 1001},
        {"gid": 1001},
        {"start_time": START_TIME + 1},
        {"cgroup_dev": 18},
        {"cgroup_ino": 30},
        {"unit_generation": 10},
        {"invocation_id": "2" * 32},
        {"mcs_pair": "c0,c2"},
    ],
)
def test_peer_evidence_drift_between_attestation_stages_denies(changed):
    runtime = FakeRuntimeOperations(evidence_values=(EVIDENCE, evidence(**changed)))
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="peer evidence drifted"):
        _attest(runtime=runtime, provider=provider)

    assert provider.calls == []
    assert runtime.closed == []


def test_pid_reuse_drift_from_pinned_linux_attestation_closes_linux_fds():
    linux = FakeLinuxOperations(drift_at=5)
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="kernel peer attestation failed"):
        _attest(linux=linux, provider=provider)

    assert provider.calls == []
    assert linux.closed == [CGROUP_FD, PROC_FD, PID_FD]


@pytest.mark.parametrize("resolved", [None, object(), principal(agent_id="other")])
def test_unknown_or_drifted_resolved_principal_denies(resolved):
    resolver = FakeResolver(value=resolved)
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="principal resolution failed"):
        _attest(resolver=resolver, provider=provider)

    assert provider.calls == []


@pytest.mark.parametrize(
    "runtime,resolver,identity",
    [
        (
            FakeRuntimeOperations(evidence_values=(evidence(mcs_pair="c0,c2"),)),
            None,
            IDENTITY,
        ),
        (None, FakeResolver(principal(mcs_pair="c0,c2")), IDENTITY),
        (None, None, dataclasses.replace(IDENTITY, mcs_pair="c0,c2")),
    ],
)
def test_mcs_must_match_evidence_principal_and_identity(runtime, resolver, identity):
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="principal resolution failed"):
        _attest(
            runtime=runtime,
            resolver=resolver,
            identity=identity,
            provider=provider,
        )

    assert provider.calls == []


def test_resolver_error_is_sparse_and_does_not_reach_provider():
    resolver = FakeResolver(error=RuntimeError("private resolver detail"))
    provider = FakeProvider()

    with pytest.raises(
        RuntimeBoundaryError, match="principal resolution failed"
    ) as error:
        _attest(resolver=resolver, provider=provider)

    assert error.value.__cause__ is None
    assert provider.calls == []


def test_request_identity_attempt_is_not_accepted_as_provider_profile():
    provider = FakeProvider()

    with pytest.raises(RuntimeBoundaryError, match="runtime binding is invalid"):
        _attest(profile_id=PRINCIPAL, provider=provider)

    assert provider.calls == []


def test_provider_error_does_not_leak_or_close_unowned_fds():
    runtime = FakeRuntimeOperations()
    provider = FakeProvider(error=RuntimeError("private provider detail"))

    with pytest.raises(
        RuntimeBoundaryError, match="credential projection failed"
    ) as error:
        _attest(runtime=runtime, provider=provider)

    assert error.value.__cause__ is None
    assert runtime.closed == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile_id", "other.profile"),
        ("binding_id", "hmac-sha256:" + "d" * 64),
        ("generation", GENERATION + 1),
        ("provider", "gemini_api"),
    ],
)
def test_projection_binding_drift_closes_all_transferred_fds_once(field, value):
    runtime = FakeRuntimeOperations()
    projection_values = {
        "profile_id": PROFILE_ID,
        "binding_id": BINDING_ID,
        "generation": GENERATION,
        "provider": PROVIDER,
        "fds": (101, 102),
    }
    projection_values[field] = value
    provider = FakeProvider(value=CredentialProjection(**projection_values))

    with pytest.raises(
        RuntimeBoundaryError, match="credential projection binding drifted"
    ):
        _attest(runtime=runtime, provider=provider)

    assert runtime.closed == [101, 102]


def test_duplicate_projection_fd_is_closed_exactly_once_on_validation_error():
    runtime = FakeRuntimeOperations()
    provider = FakeProvider(
        value=CredentialProjection(
            PROFILE_ID, BINDING_ID, GENERATION, PROVIDER, (101, 101)
        )
    )

    with pytest.raises(RuntimeBoundaryError, match="credential projection is invalid"):
        _attest(runtime=runtime, provider=provider)

    assert runtime.closed == [101]


def test_malformed_projection_fd_container_still_closes_transferred_fds_once():
    runtime = FakeRuntimeOperations()
    provider = FakeProvider(
        value=CredentialProjection(
            PROFILE_ID, BINDING_ID, GENERATION, PROVIDER, [101, 101]
        )
    )

    with pytest.raises(RuntimeBoundaryError, match="credential projection is invalid"):
        _attest(runtime=runtime, provider=provider)

    assert runtime.closed == [101]


def test_one_shot_consumer_transfers_projection_once_without_reclosing_transferred_fds():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    consumer = OneShotGrantConsumer(grant, runtime)

    assert consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY) is grant.projection
    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY)
    assert runtime.closed == []


def test_same_grant_cannot_be_consumed_by_two_consumer_instances():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    first = OneShotGrantConsumer(grant, runtime)
    second = OneShotGrantConsumer(grant, runtime)

    assert first.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY) is grant.projection
    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        second.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY)
    assert runtime.closed == []


def test_dataclasses_replace_is_unissued_after_original_gc():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    replay = dataclasses.replace(grant)
    original_ref = weakref.ref(grant)
    consumer = OneShotGrantConsumer(grant, runtime)

    assert consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY) is grant.projection
    del consumer
    del grant
    gc.collect()
    assert original_ref() is None

    with pytest.raises(RuntimeBoundaryError, match="start grant is invalid"):
        OneShotGrantConsumer(replay, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == []


@pytest.mark.parametrize(
    "clone_grant", (copy.copy, copy.deepcopy), ids=("copy", "deepcopy")
)
def test_copy_replay_stays_consumed_after_original_gc(clone_grant):
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    replay = clone_grant(grant)
    consumer = OneShotGrantConsumer(grant, runtime)

    assert consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY) is grant.projection
    del consumer
    del grant
    gc.collect()

    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        OneShotGrantConsumer(replay, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == []


@pytest.mark.parametrize(
    "clone_grant",
    (copy.copy, copy.deepcopy),
    ids=("copy", "deepcopy"),
)
def test_clone_replay_after_failed_consume_does_not_reclose_fds(
    clone_grant,
):
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    replay = clone_grant(grant)
    consumer = OneShotGrantConsumer(grant, runtime)

    with pytest.raises(RuntimeBoundaryError, match="start grant binding drifted"):
        consumer.consume(
            PEER, dataclasses.replace(EVIDENCE, mcs_pair="c0,c2"), PRINCIPAL, IDENTITY
        )
    assert runtime.closed == [101, 102]
    del consumer
    del grant
    gc.collect()

    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        OneShotGrantConsumer(replay, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == [101, 102]


def test_public_field_reconstruction_is_not_an_issuer_grant():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    replay = StartGrant(
        grant.peer,
        grant.evidence,
        grant.principal,
        grant.identity,
        grant.profile_id,
        grant.binding_id,
        grant.generation,
        grant.provider,
        grant.projection,
        grant.release,
    )
    consumer = OneShotGrantConsumer(grant, runtime)

    assert consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY) is grant.projection
    del consumer
    del grant
    gc.collect()

    with pytest.raises(RuntimeBoundaryError, match="start grant is invalid"):
        OneShotGrantConsumer(replay, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == []


def test_start_grant_constructor_rejects_private_state_injection():
    grant = _attest()
    public_values = tuple(
        getattr(grant, name)
        for name in (
            "peer",
            "evidence",
            "principal",
            "identity",
            "profile_id",
            "binding_id",
            "generation",
            "provider",
            "projection",
            "release",
        )
    )

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        StartGrant(*public_values, _grant_state=object())


def test_coherently_rebound_clone_cannot_escape_issuer_binding():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    rebound_binding = "hmac-sha256:" + "d" * 64
    rebound = dataclasses.replace(
        grant,
        binding_id=rebound_binding,
        projection=CredentialProjection(
            PROFILE_ID, rebound_binding, GENERATION, PROVIDER, (201, 202)
        ),
    )

    with pytest.raises(RuntimeBoundaryError, match="start grant is invalid"):
        OneShotGrantConsumer(rebound, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == []

    with pytest.raises(RuntimeBoundaryError, match="start grant binding drifted"):
        OneShotGrantConsumer(grant, runtime).consume(
            PEER, dataclasses.replace(EVIDENCE, mcs_pair="c0,c2"), PRINCIPAL, IDENTITY
        )
    assert runtime.closed == [101, 102]


def test_issued_release_field_drift_is_detected_by_ten_field_carrier():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    object.__setattr__(grant, "release", release_spec(policy_abi="policy-v2"))

    with pytest.raises(RuntimeBoundaryError, match="start grant binding drifted"):
        OneShotGrantConsumer(grant, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )

    assert runtime.closed == [101, 102]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("peer", BrokerPeer(PEER.pid + 1)),
        ("evidence", evidence(start_time=START_TIME + 1)),
        ("principal", principal(cgroup_ino=30)),
        ("identity", dataclasses.replace(IDENTITY, manifest_generation=4)),
        ("profile_id", "profile.two"),
        ("binding_id", "hmac-sha256:" + "e" * 64),
        ("generation", GENERATION + 1),
        ("provider", "openai_api"),
        (
            "projection",
            CredentialProjection(
                PROFILE_ID,
                BINDING_ID,
                GENERATION,
                PROVIDER,
                (201, 202),
            ),
        ),
        ("release", release_spec(policy_abi="policy-v2")),
    ),
)
def test_each_of_ten_issued_grant_fields_is_bound(field, value):
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    object.__setattr__(grant, field, value)

    with pytest.raises(RuntimeBoundaryError):
        OneShotGrantConsumer(grant, runtime).consume(
            PEER,
            EVIDENCE,
            PRINCIPAL,
            IDENTITY,
        )

    assert runtime.closed == [101, 102]


def test_two_distinct_grants_remain_independently_consumable():
    runtime = FakeRuntimeOperations()
    first_grant = _attest(runtime=runtime)
    second_grant = _attest(runtime=runtime)

    assert first_grant == second_grant

    assert (
        OneShotGrantConsumer(first_grant, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
        is first_grant.projection
    )
    assert (
        OneShotGrantConsumer(second_grant, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
        is second_grant.projection
    )
    assert runtime.closed == []


def test_grant_state_lifetime_covers_all_aliases_without_global_retention():
    grant = _attest()
    replay = copy.copy(grant)
    state_ref = weakref.ref(grant._grant_state)

    del grant
    gc.collect()
    assert state_ref() is not None

    del replay
    gc.collect()
    assert state_ref() is None


def test_consumed_grant_claim_expires_with_grant_lifetime():
    runtime = FakeRuntimeOperations()

    def consume_ephemeral_grant():
        grant = _attest(runtime=runtime)
        assert (
            OneShotGrantConsumer(grant, runtime).consume(
                PEER, EVIDENCE, PRINCIPAL, IDENTITY
            )
            is grant.projection
        )

    consume_ephemeral_grant()
    gc.collect()

    replacement = _attest(runtime=runtime)
    assert (
        OneShotGrantConsumer(replacement, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
        is replacement.projection
    )
    assert runtime.closed == []


def test_concurrent_consume_has_exactly_one_projection_winner():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    consumers = (
        OneShotGrantConsumer(grant, runtime),
        OneShotGrantConsumer(copy.copy(grant), runtime),
    )
    barrier = Barrier(2)

    def consume(consumer):
        barrier.wait()
        try:
            return consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY)
        except RuntimeBoundaryError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(consume, consumers))

    assert sum(outcome is grant.projection for outcome in outcomes) == 1
    errors = tuple(
        outcome for outcome in outcomes if isinstance(outcome, RuntimeBoundaryError)
    )
    assert len(errors) == 1
    assert str(errors[0]) == "start grant already consumed"
    assert runtime.closed == []


def test_concurrent_failed_consume_closes_issued_fds_once():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    consumers = (
        OneShotGrantConsumer(grant, runtime),
        OneShotGrantConsumer(copy.deepcopy(grant), runtime),
    )
    barrier = Barrier(2)
    drifted_evidence = dataclasses.replace(EVIDENCE, mcs_pair="c0,c2")

    def consume(consumer):
        barrier.wait()
        try:
            consumer.consume(PEER, drifted_evidence, PRINCIPAL, IDENTITY)
        except RuntimeBoundaryError as error:
            return str(error)
        raise AssertionError("drifted grant was consumed")

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(consume, consumers))

    assert sorted(outcomes) == [
        "start grant already consumed",
        "start grant binding drifted",
    ]
    assert runtime.closed == [101, 102]


def test_binding_drift_consumes_grant_across_consumers_and_closes_fds_once():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    drifted_consumer = OneShotGrantConsumer(grant, runtime)
    replay_consumer = OneShotGrantConsumer(grant, runtime)

    with pytest.raises(RuntimeBoundaryError, match="start grant binding drifted"):
        drifted_consumer.consume(
            PEER, dataclasses.replace(EVIDENCE, mcs_pair="c0,c2"), PRINCIPAL, IDENTITY
        )
    assert runtime.closed == [101, 102]

    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        replay_consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY)
    assert runtime.closed == [101, 102]


def test_one_shot_consumer_rejects_binding_drift_and_closes_owned_fds_once():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    consumer = OneShotGrantConsumer(grant, runtime)

    with pytest.raises(RuntimeBoundaryError, match="start grant binding drifted"):
        consumer.consume(
            PEER, dataclasses.replace(EVIDENCE, mcs_pair="c0,c2"), PRINCIPAL, IDENTITY
        )
    assert runtime.closed == [101, 102]

    with pytest.raises(RuntimeBoundaryError, match="start grant already consumed"):
        consumer.consume(PEER, EVIDENCE, PRINCIPAL, IDENTITY)
    assert runtime.closed == [101, 102]


def test_dataclasses_replace_projection_drift_is_unissued_and_closes_no_fd():
    runtime = FakeRuntimeOperations()
    grant = _attest(runtime=runtime)
    drifted = dataclasses.replace(
        grant,
        projection=dataclasses.replace(
            grant.projection, binding_id="hmac-sha256:" + "e" * 64
        ),
    )
    with pytest.raises(RuntimeBoundaryError, match="start grant is invalid"):
        OneShotGrantConsumer(drifted, runtime).consume(
            PEER, EVIDENCE, PRINCIPAL, IDENTITY
        )
    assert runtime.closed == []


def test_issued_start_grant_serialization_fails_closed():
    grant = _attest()

    with pytest.raises(TypeError, match="start grant is not serializable"):
        pickle.dumps(grant)


def test_internal_grant_issuer_is_only_called_by_attestation_and_not_exported():
    import codex_master.fleet_home_broker_runtime as runtime

    source = Path(runtime.__file__).read_text()
    tree = ast.parse(source)
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }

    issuer_calls = [
        function_name
        for function_name, function in functions.items()
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_issue_start_grant"
    ]
    constructors = [
        function_name
        for function_name, function in functions.items()
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "StartGrant"
    ]
    assigned_names = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    assert issuer_calls == ["_issue_trusted_start_grant", "attest_kernel_peer"]
    assert constructors == ["_issue_start_grant"]
    assert "_issue_start_grant" not in runtime.__all__
    assert "_issue_trusted_start_grant" not in runtime.__all__
    assert "_START_GRANT_ISSUER" not in assigned_names


def test_trusted_operations_are_called_without_getattr_preprobes():
    import codex_master.fleet_home_broker_runtime as runtime

    tree = ast.parse(Path(runtime.__file__).read_text())

    assert [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
    ] == []


def test_runtime_module_imports_only_offline_contracts():
    source = (
        Path(__file__).resolve().parents[1]
        / "src/codex_master/fleet_home_broker_runtime.py"
    ).read_text()
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".")[0])

    assert imported <= {
        "__future__",
        "dataclasses",
        "threading",
        "typing",
        "weakref",
        "codex_master",
    }
    forbidden = {
        "socket",
        "os",
        "pathlib",
        "subprocess",
        "logging",
        "systemd",
        "selinux",
        "mount",
        "open",
        "read",
        "write",
        "request",
        "secret",
        "bytes",
        "auth",
        "home",
    }
    assert forbidden.isdisjoint(
        token.id for token in ast.walk(tree) if isinstance(token, ast.Name)
    )


def test_runtime_api_exports_only_a3a_surface():
    import codex_master.fleet_home_broker_runtime as runtime

    assert runtime.__all__ == (
        "BrokerReleaseSpec",
        "CredentialProjection",
        "CredentialProjectionProvider",
        "KernelPeerEvidence",
        "OneShotGrantConsumer",
        "RuntimeBoundaryError",
        "RuntimePeerOperations",
        "RuntimePrincipalResolver",
        "StartGrant",
        "TrustedPrincipalGrantContext",
        "attest_kernel_peer",
    )
