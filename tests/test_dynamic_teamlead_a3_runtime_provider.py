from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError, fields, replace
import pickle
from pathlib import Path

import pytest

from codex_master.dynamic_teamlead import DynamicTeamleadRequest, ProfileBinding
from codex_master.dynamic_teamlead_a3_runtime_provider import (
    DynamicTeamleadA3RuntimeContext,
    DynamicTeamleadA3RuntimeProviderError,
    RootOwnedDynamicTeamleadStartPort,
    build_root_owned_dynamic_teamlead_start_port,
    validate_dynamic_teamlead_a3_runtime_context,
)
from codex_master.dynamic_teamlead_a3_registry import FleetV2RegistryOperations
from codex_master.dynamic_teamlead_coordinator import (
    DynamicTeamleadCoordinatorCode,
    DynamicTeamleadCoordinatorError,
    DynamicTeamleadCoordinatorRequest,
)
from codex_master.dynamic_teamlead_start import dynamic_teamlead_start
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_client import ScmFrame
from codex_master.fleet_home_broker_client_seqpacket import (
    SeqpacketBrokerClientOperations,
)
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    AttestHomeRequest,
    BindingExpectation,
    ChpbMessageKind,
    ChpbTransactionOperation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    TransactionBinding,
)
from codex_master.fleet_home_broker_runtime import (
    BrokerReleaseSpec,
    TrustedPrincipalGrantContext,
)
from codex_master.dynamic_teamlead_a3_runner import RootDynamicTeamleadStartComposition
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

from test_dynamic_teamlead_coordinator import direct_success_frames
from test_fleet_root_system_bus import a3_runtime_context, offline_runner_authority


AGENT_ID = "tl-00000000000000000000000000000001"
ACCOUNT_ID = "account-one"
PROFILE_ID = "profile-one"
BINDING_ID = "hmac-sha256:" + "a" * 64
REGISTRY_GENERATION = 7
MUTATION_REQUEST_ID = "a" * 32
ATTESTATION_REQUEST_ID = "b" * 32
TRANSACTION_ID = "c" * 32
STORE_UUID = "d" * 32


def account() -> FleetAccountV2:
    return FleetAccountV2(
        account_id=ACCOUNT_ID,
        label="Account One",
        provider=Provider.OPENAI_CHATGPT,
        auth_kind=AuthKind.CHATGPT_SESSION,
        secret_state=SecretState.CONFIGURED,
        limit_state=LimitState.READY,
        enabled=True,
        reset_at_utc=None,
        last_probe_at_utc=None,
        limit_reason=None,
        credential_binding_id=BINDING_ID,
    )


def runtime_principal() -> FleetRuntimePrincipalV2:
    return FleetRuntimePrincipalV2(
        principal_id=AGENT_ID,
        account_id=ACCOUNT_ID,
        profile_id=PROFILE_ID,
        credential_binding_id=BINDING_ID,
        class_id="teamleiterin",
        lifecycle="persistent",
        provider=Provider.OPENAI_CHATGPT,
        runner=RunnerKind.CODEX_CLI,
        model="gpt-5.6-terra",
        reasoning="xhigh",
        enabled=True,
    )


def snapshot() -> FleetSnapshotV2:
    return FleetSnapshotV2(
        schema_version=2,
        generation=REGISTRY_GENERATION,
        accounts=(account(),),
        series=(),
        runtime_principals=(runtime_principal(),),
    )


def selection() -> DynamicTeamleadRequest:
    return DynamicTeamleadRequest(
        agent_id=AGENT_ID,
        account_id=ACCOUNT_ID,
        registry_generation=REGISTRY_GENERATION,
        model="gpt-5.6-terra",
        reasoning="xhigh",
    )


def profile_binding() -> ProfileBinding:
    return ProfileBinding(PROFILE_ID, BINDING_ID)


def principal_binding() -> PrincipalBinding:
    return PrincipalBinding(
        agent_id=AGENT_ID,
        manifest_generation=3,
        unit_generation=9,
        cgroup_dev=17,
        cgroup_ino=29,
        invocation_id="4" * 32,
        mcs_pair="c0,c1",
        fencing_epoch=4,
    )


def identity() -> BrokerIdentity:
    return BrokerIdentity(
        agent_id=AGENT_ID,
        manifest_generation=3,
        mcs_pair="c0,c1",
        slot_snapshot="slot-7",
        policy_generation=7,
        projection_digest="5" * 64,
        executable_fingerprint="6" * 64,
        fencing_epoch=4,
    )


def release() -> BrokerReleaseSpec:
    return BrokerReleaseSpec(
        joint_release_version=1,
        release_id="0.11.0",
        server_digest="1" * 64,
        broker_manifest_digest="2" * 64,
        chpb_abi="CHPB/2",
        policy_abi="policy-v1",
        provider_abi="provider-v1",
        unit_digest="3" * 64,
        selinux_digest="4" * 64,
        socket_unit="codex-master-home-broker.socket",
        service_unit="codex-master-home-broker.service",
        system_bus_name="org.codex_master.HomeBrokerControl",
        system_bus_path="/org/codex_master/HomeBrokerControl",
        system_bus_interface="org.codex_master.HomeBrokerControl1",
        broker_domain="codex_master_home_broker_t",
        gateway_domain="codex_master_control_t",
        socket_type="codex_master_home_broker_runtime_t",
        agent_domain="codex_master_agent_t",
    )


def coordinator_request(
    current_snapshot: FleetSnapshotV2,
    current_selection: DynamicTeamleadRequest,
    current_profile: ProfileBinding,
    current_principal: PrincipalBinding,
    current_identity: BrokerIdentity,
) -> DynamicTeamleadCoordinatorRequest:
    expected = BindingExpectation(
        current_principal.agent_id,
        current_principal.manifest_generation,
        current_principal.unit_generation,
        current_identity.policy_generation,
        current_identity.projection_digest,
        current_principal.fencing_epoch,
    )
    binding = TransactionBinding(
        ChpbTransactionOperation.PROVISION,
        TRANSACTION_ID,
        STORE_UUID,
        current_principal,
        PolicyBinding(
            current_identity.policy_generation,
            current_identity.projection_digest,
        ),
    )
    return DynamicTeamleadCoordinatorRequest(
        snapshot=current_snapshot,
        selection=current_selection,
        profile_binding=current_profile,
        runtime_principal=current_snapshot.runtime_principals[0],
        expected_principal=current_principal,
        identity=current_identity,
        mutation=ProvisionHomeRequest(
            "CHPB/2",
            ChpbMessageKind.PROVISION_HOME,
            MUTATION_REQUEST_ID,
            TRANSACTION_ID,
            expected,
            binding,
        ),
        terminal_requests=(),
        attestation=AttestHomeRequest(
            "CHPB/2",
            ChpbMessageKind.ATTEST_HOME,
            ATTESTATION_REQUEST_ID,
            TRANSACTION_ID,
            expected,
        ),
    )


def valid_value() -> DynamicTeamleadA3RuntimeContext:
    current_snapshot = snapshot()
    current_selection = selection()
    current_profile = profile_binding()
    current_principal = principal_binding()
    current_identity = identity()
    trusted = TrustedPrincipalGrantContext(
        snapshot=current_snapshot,
        selection=current_selection,
        profile_binding=current_profile,
        expected_principal=current_principal,
        identity=current_identity,
    )
    request = coordinator_request(
        current_snapshot,
        current_selection,
        current_profile,
        current_principal,
        current_identity,
    )
    return DynamicTeamleadA3RuntimeContext(trusted, request, release())


def assert_invalid(value: object) -> None:
    with pytest.raises(DynamicTeamleadA3RuntimeProviderError) as caught:
        validate_dynamic_teamlead_a3_runtime_context(value)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_dynamic_teamlead_a3_runtime_context"


class ContextEqualityImpostor:
    def __ne__(self, other: object) -> bool:
        del other
        return False


def test_validate_returns_same_frozen_context_repeatedly() -> None:
    value = valid_value()

    assert validate_dynamic_teamlead_a3_runtime_context(value) is value
    assert validate_dynamic_teamlead_a3_runtime_context(value) is value
    with pytest.raises(FrozenInstanceError):
        value.release = release()  # type: ignore[misc]


def test_rejects_equal_but_distinct_snapshot() -> None:
    value = valid_value()
    distinct_snapshot = replace(value.context.snapshot)
    trusted = replace(value.context, snapshot=distinct_snapshot)

    assert distinct_snapshot == value.request.snapshot
    assert distinct_snapshot is not value.request.snapshot
    assert_invalid(replace(value, context=trusted))


def test_rejects_mutable_context_impostor() -> None:
    value = valid_value()

    class MutableImpostor:
        context = value.context
        request = value.request
        release = value.release

    assert_invalid(MutableImpostor())


def test_rejects_non_v2_snapshot_impostor_even_when_shared() -> None:
    value = valid_value()

    class MutableSnapshotImpostor:
        schema_version = 2
        generation = REGISTRY_GENERATION
        accounts = value.context.snapshot.accounts
        series = ()
        runtime_principals = value.context.snapshot.runtime_principals

    impostor = MutableSnapshotImpostor()
    trusted = replace(value.context, snapshot=impostor)
    request = replace(value.request, snapshot=impostor)

    assert_invalid(replace(value, context=trusted, request=request))


def test_rejects_non_v2_schema() -> None:
    value = valid_value()
    stale = replace(value.context.snapshot, schema_version=1)
    trusted = replace(value.context, snapshot=stale)
    request = replace(value.request, snapshot=stale)

    assert_invalid(replace(value, context=trusted, request=request))


@pytest.mark.parametrize("member", ("expected_principal", "identity"))
def test_rejects_shared_untyped_principal_or_identity(member: str) -> None:
    value = valid_value()
    untyped = object()
    trusted = replace(value.context, **{member: untyped})
    request = replace(value.request, **{member: untyped})

    assert_invalid(replace(value, context=trusted, request=request))


@pytest.mark.parametrize("member", ("expected_principal", "identity"))
def test_rejects_context_only_equality_impostor(member: str) -> None:
    value = valid_value()
    trusted = replace(value.context, **{member: ContextEqualityImpostor()})

    assert_invalid(replace(value, context=trusted))


def test_rejects_shared_typed_principal_and_identity_foreign_to_selection() -> None:
    value = valid_value()
    foreign_agent_id = "tl-00000000000000000000000000000002"
    foreign_principal = replace(
        value.context.expected_principal,
        agent_id=foreign_agent_id,
    )
    foreign_identity = replace(value.context.identity, agent_id=foreign_agent_id)
    trusted = replace(
        value.context,
        expected_principal=foreign_principal,
        identity=foreign_identity,
    )
    request = replace(
        value.request,
        expected_principal=foreign_principal,
        identity=foreign_identity,
    )

    assert_invalid(replace(value, context=trusted, request=request))


@pytest.mark.parametrize(
    ("field", "changed"),
    (
        ("agent id", "tl-00000000000000000000000000000002"),
        ("manifest generation", 4),
        ("mcs pair", "c2,c3"),
        ("fencing epoch", 5),
    ),
)
def test_rejects_shared_identity_not_bound_to_shared_principal(
    field: str,
    changed: str | int,
) -> None:
    value = valid_value()
    field_name = field.replace(" ", "_")
    unbound_identity = replace(value.context.identity, **{field_name: changed})
    trusted = replace(value.context, identity=unbound_identity)
    request = replace(value.request, identity=unbound_identity)

    assert_invalid(replace(value, context=trusted, request=request))


def _with_chpb_messages(
    value: DynamicTeamleadA3RuntimeContext,
    *,
    mutation: ProvisionHomeRequest | None = None,
    attestation: AttestHomeRequest | None = None,
) -> DynamicTeamleadA3RuntimeContext:
    request = replace(
        value.request,
        mutation=mutation or value.request.mutation,
        attestation=attestation or value.request.attestation,
    )
    return replace(value, request=request)


@pytest.mark.parametrize(
    ("field", "changed"),
    (
        ("policy_generation", 8),
        ("projection_digest", "7" * 64),
    ),
)
def test_rejects_shared_identity_not_bound_to_chpb_policy(
    field: str,
    changed: str | int,
) -> None:
    value = valid_value()
    unbound_identity = replace(value.context.identity, **{field: changed})
    trusted = replace(value.context, identity=unbound_identity)
    request = replace(value.request, identity=unbound_identity)

    assert_invalid(replace(value, context=trusted, request=request))


def test_rejects_chpb_mutation_principal_not_bound_to_request() -> None:
    value = valid_value()
    foreign_principal = replace(
        value.request.expected_principal,
        agent_id="tl-00000000000000000000000000000002",
    )
    mutation = replace(
        value.request.mutation,
        binding=replace(value.request.mutation.binding, principal=foreign_principal),
    )

    assert_invalid(_with_chpb_messages(value, mutation=mutation))


@pytest.mark.parametrize(
    ("field", "changed"),
    (("unit_generation", 10), ("fencing_epoch", 5)),
)
def test_rejects_chpb_expectation_not_bound_to_principal(
    field: str,
    changed: int,
) -> None:
    value = valid_value()
    expectation = replace(value.request.mutation.expected, **{field: changed})
    mutation = replace(value.request.mutation, expected=expectation)
    attestation = replace(value.request.attestation, expected=expectation)

    assert_invalid(
        _with_chpb_messages(value, mutation=mutation, attestation=attestation)
    )


@pytest.mark.parametrize("transfer", (copy.copy, copy.deepcopy, pickle.dumps))
def test_context_rejects_copy_and_pickle(transfer) -> None:
    with pytest.raises(DynamicTeamleadA3RuntimeProviderError) as caught:
        transfer(valid_value())

    assert caught.value.code == "dynamic_teamlead_a3_runtime_context_nontransferable"


@pytest.mark.parametrize(
    ("name", "changed"),
    (
        (
            "selection",
            lambda value: replace(
                value,
                request=replace(
                    value.request,
                    selection=replace(
                        value.request.selection,
                        registry_generation=8,
                    ),
                ),
            ),
        ),
        (
            "snapshot generation",
            lambda value: replace(
                value,
                request=replace(
                    value.request,
                    snapshot=replace(value.request.snapshot, generation=8),
                ),
            ),
        ),
        (
            "principal binding",
            lambda value: replace(
                value,
                context=replace(
                    value.context,
                    expected_principal=replace(
                        value.context.expected_principal,
                        unit_generation=10,
                    ),
                ),
            ),
        ),
        (
            "profile credential binding",
            lambda value: replace(
                value,
                context=replace(
                    value.context,
                    profile_binding=replace(
                        value.context.profile_binding,
                        credential_binding_id="binding-two",
                    ),
                ),
            ),
        ),
        (
            "policy generation",
            lambda value: replace(
                value,
                context=replace(
                    value.context,
                    identity=replace(value.context.identity, policy_generation=8),
                ),
            ),
        ),
        (
            "projection digest",
            lambda value: replace(
                value,
                context=replace(
                    value.context,
                    identity=replace(
                        value.context.identity,
                        projection_digest="7" * 64,
                    ),
                ),
            ),
        ),
        (
            "release field",
            lambda value: replace(
                value,
                release=replace(value.release, release_id="0.11.1"),
            ),
        ),
        (
            "runtime principal",
            lambda value: replace(
                value,
                request=replace(
                    value.request,
                    runtime_principal=replace(
                        value.request.runtime_principal,
                        enabled=False,
                    ),
                ),
            ),
        ),
    ),
)
def test_rejects_altered_bound_component(name: str, changed) -> None:
    del name

    assert_invalid(changed(valid_value()))


@pytest.mark.parametrize(
    "value",
    (
        object(),
        replace(valid_value(), context=object()),
        replace(valid_value(), request=object()),
        replace(valid_value(), release=object()),
    ),
)
def test_rejects_malformed_context_members(value: object) -> None:
    assert_invalid(value)


class _RegistryStore:
    def __init__(self, captured: FleetSnapshotV2) -> None:
        self.captured = captured
        self.load_calls = 0
        self.commit_calls = 0
        self.commit_error: Exception | None = None

    def load(self) -> FleetSnapshotV2:
        self.load_calls += 1
        return self.captured

    def commit_snapshot(
        self, snapshot: FleetSnapshotV2, *, expected_generation: int
    ) -> FleetSnapshotV2:
        self.commit_calls += 1
        del expected_generation
        if self.commit_error is not None:
            raise self.commit_error
        return snapshot


class _Exchange:
    def __init__(self, frames: list[ScmFrame]) -> None:
        self.frames = list(frames)
        self.calls: list[ScmFrame] = []
        self.closed: list[int] = []

    def exchange(self, request: ScmFrame) -> ScmFrame:
        self.calls.append(request)
        return self.frames.pop(0)

    def fstat(self, fd: int) -> FdStat:
        del fd
        return FdStat(17, 31, 0o40700, 0, 0)

    def close(self, fd: int) -> None:
        self.closed.append(fd)


class _RunnerOperations:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[object, object]] = []

    def execute(self, plan: object, *, permit: object) -> None:
        self.calls.append((plan, permit))
        if self.error is not None:
            raise self.error


class _DuckExecutor:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def execute_dynamic_teamlead_runner(self, plan: object) -> None:
        self.calls.append(plan)


def _root_issued_parts() -> dict[str, object]:
    authority = offline_runner_authority()
    _host, consumer, service, _trusted_context = authority
    runtime_context = a3_runtime_context(consumer._context, service._release)
    store = _RegistryStore(runtime_context.context.snapshot)
    registry = FleetV2RegistryOperations(store, runtime_context.context.snapshot)
    exchange = _Exchange(direct_success_frames(runtime_context.request))
    broker = SeqpacketBrokerClientOperations(
        exchange,
        a3_context_identity=runtime_context,
        release_identity=service._release,
    )
    operations = _RunnerOperations()
    composition = consumer.issue_root_owned_dynamic_teamlead_start_composition(
        runtime_context,
        registry,
        broker,
        operations,
    )
    return {
        "authority": authority,
        "consumer": consumer,
        "service": service,
        "context": runtime_context,
        "store": store,
        "registry": registry,
        "exchange": exchange,
        "broker": broker,
        "operations": operations,
        "composition": composition,
    }


@pytest.fixture
def root_issued_parts():
    parts = _root_issued_parts()
    yield parts
    try:
        parts["consumer"].close()
    except Exception:
        pass


def _reconstructed_composition(
    composition: RootDynamicTeamleadStartComposition,
    **changes: object,
) -> RootDynamicTeamleadStartComposition:
    values = {
        field.name: getattr(composition, field.name)
        for field in fields(RootDynamicTeamleadStartComposition)
    }
    values.update(changes)
    result = object.__new__(RootDynamicTeamleadStartComposition)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def test_root_issued_composition_runs_coordinate_prepare_execute_once(
    root_issued_parts: dict[str, object],
) -> None:
    composition = root_issued_parts["composition"]
    assert type(composition) is RootDynamicTeamleadStartComposition

    port = build_root_owned_dynamic_teamlead_start_port(composition)

    assert type(port) is RootOwnedDynamicTeamleadStartPort
    assert port.request is composition.request
    assert port.registry_operations is composition.registry_operations
    assert port.broker_operations is composition.broker_operations
    assert dynamic_teamlead_start(port) == {
        "schema_version": 1,
        "status": "started",
        "raw_output": "not_returned",
    }
    assert len(root_issued_parts["exchange"].calls) == 2
    assert len(root_issued_parts["operations"].calls) == 1
    assert root_issued_parts["store"].load_calls == 0
    assert root_issued_parts["store"].commit_calls == 0


def test_factory_accepts_only_composition_not_duck_executor_or_evidence() -> None:
    duck = _DuckExecutor()

    with pytest.raises(TypeError):
        build_root_owned_dynamic_teamlead_start_port(duck, object())  # type: ignore[call-arg]
    with pytest.raises(DynamicTeamleadA3RuntimeProviderError):
        build_root_owned_dynamic_teamlead_start_port(duck)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ("request", "snapshot_identity", "release_identity"))
def test_factory_rejects_identity_and_generation_drift(
    root_issued_parts: dict[str, object],
    field: str,
) -> None:
    composition = root_issued_parts["composition"]
    context = root_issued_parts["context"]
    if field == "request":
        changed = replace(composition.request)
    elif field == "snapshot_identity":
        changed = replace(composition.snapshot_identity, generation=8)
    else:
        changed = replace(composition.release_identity, release_id="0.11.1")

    with pytest.raises(DynamicTeamleadA3RuntimeProviderError):
        build_root_owned_dynamic_teamlead_start_port(
            _reconstructed_composition(composition, **{field: changed})
        )
    assert context.request is composition.request


def test_factory_rejects_foreign_registry_and_broker_identity(
    root_issued_parts: dict[str, object],
) -> None:
    composition = root_issued_parts["composition"]
    context = root_issued_parts["context"]
    service = root_issued_parts["service"]
    foreign_snapshot = replace(context.context.snapshot)
    foreign_registry = FleetV2RegistryOperations(
        _RegistryStore(foreign_snapshot), foreign_snapshot
    )
    foreign_broker = SeqpacketBrokerClientOperations(
        root_issued_parts["exchange"],
        a3_context_identity=replace(context),
        release_identity=replace(service._release),
    )

    for changes in (
        {"registry_operations": foreign_registry},
        {"broker_operations": foreign_broker},
    ):
        with pytest.raises(DynamicTeamleadA3RuntimeProviderError):
            build_root_owned_dynamic_teamlead_start_port(
                _reconstructed_composition(composition, **changes)
            )


@pytest.mark.parametrize(
    "transfer",
    (copy.copy, copy.deepcopy, pickle.dumps, lambda value: replace(value)),
)
def test_port_is_factory_only_and_nontransferable(
    root_issued_parts: dict[str, object], transfer,
) -> None:
    composition = root_issued_parts["composition"]
    with pytest.raises(DynamicTeamleadA3RuntimeProviderError):
        build_root_owned_dynamic_teamlead_start_port(
            object()  # type: ignore[arg-type]
        )

    port = build_root_owned_dynamic_teamlead_start_port(composition)
    assert not hasattr(port, "__dict__")
    assert repr(port) == "<RootOwnedDynamicTeamleadStartPort redacted>"
    with pytest.raises(TypeError):
        RootOwnedDynamicTeamleadStartPort()  # type: ignore[call-arg]
    with pytest.raises((TypeError, DynamicTeamleadA3RuntimeProviderError)):
        transfer(port)


def test_consumed_root_issuance_cannot_be_repeated(
    root_issued_parts: dict[str, object],
) -> None:
    composition = root_issued_parts["composition"]
    port = build_root_owned_dynamic_teamlead_start_port(composition)
    dynamic_teamlead_start(port)

    with pytest.raises(Exception):
        root_issued_parts["consumer"].issue_root_owned_dynamic_teamlead_start_composition(
            root_issued_parts["context"],
            root_issued_parts["registry"],
            root_issued_parts["broker"],
            root_issued_parts["operations"],
        )


def test_malformed_broker_frame_fails_before_executor(
    root_issued_parts: dict[str, object],
) -> None:
    root_issued_parts["exchange"].frames = [ScmFrame(b"malformed", ())]
    port = build_root_owned_dynamic_teamlead_start_port(
        root_issued_parts["composition"]
    )

    with pytest.raises(Exception):
        dynamic_teamlead_start(port)
    assert root_issued_parts["operations"].calls == []


def test_root_issued_port_closes_home_and_skips_executor_on_registry_cas_conflict(
    root_issued_parts: dict[str, object],
) -> None:
    port = build_root_owned_dynamic_teamlead_start_port(
        root_issued_parts["composition"]
    )
    snapshot_value = port.request.snapshot
    requested_principal = port.request.runtime_principal
    root_issued_parts["store"].commit_error = RuntimeError("CAS conflict")

    # Root issuance and provider validation already completed. This test-only
    # same-process drift makes the requested principal new to the coordinator;
    # it is not an external forgery or Composition-unforgeability claim.
    object.__setattr__(snapshot_value, "runtime_principals", ())
    assert all(
        principal.principal_id != requested_principal.principal_id
        for principal in snapshot_value.runtime_principals
    )

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        dynamic_teamlead_start(port)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED
    assert root_issued_parts["store"].load_calls == 1
    assert root_issued_parts["store"].commit_calls == 1
    assert root_issued_parts["exchange"].closed == [61]
    assert root_issued_parts["operations"].calls == []


def test_executor_failure_propagates_without_legacy_fallback(
    root_issued_parts: dict[str, object],
) -> None:
    root_issued_parts["operations"].error = RuntimeError("executor failed")
    port = build_root_owned_dynamic_teamlead_start_port(
        root_issued_parts["composition"]
    )

    with pytest.raises(RuntimeError, match="executor failed"):
        dynamic_teamlead_start(port)
    assert len(root_issued_parts["operations"].calls) == 1


def test_provider_has_no_live_authority_or_state_imports() -> None:
    path = Path(__file__).parents[1] / (
        "src/codex_master/dynamic_teamlead_a3_runtime_provider.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {
        "codex_master.server",
        "codex_master.fleet_root_system_bus",
        "os",
        "socket",
        "subprocess",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported.isdisjoint(forbidden)
    forbidden_origin_attributes = {
        "__class__",
        "__module__",
        "__name__",
        "__qualname__",
    }
    used_attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert used_attributes.isdisjoint(forbidden_origin_attributes)
    string_constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert string_constants.isdisjoint(
        {
            "_ConsumerDynamicTeamleadRunnerExecutor",
            "codex_master.fleet_root_system_bus",
        }
    )
