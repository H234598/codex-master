import ast
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest
import codex_master.dynamic_teamlead_coordinator as coordinator_module

from codex_master.dynamic_teamlead import (
    DynamicTeamleadError,
    DynamicTeamleadRequest,
    ProfileBinding,
)
from codex_master.dynamic_teamlead_coordinator import (
    MAX_DYNAMIC_TEAMLEAD_TERMINAL_POLLS,
    DynamicTeamleadCoordinatorCode,
    DynamicTeamleadCoordinatorError,
    DynamicTeamleadCoordinatorRequest,
    DynamicTeamleadRegistryOperations,
    DynamicTeamleadLaunchPlan,
    coordinate_dynamic_teamlead,
)
from codex_master.fleet_home_broker_client import ScmFrame
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObservation,
    BrokerObjectState,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    BindingExpectation,
    CANONICAL_AGENT_HOME,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DirectoryIdentity,
    AttestHomeRequest,
    GetTerminalResultRequest,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    ProvisionHomeRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    encode_chpb_message,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccountV2,
    FleetRuntimePrincipalV2,
    FleetSnapshot,
    FleetSnapshotV2,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)


ACCOUNT_ID = "openai-primary"
BINDING = "hmac-sha256:" + "a" * 64
AGENT_ID = "tl-00000000000000000000000000000001"
STORE_UUID = "b" * 32
TRANSACTION_ID = "c" * 32
REQUEST_IDS = ("d" * 32, "e" * 32, "f" * 32, "1" * 32, "2" * 32)
DIRECTORY = DirectoryIdentity(17, 31, 0o40700)


def account(**changes: object) -> FleetAccountV2:
    value = FleetAccountV2(
        account_id=ACCOUNT_ID,
        label="OpenAI primary",
        provider=Provider.OPENAI_CHATGPT,
        auth_kind=AuthKind.CHATGPT_SESSION,
        secret_state=SecretState.CONFIGURED,
        limit_state=LimitState.READY,
        enabled=True,
        reset_at_utc=None,
        last_probe_at_utc=None,
        limit_reason=None,
        credential_binding_id=BINDING,
    )
    return replace(value, **changes)


def principal(**changes: object) -> FleetRuntimePrincipalV2:
    value = FleetRuntimePrincipalV2(
        principal_id=AGENT_ID,
        account_id=ACCOUNT_ID,
        profile_id="BW_Nufker",
        credential_binding_id=BINDING,
        class_id="teamleiterin",
        lifecycle="persistent",
        provider=Provider.OPENAI_CHATGPT,
        runner=RunnerKind.CODEX_CLI,
        model="gpt-5.6-terra",
        reasoning="xhigh",
        enabled=True,
    )
    return replace(value, **changes)


def snapshot(**changes: object) -> FleetSnapshotV2:
    value = FleetSnapshotV2(2, 7, (account(),), (), (principal(),))
    return replace(value, **changes)


def teamlead_request(**changes: object) -> DynamicTeamleadRequest:
    value = DynamicTeamleadRequest(
        agent_id=AGENT_ID,
        account_id=ACCOUNT_ID,
        registry_generation=7,
        model="gpt-5.6-terra",
        reasoning="xhigh",
    )
    return replace(value, **changes)


def profile_binding(**changes: object) -> ProfileBinding:
    return replace(ProfileBinding("BW_Nufker", BINDING), **changes)


def principal_binding(**changes: object) -> PrincipalBinding:
    value = PrincipalBinding(
        agent_id=AGENT_ID,
        manifest_generation=3,
        unit_generation=9,
        cgroup_dev=17,
        cgroup_ino=29,
        invocation_id="4" * 32,
        mcs_pair="c0,c1",
        fencing_epoch=4,
    )
    return replace(value, **changes)


def identity(**changes: object) -> BrokerIdentity:
    value = BrokerIdentity(
        agent_id=AGENT_ID,
        manifest_generation=3,
        mcs_pair="c0,c1",
        slot_snapshot="slot-7",
        policy_generation=7,
        projection_digest="5" * 64,
        executable_fingerprint="6" * 64,
        fencing_epoch=4,
    )
    return replace(value, **changes)


def coordinator_request(
    *,
    current: FleetSnapshotV2 | FleetSnapshot | None = None,
    candidate: FleetRuntimePrincipalV2 | None = None,
    operation: ChpbTransactionOperation = ChpbTransactionOperation.PROVISION,
    **changes: object,
) -> DynamicTeamleadCoordinatorRequest:
    current = current or snapshot()
    candidate = candidate or principal()
    selected = teamlead_request()
    expected_principal = principal_binding()
    broker_identity = identity()
    expected = BindingExpectation(
        expected_principal.agent_id,
        expected_principal.manifest_generation,
        expected_principal.unit_generation,
        broker_identity.policy_generation,
        broker_identity.projection_digest,
        expected_principal.fencing_epoch,
    )
    binding = TransactionBinding(
        operation,
        TRANSACTION_ID,
        STORE_UUID,
        expected_principal,
        PolicyBinding(
            broker_identity.policy_generation,
            broker_identity.projection_digest,
        ),
    )
    if operation is ChpbTransactionOperation.PROVISION:
        mutation = ProvisionHomeRequest(
            "CHPB/2",
            ChpbMessageKind.PROVISION_HOME,
            REQUEST_IDS[0],
            TRANSACTION_ID,
            expected,
            binding,
        )
    else:
        mutation = ReplaceHomeRequest(
            "CHPB/2",
            ChpbMessageKind.REPLACE_HOME,
            REQUEST_IDS[0],
            TRANSACTION_ID,
            expected,
            binding,
        )
    terminal_requests = tuple(
        GetTerminalResultRequest(
            "CHPB/2",
            ChpbMessageKind.GET_TERMINAL_RESULT,
            request_id,
            TRANSACTION_ID,
            expected,
        )
        for request_id in REQUEST_IDS[1:4]
    )
    attest = AttestHomeRequest(
        "CHPB/2",
        ChpbMessageKind.ATTEST_HOME,
        REQUEST_IDS[4],
        TRANSACTION_ID,
        expected,
    )
    value = DynamicTeamleadCoordinatorRequest(
        snapshot=current,
        selection=selected,
        profile_binding=profile_binding(),
        runtime_principal=candidate,
        expected_principal=expected_principal,
        identity=broker_identity,
        mutation=mutation,
        terminal_requests=terminal_requests,
        attestation=attest,
    )
    return replace(value, **changes)


def binding_for(
    request: DynamicTeamleadCoordinatorRequest,
    operation: ChpbTransactionOperation | None = None,
) -> TransactionBinding:
    if operation is None:
        return request.mutation.binding
    return replace(request.mutation.binding, operation=operation)


def status_for(
    binding: TransactionBinding,
    *,
    committed: bool,
    terminal: BrokerResultCode | None = None,
) -> TransactionStatus:
    if committed:
        return TransactionStatus(
            binding,
            B2aRecoveryPhase.COMMITTED,
            BrokerCheckpoint.COMMITTED,
            BrokerObservation(
                BrokerObjectState.FINAL_COMPLETE,
                BrokerRegistryState.CURRENT,
                1,
            ),
            1,
            terminal or BrokerResultCode.COMMITTED,
        )
    checkpoint = (
        BrokerCheckpoint.CREATE_INTENT
        if binding.operation is ChpbTransactionOperation.PROVISION
        else BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT
    )
    phase = (
        B2aRecoveryPhase.ABSENT_CREATE_PENDING
        if binding.operation is ChpbTransactionOperation.PROVISION
        else B2aRecoveryPhase.PREPARE_PENDING
    )
    object_state = (
        BrokerObjectState.ABSENT
        if binding.operation is ChpbTransactionOperation.PROVISION
        else BrokerObjectState.REPLACEMENT_ORIGINAL
    )
    return TransactionStatus(
        binding,
        phase,
        checkpoint,
        BrokerObservation(object_state, BrokerRegistryState.NOT_APPLICABLE, 0),
        1,
        terminal,
    )


def rolled_back_status(binding: TransactionBinding) -> TransactionStatus:
    return TransactionStatus(
        binding,
        B2aRecoveryPhase.ROLLED_BACK,
        BrokerCheckpoint.ROLLED_BACK,
        BrokerObservation(
            BrokerObjectState.ROLLED_BACK,
            BrokerRegistryState.NOT_APPLICABLE,
            1,
        ),
        1,
        BrokerResultCode.ROLLED_BACK,
    )


def attestation(binding: TransactionBinding) -> HomeAttestation:
    return HomeAttestation(
        binding,
        CANONICAL_AGENT_HOME,
        DIRECTORY,
        "7" * 64,
        binding.principal.mcs_pair,
    )


def reply(
    request_id: str,
    result: BrokerResultCode,
    status: TransactionStatus | None,
    home: HomeAttestation | None = None,
) -> BrokerReply:
    return BrokerReply(
        "CHPB/2",
        ChpbMessageKind.REPLY,
        request_id,
        result,
        status,
        home,
    )


def frame(value: BrokerReply, fds: tuple[int, ...] = ()) -> ScmFrame:
    return ScmFrame(encode_chpb_message(value), fds)


class FakeBroker:
    def __init__(self, frames: list[ScmFrame], *, close_error: Exception | None = None):
        self.frames = list(frames)
        self.close_error = close_error
        self.received = []
        self.fstat_calls = []
        self.closed = []

    def receive_frame(self, request):
        self.received.append(request)
        return self.frames.pop(0)

    def fstat(self, fd):
        self.fstat_calls.append(fd)
        return FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 0, 0)

    def close(self, fd):
        self.closed.append(fd)
        if self.close_error is not None:
            raise self.close_error


class FakeRegistry:
    def __init__(self, result=None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls = []

    def commit_snapshot(self, planned, *, expected_generation):
        self.calls.append((planned, expected_generation))
        if self.error is not None:
            raise self.error
        return planned if self.result is None else self.result


def successful_frames(
    request: DynamicTeamleadCoordinatorRequest,
    *,
    operation: ChpbTransactionOperation | None = None,
    pending_polls: int = 1,
    attestation_binding: TransactionBinding | None = None,
) -> list[ScmFrame]:
    binding = binding_for(request, operation)
    pending = status_for(binding, committed=False)
    committed = status_for(binding, committed=True)
    frames = [
        frame(reply(request.mutation.request_id, BrokerResultCode.PENDING, pending)),
    ]
    for index in range(pending_polls - 1):
        frames.append(
            frame(
                reply(
                    request.terminal_requests[index].request_id,
                    BrokerResultCode.PENDING,
                    pending,
                )
            )
        )
    next_id = request.terminal_requests[pending_polls - 1].request_id
    frames.append(frame(reply(next_id, BrokerResultCode.COMMITTED, committed)))
    home_binding = attestation_binding or binding
    home_status = status_for(home_binding, committed=True)
    frames.append(
        frame(
            reply(
                request.attestation.request_id,
                BrokerResultCode.OK,
                home_status,
                attestation(home_binding),
            ),
            (61,),
        )
    )
    return frames


def direct_success_frames(
    request: DynamicTeamleadCoordinatorRequest,
    *,
    operation: ChpbTransactionOperation | None = None,
    attestation_binding: TransactionBinding | None = None,
) -> list[ScmFrame]:
    binding = binding_for(request, operation)
    committed = status_for(binding, committed=True)
    home_binding = attestation_binding or binding
    return [
        frame(
            reply(request.mutation.request_id, BrokerResultCode.COMMITTED, committed)
        ),
        frame(
            reply(
                request.attestation.request_id,
                BrokerResultCode.OK,
                status_for(home_binding, committed=True),
                attestation(home_binding),
            ),
            (61,),
        ),
    ]


def test_public_contract_types_are_frozen_and_slotted() -> None:
    assert [item.name for item in fields(DynamicTeamleadCoordinatorRequest)] == [
        "snapshot",
        "selection",
        "profile_binding",
        "runtime_principal",
        "expected_principal",
        "identity",
        "mutation",
        "terminal_requests",
        "attestation",
    ]
    assert [item.name for item in fields(DynamicTeamleadLaunchPlan)] == [
        "teamlead",
        "snapshot",
        "expected_principal",
        "expectation",
        "identity",
        "home",
    ]
    assert not any(
        item.name in {"dynamic_teamlead", "expected", "mutation"}
        for item in fields(DynamicTeamleadLaunchPlan)
    )
    assert DynamicTeamleadCoordinatorRequest.__slots__
    assert DynamicTeamleadLaunchPlan.__slots__
    with pytest.raises(FrozenInstanceError):
        coordinator_request().selection = teamlead_request()
    assert not hasattr(coordinator_request(), "expected")
    assert not hasattr(coordinator_request(), "request_id")
    assert not hasattr(coordinator_module, "Request")
    assert not hasattr(coordinator_module, "LaunchPlan")
    assert not hasattr(coordinator_module, "DynamicTeamleadCoordinatorLaunchPlan")


def test_public_error_codes_are_exact() -> None:
    assert {item.value for item in DynamicTeamleadCoordinatorCode} == {
        "invalid_request",
        "runtime_principal_conflict",
        "broker_transaction_failed",
        "broker_terminal_pending",
        "broker_terminal_rejected",
        "home_binding_drift",
        "registry_cas_failed",
    }
    error = DynamicTeamleadCoordinatorError(
        DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    )
    assert error.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST


def test_registry_operations_exposes_only_commit_snapshot() -> None:
    methods = {
        name
        for name, value in DynamicTeamleadRegistryOperations.__dict__.items()
        if callable(value) and not name.startswith("_")
    }
    assert methods == {"commit_snapshot"}


def test_new_principal_is_planned_then_cas_after_attestation() -> None:
    new_principal = principal()
    request = coordinator_request(
        current=replace(snapshot(), runtime_principals=()), candidate=new_principal
    )
    broker = FakeBroker(successful_frames(request))
    registry = FakeRegistry()

    plan = coordinate_dynamic_teamlead(request, registry, broker)

    assert isinstance(plan, DynamicTeamleadLaunchPlan)
    assert plan.identity is request.identity
    assert plan.home.fd == 61
    assert plan.snapshot.generation == request.snapshot.generation + 1
    assert plan.teamlead.request.registry_generation == plan.snapshot.generation
    assert plan.snapshot.runtime_principals[-1] == new_principal
    assert len(registry.calls) == 1
    planned, expected_generation = registry.calls[0]
    assert planned == plan.snapshot
    assert expected_generation == request.snapshot.generation
    assert broker.closed == []
    assert [item.kind for item in broker.received] == [
        ChpbMessageKind.PROVISION_HOME,
        ChpbMessageKind.GET_TERMINAL_RESULT,
        ChpbMessageKind.ATTEST_HOME,
    ]
    assert len({item.request_id for item in broker.received}) == len(broker.received)
    assert {item.transaction_id for item in broker.received} == {
        request.mutation.transaction_id
    }
    assert {item.expected for item in broker.received} == {broker.received[0].expected}


def test_existing_identical_principal_does_not_cas_again() -> None:
    request = coordinator_request()
    broker = FakeBroker(direct_success_frames(request))
    registry = FakeRegistry()

    plan = coordinate_dynamic_teamlead(request, registry, broker)

    assert plan.snapshot is request.snapshot
    assert registry.calls == []
    assert [item.kind for item in broker.received] == [
        ChpbMessageKind.PROVISION_HOME,
        ChpbMessageKind.ATTEST_HOME,
    ]


def test_same_principal_id_with_drift_fails_before_broker() -> None:
    request = coordinator_request(candidate=principal(profile_id="other-profile"))
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert (
        caught.value.code is DynamicTeamleadCoordinatorCode.RUNTIME_PRINCIPAL_CONFLICT
    )
    assert broker.received == []
    assert registry.calls == []


def test_expected_principal_must_bind_dynamic_teamlead_identity() -> None:
    foreign = "tl-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    request = coordinator_request(
        expected_principal=principal_binding(agent_id=foreign),
        identity=identity(agent_id=foreign),
    )

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), FakeBroker([]))

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST


def test_malformed_expected_principal_is_coordinator_error() -> None:
    request = coordinator_request(expected_principal=object())

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), FakeBroker([]))

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST


def test_incomplete_broker_operations_are_rejected_before_mutation() -> None:
    class IncompleteBroker:
        def receive_frame(self, request):
            raise AssertionError("must not receive")

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(
            coordinator_request(), FakeRegistry(), IncompleteBroker()
        )

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST


def test_v1_keeps_existing_registry_v2_required_error() -> None:
    request = coordinator_request(current=FleetSnapshot(1, 7, (), ()))

    with pytest.raises(DynamicTeamleadError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), FakeBroker([]))

    assert caught.value.code.value == "registry_v2_required"


def test_replace_mutation_is_explicit_and_never_switched_to_provision() -> None:
    request = coordinator_request(operation=ChpbTransactionOperation.REPLACE)
    broker = FakeBroker(
        direct_success_frames(request, operation=ChpbTransactionOperation.REPLACE)
    )

    coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    mutation = broker.received[0]
    assert mutation.kind is ChpbMessageKind.REPLACE_HOME
    assert mutation.binding.operation is ChpbTransactionOperation.REPLACE


def test_deprovision_is_not_an_implicit_or_supported_mutation() -> None:
    request = coordinator_request(operation=ChpbTransactionOperation.DEPROVISION)

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), FakeBroker([]))

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST


def test_pending_terminal_is_serial_and_bounded_to_three_get_terminal_requests() -> (
    None
):
    request = coordinator_request()
    binding = binding_for(request)
    pending = status_for(binding, committed=False)
    frames = [
        frame(reply(request.mutation.request_id, BrokerResultCode.PENDING, pending))
    ]
    frames.extend(
        frame(
            reply(
                request.terminal_requests[index].request_id,
                BrokerResultCode.PENDING,
                pending,
            )
        )
        for index in range(MAX_DYNAMIC_TEAMLEAD_TERMINAL_POLLS)
    )
    broker = FakeBroker(frames)

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.BROKER_TERMINAL_PENDING
    assert [item.kind for item in broker.received] == [
        ChpbMessageKind.PROVISION_HOME,
        ChpbMessageKind.GET_TERMINAL_RESULT,
        ChpbMessageKind.GET_TERMINAL_RESULT,
        ChpbMessageKind.GET_TERMINAL_RESULT,
    ]


def test_terminal_rejection_is_distinct_from_transport_failure() -> None:
    request = coordinator_request()
    binding = binding_for(request)
    pending = status_for(binding, committed=False)
    rejected = rolled_back_status(binding)
    broker = FakeBroker(
        [
            frame(
                reply(request.mutation.request_id, BrokerResultCode.PENDING, pending)
            ),
            frame(
                reply(
                    request.terminal_requests[0].request_id,
                    BrokerResultCode.ROLLED_BACK,
                    rejected,
                )
            ),
        ]
    )

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.BROKER_TERMINAL_REJECTED


def test_transaction_receive_failure_is_mapped_before_attestation() -> None:
    request = coordinator_request()
    broker = FakeBroker(
        [
            frame(
                reply(
                    request.mutation.request_id,
                    BrokerResultCode.COMMITTED,
                    status_for(
                        binding_for(request, ChpbTransactionOperation.REPLACE),
                        committed=True,
                    ),
                )
            )
        ]
    )

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED
    assert [item.kind for item in broker.received] == [ChpbMessageKind.PROVISION_HOME]


def test_attestation_binding_drift_closes_transferred_fd_once() -> None:
    request = coordinator_request()
    drifted = binding_for(request, ChpbTransactionOperation.REPLACE)
    broker = FakeBroker(direct_success_frames(request, attestation_binding=drifted))

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.HOME_BINDING_DRIFT
    assert broker.closed == [61]


def test_registry_cas_failure_closes_home_once_and_masks_close_failure() -> None:
    request = coordinator_request(
        current=replace(snapshot(), runtime_principals=()),
        candidate=principal(),
    )
    broker = FakeBroker(successful_frames(request), close_error=OSError("close"))
    registry = FakeRegistry(error=RuntimeError("generation conflict"))

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED
    assert broker.closed == [61]


def test_registry_cas_rejects_snapshot_drift_after_commit() -> None:
    request = coordinator_request(
        current=replace(snapshot(), runtime_principals=()), candidate=principal()
    )
    drifted = replace(
        replace(snapshot(), generation=8),
        accounts=(account(label="different"),),
    )
    broker = FakeBroker(successful_frames(request))

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(result=drifted), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.REGISTRY_CAS_FAILED
    assert broker.closed == [61]


def test_registry_is_not_called_when_attestation_fails() -> None:
    request = coordinator_request(
        current=replace(snapshot(), runtime_principals=()), candidate=principal()
    )
    binding = binding_for(request)
    broker = FakeBroker(
        [
            frame(
                reply(
                    request.mutation.request_id,
                    BrokerResultCode.COMMITTED,
                    status_for(binding, committed=True),
                )
            )
        ]
    )
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.HOME_BINDING_DRIFT
    assert registry.calls == []


def test_stale_new_principal_fails_before_upsert_broker_and_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = coordinator_request(
        current=replace(snapshot(), runtime_principals=()),
        selection=teamlead_request(registry_generation=6),
    )
    upsert_calls = []

    def unexpected_upsert(*args: object, **kwargs: object) -> FleetSnapshotV2:
        upsert_calls.append((args, kwargs))
        raise AssertionError("stale request must not plan registry mutation")

    monkeypatch.setattr(
        coordinator_module, "plan_runtime_principal_upsert", unexpected_upsert
    )
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert upsert_calls == []
    assert broker.received == []
    assert registry.calls == []


def test_duplicate_request_ids_fail_before_broker_or_registry() -> None:
    base = coordinator_request()
    request = replace(
        base,
        mutation=replace(
            base.mutation,
            request_id=base.terminal_requests[0].request_id,
        ),
    )
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []
    assert registry.calls == []


def test_more_than_three_terminal_requests_fail_before_broker_or_registry() -> None:
    request = coordinator_request()
    extra = replace(request.terminal_requests[0], request_id="3" * 32)
    request = replace(request, terminal_requests=(*request.terminal_requests, extra))
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []
    assert registry.calls == []


def test_transaction_drift_fails_before_broker_or_registry() -> None:
    base = coordinator_request()
    request = coordinator_request(
        mutation=replace(base.mutation, transaction_id="8" * 32)
    )
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []
    assert registry.calls == []


def test_store_drift_is_rejected_by_full_transaction_binding() -> None:
    request = coordinator_request()
    drifted = replace(request.mutation.binding, store_uuid="8" * 32)
    broker = FakeBroker(
        [
            frame(
                reply(
                    request.mutation.request_id,
                    BrokerResultCode.COMMITTED,
                    status_for(drifted, committed=True),
                )
            )
        ]
    )
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED
    assert registry.calls == []
    assert [item.kind for item in broker.received] == [ChpbMessageKind.PROVISION_HOME]


def test_policy_drift_is_rejected_by_full_transaction_binding() -> None:
    request = coordinator_request()
    drifted = replace(
        request.mutation.binding,
        policy=PolicyBinding(8, request.identity.projection_digest),
    )
    broker = FakeBroker(
        [
            frame(
                reply(
                    request.mutation.request_id,
                    BrokerResultCode.COMMITTED,
                    status_for(drifted, committed=True),
                )
            )
        ]
    )
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.BROKER_TRANSACTION_FAILED
    assert registry.calls == []


def test_identity_drift_fails_before_broker_or_registry() -> None:
    request = coordinator_request(identity=identity(manifest_generation=8))
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []
    assert registry.calls == []


def test_expectation_drift_fails_before_broker_or_registry() -> None:
    request = coordinator_request()
    drifted = replace(
        request.attestation,
        expected=replace(request.attestation.expected, policy_generation=8),
    )
    request = replace(request, attestation=drifted)
    broker = FakeBroker([])
    registry = FakeRegistry()

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, registry, broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []
    assert registry.calls == []


def test_noncanonical_request_id_is_rejected_before_broker() -> None:
    request = coordinator_request(
        mutation=replace(coordinator_request().mutation, request_id="z" * 32)
    )
    broker = FakeBroker([])

    with pytest.raises(DynamicTeamleadCoordinatorError) as caught:
        coordinate_dynamic_teamlead(request, FakeRegistry(), broker)

    assert caught.value.code is DynamicTeamleadCoordinatorCode.INVALID_REQUEST
    assert broker.received == []


def test_launch_plan_return_uses_exact_keyword_contract() -> None:
    path = (
        Path(__file__).parents[1] / "src/codex_master/dynamic_teamlead_coordinator.py"
    )
    tree = ast.parse(path.read_text())
    coordinators = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "coordinate_dynamic_teamlead"
    ]
    assert len(coordinators) == 1
    calls = [
        node
        for node in ast.walk(coordinators[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "DynamicTeamleadLaunchPlan"
    ]
    assert len(calls) == 1
    call = calls[0]
    assert call.args == []
    assert not any(keyword.arg is None for keyword in call.keywords)
    assert [keyword.arg for keyword in call.keywords] == [
        "teamlead",
        "snapshot",
        "expected_principal",
        "expectation",
        "identity",
        "home",
    ]


def test_coordinator_imports_are_allowlisted() -> None:
    path = (
        Path(__file__).parents[1] / "src/codex_master/dynamic_teamlead_coordinator.py"
    )
    tree = ast.parse(path.read_text())
    allowed_from = {
        "dataclasses": {"dataclass", "replace"},
        "enum": {"Enum"},
        "typing": {"Protocol"},
        "codex_master.dynamic_teamlead": None,
        "codex_master.fleet_home_broker_client": None,
        "codex_master.fleet_home_broker_protocol": None,
        "codex_master.fleet_home_broker_identity": None,
        "codex_master.fleet_registry": None,
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            pytest.fail(f"direct import is forbidden: {ast.unparse(node)}")
        if isinstance(node, ast.ImportFrom):
            assert node.module in allowed_from
            names = {item.name for item in node.names}
            allowed_names = allowed_from[node.module]
            if allowed_names is not None:
                assert names <= allowed_names
