from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import pickle

import pytest

from codex_master.dynamic_teamlead import DynamicTeamleadRequest, ProfileBinding
from codex_master.dynamic_teamlead_a3_runtime_provider import (
    DynamicTeamleadA3RuntimeContext,
    DynamicTeamleadA3RuntimeProviderError,
    validate_dynamic_teamlead_a3_runtime_context,
)
from codex_master.dynamic_teamlead_coordinator import DynamicTeamleadCoordinatorRequest
from codex_master.fleet_home_broker_identity import BrokerIdentity
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
