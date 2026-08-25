from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import codex_master.fleet_runners as runners
from codex_master.dynamic_teamlead import (
    DynamicTeamleadRequest,
    ProfileBinding,
    prepare_dynamic_teamlead,
)
from codex_master.dynamic_teamlead_coordinator import DynamicTeamleadLaunchPlan
from codex_master.fleet_home_broker_client import AttestedHome
from codex_master.fleet_home_broker_identity import BrokerIdentity
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
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
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
FOREIGN_AGENT_ID = "tl-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
    return replace(FleetSnapshotV2(2, 7, (account(),), (), (principal(),)), **changes)


def request(**changes: object) -> DynamicTeamleadRequest:
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


def expected_principal(**changes: object) -> PrincipalBinding:
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


def expectation(**changes: object) -> BindingExpectation:
    value = BindingExpectation(AGENT_ID, 3, 9, 7, "5" * 64, 4)
    return replace(value, **changes)


def home(**changes: object) -> AttestedHome:
    binding = TransactionBinding(
        ChpbTransactionOperation.PROVISION,
        "c" * 32,
        "b" * 32,
        expected_principal(),
        PolicyBinding(7, "5" * 64),
    )
    attestation = HomeAttestation(
        binding,
        CANONICAL_AGENT_HOME,
        DIRECTORY,
        "7" * 64,
        binding.principal.mcs_pair,
    )
    status = TransactionStatus(
        binding,
        B2aRecoveryPhase.COMMITTED,
        BrokerCheckpoint.COMMITTED,
        BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE,
            BrokerRegistryState.CURRENT,
            1,
        ),
        1,
        BrokerResultCode.COMMITTED,
    )
    reply = BrokerReply(
        "CHPB/2",
        ChpbMessageKind.REPLY,
        "d" * 32,
        BrokerResultCode.OK,
        status,
        attestation,
    )
    return replace(AttestedHome(61, reply, attestation), **changes)


def launch(**changes: object) -> DynamicTeamleadLaunchPlan:
    current = snapshot()
    teamlead = prepare_dynamic_teamlead(current, request(), profile_binding())
    value = DynamicTeamleadLaunchPlan(
        teamlead,
        current,
        expected_principal(),
        expectation(),
        identity(),
        home(),
    )
    return replace(value, **changes)


def runner_prepare():
    return getattr(runners, "prepare_dynamic_teamlead_runner")


def assert_invalid(value: object) -> None:
    with pytest.raises(runners.FleetRunnerError) as caught:
        runner_prepare()(value)
    assert caught.value.code == "dynamic_teamlead_runner_invalid"
    assert caught.value.args == ("dynamic_teamlead_runner_invalid",)
    assert caught.value.__cause__ is None


def test_symbols_exist() -> None:
    assert hasattr(runners, "DynamicTeamleadRunnerPlan")
    assert hasattr(runners, "prepare_dynamic_teamlead_runner")


def test_valid_launch_returns_identity_preserving_runner_plan() -> None:
    value = launch()
    result = runner_prepare()(value)

    assert type(result) is runners.DynamicTeamleadRunnerPlan
    assert result.runtime_principal is value.teamlead.principal
    assert result.expected_principal is value.expected_principal
    assert result.expectation is value.expectation
    assert result.identity is value.identity
    assert result.home is value.home
    assert result.runtime_principal.enabled is True
    assert result.runtime_principal.class_id == "teamleiterin"
    assert result.runtime_principal.lifecycle == "persistent"
    assert result.runtime_principal.provider is Provider.OPENAI_CHATGPT
    assert result.runtime_principal.runner is RunnerKind.CODEX_CLI
    assert result.runtime_principal.model == "gpt-5.6-terra"
    assert result.runtime_principal.reasoning == "xhigh"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("class_id", "worker"),
        ("lifecycle", "ephemeral"),
        ("provider", Provider.OPENAI_API),
        ("runner", RunnerKind.GEMINI_CLI),
        ("model", "gpt-5.5"),
        ("reasoning", "low"),
        ("enabled", False),
    ],
)
def test_rejects_class_lifecycle_provider_runner_model_reasoning_enabled_drift(
    field: str, value: object
) -> None:
    base = launch()
    drifted = replace(base.teamlead.principal, **{field: value})
    drifted_request = base.teamlead.request
    if field in {"model", "reasoning"}:
        drifted_request = replace(drifted_request, **{field: value})
    drifted_teamlead = replace(
        base.teamlead,
        request=drifted_request,
        principal=drifted,
        **({field: value} if field in {"class_id", "lifecycle"} else {}),
    )
    assert_invalid(
        replace(
            base,
            teamlead=drifted_teamlead,
            snapshot=replace(base.snapshot, runtime_principals=(drifted,)),
        )
    )


def test_rejects_v1_legacy_snapshot_and_principal_drift() -> None:
    base = launch()
    assert_invalid(replace(base, snapshot=FleetSnapshot(1, 7, (), ())))
    legacy_request = replace(base.teamlead.request, agent_id="legacy-agent")
    assert_invalid(
        replace(base, teamlead=replace(base.teamlead, request=legacy_request))
    )
    assert_invalid(replace(base, snapshot=object()))
    malformed_principal = SimpleNamespace(principal_id=AGENT_ID)
    assert_invalid(
        replace(
            base,
            snapshot=replace(base.snapshot, runtime_principals=(malformed_principal,)),
        )
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: replace(
            value,
            expected_principal=replace(
                value.expected_principal, agent_id=FOREIGN_AGENT_ID
            ),
        ),
        lambda value: replace(
            value, expectation=replace(value.expectation, agent_id=FOREIGN_AGENT_ID)
        ),
        lambda value: replace(
            value, identity=replace(value.identity, agent_id=FOREIGN_AGENT_ID)
        ),
        lambda value: replace(
            value,
            home=replace(
                value.home,
                attestation=replace(value.home.attestation, canonical_path="/foreign"),
            ),
        ),
        lambda value: replace(value, home=replace(value.home, fd=True)),
        lambda value: replace(value, home=replace(value.home, fd=-1)),
    ],
)
def test_rejects_expectation_identity_attestation_and_fd_drift(mutator) -> None:
    assert_invalid(mutator(launch()))


def test_valid_path_never_closes_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[object] = []
    monkeypatch.setattr(runners.os, "close", lambda fd: closed.append(fd))
    value = launch()

    result = runner_prepare()(value)

    assert result.home is value.home
    assert closed == []


def test_runner_validator_has_no_forbidden_execution_or_fallback_path() -> None:
    source = Path(runners.__file__).read_text(encoding="utf-8")
    module = ast.parse(source)
    function = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "prepare_dynamic_teamlead_runner"
    )
    identifiers = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
    identifiers.update(
        node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)
    )
    assert identifiers.isdisjoint(
        {
            "build_runner_plan",
            "RunnerPlan",
            "AgentDescriptor",
            "prepare_agent_launch",
            "start",
            "host",
            "socket",
            "credential",
            "env",
            "executable",
            "legacy",
            "fallback",
            "dual",
            "fstat",
            "close",
        }
    )


def test_runner_plan_is_exactly_five_frozen_slotted_fields_without_aliases() -> None:
    plan_type = runners.DynamicTeamleadRunnerPlan
    assert [item.name for item in fields(plan_type)] == [
        "runtime_principal",
        "expected_principal",
        "expectation",
        "identity",
        "home",
    ]
    assert plan_type.__slots__ == (
        "runtime_principal",
        "expected_principal",
        "expectation",
        "identity",
        "home",
    )
    value = runner_prepare()(launch())
    with pytest.raises(FrozenInstanceError):
        value.home = value.home
    for alias in (
        "principal",
        "expected",
        "runtime",
        "attestation",
        "binding",
        "launch",
    ):
        assert not hasattr(value, alias)
