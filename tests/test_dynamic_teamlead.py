from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from codex_master.dynamic_teamlead import (
    DynamicTeamleadRequest,
    DynamicTeamleadError,
    DynamicTeamleadCode,
    ProfileBinding,
    prepare_dynamic_teamlead,
    require_committed_home_attestation,
)
from codex_master.fleet_home_broker_protocol import (
    BindingExpectation,
    BrokerReply,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbMessageKind,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
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
FOREIGN_AGENT_ID = "tl-" + "b" * 32
SECOND_FOREIGN_AGENT_ID = "tl-" + "c" * 32


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


def snapshot(**changes: object) -> FleetSnapshotV2:
    value = FleetSnapshotV2(2, 7, (account(),), (), (principal(),))
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


def request(**changes: object) -> DynamicTeamleadRequest:
    value = DynamicTeamleadRequest(
        agent_id=AGENT_ID,
        account_id=ACCOUNT_ID,
        registry_generation=7,
        model="gpt-5.6-terra",
        reasoning="xhigh",
    )
    return replace(value, **changes)


def binding(**changes: object) -> ProfileBinding:
    value = ProfileBinding(profile_id="BW_Nufker", credential_binding_id=BINDING)
    return replace(value, **changes)


def test_prepare_accepts_only_bound_v2_terra_xhigh_teamlead() -> None:
    expected_principal = principal()
    plan = prepare_dynamic_teamlead(
        snapshot(runtime_principals=(expected_principal,)), request(), binding()
    )

    assert plan.request == request()
    assert plan.profile_binding == binding()
    assert plan.principal is expected_principal
    assert plan.class_id == "teamleiterin"
    assert plan.lifecycle == "persistent"


def test_prepare_keeps_teamlead_plan_when_foreign_worker_is_present() -> None:
    expected_principal = principal()
    baseline = prepare_dynamic_teamlead(
        snapshot(runtime_principals=(expected_principal,)), request(), binding()
    )
    foreign_worker = SimpleNamespace(principal_id="dw-" + "a" * 32, enabled=True)

    with_worker = prepare_dynamic_teamlead(
        snapshot(runtime_principals=(foreign_worker, expected_principal)), request(), binding()
    )

    assert with_worker == baseline


def test_prepare_rejects_missing_runtime_principal() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(runtime_principals=()), request(), binding())

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_rejects_disabled_runtime_principal() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(runtime_principals=(principal(enabled=False),)), request(), binding())

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_rejects_duplicate_runtime_principal() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(runtime_principals=(principal(), principal())), request(), binding())

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_rejects_wrong_runtime_principal_type() -> None:
    wrong_type = SimpleNamespace(principal_id=AGENT_ID, enabled=True)
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(runtime_principals=(wrong_type,)), request(), binding())

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_rejects_runtime_principal_account_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(account_id="openai-secondary"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_rejects_runtime_principal_agent_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(principal_id=FOREIGN_AGENT_ID),)),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


@pytest.mark.parametrize(
    "runtime_principals",
    [
        (principal(principal_id=FOREIGN_AGENT_ID),),
        (
            principal(principal_id=FOREIGN_AGENT_ID),
            principal(principal_id=SECOND_FOREIGN_AGENT_ID),
        ),
        (principal(principal_id=FOREIGN_AGENT_ID, enabled=False),),
    ],
)
def test_prepare_rejects_foreign_principals_independent_of_count_or_status(
    runtime_principals: tuple[object, ...],
) -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(runtime_principals=runtime_principals), request(), binding())

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_resolves_requested_principal_independent_of_foreign_principals() -> None:
    expected_principal = principal()
    plan = prepare_dynamic_teamlead(
        snapshot(
            runtime_principals=(
                principal(principal_id=FOREIGN_AGENT_ID),
                expected_principal,
                principal(principal_id=SECOND_FOREIGN_AGENT_ID, enabled=False),
            )
        ),
        request(),
        binding(),
    )

    assert plan.principal is expected_principal


def test_prepare_rejects_runtime_principal_profile_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(profile_id="other-profile"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_rejects_runtime_principal_profile_hmac_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(credential_binding_id="hmac-sha256:" + "b" * 64),)),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_rejects_runtime_principal_account_hmac_mismatch() -> None:
    account_binding = "hmac-sha256:" + "b" * 64
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                accounts=(account(credential_binding_id=account_binding),),
                runtime_principals=(principal(),),
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_rejects_runtime_principal_class_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(class_id="other-class"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_rejects_runtime_principal_lifecycle_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(lifecycle="ephemeral"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_rejects_runtime_principal_provider_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(provider=Provider.OPENAI_API),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_rejects_runtime_principal_runner_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(runner=RunnerKind.GEMINI_CLI),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_rejects_runtime_principal_model_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(model="gpt-5.6-luna"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_rejects_runtime_principal_reasoning_mismatch() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(reasoning="high"),)), request(), binding()
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_prioritizes_identity_over_capability() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                runtime_principals=(
                    principal(profile_id="other-profile", class_id="other-class"),
                )
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_prioritizes_identity_over_account_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                accounts=(account(enabled=False),),
                runtime_principals=(principal(profile_id="other-profile"),),
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_prioritizes_identity_over_request_model_capability() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=(principal(profile_id="other-profile"),)),
            request(model="gpt-5.6-luna"),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_prioritizes_hmac_identity_over_request_reasoning_capability() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                runtime_principals=(
                    principal(credential_binding_id="hmac-sha256:" + "b" * 64),
                )
            ),
            request(reasoning="high"),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_prioritizes_identity_over_principal_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                runtime_principals=(
                    principal(enabled=False, profile_id="other-profile"),
                )
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_prepare_prioritizes_capability_over_principal_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                runtime_principals=(
                    principal(enabled=False, class_id="other-class"),
                )
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_prioritizes_request_capability_over_account_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(accounts=(account(enabled=False),)),
            request(model="gpt-5.6-luna"),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_prioritizes_principal_capability_over_account_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                accounts=(account(enabled=False),),
                runtime_principals=(principal(class_id="other-class"),),
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.INVALID_CLASS_SELECTION


def test_prepare_prioritizes_principal_eligibility_over_account_eligibility() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(
                accounts=(account(enabled=False),),
                runtime_principals=(principal(enabled=False),),
            ),
            request(),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


@pytest.mark.parametrize(
    "runtime_principals",
    [
        (),
        (principal(), principal()),
        (SimpleNamespace(principal_id=AGENT_ID, enabled=True),),
    ],
)
def test_prepare_prioritizes_principal_selection_over_later_capability_error(
    runtime_principals: tuple[object, ...],
) -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(
            snapshot(runtime_principals=runtime_principals),
            request(model="gpt-5.6-luna"),
            binding(),
        )

    assert caught.value.code is DynamicTeamleadCode.RUNTIME_PRINCIPAL_INVALID


def test_prepare_rejects_v1_registry_without_legacy_fallback() -> None:
    legacy = FleetSnapshot(
        1,
        7,
        (
            FleetAccount(
                ACCOUNT_ID,
                "OpenAI primary",
                Provider.OPENAI_CHATGPT,
                AuthKind.CHATGPT_SESSION,
                SecretState.CONFIGURED,
                LimitState.READY,
                True,
                None,
                None,
                None,
            ),
        ),
        (),
    )

    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(legacy, request(), binding())

    assert caught.value.code is DynamicTeamleadCode.REGISTRY_V2_REQUIRED


@pytest.mark.parametrize(
    ("account_change", "expected"),
    [
        ({"enabled": False}, DynamicTeamleadCode.ACCOUNT_INELIGIBLE),
        ({"limit_state": LimitState.LIMITED}, DynamicTeamleadCode.ACCOUNT_INELIGIBLE),
        ({"provider": Provider.OPENAI_API}, DynamicTeamleadCode.ACCOUNT_INELIGIBLE),
        ({"auth_kind": AuthKind.API_KEY}, DynamicTeamleadCode.ACCOUNT_INELIGIBLE),
        ({"secret_state": SecretState.MISSING}, DynamicTeamleadCode.ACCOUNT_INELIGIBLE),
        ({"credential_binding_id": None}, DynamicTeamleadCode.PROFILE_BINDING_INVALID),
    ],
)
def test_prepare_rejects_ineligible_or_unbound_account(
    account_change: dict[str, object], expected: DynamicTeamleadCode
) -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(accounts=(account(**account_change),)), request(), binding())

    assert caught.value.code is expected


@pytest.mark.parametrize(
    ("changed_request", "expected"),
    [
        ({"agent_id": "a1"}, DynamicTeamleadCode.LEGACY_TARGET_FORBIDDEN),
        ({"registry_generation": 8}, DynamicTeamleadCode.STALE_REGISTRY),
        ({"model": "gpt-5.6-luna"}, DynamicTeamleadCode.INVALID_CLASS_SELECTION),
        ({"reasoning": "high"}, DynamicTeamleadCode.INVALID_CLASS_SELECTION),
    ],
)
def test_prepare_rejects_legacy_target_stale_registry_and_non_teamlead_selection(
    changed_request: dict[str, object], expected: DynamicTeamleadCode
) -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(), request(**changed_request), binding())

    assert caught.value.code is expected


def test_prepare_rejects_profile_binding_that_does_not_match_account() -> None:
    with pytest.raises(DynamicTeamleadError) as caught:
        prepare_dynamic_teamlead(snapshot(), request(), binding(credential_binding_id="hmac-sha256:" + "b" * 64))

    assert caught.value.code is DynamicTeamleadCode.PROFILE_IDENTITY_MISMATCH


def test_committed_attestation_requires_real_broker_reply() -> None:
    expected = BindingExpectation(AGENT_ID, 1, 1, 1, "a" * 64, 0)
    reply = BrokerReply(
        CHPB_PROTOCOL,
        ChpbMessageKind.REPLY,
        "b" * 32,
        BrokerResultCode.UNSUPPORTED_PLATFORM,
        None,
        None,
    )

    with pytest.raises(DynamicTeamleadError) as caught:
        require_committed_home_attestation(reply, expected)

    assert caught.value.code is DynamicTeamleadCode.HOME_BROKER_UNAVAILABLE


def test_missing_broker_reply_is_not_treated_as_home_ready() -> None:
    expected = BindingExpectation(AGENT_ID, 1, 1, 1, "a" * 64, 0)

    with pytest.raises(DynamicTeamleadError) as caught:
        require_committed_home_attestation(None, expected)

    assert caught.value.code is DynamicTeamleadCode.HOME_BROKER_UNAVAILABLE
