from __future__ import annotations

from dataclasses import replace

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
    FleetSnapshot,
    FleetSnapshotV2,
    LimitState,
    Provider,
    SecretState,
)


ACCOUNT_ID = "openai-primary"
BINDING = "hmac-sha256:" + "a" * 64
AGENT_ID = "tl-00000000000000000000000000000001"


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
    value = FleetSnapshotV2(2, 7, (account(),), ())
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
    plan = prepare_dynamic_teamlead(snapshot(), request(), binding())

    assert plan.request == request()
    assert plan.profile_binding == binding()
    assert plan.class_id == "teamleiterin"
    assert plan.lifecycle == "persistent"


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
