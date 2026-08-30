from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError, astuple, fields, replace
from hashlib import sha256
import inspect
import json
import pickle
from pathlib import Path

import pytest

import codex_master.fleet_registry_v2_migration as migration_module
from codex_master.codex_usage_credential_authority import ProfileCredentialBinding
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetDynamicWorkerPrincipalV2,
    FleetRuntimePrincipalV2,
    FleetSeries,
    FleetSeriesMember,
    FleetSeriesV2,
    FleetSnapshot,
    FleetSnapshotV2,
    LimitState,
    MAX_GENERATION,
    Provider,
    RunnerKind,
    SecretState,
    fleet_document,
    normalize_fleet_document,
)
from codex_master.fleet_registry_v2_migration import (
    FleetRegistryV1RecoveryPlan,
    PreparedFleetRegistryV2Migration,
    RegistryV2MigrationError,
    RegistryV2QuiescenceEvidence,
    plan_fleet_registry_v1_recovery,
    prepare_fleet_registry_v2_migration,
)


GENERATION = 17
ACCOUNT_ID = "openai-primary"
PROFILE_ID = "BW_Nufker"
BINDING_ID = "hmac-sha256:" + "a" * 64
PRINCIPAL_ID = "tl-" + "1" * 32


def _canonical_digest(snapshot: FleetSnapshot | FleetSnapshotV2) -> str:
    payload = json.dumps(
        fleet_document(snapshot),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + sha256(payload).hexdigest()


def source_snapshot() -> FleetSnapshot:
    snapshot = FleetSnapshot(
        schema_version=1,
        generation=GENERATION,
        accounts=(
            FleetAccount(
                account_id=ACCOUNT_ID,
                label="OpenAI primary",
                provider=Provider.OPENAI_CHATGPT,
                auth_kind=AuthKind.CHATGPT_SESSION,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.READY,
                enabled=True,
                reset_at_utc=None,
                last_probe_at_utc="2026-08-27T00:00:00Z",
                limit_reason=None,
            ),
            FleetAccount(
                account_id="gemini-secondary",
                label="Gemini secondary",
                provider=Provider.GEMINI_API,
                auth_kind=AuthKind.API_KEY,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.READY,
                enabled=True,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            ),
        ),
        series=(
            FleetSeries(
                prefix="o",
                display_name="Old local series",
                count=2,
                runner=RunnerKind.CODEX_CLI,
                provider=Provider.OLLAMA_LOCAL,
                model="local-model",
                account_id=None,
                enabled=True,
            ),
        ),
    )
    normalized = normalize_fleet_document(fleet_document(snapshot))
    assert type(normalized) is FleetSnapshot
    return normalized


def runtime_principal(**changes: object) -> FleetRuntimePrincipalV2:
    values = {
        "principal_id": PRINCIPAL_ID,
        "account_id": ACCOUNT_ID,
        "profile_id": PROFILE_ID,
        "credential_binding_id": BINDING_ID,
        "class_id": "teamleiterin",
        "lifecycle": "persistent",
        "provider": Provider.OPENAI_CHATGPT,
        "runner": RunnerKind.CODEX_CLI,
        "model": "gpt-5.6-terra",
        "reasoning": "xhigh",
        "enabled": True,
    }
    values.update(changes)
    return FleetRuntimePrincipalV2(**values)  # type: ignore[arg-type]


def quiescence(
    source: FleetSnapshot, *, epoch: int = 41
) -> RegistryV2QuiescenceEvidence:
    return RegistryV2QuiescenceEvidence(
        source_generation=source.generation,
        source_digest=_canonical_digest(source),
        runtime_broker_epoch=epoch,
        stopped=True,
        active_principals_or_agents=0,
        active_leases_or_reservations=0,
        pending_registry_or_broker_transactions=0,
        pending_recoveries=0,
    )


def test_prepare_materializes_exact_pool_only_v2_candidate() -> None:
    source = source_snapshot()
    evidence_identity = quiescence(source)
    assert repr(evidence_identity) == "RegistryV2QuiescenceEvidence(<redacted>)"
    assert str(evidence_identity) == repr(evidence_identity)
    source_document_before = fleet_document(source)
    source_value_before = source
    observations = 0

    def probe() -> RegistryV2QuiescenceEvidence:
        nonlocal observations
        observations += 1
        return quiescence(source)

    prepared = prepare_fleet_registry_v2_migration(
        source,
        expected_generation=GENERATION,
        profile_bindings={ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)},
        runtime_principals=(runtime_principal(),),
        quiescence_probe=probe,
    )

    assert observations == 2
    assert prepared.source is source
    assert source == source_value_before
    assert fleet_document(source) == source_document_before
    assert prepared.source_digest == _canonical_digest(source)
    assert prepared.candidate_digest == _canonical_digest(prepared.candidate)
    assert prepared.quiescence_before == prepared.quiescence_after == quiescence(source)

    candidate = prepared.candidate
    assert type(candidate) is FleetSnapshotV2
    assert (candidate.schema_version, candidate.generation, candidate.series) == (
        2,
        GENERATION + 1,
        (),
    )
    assert candidate.runtime_principals == (runtime_principal(),)
    assert [item.account_id for item in candidate.accounts] == [
        "gemini-secondary",
        ACCOUNT_ID,
    ]
    for source_account, candidate_account in zip(source.accounts, candidate.accounts):
        assert astuple(candidate_account)[:-1] == astuple(source_account)
    candidate_accounts = {item.account_id: item for item in candidate.accounts}
    assert candidate_accounts[ACCOUNT_ID].credential_binding_id == BINDING_ID
    assert candidate_accounts["gemini-secondary"].credential_binding_id is None

    document = fleet_document(candidate)
    rendered = json.dumps(document, sort_keys=True)
    assert document["series"] == []
    assert "v1:" not in rendered
    assert "migration_identity" not in rendered
    assert normalize_fleet_document(document) == candidate

    with pytest.raises(FrozenInstanceError):
        prepared.source_digest = "sha256:" + "0" * 64  # type: ignore[misc]
    redacted = repr(prepared) + str(prepared)
    assert BINDING_ID not in redacted
    assert PROFILE_ID not in redacted
    assert PRINCIPAL_ID not in redacted


def _prepare(
    source: FleetSnapshot,
    *,
    evidence: tuple[RegistryV2QuiescenceEvidence, ...] | None = None,
    profile_bindings: object | None = None,
    runtime_principals: object | None = None,
) -> object:
    observations = iter(evidence or (quiescence(source), quiescence(source)))
    return prepare_fleet_registry_v2_migration(
        source,
        expected_generation=source.generation,
        profile_bindings=(
            {ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)}
            if profile_bindings is None
            else profile_bindings
        ),
        runtime_principals=(
            (runtime_principal(),) if runtime_principals is None else runtime_principals
        ),
        quiescence_probe=lambda: next(observations),
    )


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"stopped": False}, "quiescence_activity"),
        ({"active_principals_or_agents": 1}, "quiescence_activity"),
        ({"active_leases_or_reservations": 1}, "quiescence_activity"),
        ({"pending_registry_or_broker_transactions": 1}, "quiescence_activity"),
        ({"pending_recoveries": 1}, "quiescence_activity"),
        ({"source_generation": GENERATION + 1}, "quiescence_source_mismatch"),
        ({"source_digest": "sha256:" + "f" * 64}, "quiescence_source_mismatch"),
        ({"runtime_broker_epoch": -1}, "quiescence_evidence_invalid"),
    ],
)
def test_prepare_rejects_non_quiescent_or_unbound_evidence_without_mutation(
    changes: dict[str, object], code: str
) -> None:
    source = source_snapshot()
    document_before = fleet_document(source)
    invalid = replace(quiescence(source), **changes)

    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(source, evidence=(invalid, invalid))

    assert caught.value.code == code
    assert fleet_document(source) == document_before
    assert repr(caught.value) == f"RegistryV2MigrationError('{code}')"


def test_prepare_rejects_quiescence_drift() -> None:
    source = source_snapshot()
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(
            source,
            evidence=(quiescence(source), quiescence(source, epoch=42)),
        )
    assert caught.value.code == "quiescence_drift"


def test_prepare_redacts_probe_exception_and_does_not_retry() -> None:
    source = source_snapshot()
    calls = 0
    marker = "credential-like /private/profile/path"

    def probe() -> RegistryV2QuiescenceEvidence:
        nonlocal calls
        calls += 1
        raise RuntimeError(marker)

    with pytest.raises(RegistryV2MigrationError) as caught:
        prepare_fleet_registry_v2_migration(
            source,
            expected_generation=source.generation,
            profile_bindings={
                ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)
            },
            runtime_principals=(runtime_principal(),),
            quiescence_probe=probe,
        )
    assert (caught.value.code, calls) == ("quiescence_probe_failed", 1)
    assert marker not in repr(caught.value) + str(caught.value)


@pytest.mark.parametrize(
    "principal",
    [
        runtime_principal(principal_id="legacy-tl"),
        runtime_principal(class_id="arbeitsbiene"),
        runtime_principal(lifecycle="invocation"),
        runtime_principal(provider=Provider.OPENAI_API),
        runtime_principal(runner=RunnerKind.GEMINI_CLI),
        runtime_principal(model="gpt-5.6-luna"),
        runtime_principal(reasoning="high"),
    ],
)
def test_prepare_rejects_invalid_teamlead_principal(principal: object) -> None:
    source = source_snapshot()
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(source, runtime_principals=(principal,))
    assert caught.value.code == "invalid_runtime_principal"


@pytest.mark.parametrize(
    "account_changes",
    [
        {"enabled": False},
        {"secret_state": SecretState.MISSING},
        {"limit_state": LimitState.LIMITED},
    ],
)
def test_prepare_rejects_ineligible_account_for_enabled_principal(
    account_changes: dict[str, object],
) -> None:
    source = source_snapshot()
    changed_accounts = tuple(
        replace(item, **account_changes) if item.account_id == ACCOUNT_ID else item
        for item in source.accounts
    )
    changed = normalize_fleet_document(
        fleet_document(replace(source, accounts=changed_accounts))
    )
    assert type(changed) is FleetSnapshot
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(changed)
    assert caught.value.code == "invalid_runtime_principal"


@pytest.mark.parametrize(
    ("bindings", "principals", "code"),
    [
        ({}, (runtime_principal(),), "invalid_migration_binding"),
        (
            {"unknown": ProfileCredentialBinding(PROFILE_ID, BINDING_ID)},
            (runtime_principal(),),
            "invalid_migration_binding",
        ),
        (
            {ACCOUNT_ID: ProfileCredentialBinding("other-profile", BINDING_ID)},
            (runtime_principal(),),
            "invalid_migration_binding",
        ),
        (
            {
                ACCOUNT_ID: ProfileCredentialBinding(
                    PROFILE_ID, "hmac-sha256:" + "b" * 64
                )
            },
            (runtime_principal(),),
            "invalid_migration_binding",
        ),
        (
            {ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)},
            (),
            "invalid_runtime_principal",
        ),
    ],
)
def test_prepare_rejects_unknown_unattested_or_drifted_binding(
    bindings: object, principals: object, code: str
) -> None:
    source = source_snapshot()
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(source, profile_bindings=bindings, runtime_principals=principals)
    assert caught.value.code == code


def test_prepare_rejects_binding_for_wrong_provider_or_auth_kind() -> None:
    source = source_snapshot()
    account = next(item for item in source.accounts if item.account_id == ACCOUNT_ID)
    changed_accounts = tuple(
        replace(
            item,
            provider=Provider.OPENAI_API,
            auth_kind=AuthKind.API_KEY,
        )
        if item is account
        else item
        for item in source.accounts
    )
    changed = normalize_fleet_document(
        fleet_document(replace(source, accounts=changed_accounts))
    )
    assert type(changed) is FleetSnapshot
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(changed)
    assert caught.value.code == "invalid_migration_binding"


def test_prepare_rejects_dynamic_worker_input() -> None:
    source = source_snapshot()
    dynamic_worker = object.__new__(FleetDynamicWorkerPrincipalV2)
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(source, runtime_principals=(dynamic_worker,))
    assert caught.value.code == "invalid_runtime_principal"


def test_prepare_rejects_duplicate_enabled_account_binding() -> None:
    source = source_snapshot()
    primary = next(item for item in source.accounts if item.account_id == ACCOUNT_ID)
    second = replace(primary, account_id="openai-secondary", label="OpenAI secondary")
    expanded = normalize_fleet_document(
        fleet_document(replace(source, accounts=source.accounts + (second,)))
    )
    assert type(expanded) is FleetSnapshot
    second_profile = "second-profile"
    second_principal = runtime_principal(
        principal_id="tl-" + "2" * 32,
        account_id=second.account_id,
        profile_id=second_profile,
    )
    bindings = {
        ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID),
        second.account_id: ProfileCredentialBinding(second_profile, BINDING_ID),
    }

    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(
            expanded,
            profile_bindings=bindings,
            runtime_principals=(runtime_principal(), second_principal),
        )
    assert caught.value.code == "duplicate_credential_binding"


def test_prepare_allows_same_binding_on_disabled_account_with_disabled_principal() -> (
    None
):
    source = source_snapshot()
    primary = next(item for item in source.accounts if item.account_id == ACCOUNT_ID)
    second = replace(
        primary,
        account_id="openai-disabled",
        label="OpenAI disabled",
        enabled=False,
        secret_state=SecretState.MISSING,
        limit_state=LimitState.DISABLED,
    )
    expanded = normalize_fleet_document(
        fleet_document(replace(source, accounts=source.accounts + (second,)))
    )
    assert type(expanded) is FleetSnapshot
    second_profile = "disabled-profile"
    prepared = _prepare(
        expanded,
        profile_bindings={
            ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID),
            second.account_id: ProfileCredentialBinding(second_profile, BINDING_ID),
        },
        runtime_principals=(
            runtime_principal(),
            runtime_principal(
                principal_id="tl-" + "3" * 32,
                account_id=second.account_id,
                profile_id=second_profile,
                enabled=False,
            ),
        ),
    )
    assert type(prepared) is PreparedFleetRegistryV2Migration


def test_first_probe_precedes_binding_and_second_probe_follows_materialization() -> (
    None
):
    source = source_snapshot()
    events: list[str] = []

    class TrackedBindings(dict[str, ProfileCredentialBinding]):
        def items(self):  # type: ignore[no-untyped-def]
            events.append("binding")
            return super().items()

    def probe() -> RegistryV2QuiescenceEvidence:
        events.append("probe")
        return quiescence(source)

    prepared = prepare_fleet_registry_v2_migration(
        source,
        expected_generation=source.generation,
        profile_bindings=TrackedBindings(
            {ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)}
        ),
        runtime_principals=(runtime_principal(),),
        quiescence_probe=probe,
    )
    assert type(prepared) is PreparedFleetRegistryV2Migration
    assert events == ["probe", "binding", "probe"]


def _prepared() -> PreparedFleetRegistryV2Migration:
    source = source_snapshot()
    prepared = _prepare(source)
    assert type(prepared) is PreparedFleetRegistryV2Migration
    return prepared


def recovery_quiescence(
    prepared: PreparedFleetRegistryV2Migration, *, epoch: int = 51
) -> RegistryV2QuiescenceEvidence:
    return RegistryV2QuiescenceEvidence(
        source_generation=prepared.candidate.generation,
        source_digest=prepared.candidate_digest,
        runtime_broker_epoch=epoch,
        stopped=True,
        active_principals_or_agents=0,
        active_leases_or_reservations=0,
        pending_registry_or_broker_transactions=0,
        pending_recoveries=0,
    )


def _recover(
    prepared: PreparedFleetRegistryV2Migration,
    *,
    observed: FleetSnapshotV2 | None = None,
    observed_digest: str | None = None,
    evidence: tuple[RegistryV2QuiescenceEvidence, ...] | None = None,
) -> FleetRegistryV1RecoveryPlan:
    candidate = prepared.candidate if observed is None else observed
    digest = (
        _canonical_digest(candidate) if observed_digest is None else observed_digest
    )
    observations = iter(
        evidence or (recovery_quiescence(prepared), recovery_quiescence(prepared))
    )
    return plan_fleet_registry_v1_recovery(
        prepared,
        candidate,
        observed_candidate_digest=digest,
        quiescence_probe=lambda: next(observations),
    )


def test_recovery_restores_exact_v1_content_at_monotonic_generation() -> None:
    prepared = _prepared()
    plan = _recover(prepared)

    expected = replace(prepared.source, generation=GENERATION + 2)
    assert type(plan) is FleetRegistryV1RecoveryPlan
    assert plan.candidate == expected
    assert plan.candidate.accounts == prepared.source.accounts
    assert plan.candidate.series == prepared.source.series
    assert plan.observed_candidate_digest == prepared.candidate_digest
    assert (
        plan.quiescence_before == plan.quiescence_after == recovery_quiescence(prepared)
    )
    assert normalize_fleet_document(fleet_document(plan.candidate)) == plan.candidate
    with pytest.raises(FrozenInstanceError):
        plan.observed_candidate_digest = "sha256:" + "0" * 64  # type: ignore[misc]
    rendered = repr(plan) + str(plan)
    assert BINDING_ID not in rendered
    assert PROFILE_ID not in rendered


def test_recovery_calls_same_probe_exactly_twice() -> None:
    prepared = _prepared()
    calls = 0

    def probe() -> RegistryV2QuiescenceEvidence:
        nonlocal calls
        calls += 1
        return recovery_quiescence(prepared)

    plan = plan_fleet_registry_v1_recovery(
        prepared,
        prepared.candidate,
        observed_candidate_digest=prepared.candidate_digest,
        quiescence_probe=probe,
    )
    assert (type(plan), calls) == (FleetRegistryV1RecoveryPlan, 2)


@pytest.mark.parametrize("kind", ["content", "generation", "digest", "prepared"])
def test_recovery_rejects_candidate_or_prepared_drift(kind: str) -> None:
    prepared = _prepared()
    observed = prepared.candidate
    observed_digest = prepared.candidate_digest
    supplied = prepared
    expected_code = "recovery_candidate_mismatch"
    if kind == "content":
        account = observed.accounts[0]
        observed = replace(
            observed,
            accounts=(replace(account, label="drifted"),) + observed.accounts[1:],
        )
        normalized = normalize_fleet_document(fleet_document(observed))
        assert type(normalized) is FleetSnapshotV2
        observed = normalized
        observed_digest = _canonical_digest(observed)
    elif kind == "generation":
        observed = replace(observed, generation=observed.generation + 1)
        observed_digest = _canonical_digest(observed)
    elif kind == "digest":
        observed_digest = "sha256:" + "f" * 64
    else:
        supplied = _capability_clone(
            prepared,
            candidate_digest="sha256:" + "e" * 64,
        )
        expected_code = "prepared_integrity_invalid"

    with pytest.raises(RegistryV2MigrationError) as caught:
        _recover(
            supplied,
            observed=observed,
            observed_digest=observed_digest,
        )
    assert caught.value.code == expected_code


def _capability_clone(
    capability: PreparedFleetRegistryV2Migration | FleetRegistryV1RecoveryPlan,
    **changes: object,
) -> PreparedFleetRegistryV2Migration | FleetRegistryV1RecoveryPlan:
    forged = object.__new__(type(capability))
    for item in fields(capability):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(capability, item.name)),
        )
    return forged


def test_prepared_pickle_is_blocked_but_evidence_remains_transport_data() -> None:
    prepared = _prepared()
    with pytest.raises(TypeError, match="prepared_capability_not_serializable"):
        pickle.dumps(prepared)

    evidence = recovery_quiescence(prepared)
    assert pickle.loads(pickle.dumps(evidence)) == evidence


def test_recovery_plan_pickle_is_blocked() -> None:
    plan = _recover(_prepared())
    with pytest.raises(TypeError, match="recovery_capability_not_serializable"):
        pickle.dumps(plan)


def test_direct_capability_construction_is_blocked() -> None:
    prepared = _prepared()
    with pytest.raises(TypeError, match="prepared_capability_factory_required"):
        PreparedFleetRegistryV2Migration(
            prepared.source,
            prepared.candidate,
            prepared.source_digest,
            prepared.candidate_digest,
            prepared.quiescence_before,
            prepared.quiescence_after,
        )

    plan = _recover(prepared)
    with pytest.raises(TypeError, match="recovery_capability_factory_required"):
        FleetRegistryV1RecoveryPlan(
            plan.prepared,
            plan.candidate,
            plan.observed_candidate_digest,
            plan.quiescence_before,
            plan.quiescence_after,
        )


def test_dataclass_replace_cannot_reconstruct_capabilities() -> None:
    prepared = _prepared()
    with pytest.raises(TypeError, match="prepared_capability_factory_required"):
        replace(prepared, candidate_digest=prepared.candidate_digest)

    plan = _recover(prepared)
    with pytest.raises(TypeError, match="recovery_capability_factory_required"):
        replace(plan, observed_candidate_digest=plan.observed_candidate_digest)


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy])
def test_copy_cannot_clone_accepted_capabilities(copier: object) -> None:
    prepared = _prepared()
    with pytest.raises(TypeError, match="prepared_capability_not_cloneable"):
        copier(prepared)  # type: ignore[operator]

    plan = _recover(prepared)
    with pytest.raises(TypeError, match="recovery_capability_not_cloneable"):
        copier(plan)  # type: ignore[operator]


def _candidate_with(
    prepared: PreparedFleetRegistryV2Migration,
    *,
    accounts: tuple[object, ...] | None = None,
    series: tuple[object, ...] | None = None,
    runtime_principals: tuple[object, ...] | None = None,
) -> FleetSnapshotV2:
    candidate = replace(
        prepared.candidate,
        accounts=prepared.candidate.accounts if accounts is None else accounts,
        series=prepared.candidate.series if series is None else series,
        runtime_principals=(
            prepared.candidate.runtime_principals
            if runtime_principals is None
            else runtime_principals
        ),
    )
    normalized = normalize_fleet_document(fleet_document(candidate))
    assert type(normalized) is FleetSnapshotV2
    return normalized


def _assert_forged_prepared_rejected(
    prepared: PreparedFleetRegistryV2Migration,
    candidate: FleetSnapshotV2,
) -> None:
    assert normalize_fleet_document(fleet_document(candidate)) == candidate
    forged = _capability_clone(
        prepared,
        candidate=candidate,
        candidate_digest=_canonical_digest(candidate),
    )
    assert type(forged) is PreparedFleetRegistryV2Migration

    with pytest.raises(RegistryV2MigrationError) as caught:
        _recover(
            forged,
            observed=candidate,
            observed_digest=_canonical_digest(candidate),
        )
    assert caught.value.code == "prepared_integrity_invalid"


def test_recovery_rejects_sealed_pool_only_series_forge() -> None:
    prepared = _prepared()
    series = FleetSeriesV2(
        prefix="o",
        display_name="Forged shadow series",
        runner=RunnerKind.CODEX_CLI,
        provider=Provider.OLLAMA_LOCAL,
        model="forged-local-model",
        enabled=True,
        skill_profile="generic",
        task_profile="standard",
        members=(
            FleetSeriesMember(
                member_id="11111111-1111-4111-8111-111111111111",
                ordinal=1,
                account_id=None,
                enabled=True,
            ),
        ),
    )
    _assert_forged_prepared_rejected(
        prepared,
        _candidate_with(prepared, series=(series,)),
    )


@pytest.mark.parametrize("kind", ["account_label", "non_openai_binding", "attestation"])
def test_recovery_rejects_sealed_account_or_attestation_forge(kind: str) -> None:
    prepared = _prepared()
    accounts = prepared.candidate.accounts
    principals = prepared.candidate.runtime_principals
    if kind == "account_label":
        accounts = tuple(
            replace(item, label="forged-account-label")
            if item.account_id == ACCOUNT_ID
            else item
            for item in accounts
        )
    elif kind == "non_openai_binding":
        accounts = tuple(
            replace(item, credential_binding_id="forged-api-key-binding")
            if item.account_id == "gemini-secondary"
            else item
            for item in accounts
        )
    else:
        forged_binding = "hmac-sha256:" + "b" * 64
        accounts = tuple(
            replace(item, credential_binding_id=forged_binding)
            if item.account_id == ACCOUNT_ID
            else item
            for item in accounts
        )
        principals = tuple(
            replace(
                item,
                profile_id="forged-profile",
                credential_binding_id=forged_binding,
            )
            for item in principals
        )
    _assert_forged_prepared_rejected(
        prepared,
        _candidate_with(
            prepared,
            accounts=accounts,
            runtime_principals=principals,
        ),
    )


@pytest.mark.parametrize("kind", ["missing", "additional", "mismatched"])
def test_recovery_rejects_sealed_principal_set_forge(kind: str) -> None:
    prepared = _prepared()
    principals = prepared.candidate.runtime_principals
    if kind == "missing":
        principals = ()
    elif kind == "additional":
        principals = principals + (
            runtime_principal(
                principal_id="tl-" + "2" * 32,
                profile_id="forged-extra-profile",
                enabled=False,
            ),
        )
    else:
        principals = tuple(
            replace(item, profile_id="forged-mismatched-profile") for item in principals
        )
    _assert_forged_prepared_rejected(
        prepared,
        _candidate_with(prepared, runtime_principals=principals),
    )


def test_prepared_copies_and_canonically_sorts_accepted_attestations() -> None:
    source = source_snapshot()
    primary = next(item for item in source.accounts if item.account_id == ACCOUNT_ID)
    second = replace(
        primary,
        account_id="openai-disabled",
        label="OpenAI disabled",
        enabled=False,
        secret_state=SecretState.MISSING,
        limit_state=LimitState.DISABLED,
    )
    expanded = normalize_fleet_document(
        fleet_document(replace(source, accounts=source.accounts + (second,)))
    )
    assert type(expanded) is FleetSnapshot
    first_attestation = ProfileCredentialBinding(PROFILE_ID, BINDING_ID)
    second_attestation = ProfileCredentialBinding(
        "disabled-profile", "hmac-sha256:" + "c" * 64
    )
    caller_bindings = {
        second.account_id: second_attestation,
        ACCOUNT_ID: first_attestation,
    }
    observations = iter((quiescence(expanded), quiescence(expanded)))
    prepared = prepare_fleet_registry_v2_migration(
        expanded,
        expected_generation=expanded.generation,
        profile_bindings=caller_bindings,
        runtime_principals=(
            runtime_principal(),
            runtime_principal(
                principal_id="tl-" + "3" * 32,
                account_id=second.account_id,
                profile_id=second_attestation.profile_id,
                credential_binding_id=second_attestation.binding_id,
                enabled=False,
            ),
        ),
        quiescence_probe=lambda: next(observations),
    )
    caller_bindings.clear()

    assert tuple(item[0] for item in prepared.profile_bindings) == (
        second.account_id,
        ACCOUNT_ID,
    )
    stored = dict(prepared.profile_bindings)
    assert stored == {
        ACCOUNT_ID: first_attestation,
        second.account_id: second_attestation,
    }
    assert stored[ACCOUNT_ID] is not first_attestation
    assert stored[second.account_id] is not second_attestation


@pytest.mark.parametrize(
    "changes",
    [
        {"stopped": False},
        {"active_principals_or_agents": 1},
        {"active_leases_or_reservations": 1},
        {"pending_registry_or_broker_transactions": 1},
        {"pending_recoveries": 1},
        {"source_generation": GENERATION},
        {"source_digest": "sha256:" + "d" * 64},
    ],
)
def test_recovery_rejects_non_quiescent_or_unbound_evidence(
    changes: dict[str, object],
) -> None:
    prepared = _prepared()
    invalid = replace(recovery_quiescence(prepared), **changes)
    with pytest.raises(RegistryV2MigrationError) as caught:
        _recover(prepared, evidence=(invalid, invalid))
    assert caught.value.code in {"quiescence_activity", "quiescence_source_mismatch"}


def test_recovery_rejects_quiescence_drift_and_probe_exception() -> None:
    prepared = _prepared()
    with pytest.raises(RegistryV2MigrationError) as caught:
        _recover(
            prepared,
            evidence=(
                recovery_quiescence(prepared),
                recovery_quiescence(prepared, epoch=52),
            ),
        )
    assert caught.value.code == "quiescence_drift"

    marker = "secret-like recovery probe /private/path"

    def failed_probe() -> RegistryV2QuiescenceEvidence:
        raise RuntimeError(marker)

    with pytest.raises(RegistryV2MigrationError) as caught:
        plan_fleet_registry_v1_recovery(
            prepared,
            prepared.candidate,
            observed_candidate_digest=prepared.candidate_digest,
            quiescence_probe=failed_probe,
        )
    assert caught.value.code == "quiescence_probe_failed"
    assert marker not in repr(caught.value) + str(caught.value)


def test_prepare_and_recovery_fail_closed_on_generation_overflow() -> None:
    source = replace(source_snapshot(), generation=MAX_GENERATION)
    with pytest.raises(RegistryV2MigrationError) as caught:
        _prepare(source)
    assert caught.value.code == "source_generation_overflow"

    almost_max = replace(source_snapshot(), generation=MAX_GENERATION - 1)
    prepared = _prepare(almost_max)
    assert type(prepared) is PreparedFleetRegistryV2Migration
    with pytest.raises(RegistryV2MigrationError) as caught:
        _recover(prepared)
    assert caught.value.code == "recovery_generation_overflow"


def test_module_exposes_no_writer_secretreader_or_legacy_apply_surface() -> None:
    source = Path(migration_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_names = {
        "FleetService",
        "commit_snapshot",
        "read_secret",
        "materialize_g_series_v2",
        "_materialize_g_migration_locked",
        "expand_v1_for_migration",
        "LegacyFleetSeriesMember",
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert forbidden_names.isdisjoint(names)
    for function in (
        prepare_fleet_registry_v2_migration,
        plan_fleet_registry_v1_recovery,
    ):
        assert {
            "writer",
            "commit",
            "secret_reader",
            "fleet_service",
        }.isdisjoint(inspect.signature(function).parameters)
