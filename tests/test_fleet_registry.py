from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import codex_master.fleet_registry as fleet_registry
from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    canonical_resolution_decision_digest,
    resolve_agent_selection,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetRuntimePrincipalV2,
    FleetSeries,
    FleetSnapshotV2,
    FleetValidationError,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    build_inventory,
    expand_v1_for_migration,
    fleet_document,
    mark_account_limit,
    normalize_fleet_document,
    plan_account_delete,
    plan_account_disable,
    plan_account_upsert,
    plan_runtime_principal_delete,
    plan_runtime_principal_disable,
    plan_runtime_principal_upsert,
    plan_series_apply,
    plan_series_delete,
    plan_series_disable,
    public_fleet_snapshot,
    _next,
)
from codex_master.worker_resolution_carrier import (
    WorkerResolutionEvidenceV2,
    build_worker_registry_reservation,
    build_worker_resolution_carrier,
)
from codex_master.worker_resume import WorkerLifecycle
from codex_master.worker_spawn_ledger import (
    FenceEpoch,
    Generation,
    LedgerRevision,
    SpawnPhase,
    WorkerSpawnTicketV2,
)


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def valid_runtime_principal_document() -> dict[str, object]:
    return load_fixture("fleet-registry-v2.json")


def runtime_principal_dict(document: dict[str, object]) -> dict[str, object]:
    return deepcopy(document["runtime_principals"][0])  # type: ignore[index]


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def worker_registry_reservation(
    *, principal_id: str = "dw-" + "7" * 32, ticket_id: str = "ticket:worker-7"
) -> object:
    classes = (
        AgentClassPolicy(
            "arbeitsbiene",
            "ephemeral",
            ("ephemeral", "binding", "persistent"),
            ("luna",),
            "low",
            "xhigh",
            ("read", "write"),
        ),
    )
    models = (
        ModelPolicy(
            "gpt-5.6-luna",
            "luna",
            20,
            ("low", "medium", "high", "xhigh"),
            ("read", "write"),
        ),
    )
    request = ResolutionRequest(
        "read",
        "simple",
        requested_class="arbeitsbiene",
        requested_lifecycle="invocation",
    )
    decision = resolve_agent_selection(
        request, classes=classes, models=models, available_models={"gpt-5.6-luna"}
    )
    offer = build_selection_offer(
        classes=classes, models=models, available_models={"gpt-5.6-luna"}
    )
    ticket = WorkerSpawnTicketV2(
        ticket_id=ticket_id,
        request_id=ticket_id.removeprefix("ticket:"),
        requester_principal_id="worker-11",
        requester_authority_digest=_digest("a"),
        work_package_id="work-package-8",
        topic_digest=_digest("b"),
        target_class_id=decision.class_id,
        authorized_teamlead_id="teamlead-2",
        authorized_teamlead_authority_digest=_digest("c"),
        resolution_decision_digest=canonical_resolution_decision_digest(decision),
        resolution_generation=Generation(4),
        policy_digest=_digest("d"),
        policy_generation=Generation(9),
        lifecycle=WorkerLifecycle.INVOCATION,
        resume_requirement=False,
        fence_epoch=FenceEpoch(6),
        ledger_revision=LedgerRevision(1),
        phase=SpawnPhase.REQUESTED,
    )
    evidence = WorkerResolutionEvidenceV2(
        decision=decision,
        offer=offer,
        offer_generation=offer.generation,
        capability_binding_digest=_digest("e"),
        resolution_generation=ticket.resolution_generation,
        policy_digest=ticket.policy_digest,
        policy_generation=ticket.policy_generation,
        ticket_fence_epoch=ticket.fence_epoch,
    )
    carrier = build_worker_resolution_carrier(ticket, evidence)
    return build_worker_registry_reservation(
        resolution=carrier,
        principal_id=principal_id,
        ticket_ledger_revision=ticket.ledger_revision,
        ticket_fence_epoch=ticket.fence_epoch,
    )


def empty_worker_snapshot() -> FleetSnapshotV2:
    document = load_fixture("fleet-registry-v2.json")
    document["runtime_principals"] = []
    snapshot = normalize_fleet_document(document)
    assert isinstance(snapshot, FleetSnapshotV2)
    return snapshot


def test_v1_fixture_expands_deterministically_without_final_member_ids() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v1.json"))
    first = expand_v1_for_migration(snapshot)
    second = expand_v1_for_migration(snapshot)
    assert first == second
    assert [m.migration_identity for m in first.series[0].members] == ["v1:d:1", "v1:d:2"]
    assert all(not hasattr(m, "member_id") for m in first.series[0].members)


def test_v1_expansion_never_calls_uuid4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uuid, "uuid4", lambda: pytest.fail("Task 1 must not allocate member_id"))
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v1.json"))
    expand_v1_for_migration(snapshot)


def test_migration_snapshot_cannot_be_serialized_as_v2() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v1.json"))
    with pytest.raises(FleetValidationError) as caught:
        fleet_document(expand_v1_for_migration(snapshot))
    assert caught.value.code == "final_member_id_required"


def test_v2_fixture_round_trips_and_derives_count() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    assert isinstance(snapshot, FleetSnapshotV2)
    assert snapshot.schema_version == 2
    assert snapshot.series[0].count == 2
    assert isinstance(snapshot.runtime_principals, tuple)
    assert len(snapshot.runtime_principals) == 1
    assert "count" not in fleet_document(snapshot)["series"][0]
    assert normalize_fleet_document(fleet_document(snapshot)) == snapshot


def test_v2_requires_runtime_principals_root_field() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document.pop("runtime_principals")
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_document"


def test_v2_runtime_principals_are_frozen_and_slotted() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    principal = snapshot.runtime_principals[0]
    assert isinstance(principal, FleetRuntimePrincipalV2)
    with pytest.raises(FrozenInstanceError):
        principal.enabled = False  # type: ignore[misc]
    with pytest.raises(AttributeError):
        principal.extra = "nope"  # type: ignore[attr-defined]


def test_v2_runtime_principal_repr_and_str_are_redacted() -> None:
    principal = FleetRuntimePrincipalV2(
        principal_id="tl-" + "a" * 32,
        account_id="chatgpt-teamlead-1",
        profile_id="profile-marker-123",
        credential_binding_id="binding-marker-456",
        class_id="class-marker-789",
        lifecycle="persistent",
        provider=Provider.OPENAI_CHATGPT,
        runner=RunnerKind.CODEX_CLI,
        model="gpt-5.6-terra",
        reasoning="xhigh",
        enabled=True,
    )

    assert repr(principal) == "FleetRuntimePrincipalV2(<redacted>)"
    assert str(principal) == "FleetRuntimePrincipalV2(<redacted>)"
    assert "tl-" + "a" * 32 not in repr(principal)
    assert "profile-marker-123" not in repr(principal)
    assert "binding-marker-456" not in repr(principal)
    assert "class-marker-789" not in repr(principal)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", "tl-not-hex"),
        ("account_id", ""),
        ("profile_id", "bad/profile"),
        ("credential_binding_id", "binding-one"),
        ("class_id", "lead"),
        ("lifecycle", "ephemeral"),
        ("provider", "gemini_api"),
        ("runner", "gemini_cli"),
        ("model", "gpt-5.6"),
        ("reasoning", "high"),
        ("enabled", "true"),
    ],
)
def test_v2_rejects_invalid_runtime_principal_fields(field: str, value: object) -> None:
    document = valid_runtime_principal_document()
    document["runtime_principals"][0][field] = value  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_runtime_principal"

    teamlead = runtime_principal_dict(load_fixture("fleet-registry-v2.json"))
    teamlead["principal_id"] = "dw-" + "8" * 32
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document({
            **load_fixture("fleet-registry-v2.json"),
            "runtime_principals": [teamlead],
        })
    assert caught.value.code == "invalid_runtime_principal"


@pytest.mark.parametrize("field", ["series", "home", "auth", "prefix", "members", "secret"])
def test_v2_rejects_runtime_principal_private_or_series_fields(field: str) -> None:
    document = valid_runtime_principal_document()
    document["runtime_principals"][0][field] = "forbidden"  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_runtime_principal"


def test_v2_rejects_runtime_principal_account_identity_or_eligibility_mismatches() -> None:
    document = valid_runtime_principal_document()
    document["runtime_principals"][0]["account_id"] = "missing-account"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["enabled"] = False  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["secret_state"] = "missing"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["limit_state"] = "unknown"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["provider"] = "openai_api"  # type: ignore[index]
    document["accounts"][2]["auth_kind"] = "api_key"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["credential_binding_id"] = None  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)

    document = valid_runtime_principal_document()
    document["accounts"][2]["credential_binding_id"] = "hmac-sha256:" + "b" * 64  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_runtime_principal"):
        normalize_fleet_document(document)


@pytest.mark.parametrize("account_field", ["enabled", "limit_state"])
def test_v2_allows_disabled_runtime_principal_with_bound_but_unavailable_account(account_field: str) -> None:
    document = valid_runtime_principal_document()
    document["runtime_principals"][0]["enabled"] = False  # type: ignore[index]
    document["accounts"][2][account_field] = False if account_field == "enabled" else "unknown"  # type: ignore[index]
    snapshot = normalize_fleet_document(document)
    account = next(account for account in snapshot.accounts if account.account_id == "chatgpt-teamlead-1")
    assert snapshot.runtime_principals[0].enabled is False
    assert snapshot.runtime_principals[0].account_id == account.account_id
    assert snapshot.runtime_principals[0].credential_binding_id == account.credential_binding_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_id", "missing-account"),
        ("credential_binding_id", "hmac-sha256:" + "b" * 64),
    ],
)
def test_v2_rejects_disabled_runtime_principal_without_exact_account_binding(field: str, value: str) -> None:
    document = valid_runtime_principal_document()
    document["runtime_principals"][0].update(enabled=False, **{field: value})  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_runtime_principal"


def test_v2_rejects_duplicate_enabled_binding_across_all_providers_when_principal_targets_it() -> None:
    document = valid_runtime_principal_document()
    document["accounts"][0]["credential_binding_id"] = document["runtime_principals"][0]["credential_binding_id"]  # type: ignore[index]
    document["accounts"][0]["enabled"] = True  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "duplicate_credential_binding"


def test_public_v2_snapshot_redacts_runtime_principals() -> None:
    public = public_fleet_snapshot(normalize_fleet_document(load_fixture("fleet-registry-v2.json")))
    rendered = json.dumps(public)
    assert public["runtime_principal_count"] == 1
    assert "runtime_principals" not in public
    assert "principal_id" not in rendered
    assert "profile_id" not in rendered
    assert "credential_binding_id" not in rendered


def test_v2_runtime_principal_planners_apply_cas_and_disable_before_delete() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    principal = FleetRuntimePrincipalV2(
        principal_id="tl-" + "2" * 32,
        account_id="chatgpt-teamlead-1",
        profile_id="teamlead.beta",
        credential_binding_id=snapshot.runtime_principals[0].credential_binding_id,
        class_id="teamleiterin",
        lifecycle="persistent",
        provider=Provider.OPENAI_CHATGPT,
        runner=RunnerKind.CODEX_CLI,
        model="gpt-5.6-terra",
        reasoning="xhigh",
        enabled=False,
    )

    with pytest.raises(FleetValidationError, match="generation_conflict"):
        plan_runtime_principal_upsert(snapshot, principal, expected_generation=snapshot.generation + 1)

    updated = plan_runtime_principal_upsert(snapshot, principal, expected_generation=snapshot.generation)
    assert isinstance(updated, FleetSnapshotV2)
    assert updated.generation == snapshot.generation + 1
    assert updated.runtime_principals[-1] == principal

    enabled = replace(principal, enabled=True)
    enabled_snapshot = plan_runtime_principal_upsert(
        updated, enabled, expected_generation=updated.generation
    )
    assert enabled_snapshot.runtime_principals[-1] == enabled

    with pytest.raises(FleetValidationError, match="runtime_principal_must_be_disabled"):
        plan_runtime_principal_delete(snapshot, snapshot.runtime_principals[0].principal_id, expected_generation=snapshot.generation)

    disabled = plan_runtime_principal_disable(snapshot, snapshot.runtime_principals[0].principal_id, expected_generation=snapshot.generation)
    assert disabled.runtime_principals[0].enabled is False

    deleted = plan_runtime_principal_delete(
        disabled,
        disabled.runtime_principals[0].principal_id,
        expected_generation=disabled.generation,
    )
    assert deleted.generation == disabled.generation + 1
    assert deleted.runtime_principals == ()


def test_dynamic_worker_principal_round_trips_complete_resolution_carrier() -> None:
    snapshot = empty_worker_snapshot()
    reservation = worker_registry_reservation()
    lease_binding_digest = _digest("f")

    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        snapshot,
        reservation,
        lease_binding_digest=lease_binding_digest,
        expected_generation=snapshot.generation,
    )
    principal = reserved.runtime_principals[0]

    assert isinstance(principal, fleet_registry.FleetDynamicWorkerPrincipalV2)
    assert principal.principal_id == "dw-" + "7" * 32
    assert principal.ticket_id == "ticket:worker-7"
    assert principal.lease_binding_digest == lease_binding_digest
    assert principal.class_id == "arbeitsbiene"
    assert principal.lifecycle == "ephemeral"
    assert principal.model == "gpt-5.6-luna"
    assert principal.reasoning == "medium"
    assert principal.ticket_ledger_revision == 1
    assert principal.ticket_fence_epoch == 6
    assert principal.ticket_resolution_generation == 4
    assert principal.ticket_policy_generation == 9
    assert principal.ticket_policy_digest == _digest("d")
    assert principal.capability_binding_digest == _digest("e")
    assert normalize_fleet_document(fleet_document(reserved)) == reserved


def test_dynamic_worker_reserve_rejects_bad_or_leadership_carrier() -> None:
    snapshot = empty_worker_snapshot()

    with pytest.raises(FleetValidationError) as caught:
        fleet_registry.plan_dynamic_worker_principal_reserve(
            snapshot,
            object(),
            lease_binding_digest=_digest("f"),
            expected_generation=snapshot.generation,
        )
    assert caught.value.code == "invalid_worker_registry_reservation"

    with pytest.raises(FleetValidationError) as caught:
        fleet_registry.plan_dynamic_worker_principal_reserve(
            snapshot,
            worker_registry_reservation(principal_id="tl-" + "8" * 32),
            lease_binding_digest=_digest("f"),
            expected_generation=snapshot.generation,
        )
    assert caught.value.code == "invalid_runtime_principal"


def test_dynamic_worker_principal_ids_separate_teamlead_and_worker() -> None:
    document = fleet_document(
        fleet_registry.plan_dynamic_worker_principal_reserve(
            empty_worker_snapshot(),
            worker_registry_reservation(),
            lease_binding_digest=_digest("f"),
            expected_generation=5,
        )
    )
    worker = document["runtime_principals"][0]  # type: ignore[index]
    worker["principal_id"] = "tl-" + "7" * 32  # type: ignore[index]
    worker["class_id"] = "teamleiterin"  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_runtime_principal"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", "dw-not-hex"),
        ("ticket_id", ""),
        ("lease_binding_digest", "sha256:short"),
        ("ticket_policy_digest", "sha256:short"),
        ("capability_binding_digest", "sha256:short"),
        ("resolution_decision_digest", "sha256:short"),
        ("resolver_offer_generation", "sha256:short"),
        ("class_id", ""),
        ("enabled", "true"),
    ],
)
def test_dynamic_worker_principal_rejects_malformed_structural_fields(
    field: str, value: object
) -> None:
    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        empty_worker_snapshot(),
        worker_registry_reservation(),
        lease_binding_digest=_digest("f"),
        expected_generation=5,
    )
    document = fleet_document(reserved)
    document["runtime_principals"][0][field] = value  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_runtime_principal"


def test_dynamic_worker_principal_accepts_structural_policy_values() -> None:
    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        empty_worker_snapshot(),
        worker_registry_reservation(),
        lease_binding_digest=_digest("f"),
        expected_generation=5,
    )
    document = fleet_document(reserved)
    document["runtime_principals"][0].update(  # type: ignore[index]
        class_id="locally-unknown-class",
        lifecycle="locally-unknown-lifecycle",
        model="locally-unknown-model",
        reasoning="locally-unknown-reasoning",
    )
    normalized = normalize_fleet_document(document)
    assert normalized.runtime_principals[0].class_id == "locally-unknown-class"


def test_dynamic_worker_reserve_is_generation_bound_and_never_upserts() -> None:
    snapshot = empty_worker_snapshot()
    reservation = worker_registry_reservation()

    with pytest.raises(FleetValidationError, match="generation_conflict"):
        fleet_registry.plan_dynamic_worker_principal_reserve(
            snapshot,
            reservation,
            lease_binding_digest=_digest("f"),
            expected_generation=snapshot.generation + 1,
        )

    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        snapshot,
        reservation,
        lease_binding_digest=_digest("f"),
        expected_generation=snapshot.generation,
    )
    with pytest.raises(FleetValidationError, match="worker_principal_collision"):
        fleet_registry.plan_dynamic_worker_principal_reserve(
            reserved,
            reservation,
            lease_binding_digest=_digest("f"),
            expected_generation=reserved.generation,
        )
    assert reserved.generation == snapshot.generation + 1
    assert snapshot.runtime_principals == ()

    with pytest.raises(FleetValidationError, match="worker_ticket_collision"):
        fleet_registry.plan_dynamic_worker_principal_reserve(
            reserved,
            worker_registry_reservation(principal_id="dw-" + "8" * 32),
            lease_binding_digest=_digest("e"),
            expected_generation=reserved.generation,
        )

    with pytest.raises(FleetValidationError, match="worker_lease_collision"):
        fleet_registry.plan_dynamic_worker_principal_reserve(
            reserved,
            worker_registry_reservation(
                principal_id="dw-" + "8" * 32, ticket_id="ticket:worker-8"
            ),
            lease_binding_digest=_digest("f"),
            expected_generation=reserved.generation,
        )


def test_dynamic_worker_release_requires_exact_reservation() -> None:
    snapshot = empty_worker_snapshot()
    reservation = worker_registry_reservation()
    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        snapshot,
        reservation,
        lease_binding_digest=_digest("f"),
        expected_generation=snapshot.generation,
    )

    with pytest.raises(FleetValidationError, match="worker_reservation_mismatch"):
        fleet_registry.plan_dynamic_worker_principal_release(
            reserved,
            worker_registry_reservation(ticket_id="ticket:worker-drift"),
            lease_binding_digest=_digest("f"),
            expected_generation=reserved.generation,
        )

    released = fleet_registry.plan_dynamic_worker_principal_release(
        reserved,
        reservation,
        lease_binding_digest=_digest("f"),
        expected_generation=reserved.generation,
    )
    assert released.generation == reserved.generation + 1
    assert released.runtime_principals == ()
    assert reserved.runtime_principals != ()


def test_public_snapshot_excludes_all_dynamic_worker_private_markers() -> None:
    reserved = fleet_registry.plan_dynamic_worker_principal_reserve(
        empty_worker_snapshot(),
        worker_registry_reservation(),
        lease_binding_digest=_digest("f"),
        expected_generation=5,
    )
    rendered = json.dumps(public_fleet_snapshot(reserved))
    for marker in (
        "dw-" + "7" * 32,
        "ticket:worker-7",
        _digest("f"),
        "arbeitsbiene",
        "ephemeral",
        "gpt-5.6-luna",
        "ticket_id",
        "lease_binding_digest",
        "capability_binding_digest",
        "policy_digest",
        "home",
        "path",
    ):
        assert marker not in rendered


def test_registry_schema_discriminates_teamlead_and_dynamic_worker_principals() -> None:
    schema = json.loads(
        (
            Path(__file__).parents[1] / "schemas" / "codex-fleet-registry.schema.json"
        ).read_text()
    )
    items = schema["$defs"]["v2"]["properties"]["runtime_principals"]["items"]
    assert {item["$ref"] for item in items["oneOf"]} == {
        "#/$defs/runtime_principal",
        "#/$defs/dynamic_worker_principal",
    }
    worker = schema["$defs"]["dynamic_worker_principal"]
    assert worker["properties"]["principal_id"]["pattern"] == "^dw-[0-9a-f]{32}$"
    assert worker["additionalProperties"] is False


@pytest.mark.parametrize("member_id", [None, "v1:g:1", "11111111-1111-1111-8111-111111111111",
                                        "11111111-1111-4111-8111-11111111111A"])
def test_v2_requires_canonical_uuid4_member_id(member_id: object) -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][0]["member_id"] = member_id  # type: ignore[index]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_member"


def test_v2_rejects_duplicate_member_id() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][1]["member_id"] = document["series"][0]["members"][0]["member_id"]  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_duplicate_or_gapped_ordinals() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][1]["ordinal"] = 3  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_nonpositive_ordinal() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][0]["ordinal"] = 0  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_unknown_or_cross_provider_member_account() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][0]["account_id"] = "missing"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][0]["account_id"] = "local-account"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_cross_provider_existing_account() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0].update(prefix="o", provider="openai_api", runner="codex_cli")
    document["series"][0]["members"][0]["account_id"] = "gemini-project-1"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_enabled_member_under_disabled_series_or_account() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["enabled"] = False
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)
    document = load_fixture("fleet-registry-v2.json")
    document["accounts"][0]["enabled"] = False
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_gemini_member_outside_g_and_non_gemini_member_in_g() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["prefix"] = "x"
    with pytest.raises(FleetValidationError, match="invalid_series"):
        normalize_fleet_document(document)
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["provider"] = "ollama_local"
    document["series"][0]["runner"] = "codex_cli"
    with pytest.raises(FleetValidationError, match="invalid_series"):
        normalize_fleet_document(document)


def test_v2_rejects_duplicate_active_credential_binding() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["accounts"][1]["credential_binding_id"] = "binding-one"  # type: ignore[index]
    with pytest.raises(FleetValidationError, match="duplicate_credential_binding"):
        normalize_fleet_document(document)


def test_v2_reordering_preserves_final_member_ids() -> None:
    document = load_fixture("fleet-registry-v2.json")
    before = {m["account_id"]: m["member_id"] for m in document["series"][0]["members"]}  # type: ignore[index]
    document["series"][0]["members"][0]["ordinal"] = 2  # type: ignore[index]
    document["series"][0]["members"][1]["ordinal"] = 1  # type: ignore[index]
    after = normalize_fleet_document(document)
    assert {m.account_id: m.member_id for m in after.series[0].members} == before


def test_v2_repfx_and_profile_changes_preserve_final_member_ids() -> None:
    document = load_fixture("fleet-registry-v2.json")
    before = {m["ordinal"]: m["member_id"] for m in document["series"][0]["members"]}  # type: ignore[index]
    document["accounts"] = []
    document["runtime_principals"] = []
    document["series"][0].update(prefix="d", provider="ollama_local", runner="codex_cli", model="new-model", skill_profile="new-skill", task_profile="new-task")
    for member in document["series"][0]["members"]:
        member["account_id"] = None  # type: ignore[index]
        member["model_override"] = "member-model"  # type: ignore[index]
    after = normalize_fleet_document(document)
    assert {m.ordinal: m.member_id for m in after.series[0].members} == before


def test_public_v2_snapshot_redacts_credential_binding_ids() -> None:
    public = public_fleet_snapshot(normalize_fleet_document(load_fixture("fleet-registry-v2.json")))
    assert "credential_binding_id" not in json.dumps(public)


def test_v2_account_repr_and_str_redact_binding_marker() -> None:
    binding_marker = "hmac-sha256:" + "a" * 64
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    account = replace(snapshot.accounts[0], credential_binding_id=binding_marker)

    assert repr(account) == "FleetAccountV2(<redacted>)"
    assert str(account) == "FleetAccountV2(<redacted>)"
    assert binding_marker not in repr(account)
    assert "credential_binding_id" not in repr(account)


def test_v2_member_repr_and_str_redact_member_identifier() -> None:
    member_marker = "00000000-0000-4000-8000-000000000123"
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    member = replace(snapshot.series[0].members[0], member_id=member_marker)

    assert repr(member) == "FleetSeriesMember(<redacted>)"
    assert str(member) == "FleetSeriesMember(<redacted>)"
    assert member_marker not in repr(member)
    assert "member_id" not in repr(member)


def test_v2_snapshot_repr_and_str_redact_transitive_markers() -> None:
    binding_marker = "hmac-sha256:" + "a" * 64
    member_marker = "00000000-0000-4000-8000-000000000123"
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    account = replace(snapshot.accounts[0], credential_binding_id=binding_marker)
    member = replace(snapshot.series[0].members[0], member_id=member_marker)
    series = replace(snapshot.series[0], members=(member, *snapshot.series[0].members[1:]))
    snapshot = replace(snapshot, accounts=(account, *snapshot.accounts[1:]), series=(series, *snapshot.series[1:]))

    for rendered in (repr(snapshot), str(snapshot)):
        assert rendered == "FleetSnapshotV2(<redacted>)"
        assert binding_marker not in rendered
        assert member_marker not in rendered
        assert "credential_binding_id" not in rendered
        assert "member_id" not in rendered

    document = fleet_document(snapshot)
    assert document["accounts"][0]["credential_binding_id"] == binding_marker  # type: ignore[index]
    assert document["series"][0]["members"][0]["member_id"] == member_marker  # type: ignore[index]
    roundtrip = normalize_fleet_document(document)
    assert roundtrip == snapshot
    assert hash(roundtrip) == hash(snapshot)
    public = json.dumps(public_fleet_snapshot(snapshot))
    assert binding_marker not in public
    assert member_marker not in public


def test_v2_inventory_uses_member_account_and_overrides(tmp_path: Path) -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["series"][0]["members"][0].update(
        model_override="member-model", skill_profile_override="member-skill", task_profile_override="member-task"
    )
    inventory = build_inventory(normalize_fleet_document(document), tmp_path)
    assert inventory.agents["g1"].account_id == "gemini-project-1"
    assert inventory.agents["g2"].account_id == "gemini-project-2"
    assert inventory.agents["g1"].model == "member-model"
    assert inventory.agents["g1"].skill_profile == "member-skill"
    assert inventory.agents["g1"].task_profile == "member-task"


def test_v2_allows_accountless_local_member_and_rejects_missing_required_account() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["accounts"] = []
    document["runtime_principals"] = []
    document["series"][0].update(prefix="d", provider="ollama_local", runner="codex_cli")
    for member in document["series"][0]["members"]:
        member["account_id"] = None
    assert normalize_fleet_document(document).series[0].members[0].account_id is None
    document["series"][0].update(provider="openai_api", runner="codex_cli")
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_rejects_disabled_required_accountless_member() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["accounts"] = []
    document["runtime_principals"] = []
    document["series"][0].update(prefix="d", provider="openai_api", runner="codex_cli")
    for member in document["series"][0]["members"]:
        member["account_id"] = None
        member["enabled"] = False
    with pytest.raises(FleetValidationError, match="invalid_member"):
        normalize_fleet_document(document)


def test_v2_generation_cas_preserves_type_and_member_ids() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    updated = _next(snapshot)
    assert isinstance(updated, FleetSnapshotV2)
    assert updated.generation == 6
    assert [member.member_id for member in updated.series[0].members] == [
        member.member_id for member in snapshot.series[0].members
    ]
    with pytest.raises(FleetValidationError, match="generation_conflict"):
        _generation_for_test(snapshot, 6)


def _generation_for_test(snapshot: FleetSnapshotV2, expected: int) -> None:
    from codex_master.fleet_registry import _generation
    _generation(snapshot, expected)


def test_v2_writer_rejects_nonfinal_member_id() -> None:
    snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))
    member = replace(snapshot.series[0].members[0], member_id="v1:g:1")
    invalid = replace(snapshot, series=(replace(snapshot.series[0], members=(member, snapshot.series[0].members[1])),))
    with pytest.raises(FleetValidationError, match="final_member_id_required"):
        fleet_document(invalid)


def test_duplicate_non_gemini_credential_bindings_are_rejected() -> None:
    document = load_fixture("fleet-registry-v2.json")
    document["accounts"].append({
        "account_id": "unused-openai-api",
        "label": "Unused OpenAI API",
        "provider": "openai_api",
        "auth_kind": "api_key",
        "secret_state": "configured",
        "limit_state": "ready",
        "enabled": True,
        "credential_binding_id": document["accounts"][0]["credential_binding_id"],  # type: ignore[index]
    })
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "duplicate_credential_binding"


def test_registry_schema_declares_separate_v1_and_v2_contracts() -> None:
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "codex-fleet-registry.schema.json").read_text())
    assert len(schema["oneOf"]) == 2
    assert schema["$defs"]["v1_series"]["required"][:3] == ["prefix", "display_name", "count"]
    assert "members" in schema["$defs"]["v2_series"]["required"]
    assert "count" not in schema["$defs"]["v2_series"]["properties"]
    assert "member_id" in schema["$defs"]["member"]["required"]
    assert "runtime_principals" in schema["$defs"]["v2"]["required"]
    assert "runtime_principals" not in schema["$defs"]["v1"]["properties"]
    assert set(schema["$defs"]["runtime_principal"]["required"]) == {
        "principal_id", "account_id", "profile_id", "credential_binding_id", "class_id",
        "lifecycle", "provider", "runner", "model", "reasoning", "enabled",
    }
    assert schema["$defs"]["runtime_principal"]["additionalProperties"] is False
    assert schema["$defs"]["v2"]["additionalProperties"] is False
    assert schema["$defs"]["v2"]["properties"]["runtime_principals"]["maxItems"] == 64


def test_registry_schema_rejects_v1_provider_runner_regressions_and_invalid_v2_text() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads((Path(__file__).parents[1] / "schemas" / "codex-fleet-registry.schema.json").read_text())
    validator = Draft202012Validator(schema)
    v1 = load_fixture("fleet-registry-v1.json")
    v1["series"][0].update(provider="gemini_api", runner="codex_cli", account_id=None)
    assert list(validator.iter_errors(v1))
    v2 = load_fixture("fleet-registry-v2.json")
    assert not list(validator.iter_errors(v2))
    v2["series"][0]["members"][0]["model_override"] = ""
    assert list(validator.iter_errors(v2))
    missing_principals = load_fixture("fleet-registry-v2.json")
    missing_principals.pop("runtime_principals")
    assert list(validator.iter_errors(missing_principals))
    for field in ("home", "series"):
        invalid_principal = load_fixture("fleet-registry-v2.json")
        invalid_principal["runtime_principals"][0][field] = "forbidden"  # type: ignore[index]
        assert list(validator.iter_errors(invalid_principal))
    invalid_binding = load_fixture("fleet-registry-v2.json")
    invalid_binding["runtime_principals"][0]["credential_binding_id"] = "binding-one"  # type: ignore[index]
    assert list(validator.iter_errors(invalid_binding))


def test_registry_schema_rejects_v2_model_control_characters() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads((Path(__file__).parents[1] / "schemas" / "codex-fleet-registry.schema.json").read_text())
    validator = Draft202012Validator(schema)
    v2 = load_fixture("fleet-registry-v2.json")
    v2["series"][0]["model"] = "bad\u009fmodel"
    assert list(validator.iter_errors(v2))
    v2 = load_fixture("fleet-registry-v2.json")
    v2["accounts"][0]["credential_binding_id"] = "bad\nvalue"
    assert list(validator.iter_errors(v2))


def gemini_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generation": 4,
        "accounts": [
            {
                "account_id": f"gemini-project-{n}",
                "label": f"Gemini {n}",
                "provider": "gemini_api",
                "auth_kind": "api_key",
                "enabled": True,
                "limit_state": "ready",
            }
            for n in range(1, 4)
        ],
        "series": [
            {
                "prefix": prefix,
                "display_name": f"Gemini {prefix.upper()}",
                "count": 100,
                "runner": "gemini_cli",
                "provider": "gemini_api",
                "model": "gemini-3-flash-preview",
                "account_id": f"gemini-project-{n}",
                "enabled": True,
            }
            for n, prefix in enumerate(("d", "e", "f"), 1)
        ],
    }


def valid_document() -> dict[str, object]:
    document = gemini_document()
    document["accounts"] = [document["accounts"][0]]
    document["series"] = [document["series"][0]]
    return document


def test_normalizes_three_independent_gemini_series() -> None:
    snapshot = normalize_fleet_document(gemini_document())
    assert snapshot.generation == 4
    assert [series.prefix for series in snapshot.series] == ["d", "e", "f"]
    assert len({series.account_id for series in snapshot.series}) == 3


def test_normalization_sorts_entries_and_applies_safe_defaults() -> None:
    document = valid_document()
    document["accounts"] = [
        {
            "account_id": "zeta",
            "label": "Zeta",
            "provider": "gemini_api",
            "auth_kind": "api_key",
            "enabled": True,
        },
        document["accounts"][0],
    ]
    document["series"] = [
        {
            "prefix": "z",
            "display_name": "Z series",
            "count": 1,
            "runner": "gemini_cli",
            "provider": "gemini_api",
            "model": "gemini-3-flash-preview",
            "account_id": "zeta",
            "enabled": True,
        },
        document["series"][0],
    ]
    snapshot = normalize_fleet_document(document)
    assert [item.account_id for item in snapshot.accounts] == ["gemini-project-1", "zeta"]
    assert [item.prefix for item in snapshot.series] == ["d", "z"]
    assert snapshot.accounts[0].secret_state is SecretState.MISSING
    assert snapshot.accounts[1].limit_state is LimitState.UNKNOWN


def test_normalization_rejects_not_required_secret_state_for_api_account() -> None:
    document = valid_document()
    document["accounts"][0]["secret_state"] = "not_required"

    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)

    assert caught.value.code == "invalid_account"


@pytest.mark.parametrize(
    ("location", "field", "value", "code"),
    [
        ("accounts", "label", "bad\u0085label", "invalid_account"),
        ("series", "model", "bad\u009fmodel", "invalid_series"),
        ("accounts", "label", "\ud800", "invalid_document"),
    ],
)
def test_normalization_rejects_c1_controls_and_unpaired_surrogates(
    location: str, field: str, value: str, code: str
) -> None:
    document = valid_document()
    document[location][0][field] = value

    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)

    assert caught.value.code == code


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda document: document["series"].append(deepcopy(document["series"][0])), "invalid_series"),
        (lambda document: document["series"][0].update(prefix="aa"), "invalid_series"),
        (lambda document: document["series"][0].update(count=0), "invalid_series"),
        (lambda document: document["series"][0].update(count=101), "invalid_series"),
        (lambda document: document["series"][0].update(runner="codex_cli"), "invalid_series"),
        (lambda document: document["series"][0].update(account_id=None), "invalid_series"),
        (lambda document: document["accounts"][0].update(provider="openai_api"), "invalid_series"),
        (lambda document: document["accounts"][0].update(label="bad\nlabel"), "invalid_account"),
        (lambda document: document["series"][0].update(model="x" * 201), "invalid_series"),
        (lambda document: document["accounts"][0].update(reset_at_utc="2026-08-03T12:00:00"), "invalid_account"),
    ],
)
def test_normalization_rejects_invalid_contract_values(change: object, code: str) -> None:
    document = valid_document()
    change(document)  # type: ignore[operator]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == code


@pytest.mark.parametrize("field", ["secret", "token", "home", "email", "backend_account_id"])
@pytest.mark.parametrize("location", ["accounts", "series"])
def test_normalization_rejects_private_or_unknown_fields(field: str, location: str) -> None:
    document = valid_document()
    document[location][0][field] = "ignored"
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == ("invalid_account" if location == "accounts" else "invalid_series")


def test_normalization_rejects_duplicate_accounts_and_total_agent_limit() -> None:
    duplicate = valid_document()
    duplicate["accounts"].append(deepcopy(duplicate["accounts"][0]))
    excess = gemini_document()
    excess["series"] = [
        {
            "prefix": chr(ord("a") + i),
            "display_name": f"Series {i}",
            "count": 100 if i < 10 else 1,
            "runner": "gemini_cli",
            "provider": "gemini_api",
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project-1",
            "enabled": True,
        }
        for i in range(11)
    ]
    for document, code in ((duplicate, "invalid_account"), (excess, "invalid_document")):
        with pytest.raises(FleetValidationError) as caught:
            normalize_fleet_document(document)
        assert caught.value.code == code


def test_normalization_rejects_more_than_twenty_six_series() -> None:
    document = valid_document()
    document["series"] = [
        {
            "prefix": chr(ord("a") + (index % 26)),
            "display_name": f"Series {index}",
            "count": 1,
            "runner": "gemini_cli",
            "provider": "gemini_api",
            "model": "gemini-3-flash-preview",
            "account_id": "gemini-project-1",
            "enabled": True,
        }
        for index in range(27)
    ]

    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)

    assert caught.value.code == "invalid_document"


def test_normalization_enforces_local_provider_without_account() -> None:
    document = valid_document()
    document["accounts"] = []
    document["series"][0].update(provider="ollama_local", runner="codex_cli", account_id=None)
    assert normalize_fleet_document(document).series[0].account_id is None
    document["accounts"] = [{"account_id": "local", "label": "Local", "provider": "ollama_local",
                              "auth_kind": "none", "enabled": True}]
    with pytest.raises(FleetValidationError) as caught:
        normalize_fleet_document(document)
    assert caught.value.code == "invalid_account"


def test_fleet_document_round_trips_immutable_snapshot() -> None:
    snapshot = normalize_fleet_document(valid_document())
    assert normalize_fleet_document(fleet_document(snapshot)) == snapshot
    with pytest.raises(FrozenInstanceError):
        snapshot.generation = 5  # type: ignore[misc]


def test_snapshot_constructor_freezes_nested_collections() -> None:
    snapshot = normalize_fleet_document(valid_document())
    accounts = list(snapshot.accounts)
    series = list(snapshot.series)
    direct = type(snapshot)(snapshot.schema_version, snapshot.generation, accounts, series)
    assert isinstance(direct.accounts, tuple)
    assert isinstance(direct.series, tuple)
    with pytest.raises(AttributeError):
        direct.accounts.append(snapshot.accounts[0])  # type: ignore[attr-defined]


def test_inventory_derives_exact_agent_ids(tmp_path: Path) -> None:
    inventory = build_inventory(normalize_fleet_document(gemini_document()), tmp_path / "agents")
    assert inventory.agent_ids[0] == "d1"
    assert inventory.agent_ids[99] == "d100"
    assert inventory.agent_ids[100] == "e1"
    assert inventory.agent_ids[-1] == "f100"
    assert inventory.by_series["d-series"][-1] == "d100"
    assert inventory.agents["d1"].home == tmp_path / "agents" / "d1"
    assert inventory.agents["d1"].session == "codex_agent_d1_mcp"
    assert inventory.positions["f100"] == 299
    assert isinstance(inventory.agents, Mapping)
    with pytest.raises(TypeError):
        inventory.agents["x1"] = inventory.agents["d1"]  # type: ignore[index]


def test_inventory_keeps_disabled_entries_manageable(tmp_path: Path) -> None:
    document = valid_document()
    document["accounts"][0]["enabled"] = False
    document["series"][0]["enabled"] = False
    assert build_inventory(normalize_fleet_document(document), tmp_path).agents["d1"].enabled is False


def test_inventory_constructor_freezes_nested_maps() -> None:
    snapshot = normalize_fleet_document(valid_document())
    inventory = build_inventory(snapshot, Path("/tmp/agents"))
    direct = type(inventory)(list(inventory.agent_ids), dict(inventory.agents),
                             {key: list(value) for key, value in inventory.by_series.items()},
                             dict(inventory.positions), list(inventory.series_prefixes))
    with pytest.raises(TypeError):
        direct.agents["x1"] = inventory.agents["d1"]  # type: ignore[index]
    with pytest.raises(TypeError):
        direct.by_series["d-series"] = ()  # type: ignore[index]


def test_public_snapshot_uses_only_whitelisted_metadata() -> None:
    public = public_fleet_snapshot(normalize_fleet_document(valid_document()))
    allowed = {"generation", "account_count", "series_count", "agent_count", "accounts", "series",
               "label", "provider", "auth_kind", "secret_state", "limit_state", "enabled", "prefix",
               "display_name", "count", "runner", "model"}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert set(value).issubset(allowed)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(public)
    assert public["agent_count"] == 100
    assert public["accounts"][0]["secret_state"] == "missing"


def account() -> FleetAccount:
    return FleetAccount("gemini-project-1", "Changed account", Provider.GEMINI_API,
                        AuthKind.API_KEY, SecretState.CONFIGURED, LimitState.READY, True,
                        None, None, None)


def series(count: int = 3) -> FleetSeries:
    return FleetSeries("d", "Changed series", count, RunnerKind.GEMINI_CLI, Provider.GEMINI_API,
                       "gemini-3-flash-preview", "gemini-project-1", True)


def test_account_planners_are_pure_and_use_generation_compare_and_swap() -> None:
    snapshot = normalize_fleet_document(valid_document())
    changed = plan_account_upsert(snapshot, account(), expected_generation=4)
    disabled = plan_account_disable(changed, "gemini-project-1", expected_generation=5)
    limited = mark_account_limit(disabled, "gemini-project-1", reset_at_utc="2026-08-03T12:00:00Z",
                                 reason="rate_limited", expected_generation=6)
    assert snapshot.generation == 4
    assert changed.generation == 5 and changed.accounts[0].label == "Changed account"
    assert disabled.accounts[0].enabled is False
    assert limited.generation == 7 and limited.accounts[0].limit_state is LimitState.LIMITED
    with pytest.raises(FleetValidationError) as caught:
        plan_account_upsert(snapshot, account(), expected_generation=5)
    assert caught.value.code == "generation_conflict"


def test_account_upsert_rejects_mixed_snapshot_and_account_types() -> None:
    v1_snapshot = normalize_fleet_document(load_fixture("fleet-registry-v1.json"))
    v2_snapshot = normalize_fleet_document(load_fixture("fleet-registry-v2.json"))

    with pytest.raises(FleetValidationError, match="invalid_account"):
        plan_account_upsert(v2_snapshot, account(), expected_generation=v2_snapshot.generation)
    with pytest.raises(FleetValidationError, match="invalid_account"):
        plan_account_upsert(v1_snapshot, v2_snapshot.accounts[0], expected_generation=v1_snapshot.generation)


def test_delete_and_shrink_require_safe_preconditions() -> None:
    document = valid_document()
    document["series"][0]["count"] = 3
    snapshot = normalize_fleet_document(document)
    with pytest.raises(FleetValidationError) as caught:
        plan_account_delete(snapshot, "gemini-project-1", expected_generation=4)
    assert caught.value.code == "account_in_use"
    with pytest.raises(FleetValidationError) as caught:
        plan_series_apply(snapshot, series(1), expected_generation=4)
    assert caught.value.code == "remove_confirmation_required"
    changed = plan_series_apply(snapshot, series(1), expected_generation=4,
                                confirmed_remove_ids=("d2", "d3"))
    assert changed.generation == 5 and changed.series[0].count == 1
    with pytest.raises(FleetValidationError) as caught:
        plan_series_delete(snapshot, "d", expected_generation=4)
    assert caught.value.code == "series_must_be_disabled"
    disabled = plan_series_disable(snapshot, "d", expected_generation=4)
    no_series = plan_series_delete(disabled, "d", expected_generation=5)
    assert plan_account_delete(no_series, "gemini-project-1", expected_generation=6).accounts == ()
