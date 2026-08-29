from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import copy
import importlib
import json
import pickle

import pytest

from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    canonical_resolution_decision_digest,
    canonical_worker_lifecycle,
    resolve_agent_selection,
    validate_resolution_decision_offer,
)
from codex_master.worker_resolution_carrier import (
    WorkerResolutionCarrierDenied,
    WorkerResolutionEvidenceV2,
    WorkerRegistryReservationIssuerV2,
    build_worker_resolution_carrier,
)
from codex_master.worker_resume import WorkerLifecycle
from codex_master.worker_spawn_ledger import (
    FenceEpoch,
    Generation,
    LeaseBindingConsumerInputV1,
    LedgerRevision,
    SpawnPhase,
    WorkerSpawnTicketV2,
)


def _digest(char: str) -> str:
    return "sha256:" + (char * 64)


def _central_selection(*, leadership: bool = False):
    if leadership:
        classes = (
            AgentClassPolicy(
                "teamleiterin",
                "persistent",
                ("persistent",),
                ("terra",),
                "xhigh",
                "xhigh",
                ("read",),
                ("gpt-5.6-terra",),
            ),
        )
        models = (ModelPolicy("gpt-5.6-terra", "terra", 30, ("xhigh",), ("read",)),)
        request = ResolutionRequest(
            "read",
            "simple",
            requested_class="teamleiterin",
            requested_lifecycle="persistent",
            requested_model="gpt-5.6-terra",
            requested_reasoning="xhigh",
        )
    else:
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
        request,
        classes=classes,
        models=models,
        available_models={model.model_id for model in models},
    )
    return decision, build_selection_offer(
        classes=classes,
        models=models,
        available_models={model.model_id for model in models},
    )


def _ticket(
    decision, *, lifecycle: WorkerLifecycle = WorkerLifecycle.INVOCATION
) -> WorkerSpawnTicketV2:
    return WorkerSpawnTicketV2(
        ticket_id="ticket:worker-7",
        request_id="worker-7",
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
        lifecycle=lifecycle,
        resume_requirement=False,
        fence_epoch=FenceEpoch(6),
        ledger_revision=LedgerRevision(1),
        phase=SpawnPhase.REQUESTED,
    )


def _evidence(ticket, decision, offer) -> WorkerResolutionEvidenceV2:
    return WorkerResolutionEvidenceV2(
        decision=decision,
        offer=offer,
        offer_generation=offer.generation,
        capability_binding_digest=_digest("e"),
        resolution_generation=ticket.resolution_generation,
        policy_digest=ticket.policy_digest,
        policy_generation=ticket.policy_generation,
        ticket_fence_epoch=ticket.fence_epoch,
    )


def _carrier():
    decision, offer = _central_selection()
    ticket = _ticket(decision)
    evidence = _evidence(ticket, decision, offer)
    return ticket, evidence, build_worker_resolution_carrier(ticket, evidence)


def _bound_reservation(*, principal_id: str = "dw-" + "7" * 32):
    allocator_module = importlib.import_module("codex_master.runtime_account_allocator")

    class _Adapter:
        adapter_id = "adapter-carrier"

        def reserve_capability_atomically(self, _capability, evidence):
            return allocator_module.AccountReservation(
                reservation_id="reservation-carrier",
                account_binding_digest=_digest("a"),
                profile_binding_digest=_digest("b"),
                provider_adapter_id=self.adapter_id,
                capacity_evidence=evidence,
                lease_revision=1,
                evidence_revision=evidence.evidence_revision,
                fencing_token=evidence.fencing_token,
                fence_epoch=evidence.fence_epoch,
                expires_at_utc=evidence.expires_at_utc,
            )

        def release_reservation(self, _reservation):
            return True

    allocator = allocator_module.RuntimeAccountAllocator(_Adapter())
    ticket, _evidence_value, carrier = _carrier()
    p0_ticket = allocator_module.ValidatedAllocationTicket(
        ticket_id=ticket.ticket_id,
        resolution_decision=carrier.decision,
        selection_offer=carrier.offer,
        resolver_offer_generation=carrier.resolver_offer_generation,
        policy_generation=ticket.policy_generation.value,
        policy_digest=ticket.policy_digest,
        capability_binding_digest=carrier.capability_binding_digest,
        ledger_revision=1,
        phase="OFFER_VALIDATED",
        fencing_token="fence-carrier",
        fence_epoch=ticket.fence_epoch.value,
    )
    now = datetime.now(UTC)
    capacity_evidence = allocator_module.CapacityEvidence(
        ticket_id=p0_ticket.ticket_id,
        resolver_offer_generation=p0_ticket.resolver_offer_generation,
        policy_generation=p0_ticket.policy_generation,
        capability_binding_digest=p0_ticket.capability_binding_digest,
        ledger_revision=p0_ticket.ledger_revision,
        fencing_token=p0_ticket.fencing_token,
        fence_epoch=p0_ticket.fence_epoch,
        provider_adapter_id="adapter-carrier",
        capacity_units=2,
        quota_units=2,
        cost_units=2,
        resource_units=2,
        evidence_revision=1,
        observed_at_utc=now - timedelta(seconds=1),
        expires_at_utc=now + timedelta(minutes=5),
    )
    lease = allocator.allocate(p0_ticket, capacity_evidence)
    receipt = allocator.issue_lease_binding_receipt(lease, p0_ticket, capacity_evidence)
    verification = allocator.verify_lease_binding_receipt(
        receipt,
        expected_lease=lease,
        expected_ticket=p0_ticket,
        expected_capacity_evidence=capacity_evidence,
    )
    reference = allocator.lease_binding_reference_for(verification)
    allocator.close_lease_binding_verification(verification)
    binding = LeaseBindingConsumerInputV1(
        receipt=receipt,
        lease=lease,
        allocation_ticket=p0_ticket,
        capacity_evidence=capacity_evidence,
    )
    current_ticket = replace(
        ticket,
        phase=SpawnPhase.LEASE_RESERVED,
        ledger_revision=LedgerRevision(2),
        lease_binding_reference=reference,
        account_binding_digest=str(lease.account_binding_digest),
    )
    reservation = WorkerRegistryReservationIssuerV2(allocator).issue(
        resolution=carrier,
        current_ticket=current_ticket,
        principal_id=principal_id,
        lease_binding=binding,
    )
    return allocator, ticket, current_ticket, carrier, binding, reservation


def test_resolution_decision_digest_is_complete_stable_and_strict() -> None:
    decision, _offer = _central_selection()

    assert canonical_resolution_decision_digest(decision) == (
        "sha256:ccac64b2e7a8035190991375a7c8d40729e4acd3cb2e6a6f931a44c1cc91a529"
    )
    with pytest.raises(ValueError):
        canonical_resolution_decision_digest(replace(decision, fallback=1))


def test_validate_resolution_decision_offer_rejects_manipulated_option() -> None:
    decision, offer = _central_selection()
    validate_resolution_decision_offer(decision, offer)

    manipulated = replace(
        offer,
        options=tuple(
            replace(option, reasoning="invalid")
            if (
                option.class_id,
                option.lifecycle,
                option.model,
                option.reasoning,
            )
            == (
                decision.class_id,
                decision.lifecycle,
                decision.model,
                decision.reasoning,
            )
            else option
            for option in offer.options
        ),
    )
    with pytest.raises(ValueError):
        validate_resolution_decision_offer(decision, manipulated)


@pytest.mark.parametrize(
    "invalid_source", ("decision", "offer", "generation", "mismatch")
)
def test_validate_resolution_decision_offer_rejects_invalid_sources(
    invalid_source: str,
) -> None:
    decision, offer = _central_selection()
    if invalid_source == "decision":
        decision = object()
    elif invalid_source == "offer":
        offer = object()
    elif invalid_source == "generation":
        offer = replace(offer, generation=_digest("f"))
    else:
        _leader_decision, offer = _central_selection(leadership=True)

    with pytest.raises(ValueError):
        validate_resolution_decision_offer(decision, offer)


def test_canonical_worker_lifecycle_normalizes_alias_and_rejects_invalid() -> None:
    assert canonical_worker_lifecycle("invocation") == "ephemeral"
    assert canonical_worker_lifecycle("binding") == "binding"
    with pytest.raises(ValueError):
        canonical_worker_lifecycle(True)
    with pytest.raises(ValueError):
        canonical_worker_lifecycle("unknown")


def test_carrier_binds_real_central_decision_offer_and_all_ticket_generations() -> None:
    ticket, evidence, carrier = _carrier()

    assert carrier.ticket_id == ticket.ticket_id
    assert carrier.ticket_fence_epoch is ticket.fence_epoch
    assert carrier.ticket_resolution_generation is ticket.resolution_generation
    assert carrier.ticket_policy_digest == ticket.policy_digest
    assert carrier.ticket_policy_generation is ticket.policy_generation
    assert carrier.capability_binding_digest == evidence.capability_binding_digest
    assert carrier.resolution_decision_digest == ticket.resolution_decision_digest
    assert carrier.decision is evidence.decision
    assert carrier.offer is evidence.offer
    assert carrier.resolver_offer_generation == evidence.offer.generation
    assert carrier.decision.lifecycle == "ephemeral"


@pytest.mark.parametrize(
    "drift",
    (
        "offer_option",
        "offer_generation",
        "resolution_generation",
        "policy_digest",
        "policy_generation",
        "fence",
        "decision_digest",
        "capability_digest",
    ),
)
def test_carrier_rejects_decision_digest_offer_generation_policy_or_fence_drift(
    drift: str,
) -> None:
    decision, offer = _central_selection()
    ticket = _ticket(decision)
    evidence = _evidence(ticket, decision, offer)
    if drift == "offer_option":
        evidence = replace(evidence, offer=replace(offer, options=offer.options[:-1]))
    elif drift == "offer_generation":
        evidence = replace(evidence, offer_generation=_digest("f"))
    elif drift == "resolution_generation":
        evidence = replace(evidence, resolution_generation=Generation(5))
    elif drift == "policy_digest":
        evidence = replace(evidence, policy_digest=_digest("f"))
    elif drift == "policy_generation":
        evidence = replace(evidence, policy_generation=Generation(10))
    elif drift == "fence":
        evidence = replace(evidence, ticket_fence_epoch=FenceEpoch(7))
    elif drift == "decision_digest":
        ticket = replace(ticket, resolution_decision_digest=_digest("f"))
    else:
        evidence = replace(evidence, capability_binding_digest="sha256:malformed")

    with pytest.raises(WorkerResolutionCarrierDenied):
        build_worker_resolution_carrier(ticket, evidence)


@pytest.mark.parametrize("drift", ("target", "lifecycle", "leadership"))
def test_carrier_rejects_decision_outside_offer_target_lifecycle_or_leadership(
    drift: str,
) -> None:
    decision, offer = _central_selection(leadership=drift == "leadership")
    ticket = _ticket(
        decision,
        lifecycle=WorkerLifecycle.PERSISTENT
        if drift == "leadership"
        else WorkerLifecycle.INVOCATION,
    )
    if drift == "target":
        ticket = replace(ticket, target_class_id="spezialistin")
    elif drift == "lifecycle":
        ticket = replace(ticket, lifecycle=WorkerLifecycle.BINDING)

    with pytest.raises(WorkerResolutionCarrierDenied):
        build_worker_resolution_carrier(ticket, _evidence(ticket, decision, offer))


def test_carrier_normalizes_invocation_only_via_central_alias() -> None:
    ticket, _evidence_value, carrier = _carrier()

    assert ticket.lifecycle is WorkerLifecycle.INVOCATION
    assert carrier.decision.lifecycle == "ephemeral"


def test_carriers_redact_and_refuse_serialization_or_runtime_data() -> None:
    _allocator_value, _ticket, _current_ticket, carrier, _binding, reservation = (
        _bound_reservation()
    )

    assert not hasattr(reservation, "lease_binding_digest")
    assert not hasattr(reservation, "account_binding_digest")
    assert not hasattr(reservation, "profile_binding_digest")
    for value in (carrier, reservation):
        assert repr(value) == f"<{type(value).__name__} redacted>"
        assert str(value) == repr(value)
        assert not hasattr(value, "__dict__")
        with pytest.raises(TypeError):
            pickle.dumps(value)
        with pytest.raises(TypeError):
            asdict(value)
        with pytest.raises(TypeError):
            json.dumps(value)


def test_redacted_carrier_copy_is_denied() -> None:
    _ticket, _evidence_value, carrier = _carrier()

    with pytest.raises(TypeError, match="not serializable"):
        copy.copy(carrier)


def test_redacted_carrier_deepcopy_is_denied() -> None:
    _ticket, _evidence_value, carrier = _carrier()

    with pytest.raises(TypeError, match="not serializable"):
        copy.deepcopy(carrier)


def test_resolution_payload_rejects_mutation() -> None:
    import codex_master.worker_resolution_carrier as carrier_module

    ticket, evidence, _carrier_value = _carrier()
    payload = carrier_module._ResolutionPayload(
        ticket_id=ticket.ticket_id,
        ticket_fence_epoch=ticket.fence_epoch,
        ticket_resolution_generation=ticket.resolution_generation,
        ticket_policy_digest=ticket.policy_digest,
        ticket_policy_generation=ticket.policy_generation,
        capability_binding_digest=evidence.capability_binding_digest,
        resolution_decision_digest=ticket.resolution_decision_digest,
        decision=evidence.decision,
        offer=evidence.offer,
        resolver_offer_generation=evidence.offer_generation,
    )

    with pytest.raises(AttributeError, match="immutable"):
        payload.ticket_id = "ticket:replacement"


def test_resolution_payload_deepcopy_is_denied() -> None:
    import codex_master.worker_resolution_carrier as carrier_module

    ticket, evidence, _carrier_value = _carrier()
    payload = carrier_module._ResolutionPayload(
        ticket_id=ticket.ticket_id,
        ticket_fence_epoch=ticket.fence_epoch,
        ticket_resolution_generation=ticket.resolution_generation,
        ticket_policy_digest=ticket.policy_digest,
        ticket_policy_generation=ticket.policy_generation,
        capability_binding_digest=evidence.capability_binding_digest,
        resolution_decision_digest=ticket.resolution_decision_digest,
        decision=evidence.decision,
        offer=evidence.offer,
        resolver_offer_generation=evidence.offer_generation,
    )

    with pytest.raises(TypeError, match="not serializable"):
        copy.deepcopy(payload)


def test_reservation_payload_rejects_mutation() -> None:
    _allocator, _ticket, _current_ticket, _carrier, _binding, reservation = (
        _bound_reservation()
    )
    payload = object.__getattribute__(reservation, "_payload")

    with pytest.raises(AttributeError, match="immutable"):
        payload.principal_id = "dw-" + "8" * 32


def test_reservation_payload_deepcopy_is_denied() -> None:
    _allocator, _ticket, _current_ticket, _carrier, _binding, reservation = (
        _bound_reservation()
    )
    payload = object.__getattribute__(reservation, "_payload")

    with pytest.raises(TypeError, match="not serializable"):
        copy.deepcopy(payload)


@pytest.mark.parametrize(
    "drift", ("phase", "principal", "account", "binding", "allocator")
)
def test_reservation_issuer_rejects_malformed_or_drifting_bindings(drift: str) -> None:
    allocator, _ticket, current_ticket, carrier, binding, _reservation = (
        _bound_reservation()
    )
    if drift == "phase":
        current_ticket = replace(current_ticket, phase=SpawnPhase.OFFER_VALIDATED)
    elif drift == "account":
        current_ticket = replace(current_ticket, account_binding_digest=_digest("0"))
    elif drift == "principal":
        principal_id = "dw-not-hex"
    else:
        principal_id = "dw-" + "7" * 32
    if drift == "binding":
        binding = object()
    elif drift != "principal":
        principal_id = "dw-" + "7" * 32
    issuer = WorkerRegistryReservationIssuerV2(allocator)
    if drift == "allocator":
        foreign_allocator = importlib.import_module(
            "codex_master.runtime_account_allocator"
        ).RuntimeAccountAllocator(object())
        issuer = WorkerRegistryReservationIssuerV2(foreign_allocator)
    with pytest.raises(WorkerResolutionCarrierDenied):
        issuer.issue(
            resolution=carrier,
            current_ticket=current_ticket,
            principal_id=principal_id,
            lease_binding=binding,
        )


def test_reservation_rejects_premature_lease_binding() -> None:
    allocator, ticket, _current_ticket, carrier, _binding, _reservation = (
        _bound_reservation()
    )
    with pytest.raises(WorkerResolutionCarrierDenied):
        WorkerRegistryReservationIssuerV2(allocator).issue(
            resolution=carrier,
            current_ticket=ticket,
            principal_id="dw-" + "7" * 32,
            lease_binding=object(),
        )


def test_ticket_remains_digest_only_without_decision_or_offer_objects() -> None:
    ticket, evidence, _carrier_value = _carrier()

    assert not hasattr(ticket, "decision")
    assert not hasattr(ticket, "offer")
    assert not hasattr(ticket, "resolver_offer_generation")
    with pytest.raises(WorkerResolutionCarrierDenied):
        build_worker_resolution_carrier(ticket, {"decision": evidence.decision})


def test_carrier_rejects_bool_as_fence_epoch() -> None:
    decision, offer = _central_selection()
    ticket = _ticket(decision)

    with pytest.raises(WorkerResolutionCarrierDenied):
        build_worker_resolution_carrier(
            ticket,
            replace(_evidence(ticket, decision, offer), ticket_fence_epoch=True),
        )


def test_bound_reservation_issuer_rejects_fake_allocator() -> None:
    import codex_master.worker_resolution_carrier as carrier_module

    with pytest.raises(
        WorkerResolutionCarrierDenied, match="runtime account allocator"
    ):
        carrier_module.WorkerRegistryReservationIssuerV2(object())


def test_reservation_issuer_rejects_opaque_receipt_forge_and_foreign_binding() -> None:
    allocator, _ticket, current_ticket, carrier, binding, _reservation = (
        _bound_reservation()
    )
    runtime = importlib.import_module("codex_master.runtime_account_allocator")
    forged_receipt = object.__new__(runtime.LeaseBindingReceiptV1)
    object.__setattr__(
        forged_receipt,
        "_lease_binding_digest",
        runtime._OpaqueText(str(binding.receipt._lease_binding_digest)),
    )
    forged = replace(binding, receipt=forged_receipt)
    issuer = WorkerRegistryReservationIssuerV2(allocator)

    with pytest.raises(
        WorkerResolutionCarrierDenied, match="lease binding verification denied"
    ):
        issuer.issue(
            resolution=carrier,
            current_ticket=current_ticket,
            principal_id="dw-" + "7" * 32,
            lease_binding=forged,
        )
    assert allocator._active_lease_binding_verifications == {}

    (
        foreign_allocator,
        _foreign_ticket,
        _foreign_current,
        _foreign_carrier,
        foreign_binding,
        _foreign_reservation,
    ) = _bound_reservation()
    with pytest.raises(
        WorkerResolutionCarrierDenied, match="lease binding verification denied"
    ):
        issuer.issue(
            resolution=carrier,
            current_ticket=current_ticket,
            principal_id="dw-" + "7" * 32,
            lease_binding=foreign_binding,
        )
    assert allocator._active_lease_binding_verifications == {}
    assert foreign_allocator._active_lease_binding_verifications == {}


def test_carrier_primary_error_survives_real_guard_close_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allocator, _ticket, current_ticket, carrier, binding, _reservation = (
        _bound_reservation()
    )
    runtime = importlib.import_module("codex_master.runtime_account_allocator")
    original = runtime.RuntimeAccountAllocator.lease_binding_reference_for
    primary = RuntimeError("carrier-primary-error")

    def fail_after_real_reference(self, verification):
        original(self, verification)
        object.__setattr__(binding.lease, "profile_binding_digest", _digest("0"))
        raise primary

    monkeypatch.setattr(
        runtime.RuntimeAccountAllocator,
        "lease_binding_reference_for",
        fail_after_real_reference,
    )

    with pytest.raises(RuntimeError, match="carrier-primary-error") as caught:
        WorkerRegistryReservationIssuerV2(allocator).issue(
            resolution=carrier,
            current_ticket=current_ticket,
            principal_id="dw-" + "7" * 32,
            lease_binding=binding,
        )
    assert caught.value is primary
    assert caught.value.__notes__ == [
        "lease binding guard close denied; quarantine required"
    ]
    assert allocator._active_lease_binding_verifications == {}


def test_carrier_guard_close_deny_without_primary_is_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allocator, _ticket, current_ticket, carrier, binding, _reservation = (
        _bound_reservation()
    )
    runtime = importlib.import_module("codex_master.runtime_account_allocator")
    original = runtime.RuntimeAccountAllocator.lease_binding_reference_for

    def drift_after_real_reference(self, verification):
        reference = original(self, verification)
        object.__setattr__(binding.lease, "profile_binding_digest", _digest("0"))
        return reference

    monkeypatch.setattr(
        runtime.RuntimeAccountAllocator,
        "lease_binding_reference_for",
        drift_after_real_reference,
    )

    with pytest.raises(
        WorkerResolutionCarrierDenied, match="lease binding verification denied"
    ) as caught:
        WorkerRegistryReservationIssuerV2(allocator).issue(
            resolution=carrier,
            current_ticket=current_ticket,
            principal_id="dw-" + "7" * 32,
            lease_binding=binding,
        )
    assert type(caught.value.__cause__) is runtime.AllocationDenied
    assert allocator._active_lease_binding_verifications == {}
