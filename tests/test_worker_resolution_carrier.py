from dataclasses import asdict, replace
import json
import pickle

import pytest

from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    canonical_resolution_decision_digest,
    resolve_agent_selection,
)
from codex_master.worker_resolution_carrier import (
    WorkerResolutionCarrierDenied,
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
        "policy",
        "fence",
        "decision_digest",
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
    elif drift == "policy":
        evidence = replace(evidence, policy_digest=_digest("f"))
    elif drift == "fence":
        evidence = replace(evidence, ticket_fence_epoch=FenceEpoch(7))
    else:
        ticket = replace(ticket, resolution_decision_digest=_digest("f"))

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
    ticket, _evidence_value, carrier = _carrier()
    reservation = build_worker_registry_reservation(
        resolution=carrier,
        principal_id="dw-worker-7",
        ticket_ledger_revision=ticket.ledger_revision,
        ticket_fence_epoch=ticket.fence_epoch,
    )

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
