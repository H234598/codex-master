import ast
import copy
import dataclasses
import importlib
import pickle
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest

from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionRequest,
    build_selection_offer,
    canonical_resolution_decision_digest,
    resolve_agent_selection,
)

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/worker_spawn_ledger.py"
)


def _ledger_module():
    return importlib.import_module("codex_master.worker_spawn_ledger")


def _resume_module():
    return importlib.import_module("codex_master.worker_resume")


def _digest(value: str) -> str:
    return "sha256:" + (value * 64)


def _backend(module, *, before_cas=None):
    class _SharedFakeBackend(module.SpawnLedgerStatePort):
        def __init__(self) -> None:
            self._lock = Lock()
            self._state = module.SpawnLedgerStateV2.empty()
            self.cas_calls = 0

        def read(self):
            with self._lock:
                return self._state

        def compare_and_swap(self, expected_revision, replacement) -> bool:
            with self._lock:
                self.cas_calls += 1
                if before_cas is not None:
                    before_cas()
                if self._state.state_revision != expected_revision:
                    return False
                self._state = replacement
                return True

    return _SharedFakeBackend()


def _central_contract():
    classes = (
        AgentClassPolicy(
            "worker.research",
            "persistent",
            ("persistent",),
            ("luna",),
            "low",
            "xhigh",
            ("read", "write"),
        ),
    )
    models = (
        ModelPolicy("gpt-5.6-luna", "luna", 20, ("low", "medium", "high", "xhigh")),
    )
    request = ResolutionRequest(
        "read",
        "simple",
        requested_class="worker.research",
        requested_lifecycle="persistent",
        requested_model="gpt-5.6-luna",
        requested_reasoning="xhigh",
    )
    decision = resolve_agent_selection(
        request, classes=classes, models=models, available_models={models[0].model_id}
    )
    offer = build_selection_offer(
        classes=classes, models=models, available_models={models[0].model_id}
    )
    return decision, offer


def _allocator(module):
    allocator_module = importlib.import_module("codex_master.runtime_account_allocator")

    class _Adapter:
        adapter_id = "adapter-ledger"

        def __init__(self) -> None:
            self.module = allocator_module
            self.number = 0

        def reserve_capability_atomically(self, _capability, evidence):
            self.number += 1
            return self.module.AccountReservation(
                reservation_id=f"reservation-{self.number}",
                account_binding_digest=_digest("e"),
                profile_binding_digest=_digest("f"),
                provider_adapter_id=self.adapter_id,
                capacity_evidence=evidence,
                lease_revision=self.number,
                evidence_revision=evidence.evidence_revision,
                fencing_token=evidence.fencing_token,
                fence_epoch=evidence.fence_epoch,
                expires_at_utc=evidence.expires_at_utc,
            )

        def release_reservation(self, _reservation):
            return True

    return allocator_module.RuntimeAccountAllocator(_Adapter())


def _ledger(module, backend=None):
    return module.WorkerSpawnLedger(
        state_port=backend or _backend(module),
        delegable_nonleadership_class_ids=frozenset({"worker.research"}),
        allocator=_allocator(module),
    )


def _requester(module):
    return module.VerifiedPrincipalV2(
        principal_id="worker-11",
        role=module.PrincipalRole.NON_LEADERSHIP,
        authority_digest=_digest("b"),
    )


def _teamlead(module, *, principal_id: str = "teamlead-2"):
    return module.VerifiedPrincipalV2(
        principal_id=principal_id,
        role=module.PrincipalRole.TEAMLEADER,
        authority_digest=_digest("f"),
    )


def _publish(module, ledger, **overrides):
    decision, _offer = _central_contract()
    payload = {
        "request_id": "request-7",
        "requester": _requester(module),
        "work_package_id": "work-package-8",
        "topic_digest": _digest("a"),
        "target_class_id": "worker.research",
        "authorized_teamlead": _teamlead(module),
        "resolution_decision_digest": canonical_resolution_decision_digest(decision),
        "resolution_generation": module.Generation(4),
        "policy_digest": _digest("d"),
        "policy_generation": module.Generation(9),
        "lifecycle": module.WorkerLifecycle.PERSISTENT,
        "resume_requirement": True,
        "fence_epoch": module.FenceEpoch(6),
    }
    payload.update(overrides)
    return ledger.publish_requested(**payload)


def _append(module, ledger, ticket, phase, *, lease_binding=None, teamlead=None):
    return ledger.append_phase(
        ticket,
        phase,
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=teamlead or _teamlead(module),
        lease_binding=lease_binding,
    )


def _lease_binding(module, ledger, ticket):
    allocator_module = importlib.import_module("codex_master.runtime_account_allocator")
    decision, offer = _central_contract()
    p0_ticket = allocator_module.ValidatedAllocationTicket(
        ticket_id=ticket.ticket_id,
        resolution_decision=decision,
        selection_offer=offer,
        resolver_offer_generation=offer.generation,
        policy_generation=ticket.policy_generation.value,
        policy_digest=ticket.policy_digest,
        capability_binding_digest=_digest("e"),
        ledger_revision=ticket.ledger_revision.value,
        phase="OFFER_VALIDATED",
        fencing_token="fence-ledger",
        fence_epoch=ticket.fence_epoch.value,
    )
    now = datetime.now(UTC)
    evidence = allocator_module.CapacityEvidence(
        ticket_id=p0_ticket.ticket_id,
        resolver_offer_generation=offer.generation,
        policy_generation=p0_ticket.policy_generation,
        capability_binding_digest=p0_ticket.capability_binding_digest,
        ledger_revision=p0_ticket.ledger_revision,
        fencing_token=p0_ticket.fencing_token,
        fence_epoch=p0_ticket.fence_epoch,
        provider_adapter_id="adapter-ledger",
        capacity_units=2,
        quota_units=2,
        cost_units=2,
        resource_units=2,
        evidence_revision=1,
        observed_at_utc=now - timedelta(seconds=1),
        expires_at_utc=now + timedelta(minutes=5),
    )
    lease = ledger._allocator.allocate(p0_ticket, evidence)
    receipt = ledger._allocator.issue_lease_binding_receipt(lease, p0_ticket, evidence)
    return module.LeaseBindingConsumerInputV1(
        receipt=receipt,
        lease=lease,
        allocation_ticket=p0_ticket,
        capacity_evidence=evidence,
    )


def _allocator_issued_binding_pair(module, offered, dimension: str):
    runtime = importlib.import_module("codex_master.runtime_account_allocator")
    accounts = (_digest("e"), _digest("0") if dimension == "account" else _digest("e"))
    profiles = (_digest("f"), _digest("0") if dimension == "profile" else _digest("f"))

    class _MatrixAdapter:
        adapter_id = "adapter-ledger"

        def __init__(self) -> None:
            self.number = 0

        def reserve_capability_atomically(self, _capability, evidence):
            index = self.number
            self.number += 1
            return runtime.AccountReservation(
                reservation_id=f"matrix-reservation-{self.number}",
                account_binding_digest=accounts[index],
                profile_binding_digest=profiles[index],
                provider_adapter_id=self.adapter_id,
                capacity_evidence=evidence,
                lease_revision=self.number,
                evidence_revision=evidence.evidence_revision,
                fencing_token=evidence.fencing_token,
                fence_epoch=evidence.fence_epoch,
                expires_at_utc=evidence.expires_at_utc,
            )

        def release_reservation(self, _reservation):
            return True

    allocator = runtime.RuntimeAccountAllocator(_MatrixAdapter())
    decision, offer = _central_contract()
    base = {
        "ticket_id": offered.ticket_id,
        "policy_generation": offered.policy_generation.value,
        "policy_digest": offered.policy_digest,
        "ledger_revision": offered.ledger_revision.value,
        "fencing_token": "fence-ledger",
        "fence_epoch": offered.fence_epoch.value,
    }
    changed = dict(base)
    if dimension == "ticket":
        changed["ticket_id"] = "ticket:matrix-b"
    elif dimension == "policy":
        changed["policy_generation"] += 1
        changed["policy_digest"] = _digest("0")
    elif dimension == "fence":
        changed["fencing_token"] = "fence-matrix-b"
        changed["fence_epoch"] += 1
    elif dimension == "revision":
        changed["ledger_revision"] += 1

    now = datetime.now(UTC)

    def issue(values, evidence_revision):
        allocation_ticket = runtime.ValidatedAllocationTicket(
            ticket_id=values["ticket_id"],
            resolution_decision=decision,
            selection_offer=offer,
            resolver_offer_generation=offer.generation,
            policy_generation=values["policy_generation"],
            policy_digest=values["policy_digest"],
            capability_binding_digest=_digest("e"),
            ledger_revision=values["ledger_revision"],
            phase="OFFER_VALIDATED",
            fencing_token=values["fencing_token"],
            fence_epoch=values["fence_epoch"],
        )
        evidence = runtime.CapacityEvidence(
            ticket_id=allocation_ticket.ticket_id,
            resolver_offer_generation=offer.generation,
            policy_generation=allocation_ticket.policy_generation,
            capability_binding_digest=allocation_ticket.capability_binding_digest,
            ledger_revision=allocation_ticket.ledger_revision,
            fencing_token=allocation_ticket.fencing_token,
            fence_epoch=allocation_ticket.fence_epoch,
            provider_adapter_id="adapter-ledger",
            capacity_units=2,
            quota_units=2,
            cost_units=2,
            resource_units=2,
            evidence_revision=evidence_revision,
            observed_at_utc=now - timedelta(seconds=1),
            expires_at_utc=now + timedelta(minutes=5),
        )
        lease = allocator.allocate(allocation_ticket, evidence)
        receipt = allocator.issue_lease_binding_receipt(
            lease, allocation_ticket, evidence
        )
        return module.LeaseBindingConsumerInputV1(
            receipt=receipt,
            lease=lease,
            allocation_ticket=allocation_ticket,
            capacity_evidence=evidence,
        )

    bindings = (issue(base, 1), issue(changed, 2))
    for binding in bindings:
        verification = allocator.verify_lease_binding_receipt(
            binding.receipt,
            expected_lease=binding.lease,
            expected_ticket=binding.allocation_ticket,
            expected_capacity_evidence=binding.capacity_evidence,
        )
        allocator.close_lease_binding_verification(verification)
    return allocator, bindings


def _to_running(module, ledger, ticket):
    ticket = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(module),
        expected_revision=ticket.ledger_revision,
    )
    ticket = _append(module, ledger, ticket, module.SpawnPhase.OFFER_VALIDATED)
    binding = _lease_binding(module, ledger, ticket)
    ticket = _append(
        module,
        ledger,
        ticket,
        module.SpawnPhase.LEASE_RESERVED,
        lease_binding=binding,
    )
    for phase in (
        module.SpawnPhase.PROJECTED,
        module.SpawnPhase.HOME_COMMITTED,
        module.SpawnPhase.REGISTRY_RESERVED,
        module.SpawnPhase.START_GRANTED,
        module.SpawnPhase.RUNNING,
    ):
        ticket = _append(module, ledger, ticket, phase)
    return ticket


def _capsule(ticket, *, capsule: str = "2", generation: int = 2):
    resume = _resume_module()
    return resume.create_resume_capsule(
        capsule_digest=_digest(capsule),
        capsule_generation=resume.CapsuleGeneration(generation),
        bee_digest=_digest("a"),
        session_digest=_digest("b"),
        topic_digest=ticket.topic_digest,
        policy_digest=ticket.policy_digest,
        account_binding_digest=ticket.account_binding_digest,
    )


def test_worker_can_publish_requested_but_cannot_claim_or_start() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger)

    assert ticket.phase is module.SpawnPhase.REQUESTED
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead=_requester(module),
            expected_revision=ticket.ledger_revision,
        )
    assert not hasattr(ledger, "start")


def test_teamleader_claims_exactly_one_authorized_nonleadership_ticket() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger)

    claimed = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(module),
        expected_revision=ticket.ledger_revision,
    )

    assert claimed.phase is module.SpawnPhase.CLAIMED
    assert claimed.claimed_by_principal_id == "teamlead-2"
    assert claimed.ledger_revision.value == ticket.ledger_revision.value + 1
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead=_teamlead(module),
            expected_revision=claimed.ledger_revision,
        )


def test_leadership_target_is_rejected_before_any_lease() -> None:
    module = _ledger_module()
    ledger = _ledger(module)

    with pytest.raises(module.SpawnDenied):
        _publish(module, ledger, target_class_id="teamlead.research")

    assert len(ledger) == 0


def test_ticket_replay_and_revision_drift_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger)

    with pytest.raises(module.SpawnDenied):
        _publish(module, ledger)
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead=_teamlead(module),
            expected_revision=module.LedgerRevision(2),
        )

    claimed = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(module),
        expected_revision=ticket.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, ticket, module.SpawnPhase.OFFER_VALIDATED)
    assert ledger.read(claimed.request_id) == claimed


def test_wrong_teamleader_and_queen_cannot_claim_ticket() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger)
    queen = module.VerifiedPrincipalV2(
        principal_id="queen-1",
        role=module.PrincipalRole.QUEEN,
        authority_digest=_digest("f"),
    )

    for principal in (_teamlead(module, principal_id="teamlead-other"), queen):
        with pytest.raises(module.SpawnDenied):
            ledger.claim(
                ticket.request_id,
                teamlead=principal,
                expected_revision=ticket.ledger_revision,
            )


def test_legal_phase_chain_is_monotone_and_reaches_stopped() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _to_running(module, ledger, _publish(module, ledger))
    ticket = _append(module, ledger, ticket, module.SpawnPhase.DRAINING)
    ticket = ledger.bind_resume_capsule(
        ticket,
        _capsule(ticket),
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=_teamlead(module),
    )
    ticket = _append(module, ledger, ticket, module.SpawnPhase.CHECKPOINTED)
    ticket = _append(module, ledger, ticket, module.SpawnPhase.STOPPED)

    assert ticket.phase is module.SpawnPhase.STOPPED
    assert ticket.ledger_revision == module.LedgerRevision(13)


def test_owner_fence_and_phase_drift_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    requested = _publish(module, ledger)
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )

    attempts = (
        {
            "teamlead": _teamlead(module, principal_id="teamlead-other"),
            "fence": claimed.fence_epoch,
            "ticket": claimed,
        },
        {
            "teamlead": _teamlead(module),
            "fence": module.FenceEpoch(claimed.fence_epoch.value + 1),
            "ticket": claimed,
        },
        {
            "teamlead": _teamlead(module),
            "fence": claimed.fence_epoch,
            "ticket": dataclasses.replace(
                claimed, phase=module.SpawnPhase.OFFER_VALIDATED
            ),
        },
    )
    for attempt in attempts:
        with pytest.raises(module.SpawnDenied):
            ledger.append_phase(
                attempt["ticket"],
                module.SpawnPhase.OFFER_VALIDATED,
                expected_revision=claimed.ledger_revision,
                expected_fence_epoch=attempt["fence"],
                teamlead=attempt["teamlead"],
            )


def test_malformed_digest_and_unknown_phase_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)

    with pytest.raises(module.SpawnDenied):
        _publish(module, ledger, resolution_decision_digest="decision-plain-text")

    class _ForeignPhase(str, Enum):
        OFFER_VALIDATED = "OFFER_VALIDATED"

    requested = _publish(module, ledger, request_id="request-8")
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, claimed, _ForeignPhase.OFFER_VALIDATED)


def test_ticket_is_frozen_slotted_redacted_and_not_serializable() -> None:
    module = _ledger_module()
    ticket = _publish(module, _ledger(module))

    assert dataclasses.is_dataclass(ticket)
    assert hasattr(type(ticket), "__slots__")
    assert repr(ticket) == "<WorkerSpawnTicketV2 redacted>"
    assert str(ticket) == repr(ticket)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ticket.request_id = "request-mutated"
    with pytest.raises(TypeError):
        pickle.dumps(ticket)


def test_ledger_imports_only_bound_allocator_runtime_boundary() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imports = {
        name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in ([node.module] if isinstance(node, ast.ImportFrom) else [])
        + [alias.name for alias in node.names]
        if name is not None
    }
    forbidden = {
        "server",
        "fleet_registry",
        "fleet_home",
        "broker",
        "mcp",
        "provider",
    }

    assert "codex_master.runtime_account_allocator" in imports
    assert not {
        name
        for name in imports
        if any(fragment in name.lower() for fragment in forbidden)
    }


def test_h1_authority_revision_fence_generation_and_phase_are_nominal() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger, fence_epoch=module.FenceEpoch(1))

    class _EqualitySpoof:
        def __eq__(self, _other) -> bool:
            return True

    class _ForeignRole(str, Enum):
        TEAMLEADER = "teamleader"

    with pytest.raises(module.SpawnDenied):
        module.VerifiedPrincipalV2("", module.PrincipalRole.TEAMLEADER, _digest("f"))
    with pytest.raises(module.SpawnDenied):
        module.VerifiedPrincipalV2("teamlead-2", _ForeignRole.TEAMLEADER, _digest("f"))
    with pytest.raises(module.SpawnDenied):
        module.Generation(True)
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead=_EqualitySpoof(),
            expected_revision=ticket.ledger_revision,
        )
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead=_teamlead(module),
            expected_revision=True,
        )

    claimed = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(module),
        expected_revision=ticket.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        ledger.append_phase(
            claimed,
            module.SpawnPhase.OFFER_VALIDATED,
            expected_revision=claimed.ledger_revision,
            expected_fence_epoch=True,
            teamlead=_teamlead(module),
        )


def test_h2_two_ledgers_share_one_backend_and_only_one_claim_wins() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledgers = [_ledger(module, backend) for _ in range(2)]
    ticket = _publish(module, ledgers[0], request_id="request-shared")
    gate = Barrier(3)
    outcomes: list[str] = []

    def claim_once(ledger) -> None:
        gate.wait()
        try:
            ledger.claim(
                ticket.request_id,
                teamlead=_teamlead(module),
                expected_revision=ticket.ledger_revision,
            )
        except module.SpawnDenied:
            outcomes.append("denied")
        else:
            outcomes.append("claimed")

    workers = [Thread(target=claim_once, args=(ledger,)) for ledger in ledgers]
    for worker in workers:
        worker.start()
    gate.wait()
    for worker in workers:
        worker.join()

    assert outcomes.count("claimed") == 1
    assert outcomes.count("denied") == 1


def test_h2_two_ledgers_share_one_backend_and_only_one_transition_wins() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledgers = [_ledger(module, backend) for _ in range(2)]
    requested = _publish(module, ledgers[0], request_id="request-transition")
    claimed = ledgers[0].claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    gate = Barrier(3)
    outcomes: list[str] = []

    def append_once(ledger) -> None:
        gate.wait()
        try:
            _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
        except module.SpawnDenied:
            outcomes.append("denied")
        else:
            outcomes.append("advanced")

    workers = [Thread(target=append_once, args=(ledger,)) for ledger in ledgers]
    for worker in workers:
        worker.start()
    gate.wait()
    for worker in workers:
        worker.join()

    assert outcomes.count("advanced") == 1
    assert outcomes.count("denied") == 1


def test_h4_exact_gather_phase_graph_has_no_old_escape_phases() -> None:
    module = _ledger_module()
    assert set(module.SpawnPhase.__members__) == {
        "REQUESTED",
        "CLAIMED",
        "OFFER_VALIDATED",
        "LEASE_RESERVED",
        "PROJECTED",
        "HOME_COMMITTED",
        "REGISTRY_RESERVED",
        "START_GRANTED",
        "RUNNING",
        "DRAINING",
        "CHECKPOINTED",
        "STOPPED",
        "DENIED",
        "ROLLED_BACK",
        "QUARANTINED",
    }


def test_h4_skip_backward_and_terminal_escape_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    requested = _publish(module, ledger)
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, claimed, module.SpawnPhase.LEASE_RESERVED)

    offered = _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, offered, module.SpawnPhase.CLAIMED)

    ephemeral = _ledger(module)
    stopped = _to_running(
        module,
        ephemeral,
        _publish(
            module,
            ephemeral,
            lifecycle=module.WorkerLifecycle.EPHEMERAL,
            resume_requirement=False,
        ),
    )
    stopped = _append(module, ephemeral, stopped, module.SpawnPhase.DRAINING)
    stopped = _append(module, ephemeral, stopped, module.SpawnPhase.CHECKPOINTED)
    stopped = _append(module, ephemeral, stopped, module.SpawnPhase.STOPPED)
    with pytest.raises(module.SpawnDenied):
        _append(module, ephemeral, stopped, module.SpawnPhase.QUARANTINED)


def test_h4_persistent_terminal_paths_require_bound_capsule() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _to_running(module, ledger, _publish(module, ledger))
    ticket = _append(module, ledger, ticket, module.SpawnPhase.DRAINING)

    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, ticket, module.SpawnPhase.CHECKPOINTED)

    capsule = _capsule(ticket)
    bound = ledger.bind_resume_capsule(
        ticket,
        capsule,
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=_teamlead(module),
    )
    checkpointed = _append(module, ledger, bound, module.SpawnPhase.CHECKPOINTED)
    stopped = _append(module, ledger, checkpointed, module.SpawnPhase.STOPPED)
    assert stopped.phase is module.SpawnPhase.STOPPED


def test_h4_binding_and_resumable_rollback_require_bound_capsule() -> None:
    module = _ledger_module()
    for lifecycle, resumable in (
        (module.WorkerLifecycle.BINDING, False),
        (module.WorkerLifecycle.INVOCATION, True),
    ):
        ledger = _ledger(module)
        ticket = _publish(
            module,
            ledger,
            lifecycle=lifecycle,
            resume_requirement=resumable,
        )
        ticket = ledger.claim(
            ticket.request_id,
            teamlead=_teamlead(module),
            expected_revision=ticket.ledger_revision,
        )
        ticket = _append(module, ledger, ticket, module.SpawnPhase.OFFER_VALIDATED)
        binding = _lease_binding(module, ledger, ticket)
        with pytest.raises(TypeError, match="internals are not serializable"):
            copy.copy(binding)
        with pytest.raises(TypeError, match="internals are not serializable"):
            copy.deepcopy(binding)
        ticket = _append(
            module,
            ledger,
            ticket,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=binding,
        )
        with pytest.raises(module.SpawnDenied):
            _append(module, ledger, ticket, module.SpawnPhase.ROLLED_BACK)
        ticket = ledger.bind_resume_capsule(
            ticket,
            _capsule(ticket),
            expected_revision=ticket.ledger_revision,
            expected_fence_epoch=ticket.fence_epoch,
            teamlead=_teamlead(module),
        )
        assert (
            _append(module, ledger, ticket, module.SpawnPhase.ROLLED_BACK).phase
            is module.SpawnPhase.ROLLED_BACK
        )


def test_ephemeral_and_invocation_terminal_paths_need_no_capsule() -> None:
    module = _ledger_module()
    for lifecycle in (
        module.WorkerLifecycle.EPHEMERAL,
        module.WorkerLifecycle.INVOCATION,
    ):
        ledger = _ledger(module)
        ticket = _to_running(
            module,
            ledger,
            _publish(
                module,
                ledger,
                lifecycle=lifecycle,
                resume_requirement=False,
            ),
        )
        ticket = _append(module, ledger, ticket, module.SpawnPhase.DRAINING)
        ticket = _append(module, ledger, ticket, module.SpawnPhase.CHECKPOINTED)
        ticket = _append(module, ledger, ticket, module.SpawnPhase.STOPPED)
        assert ticket.phase is module.SpawnPhase.STOPPED


def test_bound_ledger_rejects_fake_allocator_before_any_operation() -> None:
    module = _ledger_module()

    with pytest.raises(module.SpawnDenied, match="runtime account allocator"):
        module.WorkerSpawnLedger(
            state_port=_backend(module),
            delegable_nonleadership_class_ids=frozenset({"worker.research"}),
            allocator=object(),
        )


@pytest.mark.parametrize(
    "drift", ("ticket", "lease", "account", "profile", "policy", "fence", "revision")
)
def test_lease_binding_cross_dimension_drift_denies_before_ledger_cas(
    drift: str,
) -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    ticket = ledger.claim(
        _publish(module, ledger).request_id,
        teamlead=_teamlead(module),
        expected_revision=module.LedgerRevision(1),
    )
    offered = _append(module, ledger, ticket, module.SpawnPhase.OFFER_VALIDATED)
    binding = _lease_binding(module, ledger, offered)
    cas_before = backend.cas_calls

    if drift == "ticket":
        allocation_ticket = dataclasses.replace(
            binding.allocation_ticket, ticket_id="ticket:foreign"
        )
        binding = dataclasses.replace(binding, allocation_ticket=allocation_ticket)
    elif drift == "lease":
        binding = dataclasses.replace(
            binding,
            lease=dataclasses.replace(binding.lease),
        )
    elif drift == "account":
        binding = dataclasses.replace(
            binding,
            lease=dataclasses.replace(
                binding.lease,
                account_binding_digest=_digest("0"),
            ),
        )
    elif drift == "profile":
        binding = dataclasses.replace(
            binding,
            lease=dataclasses.replace(
                binding.lease,
                profile_binding_digest=_digest("0"),
            ),
        )
    elif drift == "policy":
        allocation_ticket = dataclasses.replace(
            binding.allocation_ticket, policy_digest=_digest("0")
        )
        binding = dataclasses.replace(binding, allocation_ticket=allocation_ticket)
    elif drift == "fence":
        allocation_ticket = dataclasses.replace(
            binding.allocation_ticket, fence_epoch=7
        )
        binding = dataclasses.replace(binding, allocation_ticket=allocation_ticket)
    else:
        evidence = dataclasses.replace(
            binding.capacity_evidence,
            evidence_revision=binding.capacity_evidence.evidence_revision + 1,
        )
        binding = dataclasses.replace(binding, capacity_evidence=evidence)

    with pytest.raises(module.SpawnDenied, match="lease binding verification denied"):
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=binding,
        )
    assert backend.cas_calls == cas_before
    assert ledger.read(offered.request_id) == offered
    assert ledger._allocator._active_lease_binding_verifications == {}


@pytest.mark.parametrize(
    "dimension",
    ("ticket", "lease", "account", "profile", "policy", "fence", "revision"),
)
def test_allocator_issued_ab_cross_binding_matrix_denies_before_ledger_cas(
    dimension: str,
) -> None:
    module = _ledger_module()
    backend = _backend(module)
    provisional = _ledger(module, backend)
    requested = _publish(module, provisional, request_id=f"matrix-{dimension}")
    claimed = provisional.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    offered = _append(module, provisional, claimed, module.SpawnPhase.OFFER_VALIDATED)
    allocator, (binding_a, binding_b) = _allocator_issued_binding_pair(
        module, offered, dimension
    )
    ledger = module.WorkerSpawnLedger(
        state_port=backend,
        delegable_nonleadership_class_ids=frozenset({"worker.research"}),
        allocator=allocator,
    )
    if dimension == "ticket":
        attack = module.LeaseBindingConsumerInputV1(
            receipt=binding_a.receipt,
            lease=binding_a.lease,
            allocation_ticket=binding_b.allocation_ticket,
            capacity_evidence=binding_a.capacity_evidence,
        )
    elif dimension in {"lease", "account", "profile"}:
        attack = module.LeaseBindingConsumerInputV1(
            receipt=binding_a.receipt,
            lease=binding_b.lease,
            allocation_ticket=binding_a.allocation_ticket,
            capacity_evidence=binding_a.capacity_evidence,
        )
    elif dimension in {"policy", "fence"}:
        attack = module.LeaseBindingConsumerInputV1(
            receipt=binding_a.receipt,
            lease=binding_a.lease,
            allocation_ticket=binding_b.allocation_ticket,
            capacity_evidence=binding_b.capacity_evidence,
        )
    else:
        attack = module.LeaseBindingConsumerInputV1(
            receipt=binding_a.receipt,
            lease=binding_a.lease,
            allocation_ticket=binding_a.allocation_ticket,
            capacity_evidence=binding_b.capacity_evidence,
        )
    cas_before = backend.cas_calls

    with pytest.raises(module.SpawnDenied, match="lease binding verification denied"):
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=attack,
        )
    assert backend.cas_calls == cas_before
    assert ledger.read(offered.request_id) == offered
    assert allocator._active_lease_binding_verifications == {}


def test_opaque_receipt_forge_and_foreign_allocator_deny_before_ledger_cas() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    requested = _publish(module, ledger)
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    offered = _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
    binding = _lease_binding(module, ledger, offered)
    runtime = importlib.import_module("codex_master.runtime_account_allocator")
    forged_receipt = object.__new__(runtime.LeaseBindingReceiptV1)
    object.__setattr__(
        forged_receipt,
        "_lease_binding_digest",
        runtime._OpaqueText(str(binding.receipt._lease_binding_digest)),
    )
    forged = dataclasses.replace(binding, receipt=forged_receipt)
    cas_before = backend.cas_calls

    with pytest.raises(module.SpawnDenied, match="lease binding verification denied"):
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=forged,
        )
    assert backend.cas_calls == cas_before

    foreign = _ledger(module)
    foreign_binding = _lease_binding(module, foreign, offered)
    with pytest.raises(module.SpawnDenied, match="lease binding verification denied"):
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=foreign_binding,
        )
    assert backend.cas_calls == cas_before
    assert ledger._allocator._active_lease_binding_verifications == {}


def test_ledger_guard_covers_cas_and_preserves_primary_error_on_close_drift() -> None:
    module = _ledger_module()
    observed: list[bool] = []
    armed = False

    def fail_after_drifting_lease() -> None:
        if not armed:
            return
        observed.append(bool(ledger._allocator._active_lease_binding_verifications))
        object.__setattr__(binding.lease, "profile_binding_digest", _digest("0"))
        raise RuntimeError("primary-cas-error")

    backend = _backend(module, before_cas=fail_after_drifting_lease)
    ledger = _ledger(module, backend)
    requested = _publish(module, ledger, request_id="request-primary")
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    offered = _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
    binding = _lease_binding(module, ledger, offered)
    cas_before = backend.cas_calls
    armed = True

    with pytest.raises(module.SpawnDenied, match="ledger CAS failed") as caught:
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=binding,
        )
    assert caught.value.__notes__ == [
        "lease binding guard close denied; quarantine required"
    ]
    assert observed[-1] is True
    assert backend.cas_calls == cas_before + 1
    assert ledger._allocator._active_lease_binding_verifications == {}


def test_ledger_close_deny_without_primary_is_hard_and_does_not_retry() -> None:
    module = _ledger_module()
    holder: list[object] = []

    def drift_after_cas() -> None:
        if not holder:
            return
        binding = holder[0]
        object.__setattr__(binding.lease, "profile_binding_digest", _digest("0"))

    backend = _backend(module, before_cas=drift_after_cas)
    ledger = _ledger(module, backend)
    requested = _publish(module, ledger, request_id="request-close")
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    offered = _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
    binding = _lease_binding(module, ledger, offered)
    holder.append(binding)
    cas_before = backend.cas_calls

    with pytest.raises(module.SpawnDenied, match="lease binding verification denied"):
        _append(
            module,
            ledger,
            offered,
            module.SpawnPhase.LEASE_RESERVED,
            lease_binding=binding,
        )
    assert backend.cas_calls == cas_before + 1
    assert ledger._allocator._active_lease_binding_verifications == {}


def _record_failure(module, ledger, ticket, **overrides):
    payload = {
        "primary_failure_code": module.WorkerFailureCodeV1.PRE_A3_FAILURE,
        "primary_failure_origin": module.WorkerFailureOriginV1.PRE_A3,
        "compensation_status": module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
        "expected_revision": ticket.ledger_revision,
        "expected_fence_epoch": ticket.fence_epoch,
        "teamlead": _teamlead(module),
    }
    payload.update(overrides)
    return ledger.record_failure(ticket, **payload)


def _lease_reserved_ticket(module, ledger, *, request_id: str):
    requested = _publish(module, ledger, request_id=request_id)
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    offered = _append(module, ledger, claimed, module.SpawnPhase.OFFER_VALIDATED)
    return _append(
        module,
        ledger,
        offered,
        module.SpawnPhase.LEASE_RESERVED,
        lease_binding=_lease_binding(module, ledger, offered),
    )


def test_p2_failure_enums_and_journals_require_exact_nominal_values() -> None:
    module = _ledger_module()

    assert {member.value for member in module.WorkerFailureCodeV1} == {
        "PRE_A3_FAILURE",
        "A3_EXECUTION_FAILED_OR_UNKNOWN",
        "START_STATE_UNKNOWN",
    }
    assert {member.value for member in module.WorkerFailureOriginV1} == {
        "PRE_A3",
        "A3_ENTERED",
        "RECOVERY_UNKNOWN",
    }
    assert {member.value for member in module.CompensationStatusV1} == {
        "NONE",
        "REGISTRY_RELEASE_PENDING",
        "REGISTRY_RELEASED",
        "HOME_RELEASE_FAILED",
        "LEASE_RELEASE_FAILED",
        "COMPENSATED",
        "QUARANTINED",
    }
    with pytest.raises(ValueError):
        module.WorkerFailureCodeV1("PRE_A3_FAILURE ")
    with pytest.raises(ValueError):
        module.WorkerFailureOriginV1("PRE_A3 ")
    with pytest.raises(ValueError):
        module.CompensationStatusV1("QUARANTINED ")

    class _ForeignCode(str, Enum):
        PRE_A3_FAILURE = "PRE_A3_FAILURE"

    with pytest.raises(module.SpawnDenied):
        module.WorkerFailureJournalV1(
            primary_failure_code=_ForeignCode.PRE_A3_FAILURE,
            primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
            compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            ticket_id="ticket:7",
            ledger_revision=module.LedgerRevision(1),
            fence_epoch=module.FenceEpoch(6),
        )
    with pytest.raises(module.SpawnDenied):
        module.WorkerFailureJournalV1(
            primary_failure_code="PRE_A3_FAILURE",
            primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
            compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            ticket_id="ticket:7",
            ledger_revision=module.LedgerRevision(1),
            fence_epoch=module.FenceEpoch(6),
        )
    with pytest.raises(module.SpawnDenied):
        module.WorkerRegistryIntentV1(
            ticket_id="ticket:7",
            ledger_revision=module.LedgerRevision(1),
            fence_epoch=True,
        )
    with pytest.raises(TypeError):
        module.WorkerFailureJournalV1(
            primary_failure_code=module.WorkerFailureCodeV1.PRE_A3_FAILURE,
            primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
            compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            ticket_id="ticket:7",
            ledger_revision=module.LedgerRevision(1),
        )

    state = module.SpawnLedgerStateV2.empty()
    intent = module.WorkerRegistryIntentV1(
        ticket_id="ticket:7",
        ledger_revision=module.LedgerRevision(1),
        fence_epoch=module.FenceEpoch(6),
    )
    journal = module.WorkerFailureJournalV1(
        primary_failure_code=module.WorkerFailureCodeV1.PRE_A3_FAILURE,
        primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
        compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
        ticket_id="ticket:7",
        ledger_revision=module.LedgerRevision(1),
        fence_epoch=module.FenceEpoch(6),
    )
    with pytest.raises(module.SpawnDenied):
        dataclasses.replace(state, registry_intents=(intent, intent))
    with pytest.raises(module.SpawnDenied):
        dataclasses.replace(state, failure_journals=(journal, journal))
    with pytest.raises(module.SpawnDenied):
        dataclasses.replace(state, registry_intents=(journal,))
    with pytest.raises(module.SpawnDenied):
        dataclasses.replace(state, failure_journals=(intent,))


def test_p2_journal_values_are_frozen_slotted_redacted_and_not_serializable() -> None:
    module = _ledger_module()
    intent = module.WorkerRegistryIntentV1(
        ticket_id="ticket:7",
        ledger_revision=module.LedgerRevision(1),
        fence_epoch=module.FenceEpoch(6),
    )
    journal = module.WorkerFailureJournalV1(
        primary_failure_code=module.WorkerFailureCodeV1.PRE_A3_FAILURE,
        primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
        compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
        ticket_id="ticket:7",
        ledger_revision=module.LedgerRevision(1),
        fence_epoch=module.FenceEpoch(6),
    )

    for value, name in (
        (intent, "WorkerRegistryIntentV1"),
        (journal, "WorkerFailureJournalV1"),
    ):
        assert dataclasses.is_dataclass(value)
        assert hasattr(type(value), "__slots__")
        assert repr(value) == f"<{name} redacted>"
        assert str(value) == repr(value)
        with pytest.raises(dataclasses.FrozenInstanceError):
            value.ticket_id = "secret:/home/credential"  # type: ignore[misc]
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(value)

    class _SecretTicketId:
        def __repr__(self) -> str:
            return "secret:/home/credential Exception('token')"

    with pytest.raises(module.SpawnDenied) as error:
        module.WorkerFailureJournalV1(
            primary_failure_code=module.WorkerFailureCodeV1.PRE_A3_FAILURE,
            primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
            compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            ticket_id=_SecretTicketId(),
            ledger_revision=module.LedgerRevision(1),
            fence_epoch=module.FenceEpoch(6),
        )
    assert "secret:/home/credential" not in str(error.value)
    assert "Exception('token')" not in str(error.value)


def test_p2_registry_intent_is_owner_bound_single_cas_and_phase_stable() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    requested = _publish(module, ledger, request_id="intent")
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )
    cas_before = backend.cas_calls

    recorded = ledger.record_registry_intent(
        claimed,
        expected_revision=claimed.ledger_revision,
        expected_fence_epoch=claimed.fence_epoch,
        teamlead=_teamlead(module),
    )

    assert recorded.phase is claimed.phase
    assert recorded.ledger_revision == module.LedgerRevision(
        claimed.ledger_revision.value + 1
    )
    assert backend.cas_calls == cas_before + 1
    state = backend.read()
    assert len(state.registry_intents) == 1
    assert state.registry_intents[0].ticket_id == recorded.ticket_id
    assert state.registry_intents[0].ledger_revision == recorded.ledger_revision
    assert state.registry_intents[0].fence_epoch == recorded.fence_epoch

    for kwargs in (
        {
            "teamlead": _teamlead(module, principal_id="teamlead-other"),
            "expected_revision": recorded.ledger_revision,
            "expected_fence_epoch": recorded.fence_epoch,
        },
        {
            "teamlead": _teamlead(module),
            "expected_revision": recorded.ledger_revision,
            "expected_fence_epoch": module.FenceEpoch(recorded.fence_epoch.value + 1),
        },
        {
            "teamlead": _teamlead(module),
            "expected_revision": module.LedgerRevision(
                recorded.ledger_revision.value - 1
            ),
            "expected_fence_epoch": recorded.fence_epoch,
        },
    ):
        with pytest.raises(module.SpawnDenied):
            ledger.record_registry_intent(recorded, **kwargs)
    cas_after_first = backend.cas_calls
    with pytest.raises(module.SpawnDenied, match="intent replay"):
        ledger.record_registry_intent(
            recorded,
            expected_revision=recorded.ledger_revision,
            expected_fence_epoch=recorded.fence_epoch,
            teamlead=_teamlead(module),
        )
    assert backend.cas_calls == cas_after_first


def test_p2_failure_record_binds_current_ticket_and_never_retries_cas() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    requested = _publish(module, ledger, request_id="failure")
    claimed = ledger.claim(
        requested.request_id,
        teamlead=_teamlead(module),
        expected_revision=requested.ledger_revision,
    )

    for kwargs in (
        {
            "teamlead": _teamlead(module, principal_id="teamlead-other"),
            "expected_revision": claimed.ledger_revision,
            "expected_fence_epoch": claimed.fence_epoch,
        },
        {
            "teamlead": _teamlead(module),
            "expected_revision": claimed.ledger_revision,
            "expected_fence_epoch": module.FenceEpoch(claimed.fence_epoch.value + 1),
        },
        {
            "teamlead": _teamlead(module),
            "expected_revision": module.LedgerRevision(
                claimed.ledger_revision.value + 1
            ),
            "expected_fence_epoch": claimed.fence_epoch,
        },
    ):
        with pytest.raises(module.SpawnDenied):
            _record_failure(module, ledger, claimed, **kwargs)
    assert backend.cas_calls == 2

    recorded = _record_failure(module, ledger, claimed)
    assert recorded.phase is claimed.phase
    assert recorded.ledger_revision == module.LedgerRevision(
        claimed.ledger_revision.value + 1
    )
    assert backend.cas_calls == 3
    state = backend.read()
    assert len(state.failure_journals) == 1
    assert state.failure_journals[0].ticket_id == recorded.ticket_id
    assert state.failure_journals[0].ledger_revision == recorded.ledger_revision

    with pytest.raises(module.SpawnDenied, match="failure journal replay"):
        _record_failure(module, ledger, recorded)
    assert backend.cas_calls == 3
    assert ledger.read(recorded.request_id) == recorded

    foreign_ledger = _ledger(module)
    foreign = _publish(module, foreign_ledger, request_id="foreign")
    with pytest.raises(module.SpawnDenied):
        _record_failure(module, ledger, foreign)
    assert backend.cas_calls == 3

    armed = [False]
    holder = []

    def conflict_before_cas() -> None:
        if not armed[0]:
            return
        current = holder[0]._state
        holder[0]._state = dataclasses.replace(
            current,
            state_revision=module.LedgerRevision(current.state_revision.value + 1),
        )

    conflict_backend = _backend(module, before_cas=conflict_before_cas)
    holder.append(conflict_backend)
    conflict_ledger = _ledger(module, conflict_backend)
    conflict_ticket = _publish(module, conflict_ledger, request_id="cas-conflict")
    armed[0] = True
    cas_before = conflict_backend.cas_calls
    with pytest.raises(module.SpawnDenied, match="ledger CAS conflict"):
        _record_failure(module, conflict_ledger, conflict_ticket)
    assert conflict_backend.cas_calls == cas_before + 1
    assert conflict_backend.read().failure_journals == ()


def test_p2_failure_primary_fields_are_immutable_and_status_is_monotone() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    ticket = _publish(module, ledger, request_id="status")
    failed = _record_failure(module, ledger, ticket)
    initial = backend.read().failure_journals[0]

    released = ledger.advance_compensation_status(
        failed,
        compensation_status=module.CompensationStatusV1.REGISTRY_RELEASED,
        expected_revision=failed.ledger_revision,
        expected_fence_epoch=failed.fence_epoch,
        teamlead=_teamlead(module),
    )
    compensated = ledger.advance_compensation_status(
        released,
        compensation_status=module.CompensationStatusV1.COMPENSATED,
        expected_revision=released.ledger_revision,
        expected_fence_epoch=released.fence_epoch,
        teamlead=_teamlead(module),
    )
    final = backend.read().failure_journals[0]
    assert final.primary_failure_code is initial.primary_failure_code
    assert final.primary_failure_origin is initial.primary_failure_origin
    assert final.compensation_status is module.CompensationStatusV1.COMPENSATED
    assert final.ticket_id == compensated.ticket_id
    assert final.ledger_revision == compensated.ledger_revision
    assert final.fence_epoch == compensated.fence_epoch
    assert compensated.phase is ticket.phase

    with pytest.raises(module.SpawnDenied, match="illegal compensation transition"):
        ledger.advance_compensation_status(
            compensated,
            compensation_status=module.CompensationStatusV1.QUARANTINED,
            expected_revision=compensated.ledger_revision,
            expected_fence_epoch=compensated.fence_epoch,
            teamlead=_teamlead(module),
        )
    bad_ledger = _ledger(module)
    bad_ticket = _publish(module, bad_ledger, request_id="bad-code")
    with pytest.raises(module.SpawnDenied):
        _record_failure(
            module,
            bad_ledger,
            bad_ticket,
            primary_failure_code=module.WorkerFailureCodeV1.A3_EXECUTION_FAILED_OR_UNKNOWN,
            primary_failure_origin=module.WorkerFailureOriginV1.PRE_A3,
        )


@pytest.mark.parametrize(
    "statuses",
    (
        ("QUARANTINED",),
        ("REGISTRY_RELEASED", "COMPENSATED"),
        ("REGISTRY_RELEASED", "HOME_RELEASE_FAILED", "QUARANTINED"),
        ("REGISTRY_RELEASED", "LEASE_RELEASE_FAILED", "QUARANTINED"),
    ),
)
def test_p2_compensation_matrix_accepts_only_forward_paths(statuses) -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(module, ledger, request_id="matrix-" + "-".join(statuses))
    current = _record_failure(module, ledger, ticket)

    for status in statuses:
        current = ledger.advance_compensation_status(
            current,
            compensation_status=module.CompensationStatusV1(status),
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=_teamlead(module),
        )

    with pytest.raises(module.SpawnDenied, match="illegal compensation transition"):
        ledger.advance_compensation_status(
            current,
            compensation_status=module.CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=_teamlead(module),
        )

    fresh_ledger = _ledger(module)
    fresh = _publish(module, fresh_ledger, request_id="invalid-initial-" + statuses[0])
    with pytest.raises(module.SpawnDenied):
        _record_failure(
            module,
            fresh_ledger,
            fresh,
            compensation_status=module.CompensationStatusV1.NONE,
        )


def test_p2_rollback_requires_compensated_pre_a3_journal() -> None:
    module = _ledger_module()
    backend = _backend(module)
    ledger = _ledger(module, backend)
    reserved = _lease_reserved_ticket(module, ledger, request_id="rollback-journal")
    failed = _record_failure(module, ledger, reserved)
    bound = ledger.bind_resume_capsule(
        failed,
        _capsule(failed),
        expected_revision=failed.ledger_revision,
        expected_fence_epoch=failed.fence_epoch,
        teamlead=_teamlead(module),
    )

    with pytest.raises(module.SpawnDenied):
        _append(module, ledger, bound, module.SpawnPhase.ROLLED_BACK)

    released = ledger.advance_compensation_status(
        bound,
        compensation_status=module.CompensationStatusV1.REGISTRY_RELEASED,
        expected_revision=bound.ledger_revision,
        expected_fence_epoch=bound.fence_epoch,
        teamlead=_teamlead(module),
    )
    compensated = ledger.advance_compensation_status(
        released,
        compensation_status=module.CompensationStatusV1.COMPENSATED,
        expected_revision=released.ledger_revision,
        expected_fence_epoch=released.fence_epoch,
        teamlead=_teamlead(module),
    )
    rolled_back = _append(module, ledger, compensated, module.SpawnPhase.ROLLED_BACK)
    assert rolled_back.phase is module.SpawnPhase.ROLLED_BACK
    assert backend.read().failure_journals[0].primary_failure_origin is (
        module.WorkerFailureOriginV1.PRE_A3
    )


def test_p2_a3_and_recovery_unknown_failures_quarantine_without_rollback() -> None:
    module = _ledger_module()
    cases = (
        (
            module.WorkerFailureCodeV1.A3_EXECUTION_FAILED_OR_UNKNOWN,
            module.WorkerFailureOriginV1.A3_ENTERED,
        ),
        (
            module.WorkerFailureCodeV1.START_STATE_UNKNOWN,
            module.WorkerFailureOriginV1.RECOVERY_UNKNOWN,
        ),
    )
    for index, (code, origin) in enumerate(cases):
        backend = _backend(module)
        ledger = _ledger(module, backend)
        reserved = _lease_reserved_ticket(
            module, ledger, request_id=f"quarantine-{index}"
        )
        failed = _record_failure(
            module,
            ledger,
            reserved,
            primary_failure_code=code,
            primary_failure_origin=origin,
            compensation_status=module.CompensationStatusV1.QUARANTINED,
        )
        with pytest.raises(module.SpawnDenied):
            _append(module, ledger, failed, module.SpawnPhase.ROLLED_BACK)
        quarantined = _append(module, ledger, failed, module.SpawnPhase.QUARANTINED)
        assert quarantined.phase is module.SpawnPhase.QUARANTINED
        assert backend.read().failure_journals[0].compensation_status is (
            module.CompensationStatusV1.QUARANTINED
        )
        assert ledger._allocator._active_lease_binding_verifications == {}


def test_p2_journal_state_keeps_h4_phase_graph_and_internal_exports() -> None:
    module = _ledger_module()
    assert set(module.SpawnPhase.__members__) == {
        "REQUESTED",
        "CLAIMED",
        "OFFER_VALIDATED",
        "LEASE_RESERVED",
        "PROJECTED",
        "HOME_COMMITTED",
        "REGISTRY_RESERVED",
        "START_GRANTED",
        "RUNNING",
        "DRAINING",
        "CHECKPOINTED",
        "STOPPED",
        "DENIED",
        "ROLLED_BACK",
        "QUARANTINED",
    }
    assert "WorkerRegistryIntentV1" not in module.__all__
    assert "WorkerFailureJournalV1" not in module.__all__
