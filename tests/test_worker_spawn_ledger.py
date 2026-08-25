import ast
import dataclasses
from enum import Enum
import importlib
import pickle
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/worker_spawn_ledger.py"
)


def _ledger_module():
    return importlib.import_module("codex_master.worker_spawn_ledger")


def _resume_module():
    return importlib.import_module("codex_master.worker_resume")


def _digest(value: str) -> str:
    return "sha256:" + (value * 64)


def _backend(module):
    class _SharedFakeBackend(module.SpawnLedgerStatePort):
        def __init__(self) -> None:
            self._lock = Lock()
            self._state = module.SpawnLedgerStateV2.empty()

        def read(self):
            with self._lock:
                return self._state

        def compare_and_swap(self, expected_revision, replacement) -> bool:
            with self._lock:
                if self._state.state_revision != expected_revision:
                    return False
                self._state = replacement
                return True

    return _SharedFakeBackend()


def _ledger(module, backend=None):
    return module.WorkerSpawnLedger(
        state_port=backend or _backend(module),
        delegable_nonleadership_class_ids=frozenset({"worker.research"}),
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
    payload = {
        "request_id": "request-7",
        "requester": _requester(module),
        "work_package_id": "work-package-8",
        "topic_digest": _digest("a"),
        "target_class_id": "worker.research",
        "authorized_teamlead": _teamlead(module),
        "resolution_decision_digest": _digest("c"),
        "resolution_generation": module.Generation(4),
        "policy_digest": _digest("d"),
        "policy_generation": module.Generation(9),
        "lifecycle": module.WorkerLifecycle.PERSISTENT,
        "resume_requirement": True,
        "fence_epoch": module.FenceEpoch(6),
    }
    payload.update(overrides)
    return ledger.publish_requested(**payload)


def _append(module, ledger, ticket, phase, *, lease_evidence=None, teamlead=None):
    return ledger.append_phase(
        ticket,
        phase,
        expected_revision=ticket.ledger_revision,
        expected_fence_epoch=ticket.fence_epoch,
        teamlead=teamlead or _teamlead(module),
        lease_evidence=lease_evidence,
    )


def _lease_evidence(module, *, lease: str = "1", account: str = "e"):
    return module.LeaseReservationEvidenceV2(
        lease_binding_digest=_digest(lease),
        account_binding_digest=_digest(account),
    )


def _to_running(module, ledger, ticket):
    ticket = ledger.claim(
        ticket.request_id,
        teamlead=_teamlead(module),
        expected_revision=ticket.ledger_revision,
    )
    ticket = _append(module, ledger, ticket, module.SpawnPhase.OFFER_VALIDATED)
    ticket = _append(
        module,
        ledger,
        ticket,
        module.SpawnPhase.LEASE_RESERVED,
        lease_evidence=_lease_evidence(module),
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


def test_ledger_is_local_and_has_no_runtime_boundary_imports() -> None:
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
        "runtime_account_allocator",
        "fleet_registry",
        "fleet_home",
        "broker",
        "mcp",
        "provider",
    }

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
        ticket = _append(
            module,
            ledger,
            ticket,
            module.SpawnPhase.LEASE_RESERVED,
            lease_evidence=_lease_evidence(module),
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
