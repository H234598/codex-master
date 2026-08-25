import ast
import dataclasses
import importlib.util
import pickle
import sys
from threading import Barrier, Thread
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "src/codex_master/worker_spawn_ledger.py"
)


def _ledger_module():
    assert MODULE_PATH.is_file(), "worker_spawn_ledger module is missing"
    spec = importlib.util.spec_from_file_location(
        "worker_spawn_ledger_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _digest(value: str) -> str:
    return "sha256:" + (value * 64)


def _ledger(module):
    return module.WorkerSpawnLedger(
        delegable_nonleadership_class_ids=frozenset({"worker.research"})
    )


def _publish(ledger, **overrides):
    payload = {
        "request_id": "request-7",
        "requester_principal_id": "worker-11",
        "requester_role": "worker",
        "work_package_id": "work-package-8",
        "topic_digest": _digest("a"),
        "target_class_id": "worker.research",
        "authorized_teamlead_id": "teamlead-2",
        "authority_digest": _digest("b"),
        "resolution_decision_digest": _digest("c"),
        "resolution_generation": 4,
        "policy_generation": 9,
        "lifecycle": "persistent",
        "resume_requirement": True,
        "fence_epoch": 6,
    }
    payload.update(overrides)
    return ledger.publish_requested(**payload)


def test_worker_can_publish_requested_but_cannot_claim_or_start() -> None:
    module = _ledger_module()
    ledger = _ledger(module)

    ticket = _publish(ledger)

    assert ticket.phase is module.SpawnPhase.REQUESTED
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead_principal_id="worker-11",
            expected_revision=ticket.ledger_revision,
        )
    assert not hasattr(ledger, "start")


def test_teamleader_claims_exactly_one_authorized_nonleadership_ticket() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(ledger)

    claimed = ledger.claim(
        ticket.request_id,
        teamlead_principal_id="teamlead-2",
        expected_revision=ticket.ledger_revision,
    )

    assert claimed.phase is module.SpawnPhase.CLAIMED
    assert claimed.claimed_by_principal_id == "teamlead-2"
    assert claimed.ledger_revision == ticket.ledger_revision + 1
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead_principal_id="teamlead-2",
            expected_revision=claimed.ledger_revision,
        )


def test_leadership_target_is_rejected_before_any_lease() -> None:
    module = _ledger_module()
    ledger = _ledger(module)

    with pytest.raises(module.SpawnDenied):
        _publish(ledger, target_class_id="teamlead.research")

    assert len(ledger) == 0


def test_ticket_replay_and_revision_drift_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(ledger)

    with pytest.raises(module.SpawnDenied):
        _publish(ledger)
    with pytest.raises(module.SpawnDenied):
        ledger.claim(
            ticket.request_id,
            teamlead_principal_id="teamlead-2",
            expected_revision=ticket.ledger_revision + 1,
        )

    claimed = ledger.claim(
        ticket.request_id,
        teamlead_principal_id="teamlead-2",
        expected_revision=ticket.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        ledger.append_phase(
            ticket,
            module.SpawnPhase.OFFER_VALIDATED,
            expected_revision=ticket.ledger_revision,
            expected_fence_epoch=ticket.fence_epoch,
            teamlead_principal_id="teamlead-2",
        )
    assert claimed.phase is module.SpawnPhase.CLAIMED


def test_racing_claims_are_serialized_to_one_authorized_teamleader() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(ledger, request_id="request-race")
    gate = Barrier(9)
    outcomes: list[str] = []

    def claim_once() -> None:
        gate.wait()
        try:
            ledger.claim(
                ticket.request_id,
                teamlead_principal_id="teamlead-2",
                expected_revision=ticket.ledger_revision,
            )
        except module.SpawnDenied:
            outcomes.append("denied")
        else:
            outcomes.append("claimed")

    workers = [Thread(target=claim_once) for _ in range(8)]
    for worker in workers:
        worker.start()
    gate.wait()
    for worker in workers:
        worker.join()

    assert type(ledger._claim_lock).__name__ == "RLock"
    assert outcomes.count("claimed") == 1
    assert outcomes.count("denied") == 7


def test_wrong_teamleader_and_queen_cannot_claim_ticket() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = _publish(ledger)

    for principal_id in ("teamlead-other", "queen-1"):
        with pytest.raises(module.SpawnDenied):
            ledger.claim(
                ticket.request_id,
                teamlead_principal_id=principal_id,
                expected_revision=ticket.ledger_revision,
            )


def test_legal_phase_chain_is_monotone_and_reaches_running() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    ticket = ledger.claim(
        _publish(ledger).request_id,
        teamlead_principal_id="teamlead-2",
        expected_revision=1,
    )
    phases = (
        module.SpawnPhase.OFFER_VALIDATED,
        module.SpawnPhase.LEASE_RESERVED,
        module.SpawnPhase.HOME_ATTESTED,
        module.SpawnPhase.REGISTRY_COMMITTED,
        module.SpawnPhase.START_GRANTED,
        module.SpawnPhase.RUNNING,
        module.SpawnPhase.RELEASE_PENDING,
    )

    for phase in phases:
        ticket = ledger.append_phase(
            ticket,
            phase,
            expected_revision=ticket.ledger_revision,
            expected_fence_epoch=ticket.fence_epoch,
            teamlead_principal_id="teamlead-2",
        )

    assert ticket.phase is module.SpawnPhase.RELEASE_PENDING
    assert ticket.ledger_revision == len(phases) + 2


def test_owner_fence_and_phase_drift_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)
    requested = _publish(ledger)
    claimed = ledger.claim(
        requested.request_id,
        teamlead_principal_id="teamlead-2",
        expected_revision=requested.ledger_revision,
    )

    calls = (
        {
            "teamlead_principal_id": "teamlead-other",
            "expected_fence_epoch": claimed.fence_epoch,
            "ticket": claimed,
        },
        {
            "teamlead_principal_id": "teamlead-2",
            "expected_fence_epoch": claimed.fence_epoch + 1,
            "ticket": claimed,
        },
        {
            "teamlead_principal_id": "teamlead-2",
            "expected_fence_epoch": claimed.fence_epoch,
            "ticket": dataclasses.replace(
                claimed, phase=module.SpawnPhase.OFFER_VALIDATED
            ),
        },
    )
    for call in calls:
        with pytest.raises(module.SpawnDenied):
            ledger.append_phase(
                call["ticket"],
                module.SpawnPhase.OFFER_VALIDATED,
                expected_revision=claimed.ledger_revision,
                expected_fence_epoch=call["expected_fence_epoch"],
                teamlead_principal_id=call["teamlead_principal_id"],
            )


def test_malformed_digest_and_unknown_phase_fail_closed() -> None:
    module = _ledger_module()
    ledger = _ledger(module)

    with pytest.raises(module.SpawnDenied):
        _publish(ledger, resolution_decision_digest="decision-plain-text")

    requested = _publish(ledger, request_id="request-8")
    claimed = ledger.claim(
        requested.request_id,
        teamlead_principal_id="teamlead-2",
        expected_revision=requested.ledger_revision,
    )
    with pytest.raises(module.SpawnDenied):
        ledger.append_phase(
            claimed,
            "NOT_A_PHASE",
            expected_revision=claimed.ledger_revision,
            expected_fence_epoch=claimed.fence_epoch,
            teamlead_principal_id="teamlead-2",
        )


def test_ticket_is_frozen_slotted_redacted_and_not_serializable() -> None:
    module = _ledger_module()
    ticket = _publish(_ledger(module))

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
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
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
