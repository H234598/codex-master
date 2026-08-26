from __future__ import annotations

import ast
import copy
import dataclasses
from datetime import UTC, datetime, timedelta
import importlib
import json
from pathlib import Path
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
from codex_master.fleet_registry import FleetSnapshotV2
from codex_master.runtime_account_allocator import (
    AccountReservation,
    CapacityEvidence,
    RuntimeAccountAllocator,
    ValidatedAllocationTicket,
)
from codex_master.worker_resolution_carrier import (
    WorkerResolutionEvidenceV2,
    build_worker_resolution_carrier,
)
from codex_master.worker_resume import WorkerLifecycle
from codex_master.worker_spawn_ledger import (
    CompensationStatusV1,
    FenceEpoch,
    Generation,
    LedgerRevision,
    PrincipalRole,
    SpawnLedgerStatePort,
    SpawnLedgerStateV2,
    SpawnPhase,
    VerifiedPrincipalV2,
    WorkerFailureCodeV1,
    WorkerFailureOriginV1,
    WorkerSpawnLedger,
)


FUNCTION_TEST_MATRIX_V1: dict[str, str] = {
    "codex_master.dynamic_worker_coordinator.coordinate_dynamic_worker_pre_start": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_coordinate_dynamic_worker_pre_start_orders_bindings_intent_home_and_single_reserve_cas"
    ),
    "codex_master.dynamic_worker_coordinator.compensate_dynamic_worker_not_started": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_compensate_dynamic_worker_not_started_releases_exact_once_after_failure_intent"
    ),
    "codex_master.dynamic_worker_coordinator.quarantine_dynamic_worker_unknown_or_started": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_quarantine_dynamic_worker_unknown_or_started_has_zero_release_cleanup_or_retry"
    ),
    "codex_master.dynamic_worker_coordinator.PreStartReceiptV1": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_pre_start_receipt_is_bound_redacted_and_nonserializable"
    ),
    "codex_master.dynamic_worker_coordinator.DynamicWorkerPreStartPortV1.coordinate": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_b5_port_coordinate_returns_only_bound_prestart_receipt"
    ),
    "codex_master.dynamic_worker_coordinator.DynamicWorkerPreStartPortV1.compensate_not_started": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_b5_port_compensates_once_only_with_live_bound_receipt"
    ),
    "codex_master.dynamic_worker_coordinator.DynamicWorkerPreStartPortV1.quarantine_unknown_or_started": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_b5_port_quarantine_is_single_use_and_non_destructive"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerAllocationPortV1.issue": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerAllocationPortV1__issue"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerProjectionPortV1.project": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerProjectionPortV1__project"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerHomePortV1.commit": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerHomePortV1__commit"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerHomePortV1.cleanup": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerHomePortV1__cleanup"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerRegistryPortV1.read_snapshot": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerRegistryPortV1__read_snapshot"
    ),
    "codex_master.dynamic_worker_coordinator._DynamicWorkerRegistryPortV1.compare_and_swap": (
        "tests/test_dynamic_worker_coordinator.py::"
        "test_function_contract__dynamic_worker_coordinator___DynamicWorkerRegistryPortV1__compare_and_swap"
    ),
}


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src/codex_master/dynamic_worker_coordinator.py"
)


class _ProcessCrash(BaseException):
    pass


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _coordinator():
    return importlib.import_module("codex_master.dynamic_worker_coordinator")


class _LedgerBackend(SpawnLedgerStatePort):
    def __init__(self, events: list[str]) -> None:
        self._state = SpawnLedgerStateV2.empty()
        self.events = events
        self.cas_calls = 0
        self.crash_before: str | None = None

    def read(self) -> SpawnLedgerStateV2:
        return self._state

    def compare_and_swap(
        self,
        expected_revision: LedgerRevision,
        replacement: SpawnLedgerStateV2,
    ) -> bool:
        self.cas_calls += 1
        current_ticket = self._state.tickets[0] if self._state.tickets else None
        replacement_ticket = replacement.tickets[0] if replacement.tickets else None
        if len(replacement.registry_intents) > len(self._state.registry_intents):
            event = "ledger:intent"
        elif len(replacement.failure_journals) > len(self._state.failure_journals):
            event = "ledger:failure"
        elif (
            replacement.failure_journals
            and self._state.failure_journals
            and replacement.failure_journals[0].compensation_status
            is not self._state.failure_journals[0].compensation_status
        ):
            event = (
                "ledger:compensation:"
                + replacement.failure_journals[0].compensation_status.value
            )
        elif current_ticket is None and replacement_ticket is not None:
            event = "ledger:REQUESTED"
        elif replacement_ticket is not None and (
            current_ticket is None
            or replacement_ticket.phase is not current_ticket.phase
        ):
            event = "ledger:" + replacement_ticket.phase.value
        else:
            event = "ledger:revision"
        self.events.append(event)
        if self.crash_before == event:
            raise _ProcessCrash(event)
        if self._state.state_revision != expected_revision:
            return False
        self._state = replacement
        return True


class _Adapter:
    adapter_id = "adapter-b5-3"

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reservations = 0
        self.releases = 0

    def reserve_capability_atomically(self, _capability, evidence):
        self.events.append("lease:reserve")
        self.reservations += 1
        return AccountReservation(
            reservation_id=f"reservation-b5-3-{self.reservations}",
            account_binding_digest=_digest("e"),
            profile_binding_digest=_digest("f"),
            provider_adapter_id=self.adapter_id,
            capacity_evidence=evidence,
            lease_revision=self.reservations,
            evidence_revision=evidence.evidence_revision,
            fencing_token=evidence.fencing_token,
            fence_epoch=evidence.fence_epoch,
            expires_at_utc=evidence.expires_at_utc,
        )

    def release_reservation(self, _reservation):
        self.events.append("lease:revoke")
        self.releases += 1
        return True


class _Registry:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.snapshot = FleetSnapshotV2(2, 5, (), (), ())
        self.cas_calls = 0
        self.read_calls = 0
        self.mode = "success"
        self.crash_on_read = False
        self.read_error_after: int | None = None

    def read_snapshot(self) -> FleetSnapshotV2:
        self.events.append("registry:read")
        self.read_calls += 1
        if self.crash_on_read:
            raise _ProcessCrash("registry:read")
        if (
            self.read_error_after is not None
            and self.read_calls > self.read_error_after
        ):
            raise RuntimeError("secret unreadable registry")
        return self.snapshot

    def compare_and_swap(
        self, candidate: FleetSnapshotV2, *, expected_generation: int
    ) -> FleetSnapshotV2:
        self.events.append("registry:cas")
        self.cas_calls += 1
        assert expected_generation == self.snapshot.generation
        if self.mode == "timeout_before":
            raise TimeoutError("secret registry timeout")
        if self.mode == "timeout_after":
            self.snapshot = candidate
            raise TimeoutError("secret registry timeout")
        if self.mode == "crash_after":
            self.snapshot = candidate
            raise _ProcessCrash("registry:cas:after")
        if self.mode == "old_return":
            return self.snapshot
        if self.mode == "drift":
            self.snapshot = FleetSnapshotV2(
                2, candidate.generation, (), (), self.snapshot.runtime_principals
            )
            return self.snapshot
        self.snapshot = candidate
        return candidate


@dataclasses.dataclass
class _Harness:
    module: object
    events: list[str]
    backend: _LedgerBackend
    adapter: _Adapter
    allocator: RuntimeAccountAllocator
    registry: _Registry
    ledger: WorkerSpawnLedger
    ticket: object
    carrier: object
    teamlead: VerifiedPrincipalV2
    allocation_port: object
    projection_port: object
    home_port: object
    registry_port: object
    port: object
    home_cleanup_calls: int = 0
    projection_error: bool = False
    home_cleanup_error: bool = False

    def restart_port(self):
        return self.module.DynamicWorkerPreStartPortV1(
            ledger=self.ledger,
            state_port=self.backend,
            allocator=self.allocator,
            allocation_port=self.allocation_port,
            projection_port=self.projection_port,
            home_port=self.home_port,
            registry_port=self.registry_port,
            teamlead=self.teamlead,
            principal_id="dw-" + "7" * 32,
        )


def _central_selection():
    classes = (
        AgentClassPolicy(
            "worker.research",
            "ephemeral",
            ("ephemeral",),
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
        requested_class="worker.research",
        requested_lifecycle="invocation",
    )
    decision = resolve_agent_selection(
        request,
        classes=classes,
        models=models,
        available_models={models[0].model_id},
    )
    offer = build_selection_offer(
        classes=classes,
        models=models,
        available_models={models[0].model_id},
    )
    return decision, offer


def _build_harness() -> _Harness:
    module = _coordinator()
    events: list[str] = []
    backend = _LedgerBackend(events)
    adapter = _Adapter(events)
    allocator = RuntimeAccountAllocator(adapter)
    ledger = WorkerSpawnLedger(
        state_port=backend,
        delegable_nonleadership_class_ids=frozenset({"worker.research"}),
        allocator=allocator,
    )
    requester = VerifiedPrincipalV2(
        principal_id="worker-requester",
        role=PrincipalRole.NON_LEADERSHIP,
        authority_digest=_digest("a"),
    )
    teamlead = VerifiedPrincipalV2(
        principal_id="teamlead-carla",
        role=PrincipalRole.TEAMLEADER,
        authority_digest=_digest("b"),
    )
    decision, offer = _central_selection()
    requested = ledger.publish_requested(
        request_id="b5-3-request",
        requester=requester,
        work_package_id="b5-3-package",
        topic_digest=_digest("c"),
        target_class_id="worker.research",
        authorized_teamlead=teamlead,
        resolution_decision_digest=canonical_resolution_decision_digest(decision),
        resolution_generation=Generation(4),
        policy_digest=_digest("d"),
        policy_generation=Generation(9),
        lifecycle=WorkerLifecycle.INVOCATION,
        resume_requirement=False,
        fence_epoch=FenceEpoch(6),
    )
    ticket = ledger.claim(
        requested.request_id,
        teamlead=teamlead,
        expected_revision=requested.ledger_revision,
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
    registry = _Registry(events)
    harness_box: list[_Harness] = []

    def issue_allocation(offered, bound_carrier):
        events.append("allocation:issue")
        assert offered.phase is SpawnPhase.OFFER_VALIDATED
        assert bound_carrier is carrier
        allocation_ticket = ValidatedAllocationTicket(
            ticket_id=offered.ticket_id,
            resolution_decision=bound_carrier.decision,
            selection_offer=bound_carrier.offer,
            resolver_offer_generation=bound_carrier.resolver_offer_generation,
            policy_generation=offered.policy_generation.value,
            policy_digest=offered.policy_digest,
            capability_binding_digest=bound_carrier.capability_binding_digest,
            ledger_revision=offered.ledger_revision.value,
            phase="OFFER_VALIDATED",
            fencing_token="fence-b5-3",
            fence_epoch=offered.fence_epoch.value,
        )
        now = datetime.now(UTC)
        capacity = CapacityEvidence(
            ticket_id=allocation_ticket.ticket_id,
            resolver_offer_generation=allocation_ticket.resolver_offer_generation,
            policy_generation=allocation_ticket.policy_generation,
            capability_binding_digest=allocation_ticket.capability_binding_digest,
            ledger_revision=allocation_ticket.ledger_revision,
            fencing_token=allocation_ticket.fencing_token,
            fence_epoch=allocation_ticket.fence_epoch,
            provider_adapter_id=adapter.adapter_id,
            capacity_units=2,
            quota_units=2,
            cost_units=2,
            resource_units=2,
            evidence_revision=adapter.reservations + 1,
            observed_at_utc=now - timedelta(seconds=1),
            expires_at_utc=now + timedelta(minutes=5),
        )
        return allocation_ticket, capacity

    def project(leased, bound_carrier, lease_binding):
        events.append("projection:project")
        assert leased.phase is SpawnPhase.LEASE_RESERVED
        assert bound_carrier is carrier
        assert lease_binding.allocation_ticket.ticket_id == leased.ticket_id
        if harness_box[0].projection_error:
            raise RuntimeError("secret projection error")
        return object()

    def commit_home(projected, projection_receipt, lease_binding):
        events.append("home:commit")
        assert projected.phase is SpawnPhase.PROJECTED
        assert projection_receipt is not None
        assert lease_binding.lease is not None
        return object()

    def cleanup_home(home_receipt):
        events.append("home:cleanup")
        assert home_receipt is not None
        harness_box[0].home_cleanup_calls += 1
        if harness_box[0].home_cleanup_error:
            raise RuntimeError("secret home cleanup error")

    allocation_port = module._DynamicWorkerAllocationPortV1(issue=issue_allocation)
    projection_port = module._DynamicWorkerProjectionPortV1(project=project)
    home_port = module._DynamicWorkerHomePortV1(
        commit=commit_home,
        cleanup=cleanup_home,
    )
    registry_port = module._DynamicWorkerRegistryPortV1(
        read_snapshot=registry.read_snapshot,
        compare_and_swap=registry.compare_and_swap,
    )
    port = module.DynamicWorkerPreStartPortV1(
        ledger=ledger,
        state_port=backend,
        allocator=allocator,
        allocation_port=allocation_port,
        projection_port=projection_port,
        home_port=home_port,
        registry_port=registry_port,
        teamlead=teamlead,
        principal_id="dw-" + "7" * 32,
    )
    harness = _Harness(
        module=module,
        events=events,
        backend=backend,
        adapter=adapter,
        allocator=allocator,
        registry=registry,
        ledger=ledger,
        ticket=ticket,
        carrier=carrier,
        teamlead=teamlead,
        allocation_port=allocation_port,
        projection_port=projection_port,
        home_port=home_port,
        registry_port=registry_port,
        port=port,
    )
    harness_box.append(harness)
    events.clear()
    return harness


def _coordinate_success(harness: _Harness):
    return harness.port.coordinate(harness.ticket, harness.carrier)


def _current_ticket(harness: _Harness):
    return harness.ledger.read(harness.ticket.request_id)


def _journal(harness: _Harness):
    return harness.backend.read().failure_journals[0]


def test_coordinate_dynamic_worker_pre_start_orders_bindings_intent_home_and_single_reserve_cas() -> (
    None
):
    harness = _build_harness()

    receipt = harness.module.coordinate_dynamic_worker_pre_start(
        harness.port, harness.ticket, harness.carrier
    )

    assert type(receipt) is harness.module.PreStartReceiptV1
    assert _current_ticket(harness).phase is SpawnPhase.REGISTRY_RESERVED
    assert harness.registry.cas_calls == 1
    assert harness.events == [
        "ledger:OFFER_VALIDATED",
        "allocation:issue",
        "lease:reserve",
        "ledger:LEASE_RESERVED",
        "projection:project",
        "ledger:PROJECTED",
        "home:commit",
        "ledger:HOME_COMMITTED",
        "ledger:intent",
        "registry:read",
        "registry:cas",
        "ledger:REGISTRY_RESERVED",
    ]
    assert all("prepare" not in event and "a3" not in event for event in harness.events)


def test_compensate_dynamic_worker_not_started_releases_exact_once_after_failure_intent() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.events.clear()

    result = harness.module.compensate_dynamic_worker_not_started(harness.port, receipt)

    assert result == {"status": "ROLLED_BACK", "reason": "PRE_A3_COMPENSATED"}
    assert harness.registry.cas_calls == 2
    assert harness.home_cleanup_calls == 1
    assert harness.adapter.releases == 1
    assert _current_ticket(harness).phase is SpawnPhase.ROLLED_BACK
    assert _journal(harness).primary_failure_code is WorkerFailureCodeV1.PRE_A3_FAILURE
    assert _journal(harness).primary_failure_origin is WorkerFailureOriginV1.PRE_A3
    assert _journal(harness).compensation_status is CompensationStatusV1.COMPENSATED
    assert harness.events == [
        "ledger:failure",
        "registry:read",
        "registry:cas",
        "ledger:compensation:REGISTRY_RELEASED",
        "home:cleanup",
        "lease:revoke",
        "ledger:compensation:COMPENSATED",
        "ledger:ROLLED_BACK",
    ]


def test_quarantine_dynamic_worker_unknown_or_started_has_zero_release_cleanup_or_retry() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.events.clear()

    result = harness.module.quarantine_dynamic_worker_unknown_or_started(
        harness.port, receipt
    )

    assert result == {
        "status": "QUARANTINED",
        "reason": "STATE_UNKNOWN_OR_STARTED",
    }
    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 1
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0
    assert harness.events == ["ledger:failure", "ledger:QUARANTINED"]


def test_pre_start_receipt_is_bound_redacted_and_nonserializable() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)

    assert dataclasses.is_dataclass(receipt)
    assert hasattr(type(receipt), "__slots__")
    assert repr(receipt) == "<PreStartReceiptV1 redacted>"
    assert str(receipt) == repr(receipt)
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt._port_token = object()  # type: ignore[misc]
    for operation in (copy.copy, copy.deepcopy, pickle.dumps, dataclasses.asdict):
        with pytest.raises(TypeError):
            operation(receipt)
    with pytest.raises(TypeError):
        json.dumps(receipt)
    private_values = (
        harness.allocation_port,
        harness.projection_port,
        harness.home_port,
        harness.registry_port,
        object.__getattribute__(receipt, "_attempt"),
    )
    for value in private_values:
        assert dataclasses.is_dataclass(value)
        assert hasattr(type(value), "__slots__")
        assert repr(value) == f"<{type(value).__name__} redacted>"
        with pytest.raises(TypeError):
            copy.copy(value)
        first_field = dataclasses.fields(value)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, first_field, object())


def test_b5_port_coordinate_returns_only_bound_prestart_receipt() -> None:
    harness = _build_harness()
    receipt = harness.port.coordinate(harness.ticket, harness.carrier)

    assert type(receipt) is harness.module.PreStartReceiptV1
    with pytest.raises(TypeError):
        harness.module.PreStartReceiptV1()
    forged = harness.module.PreStartReceiptV1(object(), object())
    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.compensate_not_started(forged)


def test_b5_port_compensates_once_only_with_live_bound_receipt() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    foreign = _build_harness()
    before = (harness.registry.cas_calls, harness.adapter.releases)

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        foreign.port.compensate_not_started(receipt)
    harness.port.compensate_not_started(receipt)
    after = (harness.registry.cas_calls, harness.adapter.releases)
    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.compensate_not_started(receipt)

    assert before == (1, 0)
    assert after == (2, 1)
    assert (harness.registry.cas_calls, harness.adapter.releases) == after


def test_b5_port_quarantine_is_single_use_and_non_destructive() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)

    harness.port.quarantine_unknown_or_started(receipt)
    counts = (
        harness.registry.cas_calls,
        harness.home_cleanup_calls,
        harness.adapter.releases,
    )
    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.quarantine_unknown_or_started(receipt)

    assert counts == (1, 0, 0)
    assert (
        harness.registry.cas_calls,
        harness.home_cleanup_calls,
        harness.adapter.releases,
    ) == counts


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerAllocationPortV1__issue() -> (
    None
):
    harness = _build_harness()
    _coordinate_success(harness)
    assert harness.events.count("allocation:issue") == 1
    assert (
        harness.events.index("ledger:OFFER_VALIDATED")
        < harness.events.index("allocation:issue")
        < harness.events.index("ledger:LEASE_RESERVED")
    )


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerProjectionPortV1__project() -> (
    None
):
    harness = _build_harness()
    _coordinate_success(harness)
    assert harness.events.count("projection:project") == 1
    assert (
        harness.events.index("ledger:LEASE_RESERVED")
        < harness.events.index("projection:project")
        < harness.events.index("ledger:PROJECTED")
    )


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerHomePortV1__commit() -> (
    None
):
    harness = _build_harness()
    _coordinate_success(harness)
    assert harness.events.count("home:commit") == 1
    assert (
        harness.events.index("ledger:PROJECTED")
        < harness.events.index("home:commit")
        < harness.events.index("ledger:HOME_COMMITTED")
    )


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerHomePortV1__cleanup() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.events.clear()
    harness.port.compensate_not_started(receipt)
    assert harness.events.count("home:cleanup") == 1
    assert (
        harness.events.index("ledger:compensation:REGISTRY_RELEASED")
        < harness.events.index("home:cleanup")
        < harness.events.index("lease:revoke")
    )


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerRegistryPortV1__read_snapshot() -> (
    None
):
    harness = _build_harness()
    _coordinate_success(harness)
    assert harness.registry.read_calls == 1
    assert harness.events.index("ledger:intent") < harness.events.index("registry:read")


def test_function_contract__dynamic_worker_coordinator___DynamicWorkerRegistryPortV1__compare_and_swap() -> (
    None
):
    harness = _build_harness()
    _coordinate_success(harness)
    assert harness.registry.cas_calls == 1
    assert (
        harness.events.index("registry:read")
        < harness.events.index("registry:cas")
        < harness.events.index("ledger:REGISTRY_RESERVED")
    )


def test_crash_before_registry_intent_has_no_registry_cas_or_start_visibility() -> None:
    harness = _build_harness()
    harness.backend.crash_before = "ledger:intent"

    with pytest.raises(_ProcessCrash):
        harness.port.coordinate(harness.ticket, harness.carrier)

    assert harness.registry.cas_calls == 0
    assert _current_ticket(harness).phase is SpawnPhase.HOME_COMMITTED
    assert harness.backend.read().registry_intents == ()


def test_process_crash_after_registry_intent_before_reserve_cas_quarantines_without_retry() -> (
    None
):
    harness = _build_harness()
    harness.registry.crash_on_read = True

    with pytest.raises(_ProcessCrash):
        harness.port.coordinate(harness.ticket, harness.carrier)
    harness.registry.crash_on_read = False
    restarted = harness.restart_port()
    current = _current_ticket(harness)
    result = harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, current, recovery_unknown=True
    )

    assert result["status"] == "QUARANTINED"
    assert harness.registry.cas_calls == 0
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_reserve_cas_timeout_classifies_once_read_only_and_never_retries() -> None:
    persisted = _build_harness()
    persisted.registry.mode = "timeout_after"
    receipt = persisted.port.coordinate(persisted.ticket, persisted.carrier)
    assert type(receipt) is persisted.module.PreStartReceiptV1
    assert persisted.registry.cas_calls == 1
    assert persisted.registry.read_calls == 2

    unknown = _build_harness()
    unknown.registry.mode = "timeout_before"
    with pytest.raises(unknown.module.DynamicWorkerCoordinatorDenied):
        unknown.port.coordinate(unknown.ticket, unknown.carrier)
    assert unknown.registry.cas_calls == 1
    assert unknown.registry.read_calls == 2
    assert _current_ticket(unknown).phase is SpawnPhase.QUARANTINED
    assert unknown.home_cleanup_calls == 0
    assert unknown.adapter.releases == 0


def test_reserve_cas_unreadable_classification_quarantines_without_retry() -> None:
    harness = _build_harness()
    harness.registry.mode = "timeout_before"
    harness.registry.read_error_after = 1

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.coordinate(harness.ticket, harness.carrier)

    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 1
    assert harness.registry.read_calls == 2
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_registry_initial_read_unreadable_quarantines_without_cleanup_or_revoke() -> (
    None
):
    reserve = _build_harness()
    reserve.registry.read_error_after = 0

    with pytest.raises(reserve.module.DynamicWorkerCoordinatorDenied):
        reserve.port.coordinate(reserve.ticket, reserve.carrier)

    release = _build_harness()
    receipt = _coordinate_success(release)
    reads_before = release.registry.read_calls
    release.registry.read_error_after = reads_before

    result = None
    release_error = None
    try:
        result = release.port.compensate_not_started(receipt)
    except Exception as exc:  # contract probe: raw dependency errors must not escape
        release_error = type(exc).__name__

    actual = (
        (
            _current_ticket(reserve).phase,
            reserve.registry.cas_calls,
            reserve.home_cleanup_calls,
            reserve.adapter.releases,
        ),
        (
            release_error,
            None if result is None else result["status"],
            _current_ticket(release).phase,
            _journal(release).compensation_status,
            release.registry.read_calls - reads_before,
            release.registry.cas_calls,
            release.home_cleanup_calls,
            release.adapter.releases,
        ),
    )
    expected = (
        (SpawnPhase.QUARANTINED, 0, 0, 0),
        (
            None,
            "QUARANTINED",
            SpawnPhase.QUARANTINED,
            CompensationStatusV1.QUARANTINED,
            1,
            1,
            0,
            0,
        ),
    )
    assert actual == expected


@pytest.mark.parametrize("mode", ["old_return", "drift"])
def test_reserve_old_or_drift_return_quarantines_without_retry(mode: str) -> None:
    harness = _build_harness()
    harness.registry.mode = mode

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.coordinate(harness.ticket, harness.carrier)

    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 1
    assert harness.registry.read_calls == 2
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_crash_after_reserve_cas_before_registry_reserved_ack_never_exposes_receipt_or_start() -> (
    None
):
    harness = _build_harness()
    harness.registry.mode = "crash_after"

    with pytest.raises(_ProcessCrash):
        harness.port.coordinate(harness.ticket, harness.carrier)
    harness.registry.mode = "success"
    restarted = harness.restart_port()
    current = _current_ticket(harness)
    result = harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, current, recovery_unknown=True
    )

    assert result["status"] == "QUARANTINED"
    assert harness.registry.cas_calls == 1
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_crash_before_failure_journal_has_no_release_cas_cleanup_or_retry() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.backend.crash_before = "ledger:failure"
    cas_before = harness.registry.cas_calls

    with pytest.raises(_ProcessCrash):
        harness.port.compensate_not_started(receipt)
    harness.backend.crash_before = None
    restarted = harness.restart_port()
    current = _current_ticket(harness)
    harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, current, recovery_unknown=True
    )

    assert harness.registry.cas_calls == cas_before
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_crash_after_failure_journal_preserves_primary_error_and_quarantines_without_release() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.crash_on_read = True

    with pytest.raises(_ProcessCrash):
        harness.port.compensate_not_started(receipt)
    primary = (
        _journal(harness).primary_failure_code,
        _journal(harness).primary_failure_origin,
    )
    harness.registry.crash_on_read = False
    restarted = harness.restart_port()
    harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, _current_ticket(harness), recovery_unknown=True
    )

    assert primary == (
        WorkerFailureCodeV1.PRE_A3_FAILURE,
        WorkerFailureOriginV1.PRE_A3,
    )
    assert (
        _journal(harness).primary_failure_code,
        _journal(harness).primary_failure_origin,
    ) == primary
    assert harness.registry.cas_calls == 1
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_crash_after_release_intent_before_release_cas_preserves_primary_failure_and_quarantines() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.crash_on_read = True

    with pytest.raises(_ProcessCrash):
        harness.port.compensate_not_started(receipt)
    journal_before = _journal(harness)
    harness.registry.crash_on_read = False
    restarted = harness.restart_port()
    harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, _current_ticket(harness), recovery_unknown=True
    )

    assert _journal(harness).primary_failure_code is journal_before.primary_failure_code
    assert (
        _journal(harness).primary_failure_origin
        is journal_before.primary_failure_origin
    )
    assert _journal(harness).compensation_status is CompensationStatusV1.QUARANTINED
    assert harness.registry.cas_calls == 1


def test_release_cas_timeout_reads_once_never_retries_and_cleans_only_after_exact_release() -> (
    None
):
    released = _build_harness()
    released_receipt = _coordinate_success(released)
    released.registry.mode = "timeout_after"
    reads_before = released.registry.read_calls
    result = released.port.compensate_not_started(released_receipt)
    assert result["status"] == "ROLLED_BACK"
    assert released.registry.cas_calls == 2
    assert released.registry.read_calls == reads_before + 2
    assert released.home_cleanup_calls == 1
    assert released.adapter.releases == 1

    unknown = _build_harness()
    unknown_receipt = _coordinate_success(unknown)
    unknown.registry.mode = "timeout_before"
    reads_before = unknown.registry.read_calls
    result = unknown.port.compensate_not_started(unknown_receipt)
    assert result["status"] == "QUARANTINED"
    assert unknown.registry.cas_calls == 2
    assert unknown.registry.read_calls == reads_before + 2
    assert unknown.home_cleanup_calls == 0
    assert unknown.adapter.releases == 0


def test_release_cas_unreadable_classification_quarantines_without_cleanup() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.mode = "timeout_before"
    harness.registry.read_error_after = harness.registry.read_calls + 1
    reads_before = harness.registry.read_calls

    result = harness.port.compensate_not_started(receipt)

    assert result["status"] == "QUARANTINED"
    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 2
    assert harness.registry.read_calls == reads_before + 2
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_pre_intent_projection_failure_compensates_without_registry_access() -> None:
    harness = _build_harness()
    harness.projection_error = True

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.coordinate(harness.ticket, harness.carrier)

    assert _current_ticket(harness).phase is SpawnPhase.ROLLED_BACK
    assert harness.registry.read_calls == 0
    assert harness.registry.cas_calls == 0
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 1


@pytest.mark.parametrize("outcome", ["timeout_after_effect", "missing_receipt"])
def test_home_commit_unknown_quarantines_without_cleanup_or_lease_revoke(
    outcome: str,
) -> None:
    harness = _build_harness()
    persisted_effects = 0
    original_commit = harness.home_port.commit

    def commit_then_timeout(ticket, projection_receipt, lease_binding):
        nonlocal persisted_effects
        original_commit(ticket, projection_receipt, lease_binding)
        persisted_effects += 1
        if outcome == "timeout_after_effect":
            raise TimeoutError("opaque home commit outcome")
        return None

    home_port = harness.module._DynamicWorkerHomePortV1(
        commit=commit_then_timeout,
        cleanup=harness.home_port.cleanup,
    )
    port = harness.module.DynamicWorkerPreStartPortV1(
        ledger=harness.ledger,
        state_port=harness.backend,
        allocator=harness.allocator,
        allocation_port=harness.allocation_port,
        projection_port=harness.projection_port,
        home_port=home_port,
        registry_port=harness.registry_port,
        teamlead=harness.teamlead,
        principal_id="dw-" + "7" * 32,
    )

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        port.coordinate(harness.ticket, harness.carrier)

    assert persisted_effects == 1
    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.read_calls == 0
    assert harness.registry.cas_calls == 0
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_release_drift_quarantines_without_cleanup_or_revoke() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.mode = "drift"

    result = harness.port.compensate_not_started(receipt)

    assert result["status"] == "QUARANTINED"
    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 2
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_foreign_registry_snapshot_before_release_quarantines_without_cas() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.snapshot = FleetSnapshotV2(
        2,
        harness.registry.snapshot.generation + 1,
        (),
        (),
        (),
    )
    cas_before = harness.registry.cas_calls

    result = harness.port.compensate_not_started(receipt)

    assert result["status"] == "QUARANTINED"
    assert harness.registry.cas_calls == cas_before
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0


def test_process_crash_after_release_cas_leaves_home_and_lease_for_quarantine() -> None:
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.registry.mode = "crash_after"

    with pytest.raises(_ProcessCrash):
        harness.port.compensate_not_started(receipt)
    harness.registry.mode = "success"
    restarted = harness.restart_port()
    harness.module.quarantine_dynamic_worker_unknown_or_started(
        restarted, _current_ticket(harness), recovery_unknown=True
    )

    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert harness.registry.cas_calls == 2
    assert harness.home_cleanup_calls == 0
    assert harness.adapter.releases == 0
    assert _journal(harness).primary_failure_code is WorkerFailureCodeV1.PRE_A3_FAILURE


def test_home_cleanup_failure_preserves_primary_and_quarantines_without_revoke() -> (
    None
):
    harness = _build_harness()
    receipt = _coordinate_success(harness)
    harness.home_cleanup_error = True

    result = harness.port.compensate_not_started(receipt)

    assert result["status"] == "QUARANTINED"
    assert _current_ticket(harness).phase is SpawnPhase.QUARANTINED
    assert _journal(harness).primary_failure_code is WorkerFailureCodeV1.PRE_A3_FAILURE
    assert _journal(harness).primary_failure_origin is WorkerFailureOriginV1.PRE_A3
    assert _journal(harness).compensation_status is CompensationStatusV1.QUARANTINED
    assert harness.home_cleanup_calls == 1
    assert harness.adapter.releases == 0


def test_forged_carrier_ticket_or_cross_allocator_binding_has_no_effect() -> None:
    harness = _build_harness()
    foreign = _build_harness()

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.port.coordinate(harness.ticket, foreign.carrier)
    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        foreign.port.coordinate(harness.ticket, harness.carrier)

    assert harness.registry.cas_calls == foreign.registry.cas_calls == 0
    assert harness.adapter.reservations == foreign.adapter.reservations == 0


def test_recovery_ticket_rejects_mismatched_ledger_allocator_and_state_port() -> None:
    harness = _build_harness()
    _coordinate_success(harness)
    foreign = _build_harness()
    forged_port = harness.module.DynamicWorkerPreStartPortV1(
        ledger=harness.ledger,
        state_port=foreign.backend,
        allocator=foreign.allocator,
        allocation_port=foreign.allocation_port,
        projection_port=foreign.projection_port,
        home_port=foreign.home_port,
        registry_port=foreign.registry_port,
        teamlead=harness.teamlead,
        principal_id="dw-" + "7" * 32,
    )
    current = _current_ticket(harness)
    events_before = tuple(harness.events)

    with pytest.raises(harness.module.DynamicWorkerCoordinatorDenied):
        harness.module.quarantine_dynamic_worker_unknown_or_started(
            forged_port, current, recovery_unknown=True
        )

    assert _current_ticket(harness).phase is SpawnPhase.REGISTRY_RESERVED
    assert tuple(harness.events) == events_before


def test_function_matrix_ast_imports_public_surface_and_nodes_are_exact() -> None:
    module = _coordinator()
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    definitions: set[str] = set()
    callable_fields: set[str] = set()
    imports: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.add(f"codex_master.dynamic_worker_coordinator.{node.name}")
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions.add(
                        "codex_master.dynamic_worker_coordinator."
                        f"{node.name}.{child.name}"
                    )
                elif isinstance(child, ast.AnnAssign) and isinstance(
                    child.target, ast.Name
                ):
                    annotation = ast.unparse(child.annotation)
                    if "Callable" in annotation:
                        callable_fields.add(
                            "codex_master.dynamic_worker_coordinator."
                            f"{node.name}.{child.target.id}"
                        )
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    expected = (
        definitions
        | callable_fields
        | {"codex_master.dynamic_worker_coordinator.PreStartReceiptV1"}
    )
    assert expected == set(FUNCTION_TEST_MATRIX_V1)
    assert len(set(FUNCTION_TEST_MATRIX_V1.values())) == len(FUNCTION_TEST_MATRIX_V1)
    assert module.__all__ == ["DynamicWorkerPreStartPortV1", "PreStartReceiptV1"]
    forbidden = {
        "server",
        "mcp",
        "broker",
        "agent_start",
        "dynamic_worker_start",
        "dynamic_teamlead",
        "teamlead_coordinator",
        "b4",
        "tl_",
        "tl-",
    }
    assert not {
        name
        for name in imports
        if any(fragment in name.lower() for fragment in forbidden)
    }
    assert imports <= {
        "__future__",
        "collections.abc",
        "dataclasses",
        "codex_master.fleet_registry",
        "codex_master.runtime_account_allocator",
        "codex_master.worker_resolution_carrier",
        "codex_master.worker_spawn_ledger",
    }
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert ".prepare(" not in source
    assert ".execute(" not in source
    assert not {
        token
        for token in (
            "resolve_agent_selection",
            "build_selection_offer",
            "legacy",
            "fallback",
            "dualwrite",
            "dynamic_worker_start",
        )
        if token in source.lower()
    }
