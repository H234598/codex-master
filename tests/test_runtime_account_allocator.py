import ast
import dataclasses
import importlib.util
import inspect
import json
import pickle
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from codex_master.agent_resolver import (
    AgentClassPolicy,
    ModelPolicy,
    ResolutionDecision as CentralResolutionDecision,
    ResolutionRequest,
    build_selection_offer,
    resolve_agent_selection,
)


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src/codex_master/runtime_account_allocator.py"
)


def _allocator_module():
    assert MODULE_PATH.is_file(), "runtime_account_allocator module is missing"
    spec = importlib.util.spec_from_file_location(
        "runtime_account_allocator_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _real_resolution_contract():
    classes = (
        AgentClassPolicy(
            class_id="arbeitsbiene",
            default_lifecycle="ephemeral",
            allowed_lifecycles=("ephemeral",),
            allowed_families=("luna",),
            min_reasoning="low",
            max_reasoning="high",
            supported_scopes=("read",),
        ),
    )
    models = (
        ModelPolicy(
            model_id="gpt-5.6-luna",
            family="luna",
            rank=20,
            reasoning_levels=("low", "medium", "high"),
        ),
    )
    available_models = {models[0].model_id}
    offer = build_selection_offer(
        classes=classes,
        models=models,
        available_models=available_models,
    )
    decision = resolve_agent_selection(
        ResolutionRequest("read", "simple", requested_class="arbeitsbiene"),
        classes=classes,
        models=models,
        available_models=available_models,
    )
    return offer, decision


def _central_ticket(module, **changes):
    offer, decision = _real_resolution_contract()
    values = {
        "ticket_id": "ticket-A",
        "resolution_decision": decision,
        "selection_offer": offer,
        "resolver_offer_generation": offer.generation,
        "policy_generation": 11,
        "capability_binding_digest": "capability-A",
        "ledger_revision": 3,
        "phase": "OFFER_VALIDATED",
        "fencing_token": "fence-A",
    }
    values.update(changes)
    return module.ValidatedAllocationTicket(**values)


def _unselected_capacity_evidence(module, **changes):
    now = datetime.now(UTC)
    offer, _decision = _real_resolution_contract()
    values = {
        "ticket_id": "ticket-A",
        "resolver_offer_generation": offer.generation,
        "policy_generation": 11,
        "capability_binding_digest": "capability-A",
        "ledger_revision": 3,
        "fencing_token": "fence-A",
        "provider_adapter_id": "adapter-A",
        "capacity_units": 2,
        "quota_units": 2,
        "cost_units": 2,
        "resource_units": 2,
        "evidence_revision": 1,
        "observed_at_utc": now - timedelta(minutes=1),
        "expires_at_utc": now + timedelta(minutes=1),
    }
    values.update(changes)
    return module.CapacityEvidence(**values)


class _AtomicAdapter:
    adapter_id = "adapter-A"

    def __init__(self, module) -> None:
        self._module = module
        self._lock = Lock()
        self.reserve_calls = 0
        self.released_reservation_ids: list[str] = []

    def reserve_capability_atomically(
        self, capability_binding_digest, capacity_evidence
    ):
        assert capability_binding_digest == "capability-A"
        with self._lock:
            self.reserve_calls += 1
            reservation_number = self.reserve_calls
        return self._module.AccountReservation(
            reservation_id=f"reservation-{reservation_number}",
            account_binding_digest="account-from-adapter",
            profile_binding_digest="profile-from-adapter",
            provider_adapter_id=self.adapter_id,
            lease_revision=reservation_number,
            evidence_revision=capacity_evidence.evidence_revision,
            fencing_token=capacity_evidence.fencing_token,
            expires_at_utc=capacity_evidence.expires_at_utc,
        )

    def release_reservation(self, reservation) -> bool:
        self.released_reservation_ids.append(reservation.reservation_id)
        return True


class _ReleaseProofAdapter(_AtomicAdapter):
    def __init__(self, module, *release_outcomes) -> None:
        super().__init__(module)
        self._release_outcomes = list(release_outcomes)
        self.outstanding_reservation_ids: set[str] = set()
        self.release_calls: list[str] = []

    def reserve_capability_atomically(
        self, capability_binding_digest, capacity_evidence
    ):
        reservation = super().reserve_capability_atomically(
            capability_binding_digest, capacity_evidence
        )
        self.outstanding_reservation_ids.add(reservation.reservation_id)
        return reservation

    def release_reservation(self, reservation):
        self.release_calls.append(reservation.reservation_id)
        outcome = self._release_outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome is True:
            self.outstanding_reservation_ids.remove(reservation.reservation_id)
        return outcome


def test_allocator_consumes_central_decision_and_adapter_selects_account() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)

    lease = module.RuntimeAccountAllocator(adapter).allocate(
        _central_ticket(module), _unselected_capacity_evidence(module)
    )

    assert module.ResolutionDecision is CentralResolutionDecision
    assert lease.account_binding_digest == "account-from-adapter"
    assert lease.profile_binding_digest == "profile-from-adapter"


def test_allocator_accepts_real_resolution_and_string_offer_generation() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    offer, decision = _real_resolution_contract()
    ticket = module.ValidatedAllocationTicket(
        ticket_id="ticket-A",
        resolution_decision=decision,
        selection_offer=offer,
        resolver_offer_generation=offer.generation,
        policy_generation=11,
        capability_binding_digest="capability-A",
        ledger_revision=3,
        phase="OFFER_VALIDATED",
        fencing_token="fence-A",
    )
    evidence = _unselected_capacity_evidence(
        module,
        resolver_offer_generation=offer.generation,
    )

    lease = module.RuntimeAccountAllocator(adapter).allocate(ticket, evidence)

    assert offer.generation.startswith("sha256:")
    assert lease.account_binding_digest == "account-from-adapter"


def test_allocator_rejects_invalid_missing_or_offer_mismatched_decisions() -> None:
    module = _allocator_module()
    offer, decision = _real_resolution_contract()
    base_ticket = module.ValidatedAllocationTicket(
        ticket_id="ticket-A",
        resolution_decision=decision,
        selection_offer=offer,
        resolver_offer_generation=offer.generation,
        policy_generation=11,
        capability_binding_digest="capability-A",
        ledger_revision=3,
        phase="OFFER_VALIDATED",
        fencing_token="fence-A",
    )
    evidence = _unselected_capacity_evidence(
        module,
        resolver_offer_generation=offer.generation,
    )
    invalid_tickets = (
        dataclasses.replace(
            base_ticket,
            resolution_decision=dataclasses.replace(decision, class_id=""),
        ),
        dataclasses.replace(
            base_ticket,
            resolution_decision=dataclasses.replace(decision, model=1),
        ),
        dataclasses.replace(
            base_ticket,
            resolution_decision=SimpleNamespace(
                class_id=decision.class_id,
                lifecycle=decision.lifecycle,
                model=decision.model,
            ),
        ),
        dataclasses.replace(
            base_ticket,
            resolution_decision=dataclasses.replace(
                decision, model="gpt-5.6-not-offered"
            ),
        ),
        dataclasses.replace(base_ticket, selection_offer=object()),
        dataclasses.replace(
            base_ticket,
            selection_offer=dataclasses.replace(offer, options=()),
        ),
        dataclasses.replace(base_ticket, resolver_offer_generation=7),
        dataclasses.replace(base_ticket, resolver_offer_generation="sha256:mismatch"),
    )

    for ticket in invalid_tickets:
        adapter = _AtomicAdapter(module)
        _assert_sparse_denial(
            module,
            lambda ticket=ticket, adapter=adapter: module.RuntimeAccountAllocator(
                adapter
            ).allocate(ticket, evidence),
        )
        assert adapter.reserve_calls == 0


def test_parallel_capacity_one_is_fenced_to_one_lease() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    snapshot_barrier = Barrier(2)

    class SynchronizedSnapshotRecords(dict):
        def values(self):
            snapshot = tuple(super().values())
            snapshot_barrier.wait(timeout=2)
            return snapshot

    allocator._records = SynchronizedSnapshotRecords()

    def allocate_once():
        try:
            return allocator.allocate(
                _central_ticket(module),
                _unselected_capacity_evidence(
                    module,
                    capacity_units=1,
                    quota_units=1,
                    cost_units=1,
                    resource_units=1,
                ),
            )
        except module.AllocationDenied as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _index: allocate_once(), range(2)))

    leases = [
        result for result in results if isinstance(result, module.CredentialLease)
    ]
    denials = [
        result for result in results if isinstance(result, module.AllocationDenied)
    ]
    assert len(leases) == 1
    assert len(denials) == 1
    assert len(adapter.released_reservation_ids) == 1


def test_rejected_second_reservation_is_compensated_once() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    evidence = _unselected_capacity_evidence(
        module,
        capacity_units=1,
        quota_units=1,
        cost_units=1,
        resource_units=1,
    )

    allocator.allocate(_central_ticket(module), evidence)
    with pytest.raises(
        module.AllocationDenied, match="runtime account allocation denied"
    ):
        allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(evidence, evidence_revision=2),
        )

    assert adapter.reserve_calls == 2
    assert adapter.released_reservation_ids == ["reservation-2"]


def test_duplicate_lease_revision_is_rejected_and_compensated() -> None:
    module = _allocator_module()

    class DuplicateRevisionAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            reservation = super().reserve_capability_atomically(
                capability_binding_digest, capacity_evidence
            )
            return dataclasses.replace(reservation, lease_revision=1)

    adapter = DuplicateRevisionAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    evidence = _unselected_capacity_evidence(module)
    allocator.allocate(_central_ticket(module), evidence)

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(evidence, evidence_revision=2),
        ),
    )

    assert adapter.released_reservation_ids == ["reservation-2"]


def test_revoked_account_rejects_replayed_evidence_and_lease_revisions() -> None:
    module = _allocator_module()
    evidence = _unselected_capacity_evidence(module)

    evidence_adapter = _AtomicAdapter(module)
    evidence_allocator = module.RuntimeAccountAllocator(evidence_adapter)
    evidence_lease = evidence_allocator.allocate(_central_ticket(module), evidence)
    evidence_allocator.revoke(evidence_lease, "completed")

    _assert_sparse_denial(
        module,
        lambda: evidence_allocator.allocate(_central_ticket(module), evidence),
    )
    assert evidence_adapter.released_reservation_ids == [
        "reservation-1",
        "reservation-2",
    ]

    class ReplayedLeaseRevisionAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            reservation = super().reserve_capability_atomically(
                capability_binding_digest, capacity_evidence
            )
            return dataclasses.replace(reservation, lease_revision=1)

    lease_adapter = ReplayedLeaseRevisionAdapter(module)
    lease_allocator = module.RuntimeAccountAllocator(lease_adapter)
    lease = lease_allocator.allocate(_central_ticket(module), evidence)
    lease_allocator.revoke(lease, "completed")

    _assert_sparse_denial(
        module,
        lambda: lease_allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(evidence, evidence_revision=2),
        ),
    )
    assert lease_adapter.released_reservation_ids == [
        "reservation-1",
        "reservation-2",
    ]


def test_revoke_release_exception_stays_pending_and_retries_idempotently() -> None:
    module = _allocator_module()
    adapter = _ReleaseProofAdapter(module, RuntimeError("release-secret"), True, True)
    allocator = module.RuntimeAccountAllocator(adapter)
    capacity_one = _unselected_capacity_evidence(
        module,
        capacity_units=1,
        quota_units=1,
        cost_units=1,
        resource_units=1,
    )
    lease = allocator.allocate(_central_ticket(module), capacity_one)

    allocator.revoke(lease, "completed")

    assert adapter.outstanding_reservation_ids == {"reservation-1"}
    assert allocator._records[lease.lease_id].state.value == "release_pending"
    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(capacity_one, evidence_revision=2),
        ),
    )
    assert adapter.outstanding_reservation_ids == {"reservation-1"}

    allocator.revoke(lease, "retry")
    allocator.revoke(lease, "already-released")

    assert adapter.outstanding_reservation_ids == set()
    assert adapter.release_calls == [
        "reservation-1",
        "reservation-2",
        "reservation-1",
    ]
    assert allocator._records[lease.lease_id].state is module.LeaseState.REVOKED


def test_rejected_reservation_false_release_is_bound_until_recovery() -> None:
    module = _allocator_module()
    adapter = _ReleaseProofAdapter(module, False, True)
    allocator = module.RuntimeAccountAllocator(adapter)
    evidence = _unselected_capacity_evidence(
        module,
        capacity_units=1,
        quota_units=1,
        cost_units=1,
        resource_units=1,
    )
    allocator.allocate(_central_ticket(module), evidence)

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(evidence, evidence_revision=2),
        ),
    )

    assert adapter.outstanding_reservation_ids == {
        "reservation-1",
        "reservation-2",
    }
    assert allocator.recover_pending_releases() == 0
    assert allocator.recover_pending_releases() == 0
    assert adapter.outstanding_reservation_ids == {"reservation-1"}
    assert adapter.release_calls == ["reservation-2", "reservation-2"]


def test_malformed_release_proof_requires_phase_bound_recovery() -> None:
    module = _allocator_module()
    adapter = _ReleaseProofAdapter(module, "released", True)
    allocator = module.RuntimeAccountAllocator(adapter)
    lease = allocator.allocate(
        _central_ticket(module), _unselected_capacity_evidence(module)
    )

    allocator.revoke(lease, "completed")
    pending_evidence = _bound_transaction_evidence(
        module, lease, phase="RELEASE_PENDING"
    )

    assert allocator._records[lease.lease_id].state is module.LeaseState.RELEASE_PENDING
    assert adapter.outstanding_reservation_ids == {"reservation-1"}
    assert allocator.recover(lease, pending_evidence) is module.LeaseState.REVOKED
    assert adapter.outstanding_reservation_ids == set()
    assert adapter.release_calls == ["reservation-1", "reservation-1"]


def _bound_transaction_evidence(module, lease, **changes):
    values = {
        "ticket_id": "ticket-A",
        "lease_id": lease.lease_id,
        "lease_revision": lease.lease_revision,
        "ledger_revision": 3,
        "capability_binding_digest": "capability-A",
        "account_binding_digest": lease.account_binding_digest,
        "profile_binding_digest": lease.profile_binding_digest,
        "provider_adapter_id": lease.provider_adapter_id,
        "fencing_token": "fence-A",
        "phase": "LEASE_RESERVED",
    }
    values.update(changes)
    return module.TransactionEvidence(**values)


def test_recover_requires_existing_lease_and_ledger_phase_binding() -> None:
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_AtomicAdapter(module))
    lease = allocator.allocate(
        _central_ticket(module), _unselected_capacity_evidence(module)
    )
    forged_equal_lease = dataclasses.replace(lease)

    assert tuple(
        inspect.signature(module.RuntimeAccountAllocator.recover).parameters
    ) == (
        "self",
        "lease",
        "transaction_evidence",
    )
    for candidate_lease, evidence in (
        (forged_equal_lease, _bound_transaction_evidence(module, lease)),
        (lease, _bound_transaction_evidence(module, lease, lease_revision=True)),
        (lease, _bound_transaction_evidence(module, lease, ledger_revision=4)),
        (lease, _bound_transaction_evidence(module, lease, lease_revision=2)),
        (lease, _bound_transaction_evidence(module, lease, fencing_token="wrong")),
        (lease, _bound_transaction_evidence(module, lease, phase="PROJECTED")),
        (
            lease,
            _bound_transaction_evidence(
                module, lease, capability_binding_digest="wrong"
            ),
        ),
    ):
        with pytest.raises(
            module.AllocationDenied, match="runtime account allocation denied"
        ):
            allocator.recover(candidate_lease, evidence)

    assert (
        allocator.recover(lease, _bound_transaction_evidence(module, lease))
        is module.LeaseState.RESERVED
    )

    allocator.revoke(lease, "completed")
    _assert_sparse_denial(
        module,
        lambda: allocator.recover(lease, _bound_transaction_evidence(module, lease)),
    )


def _assert_sparse_denial(module, call) -> None:
    with pytest.raises(module.AllocationDenied) as error:
        call()
    assert str(error.value) == "runtime account allocation denied"
    assert error.value.__cause__ is None


def test_non_exact_adapter_reply_is_rejected_and_exceptions_are_sparse() -> None:
    module = _allocator_module()
    evidence = _unselected_capacity_evidence(module)
    structural_reply = SimpleNamespace(
        reservation_id="reservation-structural",
        account_binding_digest="account-from-adapter",
        profile_binding_digest="profile-from-adapter",
        provider_adapter_id="adapter-A",
        lease_revision=1,
        evidence_revision=1,
        fencing_token="fence-A",
        expires_at_utc=evidence.expires_at_utc,
    )

    class StructuralReplyAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            return structural_reply

    class ExplodingAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            raise RuntimeError("provider-secret")

    class ExplodingReleaseAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            reservation = super().reserve_capability_atomically(
                capability_binding_digest, capacity_evidence
            )
            return dataclasses.replace(reservation, evidence_revision=2)

        def release_reservation(self, reservation) -> None:
            raise RuntimeError("release-secret")

    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(StructuralReplyAdapter(module)).allocate(
            _central_ticket(module), evidence
        ),
    )
    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(ExplodingAdapter(module)).allocate(
            _central_ticket(module), evidence
        ),
    )
    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(
            ExplodingReleaseAdapter(module)
        ).allocate(_central_ticket(module), evidence),
    )


def test_none_malformed_reservations_and_adapter_identity_fail_closed() -> None:
    module = _allocator_module()
    ticket = _central_ticket(module)
    evidence = _unselected_capacity_evidence(module)

    class NoneAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            return None

    class ExplodingIdentityAdapter:
        @property
        def adapter_id(self):
            raise RuntimeError("identity-secret")

    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(NoneAdapter(module)).allocate(
            ticket, evidence
        ),
    )
    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(ExplodingIdentityAdapter()).allocate(
            ticket, evidence
        ),
    )

    valid_reservation = _AtomicAdapter(module).reserve_capability_atomically(
        "capability-A", evidence
    )

    class ExplodingTimezone(tzinfo):
        def utcoffset(self, value):
            raise RuntimeError("timezone-secret")

        def dst(self, value):
            return None

    malformed_reservations = (
        dataclasses.replace(valid_reservation, account_binding_digest=""),
        dataclasses.replace(valid_reservation, lease_revision=True),
        dataclasses.replace(valid_reservation, evidence_revision=False),
        dataclasses.replace(valid_reservation, expires_at_utc="not-a-datetime"),
        dataclasses.replace(
            valid_reservation,
            expires_at_utc=datetime(2026, 1, 1, tzinfo=ExplodingTimezone()),
        ),
        dataclasses.replace(valid_reservation, fencing_token="wrong"),
    )

    for reservation in malformed_reservations:

        class FixedReplyAdapter(_AtomicAdapter):
            def reserve_capability_atomically(
                self, capability_binding_digest, capacity_evidence
            ):
                return reservation

        adapter = FixedReplyAdapter(module)
        _assert_sparse_denial(
            module,
            lambda adapter=adapter: module.RuntimeAccountAllocator(adapter).allocate(
                ticket, evidence
            ),
        )
        assert adapter.released_reservation_ids == [reservation.reservation_id]


def test_malformed_bool_stale_and_mismatched_evidence_fail_closed() -> None:
    module = _allocator_module()
    ticket = _central_ticket(module)

    class ExplodingTimezone(tzinfo):
        def utcoffset(self, value):
            raise RuntimeError("timezone-secret")

        def dst(self, value):
            return None

    invalid_evidence = (
        _unselected_capacity_evidence(module, observed_at_utc="not-a-datetime"),
        _unselected_capacity_evidence(module, capacity_units=True),
        _unselected_capacity_evidence(module, quota_units=False),
        _unselected_capacity_evidence(
            module,
            observed_at_utc=datetime(2026, 1, 1, tzinfo=ExplodingTimezone()),
        ),
        _unselected_capacity_evidence(
            module, expires_at_utc=datetime(2000, 1, 1, tzinfo=UTC)
        ),
        _unselected_capacity_evidence(module, ticket_id="wrong"),
        _unselected_capacity_evidence(
            module, resolver_offer_generation="sha256:mismatch"
        ),
        _unselected_capacity_evidence(module, policy_generation=12),
        _unselected_capacity_evidence(module, capability_binding_digest="wrong"),
        _unselected_capacity_evidence(module, ledger_revision=4),
        _unselected_capacity_evidence(module, fencing_token="wrong"),
    )

    for evidence in invalid_evidence:
        adapter = _AtomicAdapter(module)
        _assert_sparse_denial(
            module,
            lambda evidence=evidence, adapter=adapter: module.RuntimeAccountAllocator(
                adapter
            ).allocate(ticket, evidence),
        )
        assert adapter.reserve_calls == 0


def test_bool_generation_and_ledger_evidence_fail_closed() -> None:
    module = _allocator_module()
    ticket = _central_ticket(
        module,
        policy_generation=1,
        ledger_revision=1,
    )
    evidence = _unselected_capacity_evidence(
        module,
        policy_generation=1,
        ledger_revision=1,
    )

    for invalid in (
        dataclasses.replace(evidence, resolver_offer_generation=True),
        dataclasses.replace(evidence, policy_generation=True),
        dataclasses.replace(evidence, ledger_revision=True),
    ):
        adapter = _AtomicAdapter(module)
        _assert_sparse_denial(
            module,
            lambda invalid=invalid, adapter=adapter: module.RuntimeAccountAllocator(
                adapter
            ).allocate(ticket, invalid),
        )
        assert adapter.reserve_calls == 0


def test_all_allocator_values_are_redacted_and_not_freely_serializable() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    ticket = _central_ticket(module)
    evidence = _unselected_capacity_evidence(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    lease = allocator.allocate(ticket, evidence)
    transaction = _bound_transaction_evidence(module, lease)
    reservation = allocator._records[lease.lease_id].reservation
    record = allocator._records[lease.lease_id]
    pending_adapter = _ReleaseProofAdapter(module, False)
    pending_allocator = module.RuntimeAccountAllocator(pending_adapter)
    capacity_one = _unselected_capacity_evidence(
        module,
        capacity_units=1,
        quota_units=1,
        cost_units=1,
        resource_units=1,
    )
    pending_allocator.allocate(_central_ticket(module), capacity_one)
    _assert_sparse_denial(
        module,
        lambda: pending_allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(capacity_one, evidence_revision=2),
        ),
    )
    pending_release = next(iter(pending_allocator._pending_releases.values()))

    for value in (
        ticket,
        evidence,
        transaction,
        reservation,
        lease,
        record,
        pending_release,
    ):
        assert "ticket-A" not in repr(value)
        assert "account-from-adapter" not in repr(value)
        assert "fence-A" not in str(value)
        assert str(value) == repr(value)
        with pytest.raises(TypeError, match="not serializable"):
            pickle.dumps(value)
        with pytest.raises(TypeError):
            dataclasses.asdict(value)
        with pytest.raises(TypeError):
            json.dumps(value)


def test_allocator_selects_account_only_after_validated_ticket() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    ticket = _central_ticket(module)
    evidence = _unselected_capacity_evidence(module)

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            dataclasses.replace(ticket, resolution_decision=object()), evidence
        ),
    )
    assert adapter.reserve_calls == 0

    lease = allocator.allocate(ticket, evidence)

    assert lease.account_binding_digest == "account-from-adapter"
    assert lease.profile_binding_digest == "profile-from-adapter"
    assert lease.provider_adapter_id == "adapter-A"


def test_allocator_allows_parallel_same_account_leases_only_with_capacity_evidence() -> (
    None
):
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_AtomicAdapter(module))
    ticket = _central_ticket(module)
    evidence = _unselected_capacity_evidence(module)

    first = allocator.allocate(ticket, evidence)
    second = allocator.allocate(
        ticket, dataclasses.replace(evidence, evidence_revision=2)
    )

    assert (
        first.account_binding_digest
        == second.account_binding_digest
        == "account-from-adapter"
    )
    assert first.lease_revision == 1
    assert second.lease_revision == 2


def test_allocator_denies_unknown_quota_cost_or_resource_evidence() -> None:
    module = _allocator_module()
    ticket = _central_ticket(module)

    invalid_evidence = (
        _unselected_capacity_evidence(module, capacity_units=None),
        _unselected_capacity_evidence(module, quota_units=None),
        _unselected_capacity_evidence(module, cost_units=None),
        _unselected_capacity_evidence(module, resource_units=None),
    )

    for evidence in invalid_evidence:
        adapter = _AtomicAdapter(module)
        _assert_sparse_denial(
            module,
            lambda evidence=evidence, adapter=adapter: module.RuntimeAccountAllocator(
                adapter
            ).allocate(ticket, evidence),
        )
        assert adapter.reserve_calls == 0


def test_lease_is_opaque_redacted_and_revoke_is_idempotent() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    lease = allocator.allocate(
        _central_ticket(module), _unselected_capacity_evidence(module)
    )
    transaction = _bound_transaction_evidence(module, lease)

    assert dataclasses.is_dataclass(lease)
    assert type(lease).__dataclass_params__.frozen
    assert "__dict__" not in type(lease).__slots__
    assert lease.lease_id not in repr(lease)
    assert lease.account_binding_digest not in repr(lease)
    assert str(lease) == repr(lease)
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(lease)
    with pytest.raises(TypeError):
        json.dumps(lease)

    assert allocator.revoke(lease, "completed") is None
    assert allocator.revoke(lease, "completed-again") is None
    assert adapter.released_reservation_ids == ["reservation-1"]
    _assert_sparse_denial(module, lambda: allocator.recover(lease, transaction))


def test_allocator_never_accepts_static_account_profile_or_home_selector() -> None:
    module = _allocator_module()
    fields = tuple(field.name for field in dataclasses.fields(module.CredentialLease))
    evidence_fields = {
        field.name for field in dataclasses.fields(module.CapacityEvidence)
    }
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported_modules = {
        node.module.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_modules.update(
        alias.name.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    assert tuple(
        inspect.signature(module.RuntimeAccountAllocator.allocate).parameters
    ) == (
        "self",
        "ticket",
        "capacity_evidence",
    )
    assert fields == (
        "lease_id",
        "account_binding_digest",
        "profile_binding_digest",
        "provider_adapter_id",
        "lease_revision",
        "expires_at_utc",
    )
    assert evidence_fields.isdisjoint(
        {
            "account_id",
            "account_binding_digest",
            "profile_id",
            "profile_binding_digest",
            "series_id",
            "descriptor_id",
            "home",
            "home_path",
            "credential_path",
        }
    )
    assert module.ResolutionDecision is CentralResolutionDecision
    assert not {
        imported
        for imported in imported_modules
        if any(
            forbidden in imported
            for forbidden in (
                "server",
                "registry",
                "home",
                "broker",
                "mcp",
                "usage",
            )
        )
    }


def test_provider_adapter_is_capability_based_not_class_based() -> None:
    module = _allocator_module()

    class CapabilityOnlyAdapter:
        def __init__(self) -> None:
            self._delegate = _AtomicAdapter(module)

        @property
        def adapter_id(self):
            return self._delegate.adapter_id

        def __getattribute__(self, name):
            if name in {"role", "agent_class", "series", "requested_class"}:
                raise AssertionError(f"provider policy access: {name}")
            return super().__getattribute__(name)

        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            return self._delegate.reserve_capability_atomically(
                capability_binding_digest, capacity_evidence
            )

        def release_reservation(self, reservation):
            return self._delegate.release_reservation(reservation)

    lease = module.RuntimeAccountAllocator(CapabilityOnlyAdapter()).allocate(
        _central_ticket(module), _unselected_capacity_evidence(module)
    )

    assert lease.provider_adapter_id == "adapter-A"
