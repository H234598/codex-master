import ast
import copy
import dataclasses
import hashlib
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
        "policy_digest": "sha256:" + "a" * 64,
        "capability_binding_digest": "capability-A",
        "ledger_revision": 3,
        "phase": "OFFER_VALIDATED",
        "fencing_token": "fence-A",
        "fence_epoch": 1,
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
        "fence_epoch": 1,
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
            capacity_evidence=capacity_evidence,
            lease_revision=reservation_number,
            evidence_revision=capacity_evidence.evidence_revision,
            fencing_token=capacity_evidence.fencing_token,
            fence_epoch=capacity_evidence.fence_epoch,
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
        policy_digest="sha256:" + "a" * 64,
        capability_binding_digest="capability-A",
        ledger_revision=3,
        phase="OFFER_VALIDATED",
        fencing_token="fence-A",
        fence_epoch=1,
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
        policy_digest="sha256:" + "a" * 64,
        capability_binding_digest="capability-A",
        ledger_revision=3,
        phase="OFFER_VALIDATED",
        fencing_token="fence-A",
        fence_epoch=1,
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


def test_allocator_rejects_malformed_generation_even_when_all_copies_match() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    offer, _decision = _real_resolution_contract()
    malformed_generation = "generation-without-central-content-digest"
    ticket = _central_ticket(
        module,
        selection_offer=dataclasses.replace(
            offer,
            generation=malformed_generation,
        ),
        resolver_offer_generation=malformed_generation,
    )
    evidence = _unselected_capacity_evidence(
        module,
        resolver_offer_generation=malformed_generation,
    )

    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(adapter).allocate(ticket, evidence),
    )

    assert adapter.reserve_calls == 0


def test_allocator_rejects_offer_with_unchanged_generation_and_extra_option() -> None:
    module = _allocator_module()
    adapter = _AtomicAdapter(module)
    offer, _decision = _real_resolution_contract()
    ticket = _central_ticket(
        module,
        selection_offer=dataclasses.replace(
            offer,
            options=(*offer.options, object()),
        ),
    )

    _assert_sparse_denial(
        module,
        lambda: module.RuntimeAccountAllocator(adapter).allocate(
            ticket,
            _unselected_capacity_evidence(module),
        ),
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


def test_active_reservation_replay_never_releases_existing_lease_owner() -> None:
    module = _allocator_module()

    class ReplayAdapter(_AtomicAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.replayed_reservation = None
            self.external_active = False

        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            if self.replayed_reservation is None:
                self.replayed_reservation = super().reserve_capability_atomically(
                    capability_binding_digest,
                    capacity_evidence,
                )
                self.external_active = True
            else:
                self.reserve_calls += 1
            return self.replayed_reservation

        def release_reservation(self, reservation) -> bool:
            self.released_reservation_ids.append(reservation.reservation_id)
            self.external_active = False
            return True

    adapter = ReplayAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    evidence = _unselected_capacity_evidence(module)
    lease = allocator.allocate(_central_ticket(module), evidence)

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            _central_ticket(module),
            dataclasses.replace(evidence, evidence_revision=2),
        ),
    )

    assert adapter.external_active is True
    assert adapter.released_reservation_ids == []
    assert allocator._records[lease.lease_id].state is module.LeaseState.RESERVED
    owner = next(iter(allocator._reservation_owners.values()))
    assert owner.owner_id == lease.lease_id
    assert owner.fencing_token == "fence-A"
    assert owner.phase is module.LeaseState.RESERVED


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


def test_malformed_reservation_release_reply_keeps_same_retry_reference() -> None:
    module = _allocator_module()

    class MalformedReservationAdapter(_ReleaseProofAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            reservation = super().reserve_capability_atomically(
                capability_binding_digest,
                capacity_evidence,
            )
            return dataclasses.replace(reservation, account_binding_digest="")

    adapter = MalformedReservationAdapter(module, "released", True)
    allocator = module.RuntimeAccountAllocator(adapter)

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(
            _central_ticket(module),
            _unselected_capacity_evidence(module),
        ),
    )

    assert len(allocator._pending_releases) == 1
    pending = next(iter(allocator._pending_releases.values()))
    pending_id = pending.pending_release_id
    reservation = pending.reservation
    owner = allocator._reservation_owners[pending.reservation_key]
    assert owner.owner_id == pending_id
    assert owner.fencing_token == "fence-A"
    assert owner.phase is module.LeaseState.RELEASE_PENDING
    assert allocator.recover_pending_releases() == 0
    assert adapter.release_calls == ["reservation-1", "reservation-1"]
    assert reservation.reservation_id == "reservation-1"
    assert pending_id not in allocator._pending_releases


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


def test_adapter_reply_that_becomes_stale_before_publish_is_released() -> None:
    module = _allocator_module()
    initial_now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

    class ControlledDatetime(datetime):
        current = initial_now

        @classmethod
        def now(cls, tz=None):
            del tz
            return cls.current

    observed_at = ControlledDatetime(2026, 8, 25, 11, 59, tzinfo=UTC)
    expires_at = ControlledDatetime(2026, 8, 25, 12, 1, tzinfo=UTC)
    module.datetime = ControlledDatetime

    class StalingAdapter(_AtomicAdapter):
        def reserve_capability_atomically(
            self, capability_binding_digest, capacity_evidence
        ):
            reservation = super().reserve_capability_atomically(
                capability_binding_digest,
                capacity_evidence,
            )
            ControlledDatetime.current = ControlledDatetime(
                2026, 8, 25, 12, 2, tzinfo=UTC
            )
            return reservation

    adapter = StalingAdapter(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    evidence = _unselected_capacity_evidence(
        module,
        observed_at_utc=observed_at,
        expires_at_utc=expires_at,
    )

    _assert_sparse_denial(
        module,
        lambda: allocator.allocate(_central_ticket(module), evidence),
    )

    assert adapter.released_reservation_ids == ["reservation-1"]
    assert allocator._records == {}
    assert allocator._reservation_owners == {}


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
    reservation_owner = next(iter(allocator._reservation_owners.values()))
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
        reservation_owner,
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


def _receipt_ticket(module, **changes):
    offer, decision = _real_resolution_contract()
    values = {
        "ticket_id": "ticket-vector",
        "resolution_decision": decision,
        "selection_offer": offer,
        "resolver_offer_generation": offer.generation,
        "policy_generation": 11,
        "policy_digest": "sha256:" + "d" * 64,
        "capability_binding_digest": "sha256:" + "c" * 64,
        "ledger_revision": 3,
        "phase": "OFFER_VALIDATED",
        "fencing_token": "fence-vector",
        "fence_epoch": 17,
    }
    values.update(changes)
    return module.ValidatedAllocationTicket(**values)


def _receipt_capacity_evidence(module, **changes):
    values = {
        "ticket_id": "ticket-vector",
        "resolver_offer_generation": (
            "sha256:017d00ee7993e52d69ea3ab1a99eff095072514bdf32c531aa2a0e9ffec647c4"
        ),
        "policy_generation": 11,
        "capability_binding_digest": "sha256:" + "c" * 64,
        "ledger_revision": 3,
        "fencing_token": "fence-vector",
        "fence_epoch": 17,
        "provider_adapter_id": "adapter-vector",
        "capacity_units": 1,
        "quota_units": 1,
        "cost_units": 1,
        "resource_units": 1,
        "evidence_revision": 7,
        "observed_at_utc": datetime(2000, 1, 1, tzinfo=UTC),
        "expires_at_utc": datetime(2099, 1, 2, 3, 4, 5, 678901, tzinfo=UTC),
    }
    values.update(changes)
    return module.CapacityEvidence(**values)


class _ReceiptAdapter:
    adapter_id = "adapter-vector"

    def __init__(self, module) -> None:
        self._module = module
        self.last_reservation = None

    def reserve_capability_atomically(
        self, capability_binding_digest, capacity_evidence
    ):
        assert capability_binding_digest == "sha256:" + "c" * 64
        self.last_reservation = self._module.AccountReservation(
            reservation_id="reservation-vector",
            account_binding_digest="sha256:" + "a" * 64,
            profile_binding_digest="sha256:" + "b" * 64,
            provider_adapter_id="adapter-vector",
            capacity_evidence=capacity_evidence,
            lease_revision=1,
            evidence_revision=capacity_evidence.evidence_revision,
            fencing_token=capacity_evidence.fencing_token,
            fence_epoch=capacity_evidence.fence_epoch,
            expires_at_utc=capacity_evidence.expires_at_utc,
        )
        return self.last_reservation

    def release_reservation(self, reservation) -> bool:
        return reservation is self.last_reservation


def _receipt_binding(module, adapter_type=_ReceiptAdapter):
    adapter = adapter_type(module)
    allocator = module.RuntimeAccountAllocator(adapter)
    ticket = _receipt_ticket(module)
    capacity_evidence = _receipt_capacity_evidence(module)
    module.token_urlsafe = lambda _length: "lease-vector"
    lease = allocator.allocate(ticket, capacity_evidence)
    return (
        allocator,
        adapter,
        lease,
        ticket,
        capacity_evidence,
        adapter.last_reservation,
    )


def test_allocator_issues_memoized_receipt_with_fixed_canonical_json_vector() -> None:
    module = _allocator_module()
    (
        allocator,
        _adapter,
        lease,
        ticket,
        capacity_evidence,
        _reservation,
    ) = _receipt_binding(module)

    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)

    assert receipt is allocator.issue_lease_binding_receipt(
        lease, ticket, capacity_evidence
    )
    assert type(receipt) is module.LeaseBindingReceiptV1
    expected_json = (
        b'{"account_binding_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","adapter_id":"adapter-vector",'
        b'"binding_schema":"codex-master/lease-binding/v1",'
        b'"capability_binding_digest":"sha256:cccccccccccccccccccccccccccccccc'
        b'cccccccccccccccccccccccccccccccc","capacity_evidence_revision":7,'
        b'"fence_epoch":17,"fencing_token":"fence-vector",'
        b'"lease_expires_at_utc":"2099-01-02T03:04:05.678901Z",'
        b'"lease_id":"lease-vector","lease_revision":1,"ledger_revision":3,'
        b'"policy_digest":"sha256:dddddddddddddddddddddddddddddddddddddddd'
        b'dddddddddddddddddddddddd","policy_generation":11,'
        b'"profile_binding_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        b'bbbbbbbbbbbbbbbbbbbbbbbb","reservation_id":"reservation-vector",'
        b'"resolution_decision_digest":"sha256:7c8b18c9aea0fad9c453cc0bad974801'
        b'3157286276cc1cdcff3f3c2d5000d625","resolver_offer_generation":'
        b'"sha256:017d00ee7993e52d69ea3ab1a99eff095072514bdf32c531aa2a0e9ffec647c4",'
        b'"ticket_id":"ticket-vector"}'
    )
    expected_digest = (
        "sha256:801052b31d6fee240e9407844c23651c5c690a311728e206ed310b5f8e7abbb0"
    )

    assert "sha256:" + hashlib.sha256(expected_json).hexdigest() == expected_digest
    assert receipt._lease_binding_digest == expected_digest
    assert tuple(
        inspect.signature(
            module.RuntimeAccountAllocator.issue_lease_binding_receipt
        ).parameters
    ) == ("self", "lease", "ticket", "capacity_evidence")


def test_lease_binding_receipt_has_no_forgeable_issuer_or_serialization_path() -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module)
    )
    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)

    assert repr(receipt) == "<LeaseBindingReceiptV1 redacted>"
    assert str(receipt) == repr(receipt)
    assert type(receipt).__eq__ is object.__eq__
    assert not hasattr(receipt, "__dict__")
    assert not any("issuer" in name.lower() for name in vars(module))
    assert "_RECEIPT_ISSUERS" not in vars(module)
    assert not any("issuer" in slot.lower() for slot in allocator.__slots__)
    for value in vars(module).values():
        if callable(value):
            try:
                parameters = inspect.signature(value).parameters
            except (TypeError, ValueError):
                continue
            assert "lease_binding_digest" not in parameters
    with pytest.raises(TypeError):
        module.LeaseBindingReceiptV1()
    with pytest.raises(TypeError):
        module.LeaseBindingReceiptV1(lease_binding_digest="sha256:" + "f" * 64)
    for serialize in (
        lambda: copy.copy(receipt),
        lambda: copy.deepcopy(receipt),
        lambda: pickle.dumps(receipt),
        lambda: dataclasses.asdict(receipt),
        lambda: dataclasses.replace(receipt),
        lambda: json.dumps(receipt),
    ):
        with pytest.raises(TypeError):
            serialize()


def test_lease_binding_receipt_accepts_only_exact_live_binding_objects() -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module)
    )

    for binding in (
        (dataclasses.replace(lease), ticket, capacity_evidence),
        (lease, dataclasses.replace(ticket), capacity_evidence),
        (lease, ticket, dataclasses.replace(capacity_evidence)),
        (lease, object(), capacity_evidence),
    ):
        _assert_sparse_denial(
            module,
            lambda binding=binding: allocator.issue_lease_binding_receipt(*binding),
        )

    allocator.revoke(lease, "done")
    _assert_sparse_denial(
        module,
        lambda: allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence),
    )


@pytest.mark.parametrize(
    ("target_name", "field_name", "replacement"),
    (
        ("ticket", "ticket_id", "ticket-drift"),
        ("ticket", "resolver_offer_generation", "sha256:" + "f" * 64),
        ("ticket", "policy_generation", 12),
        ("ticket", "policy_digest", "sha256:" + "e" * 64),
        ("ticket", "capability_binding_digest", "sha256:" + "e" * 64),
        ("ticket", "ledger_revision", 4),
        ("ticket", "fencing_token", "fence-drift"),
        ("ticket", "fence_epoch", 18),
        ("capacity_evidence", "provider_adapter_id", "adapter-drift"),
        ("capacity_evidence", "evidence_revision", 8),
        ("lease", "account_binding_digest", "sha256:" + "e" * 64),
        ("lease", "profile_binding_digest", "sha256:" + "e" * 64),
        ("lease", "lease_id", "lease-drift"),
        ("lease", "lease_revision", 2),
        ("lease", "expires_at_utc", datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC)),
        ("reservation", "reservation_id", "reservation-drift"),
    ),
)
def test_lease_binding_receipt_denies_each_canonical_snapshot_drift(
    target_name, field_name, replacement
) -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, reservation = (
        _receipt_binding(module)
    )
    target = {
        "ticket": ticket,
        "capacity_evidence": capacity_evidence,
        "lease": lease,
        "reservation": reservation,
    }[target_name]
    original = getattr(target, field_name)
    object.__setattr__(target, field_name, replacement)
    try:
        _assert_sparse_denial(
            module,
            lambda: allocator.issue_lease_binding_receipt(
                lease, ticket, capacity_evidence
            ),
        )
    finally:
        object.__setattr__(target, field_name, original)


def test_lease_binding_receipt_denies_resolution_decision_digest_drift() -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module)
    )
    original = ticket.resolution_decision.model
    object.__setattr__(ticket.resolution_decision, "model", "gpt-5.6-drift")
    try:
        _assert_sparse_denial(
            module,
            lambda: allocator.issue_lease_binding_receipt(
                lease, ticket, capacity_evidence
            ),
        )
    finally:
        object.__setattr__(ticket.resolution_decision, "model", original)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("account_binding_digest", "sha256:" + "a" * 64),
        ("lease_revision", True),
    ),
)
def test_lease_binding_receipt_denies_equal_lease_representation_drift(
    field_name, replacement
) -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module)
    )
    original = getattr(lease, field_name)
    object.__setattr__(lease, field_name, replacement)
    try:
        _assert_sparse_denial(
            module,
            lambda: allocator.issue_lease_binding_receipt(
                lease, ticket, capacity_evidence
            ),
        )
    finally:
        object.__setattr__(lease, field_name, original)


@pytest.mark.parametrize(
    "case",
    (
        "account",
        "profile",
        "adapter",
        "reservation_id",
        "lease_revision",
        "evidence_revision",
        "fence",
        "ticket",
        "expiry",
    ),
)
def test_lease_binding_receipt_never_reuses_cache_after_correlated_drift(case) -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, reservation = (
        _receipt_binding(module)
    )
    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)
    expiry = datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC)
    mutations = {
        "account": (
            (lease, "account_binding_digest", "sha256:" + "e" * 64),
            (reservation, "account_binding_digest", "sha256:" + "e" * 64),
        ),
        "profile": (
            (lease, "profile_binding_digest", "sha256:" + "e" * 64),
            (reservation, "profile_binding_digest", "sha256:" + "e" * 64),
        ),
        "adapter": (
            (lease, "provider_adapter_id", "adapter-drift"),
            (capacity_evidence, "provider_adapter_id", "adapter-drift"),
            (reservation, "provider_adapter_id", "adapter-drift"),
        ),
        "reservation_id": ((reservation, "reservation_id", "reservation-drift"),),
        "lease_revision": (
            (lease, "lease_revision", 2),
            (reservation, "lease_revision", 2),
        ),
        "evidence_revision": (
            (capacity_evidence, "evidence_revision", 8),
            (reservation, "evidence_revision", 8),
        ),
        "fence": (
            (ticket, "fencing_token", "fence-drift"),
            (capacity_evidence, "fencing_token", "fence-drift"),
            (reservation, "fencing_token", "fence-drift"),
            (ticket, "fence_epoch", 18),
            (capacity_evidence, "fence_epoch", 18),
            (reservation, "fence_epoch", 18),
        ),
        "ticket": (
            (ticket, "ticket_id", "ticket-drift"),
            (capacity_evidence, "ticket_id", "ticket-drift"),
        ),
        "expiry": (
            (lease, "expires_at_utc", expiry),
            (capacity_evidence, "expires_at_utc", expiry),
            (reservation, "expires_at_utc", expiry),
        ),
    }[case]
    originals = tuple(
        (target, field_name, getattr(target, field_name))
        for target, field_name, _replacement in mutations
    )
    for target, field_name, replacement in mutations:
        object.__setattr__(target, field_name, replacement)
    try:
        _assert_sparse_denial(
            module,
            lambda: allocator.issue_lease_binding_receipt(
                lease, ticket, capacity_evidence
            ),
        )
        assert receipt is not None
    finally:
        for target, field_name, original in originals:
            object.__setattr__(target, field_name, original)


def test_lease_binding_receipt_uses_allocation_adapter_snapshot_without_reread() -> (
    None
):
    module = _allocator_module()

    class SwitchingAdapter(_ReceiptAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.adapter_id_reads = 0

        @property
        def adapter_id(self):
            self.adapter_id_reads += 1
            if self.adapter_id_reads == 1:
                return "adapter-vector"
            return "adapter-drift"

    allocator, adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module, SwitchingAdapter)
    )

    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)

    assert receipt is allocator.issue_lease_binding_receipt(
        lease, ticket, capacity_evidence
    )
    assert receipt._lease_binding_digest == (
        "sha256:801052b31d6fee240e9407844c23651c5c690a311728e206ed310b5f8e7abbb0"
    )
    assert adapter.adapter_id_reads == 1


def test_lease_binding_verifier_registers_exact_live_binding_guard() -> None:
    module = _allocator_module()
    allocator, _adapter, lease, ticket, capacity_evidence, _reservation = (
        _receipt_binding(module)
    )
    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)

    verification = allocator.verify_lease_binding_receipt(
        receipt,
        expected_lease=lease,
        expected_ticket=ticket,
        expected_capacity_evidence=capacity_evidence,
    )

    assert type(verification) is module.LeaseBindingVerificationV1
    assert verification in allocator._active_lease_binding_verifications


def _verification_binding(module, adapter_type=_ReceiptAdapter):
    allocator, adapter, lease, ticket, capacity_evidence, reservation = (
        _receipt_binding(module, adapter_type)
    )
    receipt = allocator.issue_lease_binding_receipt(lease, ticket, capacity_evidence)
    return allocator, adapter, receipt, lease, ticket, capacity_evidence, reservation


def _verify_lease_binding(allocator, receipt, lease, ticket, capacity_evidence):
    return allocator.verify_lease_binding_receipt(
        receipt,
        expected_lease=lease,
        expected_ticket=ticket,
        expected_capacity_evidence=capacity_evidence,
    )


def _forged_receipt(module, digest):
    forged = object.__new__(module.LeaseBindingReceiptV1)
    object.__setattr__(forged, "_lease_binding_digest", module._OpaqueText(digest))
    return forged


def test_lease_binding_verifier_denies_exact_opaque_text_forge_and_cross_objects() -> (
    None
):
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module)
    )
    forged = _forged_receipt(module, receipt._lease_binding_digest)
    other = _verification_binding(module)

    for attempted_receipt, attempted_lease, attempted_ticket, attempted_evidence in (
        ("sha256:" + "f" * 64, lease, ticket, capacity_evidence),
        (forged, lease, ticket, capacity_evidence),
        (receipt, dataclasses.replace(lease), ticket, capacity_evidence),
        (receipt, lease, dataclasses.replace(ticket), capacity_evidence),
        (receipt, lease, ticket, dataclasses.replace(capacity_evidence)),
        (other[2], other[3], other[4], other[5]),
    ):
        _assert_sparse_denial(
            module,
            lambda attempted_receipt=attempted_receipt, attempted_lease=attempted_lease, attempted_ticket=attempted_ticket, attempted_evidence=attempted_evidence: (
                _verify_lease_binding(
                    allocator,
                    attempted_receipt,
                    attempted_lease,
                    attempted_ticket,
                    attempted_evidence,
                )
            ),
        )
    assert allocator._active_lease_binding_verifications == {}


@pytest.mark.parametrize(
    ("target_name", "field_name", "replacement"),
    (
        ("ticket", "ticket_id", "ticket-drift"),
        ("ticket", "resolver_offer_generation", "sha256:" + "f" * 64),
        ("ticket", "policy_generation", 12),
        ("ticket", "policy_digest", "sha256:" + "e" * 64),
        ("ticket", "capability_binding_digest", "sha256:" + "e" * 64),
        ("ticket", "ledger_revision", 4),
        ("ticket", "fencing_token", "fence-drift"),
        ("ticket", "fence_epoch", 18),
        ("capacity_evidence", "provider_adapter_id", "adapter-drift"),
        ("capacity_evidence", "evidence_revision", 8),
        ("lease", "account_binding_digest", "sha256:" + "e" * 64),
        ("lease", "profile_binding_digest", "sha256:" + "e" * 64),
        ("lease", "lease_id", "lease-drift"),
        ("lease", "lease_revision", 2),
        ("lease", "expires_at_utc", datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC)),
        ("reservation", "reservation_id", "reservation-drift"),
    ),
)
def test_lease_binding_verifier_denies_each_live_binding_field_drift(
    target_name, field_name, replacement
) -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, reservation = (
        _verification_binding(module)
    )
    target = {
        "ticket": ticket,
        "capacity_evidence": capacity_evidence,
        "lease": lease,
        "reservation": reservation,
    }[target_name]
    original = getattr(target, field_name)
    object.__setattr__(target, field_name, replacement)
    try:
        _assert_sparse_denial(
            module,
            lambda: _verify_lease_binding(
                allocator, receipt, lease, ticket, capacity_evidence
            ),
        )
        assert allocator._active_lease_binding_verifications == {}
    finally:
        object.__setattr__(target, field_name, original)


@pytest.mark.parametrize(
    "mutations",
    (
        (
            ("lease", "account_binding_digest", "sha256:" + "e" * 64),
            ("reservation", "account_binding_digest", "sha256:" + "e" * 64),
        ),
        (
            ("ticket", "policy_generation", 12),
            ("capacity_evidence", "policy_generation", 12),
        ),
        (
            ("ticket", "fencing_token", "fence-drift"),
            ("capacity_evidence", "fencing_token", "fence-drift"),
            ("reservation", "fencing_token", "fence-drift"),
        ),
        (
            ("lease", "expires_at_utc", datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC)),
            (
                "capacity_evidence",
                "expires_at_utc",
                datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC),
            ),
            (
                "reservation",
                "expires_at_utc",
                datetime(2099, 1, 2, 3, 4, 6, tzinfo=UTC),
            ),
        ),
    ),
)
def test_lease_binding_verifier_denies_correlated_drift(mutations) -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, reservation = (
        _verification_binding(module)
    )
    targets = {
        "ticket": ticket,
        "capacity_evidence": capacity_evidence,
        "lease": lease,
        "reservation": reservation,
    }
    originals = tuple(
        (targets[target_name], field_name, getattr(targets[target_name], field_name))
        for target_name, field_name, _replacement in mutations
    )
    for target_name, field_name, replacement in mutations:
        object.__setattr__(targets[target_name], field_name, replacement)
    try:
        _assert_sparse_denial(
            module,
            lambda: _verify_lease_binding(
                allocator, receipt, lease, ticket, capacity_evidence
            ),
        )
    finally:
        for target, field_name, original in originals:
            object.__setattr__(target, field_name, original)


def test_lease_binding_verifier_denies_pending_or_revoked_record() -> None:
    module = _allocator_module()

    class PendingReleaseAdapter(_ReceiptAdapter):
        def release_reservation(self, reservation) -> bool:
            return False

    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module, PendingReleaseAdapter)
    )
    allocator.revoke(lease, "pending")

    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            allocator, receipt, lease, ticket, capacity_evidence
        ),
    )
    assert allocator._records[lease.lease_id].state is module.LeaseState.RELEASE_PENDING

    (
        revoked_allocator,
        _revoked_adapter,
        revoked_receipt,
        revoked_lease,
        revoked_ticket,
        revoked_evidence,
        _revoked_reservation,
    ) = _verification_binding(module)
    revoked_allocator.revoke(revoked_lease, "revoked")
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            revoked_allocator,
            revoked_receipt,
            revoked_lease,
            revoked_ticket,
            revoked_evidence,
        ),
    )
    assert (
        revoked_allocator._records[revoked_lease.lease_id].state
        is module.LeaseState.REVOKED
    )


def test_lease_binding_verifier_denies_receipt_owner_and_resolution_drift() -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module)
    )
    record = allocator._records[lease.lease_id]
    allocator._records[lease.lease_id] = dataclasses.replace(record, receipt=None)
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            allocator, receipt, lease, ticket, capacity_evidence
        ),
    )

    allocator._records[lease.lease_id] = record
    owner = allocator._reservation_owners[record.reservation_key]
    allocator._reservation_owners[record.reservation_key] = dataclasses.replace(
        owner, owner_id="foreign-owner"
    )
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            allocator, receipt, lease, ticket, capacity_evidence
        ),
    )

    allocator._reservation_owners[record.reservation_key] = owner
    original_model = ticket.resolution_decision.model
    object.__setattr__(ticket.resolution_decision, "model", "gpt-5.6-drift")
    try:
        _assert_sparse_denial(
            module,
            lambda: _verify_lease_binding(
                allocator, receipt, lease, ticket, capacity_evidence
            ),
        )
    finally:
        object.__setattr__(ticket.resolution_decision, "model", original_model)


def test_lease_binding_guard_is_single_use_bound_and_reference_is_inert() -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module)
    )
    verification = _verify_lease_binding(
        allocator, receipt, lease, ticket, capacity_evidence
    )
    reference = allocator.lease_binding_reference_for(verification)
    reference_clone = object.__new__(module.LeaseBindingReferenceV1)
    object.__setattr__(reference_clone, "_digest", reference._digest)
    forged = object.__new__(module.LeaseBindingVerificationV1)
    other = _verification_binding(module)
    other_verification = _verify_lease_binding(
        other[0], other[2], other[3], other[4], other[5]
    )

    assert reference_clone == reference
    assert hash(reference_clone) == hash(reference)
    for attempted_guard in (
        forged,
        other_verification,
        reference_clone,
        str(reference),
    ):
        _assert_sparse_denial(
            module,
            lambda attempted_guard=attempted_guard: (
                allocator.close_lease_binding_verification(attempted_guard)
            ),
        )
    for attempted_guard in (reference_clone, str(reference)):
        _assert_sparse_denial(
            module,
            lambda attempted_guard=attempted_guard: (
                allocator.lease_binding_reference_for(attempted_guard)
            ),
        )
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            allocator, receipt, lease, ticket, capacity_evidence
        ),
    )
    assert verification in allocator._active_lease_binding_verifications
    allocator.close_lease_binding_verification(verification)
    _assert_sparse_denial(
        module,
        lambda: allocator.close_lease_binding_verification(verification),
    )
    other[0].close_lease_binding_verification(other_verification)


def test_private_binding_types_require_issuers_and_opaque_text_rejects_pickle() -> None:
    module = _allocator_module()

    with pytest.raises(TypeError, match="verifications are allocator-issued only"):
        module.LeaseBindingVerificationV1()
    with pytest.raises(TypeError, match="references use the private document codec"):
        module.LeaseBindingReferenceV1()
    with pytest.raises(TypeError, match="internals are not serializable"):
        pickle.dumps(module._OpaqueText("redacted"))


def test_lease_binding_reference_codec_is_redacted_and_cannot_cross_process() -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module)
    )
    verification = _verify_lease_binding(
        allocator, receipt, lease, ticket, capacity_evidence
    )
    reference = allocator.lease_binding_reference_for(verification)
    document_value = module._lease_binding_reference_to_document(reference)
    decoded = module._lease_binding_reference_from_document(document_value)
    replacement_allocator = module.RuntimeAccountAllocator(_ReceiptAdapter(module))

    assert document_value == receipt._lease_binding_digest
    assert decoded == reference
    assert repr(reference) == "<LeaseBindingReferenceV1 redacted>"
    assert str(reference) == repr(reference)
    for value in (verification, reference, decoded):
        for serialize in (
            lambda value=value: copy.copy(value),
            lambda value=value: copy.deepcopy(value),
            lambda value=value: pickle.dumps(value),
            lambda value=value: dataclasses.asdict(value),
            lambda value=value: dataclasses.replace(value),
            lambda value=value: json.dumps(value),
        ):
            with pytest.raises(TypeError):
                serialize()
    _assert_sparse_denial(
        module,
        lambda: replacement_allocator.lease_binding_reference_for(verification),
    )
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            replacement_allocator, receipt, lease, ticket, capacity_evidence
        ),
    )
    _assert_sparse_denial(
        module,
        lambda: _verify_lease_binding(
            replacement_allocator, reference, lease, ticket, capacity_evidence
        ),
    )
    allocator.close_lease_binding_verification(verification)


def test_lease_binding_guard_defers_exact_revoke_until_close_outside_lock() -> None:
    module = _allocator_module()

    class TrackingAdapter(_ReceiptAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.release_calls = []
            self.lock_observations = []
            self.allocator = None

        def release_reservation(self, reservation) -> bool:
            self.release_calls.append(reservation.reservation_id)
            self.lock_observations.append(self.allocator._lock.locked())
            return reservation is self.last_reservation

    allocator, adapter, receipt, lease, ticket, capacity_evidence, reservation = (
        _verification_binding(module, TrackingAdapter)
    )
    adapter.allocator = allocator
    verification = _verify_lease_binding(
        allocator, receipt, lease, ticket, capacity_evidence
    )

    allocator.revoke(lease, "between-verify-and-close")

    assert adapter.release_calls == []
    assert allocator._records[lease.lease_id].state is module.LeaseState.RESERVED
    (
        foreign_allocator,
        foreign_adapter,
        foreign_receipt,
        foreign_lease,
        foreign_ticket,
        foreign_evidence,
        _,
    ) = _verification_binding(module, TrackingAdapter)
    foreign_adapter.allocator = foreign_allocator
    foreign_verification = _verify_lease_binding(
        foreign_allocator,
        foreign_receipt,
        foreign_lease,
        foreign_ticket,
        foreign_evidence,
    )
    _assert_sparse_denial(
        module,
        lambda: allocator.close_lease_binding_verification(foreign_verification),
    )
    assert adapter.release_calls == []
    assert foreign_adapter.release_calls == []
    foreign_allocator.close_lease_binding_verification(foreign_verification)
    allocator.close_lease_binding_verification(verification)
    assert adapter.release_calls == [reservation.reservation_id]
    assert adapter.lock_observations == [False]
    assert allocator._records[lease.lease_id].state is module.LeaseState.REVOKED


def test_lease_binding_drifted_guard_closes_without_release_and_signals_quarantine() -> (
    None
):
    module = _allocator_module()

    class TrackingAdapter(_ReceiptAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.release_calls = []

        def release_reservation(self, reservation) -> bool:
            self.release_calls.append(reservation.reservation_id)
            return True

    allocator, adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module, TrackingAdapter)
    )
    verification = _verify_lease_binding(
        allocator, receipt, lease, ticket, capacity_evidence
    )
    original = lease.account_binding_digest
    object.__setattr__(lease, "account_binding_digest", "sha256:" + "e" * 64)
    try:
        allocator.revoke(lease, "defer-drifted-record")
        _assert_sparse_denial(
            module,
            lambda: allocator.close_lease_binding_verification(verification),
        )
        assert allocator._active_lease_binding_verifications == {}
        assert allocator._deferred_lease_binding_revokes == {}
        assert adapter.release_calls == []
    finally:
        object.__setattr__(lease, "account_binding_digest", original)


def test_lease_binding_reference_is_stable_per_record_but_guard_is_fresh() -> None:
    module = _allocator_module()
    allocator, _adapter, receipt, lease, ticket, capacity_evidence, _reservation = (
        _verification_binding(module)
    )
    first = _verify_lease_binding(allocator, receipt, lease, ticket, capacity_evidence)
    first_reference = allocator.lease_binding_reference_for(first)
    allocator.close_lease_binding_verification(first)
    second = _verify_lease_binding(allocator, receipt, lease, ticket, capacity_evidence)
    second_reference = allocator.lease_binding_reference_for(second)

    assert second is not first
    assert second_reference == first_reference
    allocator.close_lease_binding_verification(second)


def test_lease_binding_revoke_after_closed_verify_releases_once() -> None:
    module = _allocator_module()

    class TrackingAdapter(_ReceiptAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.release_calls = []

        def release_reservation(self, reservation) -> bool:
            self.release_calls.append(reservation.reservation_id)
            return reservation is self.last_reservation

    allocator, adapter, receipt, lease, ticket, capacity_evidence, reservation = (
        _verification_binding(module, TrackingAdapter)
    )
    verification = _verify_lease_binding(
        allocator, receipt, lease, ticket, capacity_evidence
    )
    allocator.close_lease_binding_verification(verification)

    allocator.revoke(lease, "after-close")

    assert adapter.release_calls == [reservation.reservation_id]
    assert allocator._records[lease.lease_id].state is module.LeaseState.REVOKED


def test_lease_binding_verify_revoke_race_has_only_two_linearized_results() -> None:
    module = _allocator_module()

    class TrackingAdapter(_ReceiptAdapter):
        def __init__(self, allocator_module) -> None:
            super().__init__(allocator_module)
            self.release_calls = []

        def release_reservation(self, reservation) -> bool:
            self.release_calls.append(reservation.reservation_id)
            return reservation is self.last_reservation

    allocator, adapter, receipt, lease, ticket, capacity_evidence, reservation = (
        _verification_binding(module, TrackingAdapter)
    )
    start = Barrier(3)

    def verify_once():
        start.wait()
        try:
            return _verify_lease_binding(
                allocator, receipt, lease, ticket, capacity_evidence
            )
        except module.AllocationDenied:
            return None

    def revoke_once() -> None:
        start.wait()
        allocator.revoke(lease, "race")

    with ThreadPoolExecutor(max_workers=2) as executor:
        verification_result = executor.submit(verify_once)
        revoke_result = executor.submit(revoke_once)
        start.wait()
        verification = verification_result.result()
        revoke_result.result()

    if verification is None:
        assert allocator._records[lease.lease_id].state is module.LeaseState.REVOKED
        assert adapter.release_calls == [reservation.reservation_id]
    else:
        assert allocator._records[lease.lease_id].state is module.LeaseState.RESERVED
        assert adapter.release_calls == []
        allocator.close_lease_binding_verification(verification)
        assert adapter.release_calls == [reservation.reservation_id]
