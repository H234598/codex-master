import ast
import dataclasses
import importlib.util
import inspect
import json
import pickle
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


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


def _ticket(module, *, approved: bool = True, phase: str = "OFFER_VALIDATED"):
    decision = module.ResolutionDecision(
        decision_id="decision-A",
        resolver_offer_generation=7,
        policy_generation=11,
        capability_binding_digest="capability-A",
        approved=approved,
    )
    return module.ValidatedAllocationTicket(
        ticket_id="ticket-A",
        resolution_decision=decision,
        resolver_offer_generation=7,
        policy_generation=11,
        phase=phase,
        fencing_token="fence-A",
    )


def _capacity_evidence(module, **changes):
    now = datetime.now(UTC)
    values = {
        "ticket_id": "ticket-A",
        "resolution_decision_id": "decision-A",
        "resolver_offer_generation": 7,
        "policy_generation": 11,
        "capability_binding_digest": "capability-A",
        "fencing_token": "fence-A",
        "provider_adapter_id": "adapter-A",
        "account_binding_digest": "account-A",
        "profile_binding_digest": "profile-A",
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


def _transaction_evidence(
    module, lease, *, fencing_token: str = "fence-A", phase: str = "LEASE_RESERVED"
):
    return module.TransactionEvidence(
        ticket_id="ticket-A",
        lease_id=lease.lease_id,
        lease_revision=lease.lease_revision,
        fencing_token=fencing_token,
        phase=phase,
    )


class _CapabilityAdapter:
    adapter_id = "adapter-A"

    def reserve_capability(self, capability_binding_digest, capacity_evidence):
        assert capability_binding_digest == "capability-A"
        return self._binding(capacity_evidence)

    @staticmethod
    def _binding(capacity_evidence):
        return _allocator_module().AccountBinding(
            account_binding_digest=capacity_evidence.account_binding_digest,
            profile_binding_digest=capacity_evidence.profile_binding_digest,
        )


def test_allocator_selects_account_only_after_validated_ticket() -> None:
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_CapabilityAdapter())
    evidence = _capacity_evidence(module)

    with pytest.raises(module.AllocationDenied):
        allocator.allocate(_ticket(module, approved=False), evidence)

    lease = allocator.allocate(_ticket(module), evidence)

    assert lease.account_binding_digest == "account-A"
    assert lease.profile_binding_digest == "profile-A"
    assert lease.provider_adapter_id == "adapter-A"


def test_allocator_allows_parallel_same_account_leases_only_with_capacity_evidence() -> (
    None
):
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_CapabilityAdapter())
    ticket = _ticket(module)

    first = allocator.allocate(ticket, _capacity_evidence(module, evidence_revision=1))
    second = allocator.allocate(ticket, _capacity_evidence(module, evidence_revision=2))

    assert first.account_binding_digest == second.account_binding_digest == "account-A"
    assert first.lease_revision == 1
    assert second.lease_revision == 2


def test_allocator_denies_unknown_quota_cost_or_resource_evidence() -> None:
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_CapabilityAdapter())
    ticket = _ticket(module)

    invalid_evidence = (
        _capacity_evidence(module, capacity_units=None),
        _capacity_evidence(module, quota_units=None),
        _capacity_evidence(module, cost_units=None),
        _capacity_evidence(module, resource_units=None),
        _capacity_evidence(module, expires_at_utc=datetime(2000, 1, 1, tzinfo=UTC)),
        _capacity_evidence(module, fencing_token="other-fence"),
    )

    for evidence in invalid_evidence:
        with pytest.raises(module.AllocationDenied):
            allocator.allocate(ticket, evidence)


def test_lease_is_opaque_redacted_and_revoke_is_idempotent() -> None:
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_CapabilityAdapter())
    lease = allocator.allocate(_ticket(module), _capacity_evidence(module))

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
    assert (
        allocator.recover(_transaction_evidence(module, lease))
        is module.LeaseState.REVOKED
    )


def test_allocator_never_accepts_static_account_profile_or_home_selector() -> None:
    module = _allocator_module()
    fields = tuple(field.name for field in dataclasses.fields(module.CredentialLease))
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
        adapter_id = "adapter-A"

        def __getattribute__(self, name):
            if name in {"role", "agent_class", "series"}:
                raise AssertionError(f"provider policy access: {name}")
            return super().__getattribute__(name)

        def reserve_capability(self, capability_binding_digest, capacity_evidence):
            assert capability_binding_digest == "capability-A"
            return module.AccountBinding(
                account_binding_digest=capacity_evidence.account_binding_digest,
                profile_binding_digest=capacity_evidence.profile_binding_digest,
            )

    lease = module.RuntimeAccountAllocator(CapabilityOnlyAdapter()).allocate(
        _ticket(module), _capacity_evidence(module)
    )

    assert lease.provider_adapter_id == "adapter-A"


def test_recover_requires_matching_lease_revision_fencing_and_phase() -> None:
    module = _allocator_module()
    allocator = module.RuntimeAccountAllocator(_CapabilityAdapter())
    lease = allocator.allocate(_ticket(module), _capacity_evidence(module))

    with pytest.raises(module.AllocationDenied):
        allocator.recover(_transaction_evidence(module, lease, fencing_token="wrong"))
    with pytest.raises(module.AllocationDenied):
        allocator.recover(
            module.TransactionEvidence(
                ticket_id="ticket-A",
                lease_id=lease.lease_id,
                lease_revision=lease.lease_revision + 1,
                fencing_token="fence-A",
                phase="LEASE_RESERVED",
            )
        )
    with pytest.raises(module.AllocationDenied):
        allocator.recover(_transaction_evidence(module, lease, phase="PROJECTED"))

    assert (
        allocator.recover(_transaction_evidence(module, lease))
        is module.LeaseState.RESERVED
    )
