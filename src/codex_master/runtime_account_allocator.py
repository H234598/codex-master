from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from secrets import token_urlsafe
from typing import Protocol


class AllocationDenied(Exception):
    pass


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("runtime account allocator internals are not serializable")


@dataclass(frozen=True, slots=True)
class ResolutionDecision:
    decision_id: str
    resolver_offer_generation: int
    policy_generation: int
    capability_binding_digest: str
    approved: bool


@dataclass(frozen=True, slots=True)
class ValidatedAllocationTicket:
    ticket_id: str
    resolution_decision: ResolutionDecision
    resolver_offer_generation: int
    policy_generation: int
    phase: str
    fencing_token: str


@dataclass(frozen=True, slots=True)
class CapacityEvidence:
    ticket_id: str
    resolution_decision_id: str
    resolver_offer_generation: int
    policy_generation: int
    capability_binding_digest: str
    fencing_token: str
    provider_adapter_id: str
    account_binding_digest: str
    profile_binding_digest: str
    capacity_units: int | None
    quota_units: int | None
    cost_units: int | None
    resource_units: int | None
    evidence_revision: int
    observed_at_utc: datetime
    expires_at_utc: datetime


@dataclass(frozen=True, slots=True)
class TransactionEvidence:
    ticket_id: str
    lease_id: str
    lease_revision: int
    fencing_token: str
    phase: str


@dataclass(frozen=True, slots=True, repr=False)
class AccountBinding(_RedactedNonSerializable):
    account_binding_digest: str
    profile_binding_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class CredentialLease(_RedactedNonSerializable):
    lease_id: str
    account_binding_digest: str
    profile_binding_digest: str
    provider_adapter_id: str
    lease_revision: int
    expires_at_utc: datetime


class CapabilityProviderAdapter(Protocol):
    adapter_id: str

    def reserve_capability(
        self, capability_binding_digest: str, capacity_evidence: CapacityEvidence
    ) -> AccountBinding | None: ...


class LeaseState(str, Enum):
    RESERVED = "reserved"
    REVOKED = "revoked"


@dataclass(slots=True)
class _LeaseRecord:
    lease: CredentialLease
    ticket_id: str
    fencing_token: str
    phase: str
    evidence_revision: int
    state: LeaseState


class RuntimeAccountAllocator:
    __slots__ = ("_provider_adapter", "_records")

    def __init__(self, provider_adapter: CapabilityProviderAdapter) -> None:
        self._provider_adapter = provider_adapter
        self._records: dict[str, _LeaseRecord] = {}

    def allocate(self, ticket: object, capacity_evidence: object) -> CredentialLease:
        if not self._ticket_is_valid(ticket) or not self._evidence_is_valid(
            ticket, capacity_evidence
        ):
            raise AllocationDenied("runtime account allocation denied")

        adapter_id = getattr(self._provider_adapter, "adapter_id", None)
        if adapter_id != capacity_evidence.provider_adapter_id:
            raise AllocationDenied("runtime account allocation denied")

        binding = self._provider_adapter.reserve_capability(
            ticket.resolution_decision.capability_binding_digest,
            capacity_evidence,
        )
        if not self._binding_matches_evidence(binding, capacity_evidence):
            raise AllocationDenied("runtime account allocation denied")

        active = [
            record
            for record in self._records.values()
            if record.state is LeaseState.RESERVED
            and record.lease.account_binding_digest
            == capacity_evidence.account_binding_digest
        ]
        if active and (
            capacity_evidence.evidence_revision
            <= max(record.evidence_revision for record in active)
            or min(
                capacity_evidence.capacity_units,
                capacity_evidence.quota_units,
                capacity_evidence.cost_units,
                capacity_evidence.resource_units,
            )
            <= len(active)
        ):
            raise AllocationDenied("runtime account allocation denied")

        lease = CredentialLease(
            lease_id=token_urlsafe(18),
            account_binding_digest=capacity_evidence.account_binding_digest,
            profile_binding_digest=capacity_evidence.profile_binding_digest,
            provider_adapter_id=adapter_id,
            lease_revision=capacity_evidence.evidence_revision,
            expires_at_utc=capacity_evidence.expires_at_utc,
        )
        self._records[lease.lease_id] = _LeaseRecord(
            lease=lease,
            ticket_id=ticket.ticket_id,
            fencing_token=ticket.fencing_token,
            phase="LEASE_RESERVED",
            evidence_revision=capacity_evidence.evidence_revision,
            state=LeaseState.RESERVED,
        )
        return lease

    def revoke(self, lease: object, reason: object) -> None:
        del reason
        if not isinstance(lease, CredentialLease):
            return
        record = self._records.get(lease.lease_id)
        if record is None or record.lease != lease:
            return
        record.state = LeaseState.REVOKED

    def recover(self, transaction_evidence: object) -> LeaseState:
        if not isinstance(transaction_evidence, TransactionEvidence):
            raise AllocationDenied("runtime account allocation denied")
        record = self._records.get(transaction_evidence.lease_id)
        if record is None or (
            transaction_evidence.ticket_id != record.ticket_id
            or transaction_evidence.lease_revision != record.lease.lease_revision
            or transaction_evidence.fencing_token != record.fencing_token
            or transaction_evidence.phase != record.phase
        ):
            raise AllocationDenied("runtime account allocation denied")
        return record.state

    @staticmethod
    def _ticket_is_valid(ticket: object) -> bool:
        if not isinstance(ticket, ValidatedAllocationTicket):
            return False
        decision = ticket.resolution_decision
        return (
            decision.approved is True
            and ticket.phase == "OFFER_VALIDATED"
            and ticket.resolver_offer_generation > 0
            and ticket.policy_generation > 0
            and ticket.resolver_offer_generation == decision.resolver_offer_generation
            and ticket.policy_generation == decision.policy_generation
        )

    @staticmethod
    def _evidence_is_valid(
        ticket: ValidatedAllocationTicket, capacity_evidence: object
    ) -> bool:
        if not isinstance(capacity_evidence, CapacityEvidence):
            return False
        decision = ticket.resolution_decision
        numeric_evidence = (
            capacity_evidence.capacity_units,
            capacity_evidence.quota_units,
            capacity_evidence.cost_units,
            capacity_evidence.resource_units,
            capacity_evidence.evidence_revision,
        )
        if any(type(value) is not int or value <= 0 for value in numeric_evidence):
            return False
        if (
            not all(
                isinstance(value, str) and value
                for value in (
                    capacity_evidence.provider_adapter_id,
                    capacity_evidence.account_binding_digest,
                    capacity_evidence.profile_binding_digest,
                )
            )
            or capacity_evidence.observed_at_utc.tzinfo is None
            or capacity_evidence.expires_at_utc.tzinfo is None
        ):
            return False
        now = datetime.now(UTC)
        return (
            capacity_evidence.ticket_id == ticket.ticket_id
            and capacity_evidence.resolution_decision_id == decision.decision_id
            and capacity_evidence.resolver_offer_generation
            == ticket.resolver_offer_generation
            and capacity_evidence.policy_generation == ticket.policy_generation
            and capacity_evidence.capability_binding_digest
            == decision.capability_binding_digest
            and capacity_evidence.fencing_token == ticket.fencing_token
            and capacity_evidence.observed_at_utc
            <= now
            <= capacity_evidence.expires_at_utc
        )

    @staticmethod
    def _binding_matches_evidence(
        binding: object, capacity_evidence: CapacityEvidence
    ) -> bool:
        return (
            getattr(binding, "account_binding_digest", None)
            == capacity_evidence.account_binding_digest
            and getattr(binding, "profile_binding_digest", None)
            == capacity_evidence.profile_binding_digest
        )


__all__ = [
    "AccountBinding",
    "AllocationDenied",
    "CapabilityProviderAdapter",
    "CapacityEvidence",
    "CredentialLease",
    "LeaseState",
    "ResolutionDecision",
    "RuntimeAccountAllocator",
    "TransactionEvidence",
    "ValidatedAllocationTicket",
]
